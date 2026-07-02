"""Replay/scoring harness regression suite (RC2 foundation).

Pins the DETERMINISTIC (tier-0 + policy) over-redaction footprint on coding-agent traffic so detection-precision
changes are validated, not made blind -- and guards the hard invariants (no PII leak, lossless rehydrate,
prompt-cache stability). Imports egress_proxy via test_egress_e2e so the same torch/httpx/fastapi stubs make it
CI-runnable (torch-free). All PII is synthetic. To also score the NEURAL tier, pass a real /detect client as the
detector on the GPU box; here we score tier-0 only (detector returns no spans).
"""
import os
import sys
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_egress_e2e import egress_proxy  # noqa: E402  (reuses its dependency stubs)
import replay_harness  # noqa: E402


# Synthetic coding-agent traffic. `must_redact` = planted PII that MUST disappear; `benign` = non-PII that must
# survive verbatim. The card is a Luhn-valid test number; the IBAN/SIN are well-formed but fictitious.
CODING_FIXTURES = [
    {'name': 'net_addrs',
     'text': 'Bind 0.0.0.0:8011, peer ::1, upstream 127.0.0.1:8001 in dev.',
     'must_redact': [],
     'benign': ['8011', '8001', '0.0.0.0', '::1', '127.0.0.1']},
    {'name': 'versions_consts',
     'text': 'Bump to 2.4.11 (was 1.10.3); MAX_TOKENS=200000; retries=3.',
     'must_redact': [],
     'benign': ['2.4.11', '1.10.3', '200000', 'MAX_TOKENS']},
    {'name': 'pii_in_comment',
     'text': '# owner devops@acme.test, test card 4111 1111 1111 1111, iban FR7630006000011234567890189',
     'must_redact': ['devops@acme.test', '4111 1111 1111 1111', 'FR7630006000011234567890189'],
     'benign': ['owner', 'card']},
    {'name': 'sin_vs_build_id',
     'text': 'User SIN 046 454 286; build id 123456789; commit a1b2c3d4e5f60718293a4b5c6d7e8f9012345678.',
     'must_redact': ['046 454 286'],
     'benign': ['123456789', 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678']},
]

# Current deterministic over-redaction footprint in CODING mode -- the TUNING TARGETS the harness exists to
# drive down. Pinned so a NEW false positive fails the suite and a precision improvement is a DELIBERATE edit.
# IP literals were REMOVED from this set once coding mode started excluding `ip` (bind/localhost/config addresses
# pass through; privacy mode still redacts them). What remains is the HARD case:
#   - a 9-digit build id hits the government_id floor (a real SIN sits next to it -> the precision/recall tension
#     that needs the neural/context tier, NOT a blanket floor demotion).
BASELINE_OVER_REDACTION = {
    ('sin_vs_build_id', '123456789'),
}


def _make_redact_fn(detector, project='replay'):
    def redact_fn(text, session):
        body = {'model': 'replay', 'messages': [{'role': 'user', 'content': text}]}
        _meta, replay = asyncio.run(
            egress_proxy.redact_body(body, {'session': session, 'project': project}, detector=detector))
        return body['messages'][0]['content'], replay
    return redact_fn


def _isolate_config(monkeypatch, tmp_path, mode):
    m = tmp_path / 'mode'; m.write_text(mode); monkeypatch.setattr(egress_proxy, '_MODE_FILE', str(m))
    a = tmp_path / 'allow'; a.write_text(''); monkeypatch.setattr(egress_proxy, '_ALLOWLIST_FILE', str(a))
    d = tmp_path / 'deny'; d.write_text(''); monkeypatch.setattr(egress_proxy, '_DENYLIST_FILE', str(d))


async def _noop_detector(text, min_score=0.5):
    return []


def test_replay_harness_coding_traffic_scorecard(monkeypatch, tmp_path):
    _isolate_config(monkeypatch, tmp_path, 'coding')
    card = replay_harness.score(CODING_FIXTURES, _make_redact_fn(_noop_detector))

    # HARD invariants -- these must never regress.
    assert card['recall_ok'], f'PII leaked (recall failure): {card["leaks"]}'
    assert card['all_rehydrate_ok'], 'a fixture did not round-trip losslessly'
    assert card['all_cache_stable'], 'a re-sent field was not byte-stable (prompt-cache regression)'

    # Over-redaction footprint pin (the precision target to drive down).
    assert set(card['over_redaction']) == BASELINE_OVER_REDACTION, (
        f'over-redaction footprint changed -- update BASELINE_OVER_REDACTION if intentional:\n'
        f'  got     {sorted(card["over_redaction"])}\n  baseline {sorted(BASELINE_OVER_REDACTION)}')


def test_replay_harness_privacy_redacts_more_than_coding(monkeypatch, tmp_path):
    """Sanity: privacy mode is at least as aggressive as coding -- a version string redacts in privacy (a date)
    but not coding (RC5), proving the harness actually discriminates policy. Recall holds in both."""
    fix = [{'name': 'ver', 'text': 'ship 2.4.11 today', 'must_redact': [], 'benign': ['2.4.11']}]
    _isolate_config(monkeypatch, tmp_path, 'coding')
    coding = replay_harness.score(fix, _make_redact_fn(_noop_detector))
    _isolate_config(monkeypatch, tmp_path, 'privacy')
    privacy = replay_harness.score(fix, _make_redact_fn(_noop_detector))
    assert coding['over_redaction_count'] == 0, 'coding mode must pass the version string (RC5)'
    assert privacy['over_redaction_count'] == 1, 'privacy mode redacts the version-shaped date'
    assert coding['recall_ok'] and privacy['recall_ok']
