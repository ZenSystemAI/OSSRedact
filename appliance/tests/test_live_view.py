"""The local LIVE ACTIVITY view (the in-memory redaction proof console) on the egress proxy.

Covers: the request/response event builders (real value <-> placeholder), label parsing, friendly client
labelling, the in-memory ring + subscriber fan-out, the loopback guard on every live endpoint (the feed shows
real PII values, so it must never be reachable over the network even though the gate listens on 0.0.0.0), the
status/clear API, the page wiring, and a real route-level end-to-end proving the event fires on a redaction.

100% SYNTHETIC data: a Luhn-valid TEST card (4111...) + RFC-2606 example values. No real PII.
"""
import os
import sys
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import egress_proxy  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


class _FakeReq:
    def __init__(self, headers=None, host='testclient'):
        self.headers = headers or {}
        self.client = type('C', (), {'host': host})()


def _reset_live():
    egress_proxy._live_ring.clear()
    egress_proxy._live_subscribers.clear()
    egress_proxy._live_seq = 0


# --- label parsing + client labelling -------------------------------------
def test_ph_label_parses_label_from_placeholder():
    assert egress_proxy._ph_label('<PERSON_001>') == 'person'
    assert egress_proxy._ph_label('<SENSITIVE_ACCOUNT_ID_002>') == 'sensitive_account_id'
    assert egress_proxy._ph_label('<PAYMENT_CARD_010>') == 'payment_card'
    assert egress_proxy._ph_label('not-a-placeholder') == 'value'


def test_client_label_prefers_header_then_ua_then_surface():
    assert egress_proxy._client_label(_FakeReq({'x-claude-code-session-id': 'abc'}), '/v1/messages') == 'Claude Code'
    assert egress_proxy._client_label(_FakeReq({'user-agent': 'codex_cli/1.2'}), '/v1/responses') == 'Codex'
    assert egress_proxy._client_label(_FakeReq({'user-agent': 'OpenCode/0.9'}), '/v1/chat/completions') == 'OpenCode'
    # no signal -> the API surface
    assert egress_proxy._client_label(_FakeReq({}), '/v1/chat/completions') == 'OpenAI-compatible'
    assert egress_proxy._client_label(_FakeReq({}), '/v1/responses') == 'Codex / Responses'


# --- event builders -------------------------------------------------------
def test_live_request_records_value_to_placeholder():
    _reset_live()
    ctx = {'session_resolved': 'sess-abcdef123456'}
    meta = {'redaction': 'redacted', 'n_spans': 2, 'n_new': 2, 'by_label': {'person': 1, 'email': 1}}
    replay = {'<PERSON_001>': 'Alex Martin', '<EMAIL_001>': 'alex@acme.example'}
    egress_proxy._live_request('/v1/messages', 'Claude Code', ctx, meta, replay, False)
    assert len(egress_proxy._live_ring) == 1
    ev = egress_proxy._live_ring[0]
    assert ev['kind'] == 'request' and ev['client'] == 'Claude Code' and ev['route'] == '/v1/messages'
    assert ev['session'] == 'sess-abcdef1'  # truncated to 12 chars
    by_ph = {e['placeholder']: e for e in ev['entities']}
    assert by_ph['<PERSON_001>']['value'] == 'Alex Martin' and by_ph['<PERSON_001>']['label'] == 'person'
    assert by_ph['<EMAIL_001>']['value'] == 'alex@acme.example' and by_ph['<EMAIL_001>']['label'] == 'email'


def test_live_request_clean_scan_has_no_entities():
    _reset_live()
    egress_proxy._live_request('/v1/messages', 'Claude Code', {}, {'redaction': 'scanned-clean', 'n_spans': 0}, {}, True)
    ev = egress_proxy._live_ring[0]
    assert ev['kind'] == 'request' and ev['entities'] == [] and ev['redaction'] == 'scanned-clean'


def test_live_response_only_emits_present_placeholders():
    _reset_live()
    replay = {'<PERSON_001>': 'Alex Martin', '<EMAIL_001>': 'alex@acme.example'}
    # the model's reply only echoed PERSON_001 -> only that one is reported as rehydrated
    egress_proxy._live_response('/v1/messages', 'Claude Code', {}, replay, {'<PERSON_001>'})
    ev = egress_proxy._live_ring[0]
    assert ev['kind'] == 'response' and ev['n_rehydrated'] == 1
    assert ev['entities'][0]['placeholder'] == '<PERSON_001>' and ev['entities'][0]['value'] == 'Alex Martin'


def test_live_response_noop_when_no_placeholders_present():
    _reset_live()
    egress_proxy._live_response('/v1/messages', 'c', {}, {'<PERSON_001>': 'X'}, set())
    assert len(egress_proxy._live_ring) == 0  # nothing came back -> no event


def test_emit_fans_out_to_subscribers_without_blocking():
    _reset_live()
    q = asyncio.Queue()
    egress_proxy._live_subscribers.add(q)
    egress_proxy._live_request('/v1/messages', 'c', {}, {'redaction': 'redacted'}, {'<PERSON_001>': 'X'}, False)
    ev = q.get_nowait()
    assert ev['kind'] == 'request' and ev['seq'] >= 1


def test_seq_is_monotonic_for_reconnect_dedup():
    _reset_live()
    for _ in range(3):
        egress_proxy._live_request('/v1/messages', 'c', {}, {'redaction': 'redacted'}, {'<PERSON_001>': 'X'}, False)
    seqs = [e['seq'] for e in egress_proxy._live_ring]
    assert seqs == sorted(seqs) and len(set(seqs)) == 3


# --- endpoint guards + behaviour ------------------------------------------
def test_all_live_endpoints_are_loopback_only():
    c = TestClient(egress_proxy.app)  # peer host 'testclient' is non-loopback; guard active
    assert c.get('/api/stream').status_code == 403
    assert c.get('/api/live/status').status_code == 403
    assert c.post('/api/live/clear').status_code == 403


def test_status_and_clear_roundtrip(monkeypatch):
    monkeypatch.setattr(egress_proxy, '_is_loopback', lambda req: True)
    _reset_live()
    egress_proxy._live_request('/v1/messages', 'c', {}, {'redaction': 'redacted'}, {'<PERSON_001>': 'X'}, False)
    c = TestClient(egress_proxy.app, headers={'x-ossredact-control': '1'})  # legit local client sends the CSRF header
    s = c.get('/api/live/status').json()
    assert s['enabled'] is True and s['buffered'] >= 1 and s['max'] == egress_proxy._LIVE_MAX
    assert c.post('/api/live/clear').json()['ok'] is True
    assert c.get('/api/live/status').json()['buffered'] == 0


def test_stream_route_is_registered_and_local_only(monkeypatch):
    # The SSE transport (an infinite generator) hangs an in-process TestClient on close, so the live wire is
    # verified in the browser proof, not here. Unit-side we assert the route exists and is loopback-guarded.
    paths = {r.path for r in egress_proxy.app.routes}
    assert '/api/stream' in paths
    assert TestClient(egress_proxy.app).get('/api/stream').status_code == 403  # non-loopback peer -> blocked


def test_stream_404_when_live_view_disabled(monkeypatch):
    monkeypatch.setattr(egress_proxy, '_is_loopback', lambda req: True)
    monkeypatch.setattr(egress_proxy, 'LIVE_VIEW', False)
    c = TestClient(egress_proxy.app)
    assert c.get('/api/stream').status_code == 404


def test_settings_page_has_both_tabs_and_stream_wiring(monkeypatch):
    monkeypatch.setattr(egress_proxy, '_is_loopback', lambda req: True)
    c = TestClient(egress_proxy.app)
    r = c.get('/')
    assert r.status_code == 200
    assert 'Live activity' in r.text and 'Do-not-redact dictionary' in r.text
    assert "EventSource('/api/stream')" in r.text


# --- real route-level end-to-end: a redaction emits a live request event ---
def test_redaction_failure_fails_closed_with_503(monkeypatch):
    """Audit #5: if redact_body raises (e.g. the map-file lock / fs op throws), the route must FAIL CLOSED with
    an explicit 503 redaction_failed -- never fall through to an upstream forward of an unredacted body."""
    async def _boom(*a, **k):
        raise RuntimeError('map lock unavailable')

    monkeypatch.setattr(egress_proxy, 'redact_body', _boom)
    c = TestClient(egress_proxy.app)
    for path, payload in [
        ('/v1/messages', {'model': 'm', 'messages': [{'role': 'user', 'content': 'hi'}]}),
        ('/v1/chat/completions', {'model': 'm', 'messages': [{'role': 'user', 'content': 'hi'}]}),
        ('/v1/responses', {'model': 'm', 'input': 'hi'}),
    ]:
        r = c.post(path, json=payload)
        assert r.status_code == 503, f'{path} must 503 on redaction failure'
        assert r.json()['error'] == 'redaction_failed'


def test_route_redaction_emits_live_event(monkeypatch):
    monkeypatch.setattr(egress_proxy, '_is_loopback', lambda req: True)
    monkeypatch.setattr(egress_proxy, 'DRYRUN', True)  # return before any upstream call

    async def _no_neural(aclient, text, min_score=0.5):
        return []   # neural finds nothing; the Tier-0 floor catches the card deterministically

    monkeypatch.setattr(egress_proxy, '_detect_neural', _no_neural)
    _reset_live()
    c = TestClient(egress_proxy.app)
    body = {'model': 'claude-3', 'max_tokens': 8,
            'messages': [{'role': 'user', 'content': 'please charge card 4111111111111111 today'}]}
    r = c.post('/v1/messages', json=body, headers={'x-claude-code-session-id': 'sess-xyz789'})
    assert r.status_code == 200
    reqs = [e for e in egress_proxy._live_ring if e['kind'] == 'request']
    assert reqs, 'a live request event should have been recorded'
    ev = reqs[-1]
    assert ev['client'] == 'Claude Code' and ev['route'] == '/v1/messages'
    vals = {e['value'] for e in ev['entities']}
    assert '4111111111111111' in vals  # the real card value is shown in the local proof view
    assert any(e['label'] == 'payment_card' for e in ev['entities'])
    # and it was actually redacted to a placeholder in the upstream body the model would have seen
    assert '4111111111111111' not in egress_proxy.json.dumps(r.json()['upstream_body'])
