"""Floor tests for the DEPLOYED appliance gate (appliance/privacy_gate.py tier0_spans).

Validates two backports made off-prod (the live redeploy is a separate, operator-gated step):
  - F14: the IBAN mod-97 deterministic backstop (the deployed floor previously had NO IBAN catch).
  - Finding A: Canadian Business Number suppression + SIN-cue override.

Torch-free (regex only). 100% synthetic / public ISO + Luhn test vectors; no real PII.
Loaded by explicit path because gate/privacy_gate.py shares the module name 'privacy_gate'.
Run: .venv-test/bin/python -m pytest appliance/tests/ -v
"""
import importlib.util
import os

_PATH = os.path.join(os.path.dirname(__file__), '..', 'privacy_gate.py')
_spec = importlib.util.spec_from_file_location('appliance_privacy_gate', _PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
tier0_spans = _mod.tier0_spans
PrivacyGate = _mod.PrivacyGate
show = _mod.show


def labset(text):
    return {(s['label'], text[s['start']:s['end']]) for s in tier0_spans(text)}


def labels(text):
    return {s['label'] for s in tier0_spans(text)}


def _span(text, value, label, start_at=0):
    i = text.index(value, start_at)
    return {'start': i, 'end': i + len(value), 'label': label, 'tier': 0, 'conf': 1.0, 'rule': 'test'}


# ---- F14: IBAN deterministic backstop ----
def test_appliance_iban_mod97_backstop():
    assert ('iban', 'GB82WEST12345698765432') in labset('solde IBAN GB82WEST12345698765432 fin')
    # a mod-97-INVALID lookalike is NOT emitted as iban (the model can still catch it)
    assert 'iban' not in labels('ref GB82WEST12345698765433 fin')


def test_appliance_iban_with_internal_spaces():
    assert ('iban', 'GB82 WEST 1234 5698 7654 32') in labset('IBAN GB82 WEST 1234 5698 7654 32 .')


def test_appliance_iban_lowercase_and_hyphenated():
    assert ('iban', 'gb82west12345698765432') in labset('IBAN gb82west12345698765432 .')
    assert ('iban', 'GB82-WEST-1234-5698-7654-32') in labset('IBAN GB82-WEST-1234-5698-7654-32 .')


# ---- Finding A: Business Number suppression + SIN-cue override ----
def test_appliance_suppresses_business_number():
    assert 'government_id' not in labels('TPS 046454286 RT0001')
    assert 'government_id' not in labels('Business number 046454286 RT0001')  # word-bounded cue (not substring)


def test_appliance_sin_cue_overrides_bn():
    # never-leak guarantee: a SIN cue before the number forces emission even with a BN-looking suffix
    assert 'government_id' in labels('NAS 046454286 RT0001')


def test_appliance_still_emits_bare_sin():
    assert ('government_id', '046454286') in labset('NAS 046454286')


# ---- Label-aware dedup: case-significant credentials stay lossless ----
def test_appliance_redact_case_sensitive_password_variants_lossless(monkeypatch):
    text = "primary AbC123xy backup abc123xy repeat abc123xy."
    spans = [_span(text, "AbC123xy", "password"), _span(text, "abc123xy", "password")]
    gate = PrivacyGate(None)
    monkeypatch.setattr(gate, 'detect', lambda _text, min_score=0.5: spans)
    redacted, mapping, _ = gate.redact(text)
    assert redacted.count("<PASSWORD_001>") == 1
    assert redacted.count("<PASSWORD_002>") == 2
    assert mapping == {"<PASSWORD_001>": "AbC123xy", "<PASSWORD_002>": "abc123xy"}
    assert PrivacyGate.rehydrate(redacted, mapping) == text


def test_appliance_demo_show_does_not_print_raw_input_or_map_value(capsys):
    class FakeGate:
        def redact(self, text, min_score=0.5):
            return (
                "Contact <EMAIL_001>",
                {"<EMAIL_001>": "demo.user@example.test"},
                [{"label": "email", "tier": 0}],
            )

    show(FakeGate(), "Contact demo.user@example.test")
    out = capsys.readouterr().out
    assert "demo.user@example.test" not in out
    assert "Contact <EMAIL_001>" in out
    assert "MAP_KEYS: ['<EMAIL_001>']" in out
    assert "ROUNDTRIP OK: True" in out
