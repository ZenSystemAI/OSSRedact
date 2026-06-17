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


def labset(text):
    return {(s['label'], text[s['start']:s['end']]) for s in tier0_spans(text)}


def labels(text):
    return {s['label'] for s in tier0_spans(text)}


# ---- F14: IBAN deterministic backstop ----
def test_appliance_iban_mod97_backstop():
    assert ('iban', 'GB82WEST12345698765432') in labset('solde IBAN GB82WEST12345698765432 fin')
    # a mod-97-INVALID lookalike is NOT emitted as iban (the model can still catch it)
    assert 'iban' not in labels('ref GB82WEST12345698765433 fin')


def test_appliance_iban_with_internal_spaces():
    assert ('iban', 'GB82 WEST 1234 5698 7654 32') in labset('IBAN GB82 WEST 1234 5698 7654 32 .')


# ---- Finding A: Business Number suppression + SIN-cue override ----
def test_appliance_suppresses_business_number():
    assert 'government_id' not in labels('TPS 046454286 RT0001')
    assert 'government_id' not in labels('Business number 046454286 RT0001')  # word-bounded cue (not substring)


def test_appliance_sin_cue_overrides_bn():
    # never-leak guarantee: a SIN cue before the number forces emission even with a BN-looking suffix
    assert 'government_id' in labels('NAS 046454286 RT0001')


def test_appliance_still_emits_bare_sin():
    assert ('government_id', '046454286') in labset('NAS 046454286')
