"""SHARED catastrophic-shape parity vectors -- the appliance (thick floor) leg.

Twin of gate/tests/test_gate_parity_vectors.py and packages/redaction-core/src/parity.test.ts: all three
load the SAME validation/parity_vectors.json and assert the SAME safety-core spans (email, UUID,
mod-97 IBAN, Luhn card, Luhn SIN + Business-Number suppression + SIN-cue override). The floors are
TIERED -- the deployed appliance floor is THICK (it also emits phone/date/postal/ip/generic-digit-run,
which the thin gate floor omits) -- so we assert by PRESENCE (label + value substring), never by exact
span-set equality. The thick floor adds tiered-only spans (e.g. a generic sensitive_account_id over the
IBAN digit tail); those are expected and do not break safety-core parity. The one ABSENCE we assert is
the Business Number suppression, which every surface must honour identically.

Loaded by explicit path because gate/privacy_gate.py shares the module name 'privacy_gate'.
Torch-free (regex only). 100% synthetic / public ISO + Luhn test vectors; no real PII.
Run: .venv-test/bin/python -m pytest appliance/tests/test_appliance_parity_vectors.py -v
"""
import importlib.util
import json
import os
import re

import pytest

_PATH = os.path.join(os.path.dirname(__file__), '..', 'privacy_gate.py')
_spec = importlib.util.spec_from_file_location('appliance_privacy_gate', _PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
tier0_spans = _mod.tier0_spans

_VECTORS_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'validation', 'parity_vectors.json')
with open(_VECTORS_PATH, encoding='utf-8') as _f:
    VECTORS = json.load(_f)


def _spans(text):
    return [(s['label'], text[s['start']:s['end']]) for s in tier0_spans(text)]


def _has(spans, label, value, digits_only=False):
    """Presence test: some span has this label whose substring contains the expected value. digits_only
    compares on digits only so separator spacing (space/NBSP/hyphen) does not matter."""
    if digits_only:
        want = re.sub(r'\D', '', value)
        return any(lab == label and want in re.sub(r'\D', '', sub) for lab, sub in spans)
    return any(lab == label and value in sub for lab, sub in spans)


@pytest.mark.parametrize('case', VECTORS, ids=[c['id'] for c in VECTORS])
def test_safety_core_parity(case):
    spans = _spans(case['text'])
    for exp in case.get('expect', []):
        assert _has(spans, exp['label'], exp['value'], exp.get('digits_only', False)), (
            f"{case['id']}: expected safety-core span {exp['label']}={exp['value']!r} not found in {spans}")
    for lab in case.get('suppress', []):
        assert not any(l == lab for l, _ in spans), (
            f"{case['id']}: label {lab!r} must be SUPPRESSED on the appliance floor but was emitted: {spans}")
