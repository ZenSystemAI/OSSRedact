"""SHARED deterministic parity vectors -- the appliance (thick floor) leg.

Twin of gate/tests/test_gate_parity_vectors.py and packages/redaction-core/src/parity.test.ts: all three
load the SAME validation/parity_vectors.json and assert the SAME safety-core spans (email, UUID,
mod-97 IBAN, Luhn card, Luhn SIN + Business-Number suppression + SIN-cue override, and cue-anchored
mailbox/header person names). The floors are
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


# --- Explicit superset guard: appliance floor ⊇ gate floor -----------------------------------------------
# The deployed appliance runs a THICKER deterministic floor than the GPU-paired gate (gate leaves loose
# shapes to its co-located neural tier). That divergence is INTENTIONAL only in one direction: the appliance
# may catch MORE, never LESS. If a future edit makes the appliance floor miss a safety-core span the gate
# floor still catches, that is a real under-redaction/leak -- this test makes that contract enforceable
# (the README's "strict superset, not drift" claim). The gate floor is loaded under a unique module name so
# it coexists with the appliance copy in one interpreter (both files share the bare name 'privacy_gate').
_GATE_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'gate', 'privacy_gate.py')
_gspec = importlib.util.spec_from_file_location('gate_privacy_gate', _GATE_PATH)
_gmod = importlib.util.module_from_spec(_gspec)
_gspec.loader.exec_module(_gmod)


def _gate_spans(text):
    return [(s['label'], text[s['start']:s['end']])
            for s in _gmod.validated_floor(text) + _gmod.cue_name_spans(text) + _gmod.cue_digit_spans(text)]


def _covered(appliance_spans, label, value):
    """True if some appliance span has this label and overlaps value (either substring contains the other),
    digit-insensitively for numeric values so separator spacing never matters."""
    dv = re.sub(r'\D', '', value)
    for lab, sub in appliance_spans:
        if lab != label:
            continue
        if value in sub or sub in value:
            return True
        if dv and dv in re.sub(r'\D', '', sub):
            return True
    return False


@pytest.mark.parametrize('case', VECTORS, ids=[c['id'] for c in VECTORS])
def test_appliance_floor_is_superset_of_gate_floor(case):
    appliance_spans = _spans(case['text'])
    for lab, sub in _gate_spans(case['text']):
        assert _covered(appliance_spans, lab, sub), (
            f"{case['id']}: gate floor emits {lab}={sub!r} but the appliance floor does not cover it -- the "
            f"appliance under-redacts vs the gate (a LEAK direction). appliance spans: {appliance_spans}")
