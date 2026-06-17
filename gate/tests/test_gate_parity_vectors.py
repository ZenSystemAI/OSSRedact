"""SHARED catastrophic-shape parity vectors -- the gate (thin floor) leg.

The floors are TIERED (thin on the GPU-paired gate, thick on offline/client), but the SAFETY
CORE must be byte-identical on EVERY surface: email, UUID, mod-97 IBAN, Luhn card, Luhn SIN with
Business-Number suppression + SIN-cue override. This suite, its appliance twin
(appliance/tests/test_appliance_parity_vectors.py) and its TS twin (packages/redaction-core/src/parity.test.ts)
all load the SAME validation/parity_vectors.json and assert the SAME spans, so if any future edit
drifts the safety core on ANY one surface, exactly one of the three suites goes red.

We assert by PRESENCE (label + value substring), never by exact span-set equality: the thick floors
legitimately add tiered-only spans (a generic digit-run sensitive_account_id over the IBAN digits,
etc.) that the thin gate floor intentionally omits. Presence + the BN suppression (absence) assertion
is what is shared. Over-redaction is the safe error; we never assert a safety-core shape is ABSENT
except for the one BN case the design deliberately suppresses.

Torch-free (no model). 100% synthetic inputs; the Luhn/mod-97-valid values are public test vectors.
Run: .venv-test/bin/python -m pytest gate/tests/test_gate_parity_vectors.py -v
"""
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from privacy_gate import validated_floor  # noqa: E402

_VECTORS_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'validation', 'parity_vectors.json')
with open(_VECTORS_PATH, encoding='utf-8') as _f:
    VECTORS = json.load(_f)


def _spans(text):
    # (label, substring) pairs as the floor reports them, offsets indexing the ORIGINAL text.
    return [(s['label'], text[s['start']:s['end']]) for s in validated_floor(text)]


def _has(spans, label, value, digits_only=False):
    """Presence test: some span has this label whose substring contains the expected value. When
    digits_only is set, compare on digits only so separator spacing (space/NBSP/hyphen) is immaterial."""
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
            f"{case['id']}: label {lab!r} must be SUPPRESSED on the gate floor but was emitted: {spans}")
