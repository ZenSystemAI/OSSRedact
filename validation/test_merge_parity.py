"""B13 cross-copy drift guard: gate/privacy_gate.py and appliance/privacy_gate.py both define merge_spans.
They are supposed to be byte-equivalent on the floor's merge contract. This test dual-loads BOTH copies
(distinct importlib module names -- a bare `import privacy_gate` is ambiguous) and feeds identical
hand-built multi-category span inputs into both, asserting the elected primary label, the union boundaries,
floor stickiness, and the recorded `labels` set all agree. If either copy drifts (e.g. one stops recording
multi-label sets, or relabels a floor span), this fails.

Torch-free: merge_spans is pure-python and both modules import only stdlib at module scope. Runs in the
gate/validation pytest process (CI: `pytest gate/tests ... validation`). 100% synthetic inputs.
"""
import os
import importlib.util

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_gate = _load('ossr_gate_pg', 'gate/privacy_gate.py')
_appl = _load('ossr_appliance_pg', 'appliance/privacy_gate.py')
gate_merge = _gate.merge_spans
appl_merge = _appl.merge_spans


# (description, spans) -- each input is fed to BOTH merge_spans copies.
CASES = [
    ('multi-category overlap records both labels', [
        {'start': 0, 'end': 10, 'label': 'government_id', 'conf': 0.95, 'tier': 0, 'rule': 'floor:sin'},
        {'start': 5, 'end': 14, 'label': 'date_of_birth', 'conf': 0.60, 'tier': 2, 'rule': 'gpu'},
    ]),
    ('floor sticky under higher-conf soft overlap', [
        {'start': 4, 'end': 20, 'label': 'payment_card', 'conf': 0.97, 'tier': 0, 'rule': 'floor:card'},
        {'start': 4, 'end': 20, 'label': 'person', 'conf': 0.99, 'tier': 2, 'rule': 'gpu'},
    ]),
    ('soft over soft, both recorded', [
        {'start': 0, 'end': 10, 'label': 'organization', 'conf': 0.70, 'tier': 2, 'rule': 'gpu'},
        {'start': 0, 'end': 10, 'label': 'person', 'conf': 0.90, 'tier': 2, 'rule': 'gpu'},
    ]),
    ('single category, no labels field', [
        {'start': 0, 'end': 10, 'label': 'address', 'conf': 0.9, 'tier': 2, 'rule': 'gpu'},
        {'start': 8, 'end': 16, 'label': 'address', 'conf': 0.8, 'tier': 2, 'rule': 'gpu'},
    ]),
    ('non-overlapping untouched', [
        {'start': 0, 'end': 6, 'label': 'email', 'conf': 0.99, 'tier': 0, 'rule': 'floor:email'},
        {'start': 20, 'end': 36, 'label': 'payment_card', 'conf': 0.97, 'tier': 0, 'rule': 'floor:card'},
    ]),
]


def _shape(merged):
    """Normalize the merge output to the parity-relevant fields (order-stable)."""
    return [
        (m['start'], m['end'], m['label'], tuple(sorted(m.get('labels', []))))
        for m in merged
    ]


def test_merge_spans_parity_across_copies():
    for desc, spans in CASES:
        g = _shape(gate_merge([dict(s) for s in spans]))
        a = _shape(appl_merge([dict(s) for s in spans]))
        assert g == a, f'gate/appliance merge_spans drift on case: {desc}\n  gate={g}\n  appl={a}'
