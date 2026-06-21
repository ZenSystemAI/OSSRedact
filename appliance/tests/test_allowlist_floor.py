"""apply_allowlist FLOOR GUARD (parity with the TS twin + the gate's FLOOR_NEVER_EXEMPT): a hard-floor span
is never dropped by the allowlist, even when its exact text is declared. Soft spans still drop. Torch-free,
synthetic inputs. Run: .venv-test/bin/python -m pytest appliance/tests/test_allowlist_floor.py -q
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import allowlist as al  # noqa: E402
from privacy_gate import FLOOR_LABELS  # noqa: E402


def _span(text, value, label):
    i = text.index(value)
    return {'start': i, 'end': i + len(value), 'label': label}


def test_floor_span_survives_allowlisting_but_soft_span_drops():
    card = '4111111111111111'
    text = f'card {card} and name Alex'
    allow = al.build_allow_set([card, 'alex'])  # user (mistakenly) allowlists a real card + their own name
    spans = [_span(text, card, 'payment_card'), _span(text, 'Alex', 'person')]
    kept = al.apply_allowlist(spans, text, allow)
    assert len(kept) == 1
    assert kept[0]['label'] == 'payment_card'  # card stays (floor); the allowlisted name drops


def test_every_floor_label_survives_allowlisting():
    text = 'value SENSITIVE here'
    allow = al.build_allow_set(['SENSITIVE'])
    for label in FLOOR_LABELS:
        kept = al.apply_allowlist([_span(text, 'SENSITIVE', label)], text, allow)
        assert len(kept) == 1, f'{label} must survive allowlisting'


def test_soft_label_still_exempt():
    text = 'hello Alex'
    allow = al.build_allow_set(['alex'])
    assert al.apply_allowlist([_span(text, 'Alex', 'person')], text, allow) == []
