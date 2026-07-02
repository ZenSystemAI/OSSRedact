"""B13 parity: the appliance merge_spans must record ALL distinct member labels on a multi-category
overlap (the 'labels' audit field), exactly like gate/privacy_gate.py. Without this the appliance floor
under-reports merged categories and a Law 25 category audit is silently lied to. Ported from
gate/tests/test_merge.py so the two copies cannot drift on label-bearing behavior.

Torch-free, 100% synthetic. Run with the appliance suite (separate process from the gate suite -- both
define a module named privacy_gate). Run: .venv-test/bin/python -m pytest appliance/tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from privacy_gate import merge_spans  # noqa: E402


def test_merge_keeps_distinct_labels_on_overlap():
    spans = [
        {'start': 0, 'end': 10, 'label': 'government_id', 'conf': 0.95, 'tier': 0, 'rule': 'floor:sin'},
        {'start': 5, 'end': 14, 'label': 'date_of_birth', 'conf': 0.60, 'tier': 2, 'rule': 'gpu'},
    ]
    out = merge_spans(spans)
    assert len(out) == 1
    assert out[0]['start'] == 0 and out[0]['end'] == 14         # union covers all chars (no leak)
    assert out[0]['label'] == 'government_id'                   # primary stays floor (sticky)
    assert set(out[0]['labels']) == {'government_id', 'date_of_birth'}  # both categories recorded


def test_merge_same_label_no_multilabel_record():
    spans = [
        {'start': 0, 'end': 10, 'label': 'address', 'conf': 0.9, 'tier': 2, 'rule': 'gpu'},
        {'start': 8, 'end': 16, 'label': 'address', 'conf': 0.8, 'tier': 2, 'rule': 'gpu'},
    ]
    out = merge_spans(spans)
    assert len(out) == 1 and out[0]['label'] == 'address'
    assert 'labels' not in out[0]   # single category -> no multi-label record


def test_merge_non_overlapping_untouched():
    spans = [
        {'start': 0, 'end': 6, 'label': 'email', 'conf': 0.99, 'tier': 0, 'rule': 'floor:email'},
        {'start': 20, 'end': 36, 'label': 'payment_card', 'conf': 0.97, 'tier': 0, 'rule': 'floor:card'},
    ]
    out = merge_spans(spans)
    assert len(out) == 2
    assert all('labels' not in s for s in out)


def test_floor_label_sticky_records_soft_overlap():
    """A Tier-0 floor span (payment_card) out-scored by a higher-conf soft span keeps its FLOOR primary
    label AND records the soft guess in 'labels'. Mirrors the gate stickiness regression."""
    spans = [
        {'start': 4, 'end': 20, 'label': 'payment_card', 'conf': 0.97, 'tier': 0, 'rule': 'floor:card'},
        {'start': 4, 'end': 20, 'label': 'person', 'conf': 0.99, 'tier': 2, 'rule': 'gpu'},  # out-scores floor
    ]
    out = merge_spans(spans)
    assert len(out) == 1
    assert out[0]['label'] == 'payment_card', 'floor label must survive a higher-conf soft overlap'
    assert out[0]['start'] == 4 and out[0]['end'] == 20
    assert set(out[0]['labels']) == {'payment_card', 'person'}   # the soft guess is still recorded


def test_soft_over_soft_unchanged_by_stickiness():
    """Non-floor overlaps keep the highest-(conf,len) election; both categories still recorded."""
    spans = [
        {'start': 0, 'end': 10, 'label': 'organization', 'conf': 0.70, 'tier': 2, 'rule': 'gpu'},
        {'start': 0, 'end': 10, 'label': 'person', 'conf': 0.90, 'tier': 2, 'rule': 'gpu'},
    ]
    out = merge_spans(spans)
    assert len(out) == 1 and out[0]['label'] == 'person'   # highest conf wins, no floor involved
    assert set(out[0]['labels']) == {'organization', 'person'}
