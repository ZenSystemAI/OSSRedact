"""Phase 2.2 tests: label-preserving merge + postal-not-stitched-into-address.

merge_spans must keep the connected-component UNION (never leave a PII fragment exposed) but, when a
cluster contains DIFFERENT labels, record ALL of them (so a downstream category filter / audit sees the
true categories, not just the elected one). post_merge_address must stitch address fragments but must NOT
absorb a postal_code into the address (postal stays its own redaction).

Torch-free. Run: .venv-test/bin/python -m pytest gate/tests/ -v. 100% synthetic inputs.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from privacy_gate import merge_spans, post_merge_address  # noqa: E402


def test_merge_keeps_distinct_labels_on_overlap():
    spans = [
        {'start': 0, 'end': 10, 'label': 'government_id', 'conf': 0.95, 'tier': 0, 'rule': 'floor:sin'},
        {'start': 5, 'end': 14, 'label': 'date_of_birth', 'conf': 0.60, 'tier': 2, 'rule': 'gpu'},
    ]
    out = merge_spans(spans)
    assert len(out) == 1
    assert out[0]['start'] == 0 and out[0]['end'] == 14         # union covers all chars (no leak)
    assert out[0]['label'] == 'government_id'                   # primary = highest confidence
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


def test_postal_not_stitched_into_address():
    text = "123 rue Principale, Montreal  H3B 1A1"
    spans = [
        {'start': 0, 'end': 27, 'label': 'address', 'conf': 0.9, 'tier': 2, 'rule': 'gpu'},
        {'start': 29, 'end': 36, 'label': 'postal_code', 'conf': 0.9, 'tier': 2, 'rule': 'gpu'},
    ]
    out = post_merge_address(spans, text)
    labels = [s['label'] for s in out]
    assert labels.count('address') == 1 and labels.count('postal_code') == 1   # both survive, distinct
    assert len(out) == 2


def test_address_fragments_still_stitch():
    text = "123 rue Principale,  Montreal QC"
    spans = [
        {'start': 0, 'end': 18, 'label': 'address', 'conf': 0.9, 'tier': 2, 'rule': 'gpu'},
        {'start': 21, 'end': 32, 'label': 'address', 'conf': 0.85, 'tier': 2, 'rule': 'gpu'},
    ]
    out = post_merge_address(spans, text)
    assert len(out) == 1 and out[0]['start'] == 0 and out[0]['end'] == 32
