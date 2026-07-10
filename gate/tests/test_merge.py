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


def test_floor_label_sticky_when_outscored_by_soft_span():
    """FLOOR STICKINESS regression (adversarial audit, 2026-06-20): a deterministic Tier-0 floor span
    (payment_card) overlapped by a HIGHER-confidence soft neural span (person/address) must keep its FLOOR
    primary label after merge -- otherwise the relabeled cluster loses its never-exempt protection and the
    allowlist drop / 'off' mode would leak the real card. Floor wins regardless of the soft span's conf."""
    text = "ref 4111111111111111 here"
    spans = [
        {'start': 4, 'end': 20, 'label': 'payment_card', 'conf': 0.97, 'tier': 0, 'rule': 'floor:card'},
        {'start': 4, 'end': 20, 'label': 'person', 'conf': 0.99, 'tier': 2, 'rule': 'gpu'},  # out-scores the floor
    ]
    out = merge_spans(spans)
    assert len(out) == 1
    assert out[0]['label'] == 'payment_card', 'floor label must survive a higher-conf soft overlap'
    assert out[0]['start'] == 4 and out[0]['end'] == 20
    assert set(out[0]['labels']) == {'payment_card', 'person'}   # the soft guess is still recorded


def test_floor_sticky_government_id_over_person():
    """Same invariant for a 9-digit government id (SIN) the model mis-tags as a person at higher conf."""
    spans = [
        {'start': 0, 'end': 9, 'label': 'government_id', 'conf': 0.60, 'tier': 0, 'rule': 'floor:sin'},
        {'start': 0, 'end': 9, 'label': 'person', 'conf': 0.95, 'tier': 2, 'rule': 'gpu'},
    ]
    out = merge_spans(spans)
    assert len(out) == 1 and out[0]['label'] == 'government_id'   # floor sticky despite person 0.95 > 0.60


def test_soft_over_soft_unchanged_by_stickiness():
    """Non-floor overlaps keep the original highest-(conf,len) election -- stickiness only touches the floor."""
    spans = [
        {'start': 0, 'end': 10, 'label': 'organization', 'conf': 0.70, 'tier': 2, 'rule': 'gpu'},
        {'start': 0, 'end': 10, 'label': 'person', 'conf': 0.90, 'tier': 2, 'rule': 'gpu'},
    ]
    out = merge_spans(spans)
    assert len(out) == 1 and out[0]['label'] == 'person'   # highest conf wins, no floor involved
