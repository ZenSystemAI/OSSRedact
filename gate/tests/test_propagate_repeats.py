"""Detect-time repeat propagation (2026-07-05: names caught early in a PDF, missed mid-doc).

Contract under test:
  - a high-conf person/org span propagates to every literal repeat (case-insensitive, word-boundary),
    rule='repeat', same label;
  - low-conf sources, short values, and non-name-ish labels (email/floor shapes) do NOT propagate;
  - a repeat inside a longer word does not match (boundary guard);
  - merge_spans unions a propagated span that overlaps an existing detection (no duplicates).
All inputs synthetic. Run: .venv-test/bin/python -m pytest gate/tests/test_propagate_repeats.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from privacy_gate import merge_spans, propagate_repeats  # noqa: E402


def _span(start, end, label, conf=0.99, tier=2, rule='gpu'):
    return {'start': start, 'end': end, 'label': label, 'tier': tier, 'conf': conf, 'rule': rule}


def test_person_full_span_propagates_bare_surname_repeats():
    # THE reported scenario (2026-07-05): the model emits ONE span "Jean Tremblay"; the mid-document
    # repeats are bare "TREMBLAY"/"tremblay" -- token-level propagation must catch them.
    text = "Client: Jean Tremblay\nsolde...\nTREMBLAY dossier\ntremblay"
    spans = propagate_repeats(text, [_span(8, 21, 'person')])
    repeats = [s for s in spans if s['rule'] == 'repeat']
    got = {(text[s['start']:s['end']], s['label']) for s in repeats}
    assert ('TREMBLAY', 'person') in got and ('tremblay', 'person') in got
    assert all(s['label'] == 'person' for s in repeats)


def test_low_conf_and_short_values_do_not_propagate():
    text = "Jo saw Jo again; maybe Dupont met Dupont"
    spans = propagate_repeats(text, [
        _span(0, 2, 'person', conf=0.99),            # 'Jo' too short
        _span(23, 29, 'person', conf=0.4),           # 'Dupont' below conf floor
    ])
    assert [s for s in spans if s['rule'] == 'repeat'] == []


def test_floor_labels_do_not_propagate():
    text = "a@b.ca then a@b.ca"
    spans = propagate_repeats(text, [_span(0, 6, 'email')])
    assert [s for s in spans if s['rule'] == 'repeat'] == []


def test_boundary_guard_blocks_inner_match():
    text = "Ing. Roy chez Royaume inc. avec Roy"
    spans = propagate_repeats(text, [_span(5, 8, 'person')])
    repeats = [text[s['start']:s['end']] for s in spans if s['rule'] == 'repeat']
    assert repeats == []  # 'Roy' is len 3 < min-len: nothing propagates at all


def test_org_propagates_and_merge_unions_overlap():
    text = "Fournisseur: Laurentide inc. paiement a Laurentide inc. recu de LAURENTIDE INC."
    detected = [_span(13, 28, 'organization'), _span(40, 56, 'organization', conf=0.8)]
    merged = merge_spans(propagate_repeats(text, detected))
    orgs = [s for s in merged if 'organization' in ([s['label']] + s.get('labels', []))]
    covered = [text[s['start']:s['end']] for s in orgs]
    assert any('LAURENTIDE INC' in c for c in covered)   # tail occurrence now covered
    assert len(orgs) == 3                                # one span per occurrence, no duplicates


def test_accented_boundary():
    text = "Mme BÉLANGER note; bélanger encore; laBÉLANGERnon"
    spans = propagate_repeats(text, [_span(4, 12, 'person')])
    repeats = [text[s['start']:s['end']] for s in spans if s['rule'] == 'repeat']
    assert repeats == ['bélanger']  # inner compound blocked by \w boundary on accented letters
