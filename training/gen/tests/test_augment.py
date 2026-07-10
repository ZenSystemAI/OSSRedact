"""Tests for inference-matching augmenters (Phase 3 Task 3.3).

Each augmenter is LENGTH-PRESERVING, so the offset-true spans stay valid (text[s:e] still slices the value).
Run: .venv-test/bin/python -m pytest training/gen/tests/test_augment.py -v. 100% synthetic.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from framework import Doc  # noqa: E402
from augment import caps, nbsp, dashes, accents, augmenters  # noqa: E402


def _row():
    d = Doc(doctype='unit', lang='fr')
    d.add("Titulaire: ")
    d.field("Jean Tremblay", "person")
    d.add(" NAS ")
    d.field("046-454-286", "government_id")
    return d.row()


def _offsets_still_valid(row):
    t = row['input']
    for s, e, lab in row['output']['spans']:
        assert 0 <= s < e <= len(t)
    return True


def test_caps_length_preserving_and_offsets_valid():
    r = caps(_row())
    assert len(r['input']) == len(_row()['input'])
    assert _offsets_still_valid(r)
    spans = {lab: r['input'][s:e] for s, e, lab in r['output']['spans']}
    assert spans['person'] == "JEAN TREMBLAY"
    # entities must be re-derived from the transformed text
    assert r['output']['entities']['person'] == ["JEAN TREMBLAY"]


def test_nbsp_substitutes_spaces_length_preserving():
    r = nbsp(_row())
    assert len(r['input']) == len(_row()['input'])
    assert " " in r['input']
    assert _offsets_still_valid(r)
    spans = {lab: r['input'][s:e] for s, e, lab in r['output']['spans']}
    assert spans['person'] == "Jean Tremblay"


def test_dashes_substitutes_hyphens_length_preserving():
    r = dashes(_row())
    assert len(r['input']) == len(_row()['input'])
    assert _offsets_still_valid(r)
    spans = {lab: r['input'][s:e] for s, e, lab in r['output']['spans']}
    assert "\u2013" in spans['government_id'] or "\u2014" in spans['government_id']


def test_accents_fold_length_preserving_and_ascii():
    d = Doc(doctype='unit', lang='fr')
    d.add("Titulaire: ")
    d.field("Geneviève Côté", "person")
    d.add(" à Montréal, Québec")
    base = d.row()
    r = accents(base)
    assert len(r['input']) == len(base['input'])
    assert _offsets_still_valid(r)
    spans = {lab: r['input'][s:e] for s, e, lab in r['output']['spans']}
    assert spans['person'] == "Genevieve Cote"      # accents folded inside the span, offsets intact
    assert "é" not in r['input'] and "è" not in r['input'] and "à" not in r['input']


def test_augmenters_registry_all_length_preserving():
    base = _row()
    assert set(augmenters()) == {'caps', 'nbsp', 'dashes', 'accents'}
    for name, fn in augmenters().items():
        r = fn(base)
        assert len(r['input']) == len(base['input']), name
        assert _offsets_still_valid(r), name
        # original row is not mutated
        assert base['input'] == _row()['input']
