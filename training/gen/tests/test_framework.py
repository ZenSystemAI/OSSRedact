"""Tests for the offset-true Doc builder (Phase 3 Task 3.1).

The builder records char spans AS IT APPENDS, so text[start:end] == value by construction (no text.find,
no find-failures). Run: .venv-test/bin/python -m pytest training/gen/tests/ -v. 100% synthetic.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from framework import Doc  # noqa: E402


def test_offsets_exact_by_construction():
    d = Doc(doctype='unit', lang='fr')
    d.add("Nom: ")
    d.field("Jean Tremblay", "person")
    d.add("  solde 1 234,56 $\n")              # negative filler, not labeled
    d.add("NAS ")
    d.field("046 454 286", "government_id")
    row = d.row()
    text = row['input']
    for s, e, lab in row['output']['spans']:
        # the recorded offset must slice back to exactly the labeled value
        assert text[s:e] != ""
    # explicit: the person + SIN slice back exactly
    spans = {lab: text[s:e] for s, e, lab in row['output']['spans']}
    assert spans['person'] == "Jean Tremblay"
    assert spans['government_id'] == "046 454 286"


def test_derived_entities_match_spans():
    d = Doc()
    d.field("a@b.ca", "email")
    d.add(" et ")
    d.field("a@b.ca", "email")     # same value twice -> entities list has both occurrences
    row = d.row()
    assert row['output']['entities']['email'] == ["a@b.ca", "a@b.ca"]
    assert len(row['output']['spans']) == 2


def test_decoy_in_text_but_not_labeled():
    d = Doc()
    d.add("SIN look-alike ")
    d.decoy("892 414 049")          # Luhn-invalid hard negative: present in text, NOT a span
    d.add(" end")
    row = d.row()
    assert "892 414 049" in row['input']
    assert row['output']['spans'] == []
    assert row['output']['entities'] == {}
    assert row['meta']['n_decoys'] == 1


def test_add_text_is_not_labeled():
    d = Doc()
    d.add("just plain words, no PII here")
    row = d.row()
    assert row['output']['spans'] == []
    assert row['input'] == "just plain words, no PII here"


def test_meta_carries_doctype_lang():
    d = Doc(doctype='flinks_stmt', lang='en')
    d.field("4242 4242 4242 4242", "payment_card")
    row = d.row()
    assert row['meta']['doctype'] == 'flinks_stmt'
    assert row['meta']['lang'] == 'en'
    assert row['meta']['synthetic'] is True
