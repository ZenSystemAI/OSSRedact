"""Tests for torch-free char-label assignment (Phase 3 Task 3.1b).

Run: .venv-test/bin/python -m pytest training/tests/test_labeling.py -v. 100% synthetic.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from labeling import char_label_array, char_label_array_from_spans  # noqa: E402

CANON = ["person", "government_id", "email", "account_number"]


def test_from_spans_assigns_exact_chars():
    text = "Nom: Jean Tremblay NAS 046 454 286"
    spans = [[5, 18, "person"], [23, 34, "government_id"]]
    cl = char_label_array_from_spans(text, spans, CANON)
    assert text[5:18] == "Jean Tremblay" and all(c == "person" for c in cl[5:18])
    assert all(c == "government_id" for c in cl[23:34])
    assert cl[0] is None and cl[19] is None     # 'Nom: ' and the space are O


def test_from_spans_skips_labels_not_in_canon():
    text = "secret hunter2 here"
    spans = [[7, 14, "password"]]               # password not in CANON -> treated as O
    cl = char_label_array_from_spans(text, spans, CANON)
    assert all(c is None for c in cl)


def test_legacy_find_path_still_works():
    text = "email a@b.ca and a@b.ca again"
    ents = {"email": ["a@b.ca"]}
    cl = char_label_array(text, ents, ["email"])
    # both occurrences located via find
    assert cl[6:12] == ["email"] * 6
    assert cl[17:23] == ["email"] * 6


def test_from_spans_out_of_range_safe():
    text = "abc"
    spans = [[0, 99, "person"]]                 # end past EOS must not crash
    cl = char_label_array_from_spans(text, spans, ["person"])
    assert cl == ["person", "person", "person"]
