"""Tests for torch-free char-label assignment and shared token-label lookup.

Run: .venv-test/bin/python -m pytest training/tests/test_labeling.py -v. 100% synthetic.

Phase 5: train_suite and eval_heldout must share one first-non-whitespace token-label
helper so GPT-BPE leading-space tokens get identical BIO gold/truth labels.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from labeling import (  # noqa: E402
    char_label_array,
    char_label_array_from_spans,
    token_char_label,
)

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


# --- Phase 5: shared first-non-whitespace token-label lookup -----------------
# Public helper: labeling.token_char_label(text, charlab, start, end) -> str | None
# Semantics (train_suite L57-60):
#   k = start
#   while k < min(end, len(charlab)) and text[k].isspace():
#       k += 1
#   return charlab[k] if k < min(end, len(charlab)) else None
# Special/pad (start == end) remain caller-side (-100 / skip both streams).


def test_token_char_label_span_after_leading_whitespace():
    """GPT-BPE-style token: leading space is inside the offset range; entity starts after it.

    text:  ' Name'  (space then person span)
    char:   01234
    span person over 'Name' [1,5); token covers full ' Name' as [0,5).
    First-char lookup would see O on the space; shared helper must return person.
    """
    text = " Name"
    assert text[0] == " " and text[1:5] == "Name"
    cl = char_label_array_from_spans(text, [[1, 5, "person"]], CANON)
    assert cl[0] is None
    assert all(c == "person" for c in cl[1:5])
    assert token_char_label(text, cl, 0, 5) == "person"


def test_token_char_label_whitespace_only_range_is_none():
    """A token whose entire [start, end) is whitespace has no entity owner -> None (O)."""
    text = "a  b"
    # positions: 0='a', 1=' ', 2=' ', 3='b'
    cl = [None] * len(text)
    assert text[1:3] == "  "
    assert token_char_label(text, cl, 1, 3) is None


def test_token_char_label_ordinary_non_whitespace_range():
    """XLM-R-style / non-leading-space token: first char is already content; no skip needed."""
    text = "Jean at desk"
    # 'Jean' [0,4) is person; token has no leading space
    cl = char_label_array_from_spans(text, [[0, 4, "person"]], CANON)
    assert token_char_label(text, cl, 0, 4) == "person"
    # interior token on unlabeled chars stays None
    assert text[5:7] == "at"
    assert token_char_label(text, cl, 5, 7) is None


def test_token_char_label_leading_ws_then_unlabeled_content_is_none():
    """Leading space skipped, but first non-ws char is O -> None (must not invent a label)."""
    text = " foo"
    cl = [None] * len(text)
    assert token_char_label(text, cl, 0, 4) is None


def test_token_char_label_empty_or_special_range_is_none():
    """start == end (special/pad) and empty ranges yield None; callers still skip both streams."""
    text = "x"
    cl = ["person"]
    assert token_char_label(text, cl, 0, 0) is None
    assert token_char_label(text, cl, 1, 1) is None
