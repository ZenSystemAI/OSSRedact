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


# --- possessive fold (live 2026-07-02: "Steven's" minted a fresh PERSON entry past an allowlisted "steven") ---

def test_possessive_span_matches_base_declaration():
    # declaring the base value covers the ASCII possessive span
    text = "reviewed Steven's patch"
    allow = al.build_allow_set(['steven'])
    assert al.apply_allowlist([_span(text, "Steven's", 'person')], text, allow) == []


def test_base_span_does_not_match_possessive_declaration():
    # DIRECTION (adversarial review 2026-07-02): the fold is LOOKUP-side only. Declaring "McDonald's"
    # covers "McDonald's" but NOT the bare span "McDonald" -- otherwise allowlisting a possessive brand
    # ("Sam's") would silently exempt every unrelated person sharing the base token ("Sam").
    text = 'lunch at McDonald today'
    allow = al.build_allow_set(["McDonald's"])
    kept = al.apply_allowlist([_span(text, 'McDonald', 'org')], text, allow)
    assert len(kept) == 1                      # bare span stays redacted
    text2 = "lunch at McDonald's today"
    assert al.apply_allowlist([_span(text2, "McDonald's", 'org')], text2, allow) == []   # exact form exempt


def test_unicode_right_single_quote_possessive():
    # U+2019 (typographic apostrophe, what editors/IMEs actually emit) folds the same as ASCII
    text = 'per Steven’s note'
    allow = al.build_allow_set(['steven'])
    assert al.apply_allowlist([_span(text, 'Steven’s', 'person')], text, allow) == []
    # a U+2019 possessive DECLARATION covers its own form but NOT the bare base span (lookup-side-only fold)
    allow2 = al.build_allow_set(['Steven’s'])
    assert al.apply_allowlist([_span('per Steven’s note', 'Steven’s', 'person')], 'per Steven’s note', allow2) == []
    assert len(al.apply_allowlist([_span('by Steven now', 'Steven', 'person')], 'by Steven now', allow2)) == 1


def test_possessive_fold_strips_only_one_suffix():
    # ONE strip only: the span "alex's's" folds to "alex's", which does not equal the declared
    # base "alex" -- a double possessive is not a near-identical variant and stays redacted.
    text = "saw alex's's oddity"
    allow = al.build_allow_set(['alex'])
    kept = al.apply_allowlist([_span(text, "alex's's", 'person')], text, allow)
    assert len(kept) == 1  # still redacted


def test_plain_trailing_s_is_not_folded():
    # only apostrophe+s folds, on the LOOKUP side; a word merely ending in "s" is untouched, and
    # the declared-value normalizer never folds (direction fix, 2026-07-02).
    assert al.normalize_allow_value('bass') == 'bass'
    assert al.normalize_allow_value("Steven's") == "steven's"
    assert al.is_allowlisted('bass', al.build_allow_set(['bas'])) is False
    assert al.is_allowlisted("Steven's", al.build_allow_set(['steven'])) is True
    assert al.is_allowlisted('Steven’s', al.build_allow_set(['steven'])) is True


def test_floor_span_never_exempt_even_via_possessive_fold():
    # the fold must not open a floor hole: declaring the exact (or possessive) text of a hard-floor
    # span still never drops it -- the guard keys on the LABEL before any text lookup happens.
    text = "card 4111111111111111's trail"
    allow = al.build_allow_set(["4111111111111111's", '4111111111111111'])
    kept = al.apply_allowlist([_span(text, "4111111111111111's", 'payment_card'),
                               _span(text, '4111111111111111', 'payment_card')], text, allow)
    assert len(kept) == 2  # both floor spans survive


def test_denylist_custom_spans_never_allowlist_exempt():
    """Defense in depth (2026-07-02): a must-redact 'custom' (denylist) span survives the allowlist filter
    even when its exact text is declared safe -- must-redact beats known-safe. The pipeline already orders
    denylist injection after this filter; this pins the same precedence inside the shared helper."""
    text = 'project zenith is internal'
    spans = [{'start': 8, 'end': 14, 'label': 'custom'}]
    allow = al.build_allow_set(['zenith'])
    assert al.apply_allowlist(spans, text, allow) == spans
