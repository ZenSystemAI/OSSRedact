"""Tests for the v11 round-2 shared cue_helpers (brand-from-IIN + digit grouping)."""
import os, sys, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cue_helpers as C   # noqa: E402
import values as V        # noqa: E402


def test_brand_label_by_prefix():
    assert C.brand_label("4888-8996-4378-5912") == "VISA"
    assert C.brand_label("5558 7840 0575 6683") == "MASTERCARD"
    assert C.brand_label("3411-524493-90928") == "AMEX"
    assert C.brand_label("  4204660199060000") == "VISA"


def test_brand_label_matches_real_payment_cards():
    random.seed(0)
    for _ in range(200):
        card = V.payment_card()
        b = C.brand_label(card)
        first = next(c for c in card if c.isdigit())
        assert (b == "VISA" and first == "4") or (b == "MASTERCARD" and first == "5") \
            or (b == "AMEX" and first == "3")


def test_group_digits():
    assert C.group_digits("8811471049", (3, 3, 4)) == "881 147 1049"
    assert C.group_digits("301815908", (3, 3, 3)) == "301 815 908"
    assert C.group_digits("123456", (3, 3, 4)) == "123 456"        # short: trailing group absorbs
    assert C.group_digits("12 34 56", (2, 2, 2)) == "12 34 56"     # strips existing sep first
    assert C.group_digits("601815908RT3517", (3, 3, 3)) != ""      # letters stripped, still groups digits


def test_group_digits_is_offset_safe_reconstructable():
    # grouped value must contain exactly the source digits in order (so a fielded span is a real substring)
    s = "7043419254"
    g = C.group_digits(s, (3, 3, 4))
    assert "".join(c for c in g if c.isdigit()) == s
