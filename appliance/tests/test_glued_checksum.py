"""B: catch checksum-validated card/IBAN even when glued to letters (the deliberate digit-run boundary
rejects them, but a Luhn/mod-97 pass is near-certainly real)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from privacy_gate import tier0_spans  # noqa: E402


def _labels(text, want):
    return {text[s['start']:s['end']] for s in tier0_spans(text) if s['label'] == want}


def test_glued_luhn_card_caught():
    assert "4111111111111111" in _labels("card4111111111111111expires", "payment_card")
    assert "4532015112830366" in _labels("xx4532015112830366yy", "payment_card")


def test_left_glued_valid_iban_caught():
    assert "GB29NWBK60161331926819" in _labels("ref ibanGB29NWBK60161331926819 ok", "iban")


def test_glued_non_luhn_run_not_a_card():
    # a 16-digit run that FAILS Luhn must not be promoted to card by the glued pass (it stays whatever the
    # boundary digit_run rule decides; the glued pass adds nothing)
    assert "1111111111111111" not in _labels("id1111111111111111x", "payment_card")


def test_hex_hash_not_card():
    assert _labels("build a1b2c3d4e5f6a7b8c9d0e1f2done", "payment_card") == set()


def test_clean_card_still_caught():
    assert "4111 1111 1111 1111" in _labels("paid 4111 1111 1111 1111 today", "payment_card")
