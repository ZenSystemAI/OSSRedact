"""Phase 2 floor tests: validated_floor fires ONLY on checksum/format-exact catastrophic shapes.

Loose shapes (date, amount, bare digit runs, postal, phone, IP) are LEFT for the neural model, which
owns recall AND labeling. Torch-free (no model). Run: .venv-test/bin/python -m pytest gate/tests/ -v
100% synthetic inputs; the Luhn/mod-97-valid values below are public test values or invented.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from privacy_gate import validated_floor  # noqa: E402


def lset(text):
    return {(s['label'], text[s['start']:s['end']]) for s in validated_floor(text)}


def test_floor_fires_on_exact_shapes():
    t = "a@b.ca 446062b5-366a-fa17-d308-8a7cb0524be4 4539148803436467 046454286"
    labs = {l for l, _ in lset(t)}
    assert "email" in labs
    assert "sensitive_account_id" in labs   # UUID
    assert "payment_card" in labs           # Luhn-valid 16
    assert "government_id" in labs          # Luhn-valid 9 (SIN)


def test_floor_does_NOT_fire_on_loose_shapes():
    # transaction date, amount, 10-digit account, postal, phone -> all LEFT for the model now
    t = "2026-06-07  1,720.46 $  8174981223  H3B 1A1  514 555 0188"
    assert lset(t) == set()


def test_floor_iban_mod97():
    assert ("iban", "GB82WEST12345698765432") in lset("solde IBAN GB82WEST12345698765432 fin")
    # a mod-97-INVALID IBAN-shaped string is NOT emitted (the model can still catch it)
    assert "iban" not in {l for l, _ in lset("ref GB82WEST12345698765433 fin")}


def test_floor_non_luhn_card_not_emitted():
    # 16 digits that FAIL Luhn -> not a floor payment_card (model owns the recall)
    assert "payment_card" not in {l for l, _ in lset("num 4539148803436460")}


def test_floor_offsets_map_to_original_with_nbsp():
    # NBSP-separated SIN: the floor matches on a length-preserving normalized copy, so the returned
    # offsets must index the ORIGINAL string (with the NBSPs intact).
    t = "NAS 046 454 286 fin"
    assert ("government_id", "046 454 286") in lset(t)
