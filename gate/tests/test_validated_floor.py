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
    # 2026-07-02: UUID demoted to the SOFT label 'uuid' (was floor 'sensitive_account_id') -- still a
    # deterministic tier-0 hit, but exemptible by mode/allowlist. Mirrors appliance tier0:uuid.
    assert "uuid" in labs                   # UUID
    assert "sensitive_account_id" not in labs  # the old floor label must NOT come back (regression guard)
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


def test_floor_iban_lowercase_and_hyphenated():
    assert ("iban", "gb82west12345698765432") in lset("solde IBAN gb82west12345698765432 fin")
    assert ("iban", "GB82-WEST-1234-5698-7654-32") in lset("solde IBAN GB82-WEST-1234-5698-7654-32 fin")


def test_floor_non_luhn_card_not_emitted():
    # 16 digits that FAIL Luhn -> not a floor payment_card (model owns the recall)
    assert "payment_card" not in {l for l, _ in lset("num 4539148803436460")}


def test_floor_suppresses_business_number_program_account():
    # 046454286 is Luhn-valid (a public SIN test vector), but "046454286 RT0001" is a Canadian Business
    # Number (GST/HST program account), printed publicly on invoices -- NOT a personal SIN. Must not emit.
    assert "government_id" not in {l for l, _ in lset("TPS 046454286 RT0001")}
    assert "government_id" not in {l for l, _ in lset("046454286 RP0001")}     # payroll program account
    assert "government_id" not in {l for l, _ in lset("046454286RT0001")}      # glued form (also clean)
    assert "government_id" not in {l for l, _ in lset("TVQ 046454286-RT0001")}  # hyphen separator


def test_floor_sin_cue_overrides_bn_suppression():
    # NEVER-LEAK GUARANTEE (Codex review): a SIN cue before the number forces emission even if an RT-suffix
    # follows. A number cannot be both a SIN and a BN program account, so this only ever adds a redaction.
    assert "government_id" in {l for l, _ in lset("NAS 046454286 RT0001")}
    assert "government_id" in {l for l, _ in lset("SIN: 046 454 286 RT0001")}
    assert "government_id" in {l for l, _ in lset("N.A.S. 046454286 RT0001")}  # dotted acronym is a SIN cue


def test_floor_sin_cue_is_word_bounded_not_substring():
    # Codex round 2: "Business"/"casino"/"using" contain "sin" -- they must NOT fire the SIN override, so a
    # BN labeled in English is still suppressed. (Without word boundaries this re-broke the common case.)
    assert "government_id" not in {l for l, _ in lset("Business number 046454286 RT0001")}
    assert "government_id" not in {l for l, _ in lset("Casino du Lac 046454286 RT0001")}


def test_floor_newline_does_not_bridge_bn_suffix():
    # a newline between the number and "RT0001" must NOT count as the BN separator (it would let a SIN-shaped
    # value be suppressed across a line break). The number stays a government_id.
    assert "government_id" in {l for l, _ in lset("compte 046454286\nRT0001")}


def test_floor_still_emits_bare_sin_without_program_suffix():
    # SIN recall preserved: a bare 9-digit Luhn number, or one trailed by an unrelated letter code, stays.
    assert ("government_id", "046454286") in lset("NAS 046454286")
    assert "government_id" in {l for l, _ in lset("046454286 ST0001")}         # ST is not an RT/RP/RC code


def test_floor_offsets_map_to_original_with_nbsp():
    # NBSP-separated SIN: the floor matches on a length-preserving normalized copy, so the returned
    # offsets must index the ORIGINAL string (with the NBSPs intact).
    t = "NAS 046 454 286 fin"
    assert ("government_id", "046 454 286") in lset(t)
