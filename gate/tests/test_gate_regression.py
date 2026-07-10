"""Characterization (golden) tests for the deterministic floor pipeline.

These pin the behavior of validated_floor -> merge_spans -> post_merge_address so future changes are
INTENTIONAL, not accidental. Updated in Phase 2 (2026-06-14): the floor was made thin (it now fires ONLY
on checksum/format-exact catastrophic shapes), so the old "loose shapes fire" assertions were flipped to
assert the new intended behavior (loose shapes are LEFT for the model). See test_validated_floor.py for the
floor's full contract.

Torch-free (floor only, no model). Run: .venv-test/bin/python -m pytest gate/tests/ -v
100% synthetic inputs; no real PII. Luhn/format-valid values below are public test values or invented.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from privacy_gate import validated_floor, merge_spans, post_merge_address  # noqa: E402


def pairs(text):
    """Full deterministic pipeline -> set of (label, matched-substring)."""
    spans = post_merge_address(merge_spans(validated_floor(text)), text)
    return {(s['label'], text[s['start']:s['end']]) for s in spans}


# ---- EXACT, checksum/format-anchored shapes: the floor KEEPS these ----

def test_exact_shapes_email_uuid_sin_card():
    t = "courriel a@b.ca; uuid 446062b5-366a-fa17-d308-8a7cb0524be4; NAS 046 454 286; carte 4539148803436467"
    got = pairs(t)
    assert ("email", "a@b.ca") in got
    # 2026-07-02: UUIDs mint the SOFT label 'uuid' (was the floor label 'sensitive_account_id'):
    # session/request ids are load-bearing in coding traffic and must stay mode/allowlist-exemptible.
    assert ("uuid", "446062b5-366a-fa17-d308-8a7cb0524be4") in got  # UUID
    assert ("government_id", "046 454 286") in got                                  # 9-digit Luhn-ok SIN
    assert ("payment_card", "4539148803436467") in got                             # 16-digit Luhn-ok card


# ---- LOOSE shapes: Phase 2 made the floor STOP firing on these (now left to the model) ----

def test_loose_shapes_no_longer_fire():
    t = "2026-06-07  1,720.46 $  8174981223  H3B 1A1  514 555 0188"
    got = pairs(t)
    labels = {l for l, _ in got}
    assert "sensitive_date" not in labels   # transaction date: gone (was a precision sink)
    assert "postal_code" not in labels      # H3B 1A1: left for the model
    assert "phone_number" not in labels     # 10-digit runs: left for the model
    assert "sensitive_account_id" not in labels  # bare 10-digit account: left for the model
    # the only floor-eligible shapes here are none, so the pipeline emits nothing
    assert got == set()


def test_date_no_longer_swallows_adjacent_digit():
    # The old connected-component merge unioned the date span with the leading '1' of the amount, leaking
    # part of it. The thin floor does not emit the date at all, so there is no span to over-redact.
    t = "2026-06-07  1,720.46 $"
    assert pairs(t) == set()


# ---- pure-negative input: the floor must not invent spans on PII-free text ----

def test_clean_text_no_spurious_spans():
    t = "Le service tourne sur le port 8080, GPU 3090, aucune donnee personnelle ici."
    assert pairs(t) == set()
