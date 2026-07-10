"""Cue-gated ID backstop (2026-07-07, plan 048 code-side round) -- miss-inventory-driven.

Contract under test:
  - each measured miss cluster (NETFILE code, policy/document/file number, account, phone, DOB)
    emits a tier-0 'floor:cue_digit' span with the right label;
  - NO bare-shape emission: the same values without their cue emit nothing (floor-diet precision);
  - BN program accounts (9-digit + RT suffix) stay suppressed under an account cue (public GST/QST);
  - NEQ / TVQ registrations are NOT backstopped (public registry -- deliberate, see module comment);
  - cue and value must share a line.
All inputs synthetic. Run: .venv-test/bin/python -m pytest gate/tests/test_cue_digit_spans.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from privacy_gate import cue_digit_spans  # noqa: E402


def _got(text):
    return {(text[s['start']:s['end']], s['label'], s['rule']) for s in cue_digit_spans(text)}


def test_netfile_access_code_fr_en():
    assert ("6XKDHZJ6", 'sensitive_account_id', 'floor:cue_digit') in _got(
        "Code d'accès NETFILE : 6XKDHZJ6")
    assert ("5KM6ANYN", 'sensitive_account_id', 'floor:cue_digit') in _got(
        "NETFILE access code: 5KM6ANYN")


def test_policy_document_file_numbers():
    assert ("P-4471 882 903", 'sensitive_account_id', 'floor:cue_digit') in _got(
        "Numéro de police : P-4471 882 903")
    assert ("EFX-RYU4BKD2", 'sensitive_account_id', 'floor:cue_digit') in _got(
        "credit file number EFX-RYU4BKD2")
    assert ("D 224-368-563", 'sensitive_account_id', 'floor:cue_digit') in _got(
        "numéro du document délivré: D 224-368-563")


def test_account_number_and_bn_suppression():
    assert ("006-02761-1234567", 'account_number', 'floor:cue_digit') in _got(
        "No de compte: 006-02761-1234567")
    # 9-digit + RT program suffix = public GST registration -> suppressed even under an account cue
    assert _got("compte 123456782RT0001") == set()


def test_phone_with_cue_shapes():
    got = _got("telephone 450.555.0194 | cellular, 367-555-0190")
    assert ("450.555.0194", 'phone_number', 'floor:cue_digit') in got
    assert ("367-555-0190", 'phone_number', 'floor:cue_digit') in got


def test_dob_three_formats():
    got = _got("né(e) le 11 janvier 1979; born June 25, 1965; date of birth: 1989-04-23")
    vals = {v for v, lab, _ in got if lab == 'date_of_birth'}
    assert vals == {"11 janvier 1979", "June 25, 1965", "1989-04-23"}


def test_no_cue_no_emission():
    # the exact same value shapes WITHOUT their cue must emit nothing (precision rule)
    assert _got("ref 6XKDHZJ6 and 450.555.0194 and 006-02761-1234567 and 11 janvier 1979") == set()


def test_neq_tvq_not_backstopped():
    assert _got("Numéro d'entreprise du Québec (NEQ) : 2231575002") == set()
    assert _got("inscription au fichier de la TVQ : 0568307503TQ0475") == set()


def test_cue_value_must_share_line():
    assert _got("No de compte:\n006-02761-1234567") == set()
