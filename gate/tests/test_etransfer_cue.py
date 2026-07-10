"""e-transfer / bank-ledger counterparty-name floor (plan 049, 2026-07-08).

Contract under test (cue_name_spans e-transfer path):
  - the counterparty name after a bank-specific ledger cue is emitted as a tier-0 person span;
  - the CUE grammars (VIR INTERAC .../ E-TRANSFER <ref> .../ Depot auto .../ Desjardins slash fields) are
    covered per bank, incl. lowercase CIBC names and a trailing reference id that must NOT enter the span;
  - a cue in prose (bare "e-Transfer <word>...") and a cue followed by a stopword produce bounded / no damage.
All names are INVENTED; the grammar is derived from real statement formats. Torch-free.
Run: python3 -m pytest gate/tests/test_etransfer_cue.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from privacy_gate import cue_name_spans  # noqa: E402


def _names(t):
    return [t[s['start']:s['end']] for s in cue_name_spans(t)]


def _persons(t):
    return [s for s in cue_name_spans(t) if s['label'] == 'person']


# (text, expected-name-substring). Every name is invented.
CATCH = [
    # BMO / National -- VIR INTERAC forms
    ("VIR INTERAC RECU MARIE JEANNE DUPUIS", "MARIE JEANNE DUPUIS"),
    ("VIR INTERAC ENVOYE JON JEAN OKAFOR", "JON JEAN OKAFOR"),
    ("VIR INTERAC ANNULE ALMA BELROSE", "ALMA BELROSE"),
    # CIBC -- E-TRANSFER <ref> <name>, incl. lowercase names
    ("2026-05-22   E-TRANSFER 016633447755 Dianne Okafor   50.00 $", "Dianne Okafor"),
    ("E-TRANSFER 108811224466 delyna morvan", "delyna morvan"),
    ("E-TRANSFER 014466882200 bern", "bern"),
    # TD / BMO alt -- INTERAC ETRNSR
    ("INTERAC ETRNSR SENT GREGORY OKAFOR", "GREGORY OKAFOR"),
    ("INTERAC ETRNSR AD RECVD PRIYA RAMASWAMY", "PRIYA RAMASWAMY"),
    # RBC -- Depot auto (accented + unaccented) / Virement forms
    ("Depot auto - virements par courriel OLIVIER DE FERLANDAIS CA7QzWvk", "OLIVIER DE FERLANDAIS"),
    ("Dépôt auto - virements par courriel MAELLE DORVALINE CAZpQt4v", "MAELLE DORVALINE"),
    ("Virement envoyé barb 9NRML3", "barb"),
    ("Virement reçu JON OKAFOR CAu3wqe5", "JON OKAFOR"),
    ("Virement en ligne reçu MARIE DUPUIS", "MARIE DUPUIS"),
    # Desjardins -- slash-delimited fields
    ("Interac e-Transfer from /Lucie Lemieux /", "Lucie Lemieux"),
    ("Interac e-Transfer to /tony okafor /", "tony okafor"),
    ("Cancellation-Interac e-Transfer to /Kevin Cote /", "Kevin Cote"),
    ("Rent/lease /Tino Bravanese                          1075.00 $", "Tino Bravanese"),
]

# cue present but NO counterparty name should be emitted (bounded / zero damage)
NO_FP = [
    "The e-Transfer feature works well for everyone today.",   # cue in prose -> no ref -> no span
    "INTERAC e-Transfer                     700.00 $",         # National no-name form
    "VIR INTERAC RECU FONDS admis",                            # first token is a ledger stopword
    "Interac e-Transfer to //",                                # empty slash field
]


def test_etransfer_cue_catches():
    for text, name in CATCH:
        assert name in _names(text), f"{name!r} not caught in {text!r} (got {_names(text)})"


def test_etransfer_cue_no_false_positives():
    for text in NO_FP:
        assert _names(text) == [], f"unexpected person span in {text!r}: {_names(text)}"


def test_ref_digits_never_in_span():
    # the leading CIBC ref and the trailing RBC hex/DEP-AUTO ref must be OUTSIDE the person span
    for text in [
        "E-TRANSFER 016633447755 Dianne Okafor   50.00 $",
        "Depot auto - virements par courriel OLIVIER DE FERLANDAIS CA7QzWvk",
        "VIR INTERAC DEP AUTO REC ALMA BELROSE 401233701",
    ]:
        for s in _persons(text):
            val = text[s['start']:s['end']]
            assert not any(c.isdigit() for c in val), f"ref digits leaked into span {val!r} of {text!r}"


def test_dep_auto_rec_trailing_ref_excluded():
    text = "VIR INTERAC DEP AUTO REC ALMA BELROSE 401233701"
    assert _names(text) == ["ALMA BELROSE"]


def test_emission_contract():
    s = _persons("VIR INTERAC RECU MARIE JEANNE DUPUIS")[0]
    assert s['label'] == 'person' and s['tier'] == 0 and s['conf'] == 0.95 and s['rule'] == 'floor:cue_name'


# ---- Codex adversarial-review regressions (2026-07-08) ----

def test_crlf_line_ending_full_name():
    # CRITICAL: CRLF ledgers -- 'DUPUIS\r' must not fail the alpha check and truncate the span to 'MARIE'.
    for form in ("VIR INTERAC RECU MARIE DUPUIS\r\nnext line",
                 "E-TRANSFER 010271459817 marie dupuis\r\nnext",
                 "Depot auto - virements par courriel MARIE DUPUIS\r\nnext"):
        names = _names(form)
        assert any('MARIE DUPUIS' in n.upper() for n in names), (form, names)
        assert not any('\r' in n or 'next' in n for n in names), (form, names)


def test_crlf_slash_field():
    names = _names("Interac e-Transfer to /Tomas Kaldera\r\nnext")
    assert names == ["Tomas Kaldera"], names


def test_leading_honorific_skipped_name_still_floors():
    # HIGH: a leading honorific must not terminate the run and drop the whole name; the span excludes it.
    for form, want in (("VIR INTERAC RECU MME MARIE DUPUIS", "MARIE DUPUIS"),
                       ("VIR INTERAC ENVOYE Monsieur Jon Okafor", "Jon Okafor"),
                       ("INTERAC ETRNSR SENT DR ALI KHAN", "ALI KHAN")):
        assert want in _names(form), (form, _names(form))


def test_amount_prose_is_not_a_person():
    # MEDIUM: 'E-TRANSFER 1000 dollars' (short ref) and 'E-TRANSFER 123456 dollars' (currency stopword)
    # must not mint a person span.
    assert _names("E-TRANSFER 1000 dollars") == []
    assert _names("please e-transfer 2500 euros to the account") == []
    assert _names("E-TRANSFER 123456 dollars") == []


# ---- harness-driven regressions (real-corpus acceptance run, 2026-07-08) ----

def test_bmo_etrnsfr_spelling():
    # The real BMO ledger spells it ETRNSFR (118x in the corpus); ETRNSR was a transcription artifact.
    assert "DENIRA CHOLETTE" in _names("INTERAC ETRNSFR AD RECVD DENIRA CHOLETTE 202598765004KZQ2W")
    assert "AZARELLE" in _names("INTERAC ETRNSFR SENT AZARELLE 20265550801QRMXOD")


def test_tangerine_colon_form():
    # Tangerine mid-line "e-Transfer To: <name>" (534 cue hits in the corpus, previously unredacted).
    assert "Fredrik Morvane" in _names("EFT Withdrawal to e-Transfer To: Fredrik Morvane 1,250.00")
    assert "karelle" in _names("e-Transfer From: karelle 40.00")
    # prose colon-cue with a function word cannot over-mask
    assert _names("please e-transfer to: the account below") == []


def test_dba_hyphen_connector():
    # "Virement envoye Traduction - Lise Charbonnel" -- a lone hyphen joins the DBA and the person.
    names = _names("Virement envoye Traduction - Lise Charbonnel 8QZTKV")
    assert any("Lise Charbonnel" in n for n in names), names


def test_middle_initial_is_not_the_article_stopword():
    # harness re-run regression: adding 'a'/'an' prose stopwords must not eat a middle initial.
    assert "DEREK A MARTEL" in _names("Depot auto - virements par courriel DEREK A MARTEL C1XyPnEvQhZk")
    assert "HELENA A MERCIER" in _names("E-TRANSFER 013557799002 HELENA A MERCIER 20.00")
    # but the article in prose after a colon-cue still stops the run (no name to the right)
    assert _names("please e-transfer to: a friend") == []


def test_leading_initial_is_a_name_token():
    # Codex final pass: a LEADING initial must not fall to the article stopword.
    assert "A. MARTEL" in _names("E-TRANSFER 013557799002 A. MARTEL 20.00")
    assert "A MARTEL" in _names("E-TRANSFER 013557799002 A MARTEL 20.00")
    assert "J. MARTEL" in _names("E-TRANSFER 013557799002 J. MARTEL 20.00")
    # but the article before a lowercase word still stops the run
    assert _names("please e-transfer to: a friend") == []
    assert _names("please e-transfer to: A friend") == []


def test_colon_cue_prose_overmask_is_intentional():
    # The Tangerine colon cue CAN over-mask prose after "e-transfer to:" -- that is the documented
    # safe error (cue-anchored over-redaction), bounded to <=5 tokens on the cue line.
    names = _names("please e-transfer to: Alice by Friday, thanks")
    assert names and all('Alice' in n for n in names) and all(len(n) <= 60 for n in names)
