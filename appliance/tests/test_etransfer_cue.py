"""e-transfer / bank-ledger counterparty-name floor -- appliance twin of gate/tests/test_etransfer_cue.py
(plan 049, 2026-07-08). Same grammar/contract; the appliance emits rule 'tier0:cue_name'. Loaded by explicit
path because gate/privacy_gate.py shares the module name 'privacy_gate'. All names INVENTED.
Run: .venv-test/bin/python -m pytest appliance/tests/test_etransfer_cue.py -q
"""
import importlib.util
import os

_PATH = os.path.join(os.path.dirname(__file__), '..', 'privacy_gate.py')
_spec = importlib.util.spec_from_file_location('appliance_privacy_gate', _PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
cue_name_spans = _mod.cue_name_spans
tier0_spans = _mod.tier0_spans


def _names(t):
    return [t[s['start']:s['end']] for s in cue_name_spans(t)]


def _persons(t):
    return [s for s in cue_name_spans(t) if s['label'] == 'person']


CATCH = [
    ("VIR INTERAC RECU MARIE JEANNE DUPUIS", "MARIE JEANNE DUPUIS"),
    ("VIR INTERAC ENVOYE JON JEAN OKAFOR", "JON JEAN OKAFOR"),
    ("E-TRANSFER 016633447755 Dianne Okafor   50.00 $", "Dianne Okafor"),
    ("E-TRANSFER 108811224466 delyna morvan", "delyna morvan"),
    ("INTERAC ETRNSR SENT GREGORY OKAFOR", "GREGORY OKAFOR"),
    ("Depot auto - virements par courriel OLIVIER DE FERLANDAIS CA7QzWvk", "OLIVIER DE FERLANDAIS"),
    ("Virement envoyé barb 9NRML3", "barb"),
    ("Interac e-Transfer from /Lucie Lemieux /", "Lucie Lemieux"),
    ("Cancellation-Interac e-Transfer to /Kevin Cote /", "Kevin Cote"),
    ("Rent/lease /Tino Bravanese                          1075.00 $", "Tino Bravanese"),
]

NO_FP = [
    "The e-Transfer feature works well for everyone today.",
    "INTERAC e-Transfer                     700.00 $",
    "VIR INTERAC RECU FONDS admis",
]


def test_etransfer_cue_catches():
    for text, name in CATCH:
        assert name in _names(text), f"{name!r} not caught in {text!r} (got {_names(text)})"


def test_etransfer_cue_no_false_positives():
    for text in NO_FP:
        assert _names(text) == [], f"unexpected person span in {text!r}: {_names(text)}"


def test_ref_digits_never_in_span():
    for text in [
        "E-TRANSFER 016633447755 Dianne Okafor   50.00 $",
        "Depot auto - virements par courriel OLIVIER DE FERLANDAIS CA7QzWvk",
        "VIR INTERAC DEP AUTO REC ALMA BELROSE 401233701",
    ]:
        for s in _persons(text):
            val = text[s['start']:s['end']]
            assert not any(c.isdigit() for c in val), f"ref digits leaked into span {val!r} of {text!r}"


def test_emission_contract_and_tier0_pickup():
    text = "VIR INTERAC RECU MARIE JEANNE DUPUIS"
    s = _persons(text)[0]
    assert s['label'] == 'person' and s['tier'] == 0 and s['conf'] == 0.95 and s['rule'] == 'tier0:cue_name'
    # the deployed appliance floor (tier0_spans) must also carry the person span (it feeds egress)
    assert ('person', 'MARIE JEANNE DUPUIS') in {(x['label'], text[x['start']:x['end']]) for x in tier0_spans(text)}


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
