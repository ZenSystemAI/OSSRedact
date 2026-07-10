#!/usr/bin/env python3
"""flinks_stmt generator: synthetic Quebec/Canada consumer bank statements in a schema-compatible
tab-delimited export layout expected by the downstream parser.

The generated records preserve the parser's COLUMN-HEADER-ROW / VALUE-ROW tabular skeleton. The header
identity block contains synthetic identifiers, while the transaction table supplies synthetic hard
negatives for privacy filtering with stable field names, delimiters, and row ordering. Synthetic
descriptions (E-TFR / EFT / PAIE / Achat Visa Débit / Frais sur effet / NCR LOAN) are ported from
build_flinks_synth.py. Per privacy-filter.ts:
 - holder name (often ALL-CAPS, joint via ' ET '/' AND ') -> person ; city + province QC -> NEGATIVE.
 - DOB = a FR/EN date WITHOUT a time (cued by 'Date de naissance') -> date_of_birth ; the request datetime
   (date WITH a time) and 'Dernière Actualisation' -> NEGATIVE decoys ; transaction dates (ISO) -> NEGATIVE.
 - account = institution-first III-TTTT(T)-AAA (parser regex (\\d{3}-\\d{4,5}-\\d{6,9})) or a bare run.
 - the two Flinks UUIDs (Requête Flinks ID / Id de connexion) -> sensitive_account_id.
 - postal (G/H/J FSA) -> postal_code ; street -> address.

LAYOUTS (>=2 distinct real structures; held-out = the suffix):
 - _layout_packed   : compact header, account-type packed on the value row (Tangerine/CIBC-style).  [train]
 - _layout_expanded : header spread over more rows, holder email/phone present (RBC eStatement-style). [train]
 - _layout_joint    : joint holders + multi-page footer + international IBAN line.                    [heldout]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402

_BANKS = ["TD", "RBC", "CIBC", "BMO", "Scotiabank", "Banque Nationale", "Tangerine", "Desjardins"]
_ACCT_TYPE = ["UNLIMITED CHEQUING ACCOUNT", "Forfait bancaire sans limite Signature", "Chequing Account",
              "Compte cheques", "EVERYDAY CHEQUING", "Compte avec interets", "STUDENT CHEQUING",
              "Tangerine Chequing Account"]
_ORGS = ["ACME", "CISSS MONTEREGIE", "ICEBERG", "iA Auto Finance", "CANADA", "COOP", "NCR", "Afterpay",
         "ECHE", "CRA", "REVENU QUEBEC", "HYDRO QUEBEC", "VIDEOTRON", "BELL", "FIDO", "KOHO"]
_MERCH = ["BURGER KING # 9", "METRO #341", "IGA #88", "TIM HORTONS #2231", "COUCHE-TARD #55", "AMZN MKTP",
          "UBER EATS", "SAQ #234", "WALMART #3012", "DOLLARAMA #91", "PHARMAPRIX #44", "COSTCO #12"]


def _money(v: float) -> str:
    s = f"{abs(v):,.2f} $"
    return ("-" + s) if v < 0 else s


def _desc() -> str:
    """A realistic Flinks transaction description -> always a DECOY (kept, never PII). Ported from
    build_flinks_synth.py (grounded in the real export). Amounts/merchants/orgs inside are negatives."""
    r = random.random()
    if r < 0.22:
        return "SEND E-TFR ***" + "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(3))
    if r < 0.30:
        return "RECEIVE E-TFR ***" + "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(3))
    if r < 0.45:
        return random.choice(_MERCH) + " _V"
    if r < 0.58:
        o = random.choice(_ORGS)
        return random.choice([f"EFT Withdrawal to {o} To {o}", f"EFT Deposit from {o} From {o}",
                              f"EFT NSF - EFT Withdrawal to {o} FEE-RET Service Fee"])
    if r < 0.70:
        return f"PAIE {random.choice(_ORGS)} PAYROLL"
    if r < 0.80:
        return f"Achat Visa Debit - {random.randint(1000,9999)} {random.choice(_MERCH)}"
    if r < 0.88:
        return "Frais sur effet sans provisions 1 @ $45.00"     # amount INSIDE description -> negative
    if r < 0.95:
        return f"NCR {random.randint(10000000000,99999999999)} LOAN"   # 11-digit merchant id -> negative
    return random.choice(["Afterpay _V", "Paiement preautorise HYDRO QUEBEC", "Frais mensuels",
                          "INTERETS", "Retrait GAB"])


def _txn_table(d: Doc, fr: bool, npages: int = 1) -> None:
    """Append the transaction table: a header row + 8-28 lines, ALL decoys (dates, descriptions, amounts,
    running balances). This volume is the moat for false-positive control."""
    d.add(("Date \tDescription \tRetraits \tDepots \tBalance\n" if fr
           else "Date \tDescription \tWithdrawals \tDeposits \tBalance\n"))
    d.add(f"-- 1 of {npages} --\n")
    bal = random.uniform(-3000, 8000)
    for _ in range(random.randint(8, 28)):
        amt = round(random.uniform(5, 2800), 2)
        bal = round(bal + (amt if random.random() < 0.5 else -amt), 2)
        d.decoy(V.iso_date()); d.add(" \t")
        d.decoy(_desc()); d.add(" \t")
        d.decoy(_money(amt)); d.add(" \t"); d.decoy(_money(bal)); d.add("\n")


def _name(lang: str) -> str:
    return V.person(lang, caps=(random.random() < 0.6))   # synthetic header names are often ALL-CAPS


def _rid() -> str:
    return str(random.randint(90000, 99999))               # short Flinks request id -> NEGATIVE


# ---------------- layout A: packed header (Tangerine / CIBC style) ----------------

def _layout_packed(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="flinks_stmt", lang=lang)
    bank = random.choice(_BANKS)

    d.add("Nom: \tHeure de la demande \tStatut de la demande \tID\n" if fr
          else "Name: \tTime of Request \tRequest Status \tRequest Id\n")
    d.field(_name(lang), "person"); d.add(" \t")
    d.decoy(V.request_datetime(lang)); d.add(" \tCompleted \t"); d.decoy(_rid()); d.add("\n")

    d.add("Identifiant de compte \tType de compte \tSolde actuel Institution Date de naissance\n" if fr
          else "Account id \tAccount Type \tCurrent Balance Institution Birth date\n")
    d.field(V.bank_account(), "account_number"); d.add(" " + random.choice(_ACCT_TYPE) + " ")
    d.decoy(_money(random.uniform(50, 9000))); d.add(" \t" + bank + " \t")
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")

    if random.random() < 0.85:                                 # international wire line -> IBAN (train)
        d.add("Virement international IBAN: " if fr else "International transfer IBAN: ")
        d.field(V.iban(), "iban"); d.add("\n")

    d.add("Adresse civile \tVille \tProvince \tCode Postal\n" if fr
          else "Civil address \tCity \tProvince \tPostal Code\n")
    d.field(V.street_address(lang), "address"); d.add(" \t")
    d.add(V.city() + " \tQC \t")                               # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    d.add("Requete Flinks ID \tId de connexion \tDerniere Actualisation\n" if fr
          else "Flinks Request Id \tLogin Id \tLast Refresh\n")
    d.field(V.uuid4(), "sensitive_account_id"); d.add(" \t")
    d.field(V.uuid4(), "sensitive_account_id"); d.add(" \t"); d.decoy(V.request_datetime(lang)); d.add("\n")

    _txn_table(d, fr, npages=1)
    return d.row()


# ---------------- layout B: expanded header with holder email/phone (RBC eStatement style) -----------

def _layout_expanded(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="flinks_stmt", lang=lang)
    bank = random.choice(_BANKS)

    d.add(bank + ("\nReleve de compte\n" if fr else "\nAccount Statement\n"))
    d.add("Nom: \tHeure de la demande \tStatut de la demande \tID\n" if fr
          else "Name: \tTime of Request \tRequest Status \tRequest Id\n")
    d.field(_name(lang), "person"); d.add(" \t")
    d.decoy(V.request_datetime(lang)); d.add(" \tCompleted \t"); d.decoy(_rid()); d.add("\n")

    d.add("Date de naissance: " if fr else "Date of birth: ")
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")
    d.add("Courriel: " if fr else "Email: "); d.field(V.email(), "email"); d.add("\n")
    d.add("Telephone: " if fr else "Phone: "); d.field(V.phone(), "phone_number"); d.add("\n")

    d.add("Identifiant de compte: " if fr else "Account id: ")
    d.field(V.bank_account(), "account_number"); d.add("  " + random.choice(_ACCT_TYPE) + "  " + bank + "\n")

    if random.random() < 0.85:                                  # international wire -> IBAN (train, common)
        d.add("Virement international IBAN: " if fr else "International transfer IBAN: ")
        d.field(V.iban(), "iban"); d.add("\n")

    d.add("Adresse civile \tVille \tProvince \tCode Postal\n" if fr
          else "Civil address \tCity \tProvince \tPostal Code\n")
    d.field(V.street_address(lang), "address"); d.add(" \t")
    d.add(V.city() + " \tQC \t")
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    d.add("Requete Flinks ID \tId de connexion \tDerniere Actualisation\n" if fr
          else "Flinks Request Id \tLogin Id \tLast Refresh\n")
    d.field(V.uuid4(), "sensitive_account_id"); d.add(" \t")
    d.field(V.uuid4(), "sensitive_account_id"); d.add(" \t"); d.decoy(V.request_datetime(lang)); d.add("\n")

    _txn_table(d, fr, npages=1)
    return d.row()


# ---------------- layout C (HELD-OUT): joint holders + multi-page + international IBAN -------------

def _layout_joint(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="flinks_stmt", lang=lang)
    bank = random.choice(_BANKS)
    npages = random.randint(2, 4)

    d.add("Nom: \tHeure de la demande \tStatut de la demande \tID\n" if fr
          else "Name: \tTime of Request \tRequest Status \tRequest Id\n")
    d.field(_name(lang), "person"); d.add(" ET " if fr else " AND ")     # joint holder
    d.field(_name(lang), "person"); d.add(" \t")
    d.decoy(V.request_datetime(lang)); d.add(" \tCompleted \t"); d.decoy(_rid()); d.add("\n")

    d.add("Identifiant de compte \tType de compte \tSolde actuel Institution Date de naissance\n" if fr
          else "Account id \tAccount Type \tCurrent Balance Institution Birth date\n")
    d.field(V.bank_account(), "account_number"); d.add(" " + random.choice(_ACCT_TYPE) + " ")
    d.decoy(_money(random.uniform(50, 9000))); d.add(" \t" + bank + " \t")
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")

    # international wire line -> IBAN positive (rare, foreign)
    d.add("Virement international IBAN: " if fr else "International transfer IBAN: ")
    d.field(V.iban(), "iban"); d.add("\n")

    d.add("Adresse civile \tVille \tProvince \tCode Postal\n" if fr
          else "Civil address \tCity \tProvince \tPostal Code\n")
    d.field(V.street_address(lang), "address"); d.add(" \t")
    d.add(V.city() + " \tQC \t")
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    d.add("Requete Flinks ID \tId de connexion \tDerniere Actualisation\n" if fr
          else "Flinks Request Id \tLogin Id \tLast Refresh\n")
    d.field(V.uuid4(), "sensitive_account_id"); d.add(" \t")
    d.field(V.uuid4(), "sensitive_account_id"); d.add(" \t"); d.decoy(V.request_datetime(lang)); d.add("\n")

    _txn_table(d, fr, npages=npages)
    return d.row()


LAYOUTS = [_layout_packed, _layout_expanded, _layout_joint]   # joint (suffix) = held-out structure


def gen(lang: str = None, split: str = "train") -> dict:
    lang = lang or ("fr" if random.random() < 0.65 else "en")
    return layouts.choose(split, LAYOUTS)(lang)


if __name__ == "__main__":
    random.seed(0)
    for sp in ("train", "heldout"):
        r = gen(split=sp); t = r["input"]
        print("=" * 70, sp, r["meta"]["lang"], r["meta"]["doctype"])
        print(t[:600])
        print("POSITIVES:", [(lab, t[s:e]) for s, e, lab in r["output"]["spans"]])
        print()
