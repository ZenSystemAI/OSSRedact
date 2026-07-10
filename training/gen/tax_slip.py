#!/usr/bin/env python3
"""tax_slip generator: synthetic Quebec/Canada employer-issued income slips in the REAL slip layout.

Grounded on the actual scaffold structures (pdftotext -layout):
 - RL-1 (Releve 1, Revenu Quebec, "Revenus d'emploi et revenus divers"): the lettered-box grid (A-W) +
   the four identity fields at the bottom (Numero d'assurance sociale du particulier / Numero de reference
   (facultatif) / Nom et adresse de l'employeur ou du payeur / Nom de famille, prenom et adresse du
   particulier) + the "Releve officiel - Revenu Quebec / Formulaire prescrit" footer.
 - T4 (federal, CRA, "Statement of Remuneration Paid"): the numbered-box grid (10 / 12 / 14 / 16 / 18 / 22
   / 24 / 26 / 44 / 46 / 52 / 55 / 56 + "Other information" coded boxes) with Employer's name, Employee's
   name and address (LAST-NAME FIRST, all caps per the guide), and the Employer's payroll account number.

PII policy (identity-only): the SUBJECT is the EMPLOYEE. POSITIVES are the employee's name, address, postal
code, the SIN (box 12 / NAS) as government_id, the LABELED employer name (organization), and -- on the T4
only -- the employer's payroll PROGRAM account number (Box 54, BN(9)+RP+4) as account_number. Everything
else is a hard negative DECOY: every box amount (dollars), the box numbers/letters themselves, the tax
year, the form codes (RL-1 / T4), the slip-code / last-slip-number metadata, the EMPLOYER's address (the
name is positive, its address is a decoy), and a Luhn-INVALID 9-digit SIN look-alike. The box-amount volume
is the false-positive moat. NOTE on tax_id (v11 round-2): the RL-1 slip FACE still carries no employer
NEQ/BN box, so we never fabricate a face field; but the TRAIN layout (_layout_rl1) now emits, as a ~30%
alternative, an employer QST(TQ)/GST(RT) registration number on a payer-correspondence cue line ("numero
d'inscription TVQ/TPS du payeur") -> tax_id. This teaches the RT/TQ registry form (collision rule 3) under
the employer block in-distribution; the held-out T4 layout is untouched and emits no tax_id. The fuller
NEQ/RT/TQ contrast still lives in the neq_register doctype. Collision rule 1 is also taught here: the Box 54
BN+RP payroll account (numeric+letter run) -> account_number, co-present with the SIN (government_id) so the
bare-numeric-ID contrast is in-distribution.

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix):
 - _layout_rl1 : Quebec RL-1, lettered boxes A-W, FR-native field labels, NAS + reference no.   [train]
 - _layout_t4  : Federal T4, numbered boxes 10-56 + "Other information" codes, employer payroll
                 account number, employee name LAST-FIRST all-caps.                             [HELD-OUT]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import cue_helpers as C         # noqa: E402
import layouts                  # noqa: E402


# ---------------- inline doctype-specific value shapes ----------------

def _box_amount() -> str:
    """A box dollar amount -> always a DECOY (transaction-level data, never PII). Mix of OQLF and plain."""
    val = random.randint(0, 145000) + random.random()
    if random.random() < 0.5:
        return f"{val:,.2f}"                                                  # 12,345.67
    return f"{int(val):,}".replace(",", " ") + f",{random.randint(0,99):02d}"  # OQLF 12 345,67


def _payroll_account() -> str:
    """Employer payroll program (BN+RP) account number -> account_number positive. 9-digit BN + RP + 4."""
    bn = "".join(random.choice("0123456789") for _ in range(9))
    return f"{bn}RP{random.randint(0, 9999):04d}"


def _employer_name(lang: str) -> str:
    return V.company(lang)


def _employer_account(lang: str) -> str:
    """Employer payroll-remittance bank/deposit account number -> account_number positive.

    Real RL-1 employer correspondence / remittance cover notes accompanying the slip routinely print the
    employer's NUMERIC payroll bank/deposit account number (the account remittances are drawn from / employer
    file account). We draw it from V.bank_account (the same numeric account value shape the held-out T4 slip's
    account_number field carries -- a bare/hyphenated digit run), so train teaches the bare-numeric account
    contrast in-distribution. Per collision rule 1 a NUMERIC bare/hyphenated run -> account_number (NOT tax_id,
    which is the RT/TQ registry form; NOT government_id, which is the Luhn SIN)."""
    return V.bank_account()


def _employer_tax_id() -> tuple[str, str]:
    """Employer/payer Revenu Quebec QST (TQ) or GST/HST (RT) registration number -> tax_id positive.
    Real RL-1 employer correspondence prints the payer's 'numero d'inscription TVQ/TPS'. We draw an RT/TQ
    form from V.tax_id() (re-sampling past the bare NEQ form so this stays a registry/business number, not a
    bare run that could read as account_number), and occasionally render the spaced variant some payers
    print -- C.group_digits only inserts spaces, so the fielded string stays a real substring of the digits
    it spaces. Returns (value, kind) where kind is 'TQ' or 'RT' for the FR/EN label wording."""
    for _ in range(8):
        tid = V.tax_id()
        if "RT" in tid:
            kind = "RT"
            break
        if "TQ" in tid:
            kind = "TQ"
            break
    else:                                   # extremely unlikely; force an RT form
        tid = "".join(random.choice("0123456789") for _ in range(9)) + f"RT{random.randint(0,9999):04d}"
        kind = "RT"
    if random.random() < 0.4:               # spaced variant: group the leading 9-digit BN run, keep suffix
        idx = tid.find(kind)
        bn, suffix = tid[:idx], tid[idx:]
        tid = C.group_digits(bn, (3, 3, 3)) + " " + suffix
    return tid, kind


def _employer_address(lang: str) -> str:
    """The employer's mailing address -> a DECOY (only the employer NAME is a positive)."""
    return V.street_address(lang) + ", " + V.city() + " (QC) " + V.postal_code()


def _t4_name_lastfirst(lang: str) -> str:
    """T4 employee name: LAST NAME, then first name, all capitals (per the CRA guide). One person span."""
    full = V.person(lang, caps=True)               # 'FIRST LAST' all-caps
    parts = full.split(" ")
    if len(parts) >= 2:
        return parts[-1] + ", " + " ".join(parts[:-1])
    return full


# RL-1 lettered boxes (real names from the scaffold). Amount boxes -> all decoys.
_RL1_BOXES = [
    ("A", "Revenus d'emploi"), ("B.A", "Cotisation au RRQ"), ("C", "Cotisation a l'assurance emploi"),
    ("D", "Cotisation a un RPA"), ("E", "Impot du Quebec retenu"), ("F", "Cotisation syndicale"),
    ("G", "Salaire admissible au RRQ"), ("H", "Cotisation au RQAP"), ("I", "Salaire admissible au RQAP"),
    ("J", "Regime prive d'ass. maladie"), ("K", "Voyages (region eloignee)"), ("L", "Autres avantages"),
    ("M", "Commissions"), ("N", "Dons de bienfaisance"), ("O", "Autres revenus"),
    ("P", "Regime d'ass. interentreprises"), ("Q", "Salaires differes"), ("S", "Pourboires recus"),
    ("V", "Nourriture et logement"), ("W", "Vehicule a moteur"),
]

# T4 numbered boxes (real names from the scaffold). Amount boxes -> all decoys.
_T4_BOXES = [
    ("14", "Employment income", "Revenus d'emploi"),
    ("16", "Employee's CPP contributions", "Cotisations de l'employe au RPC"),
    ("17", "Employee's QPP contributions", "Cotisations de l'employe au RRQ"),
    ("18", "Employee's EI premiums", "Cotisations de l'employe a l'AE"),
    ("20", "RPP contributions", "Cotisations a un RPA"),
    ("22", "Income tax deducted", "Impot sur le revenu retenu"),
    ("24", "EI insurable earnings", "Gains assurables d'AE"),
    ("26", "CPP/QPP pensionable earnings", "Gains ouvrant droit a pension RPC/RRQ"),
    ("44", "Union dues", "Cotisations syndicales"),
    ("46", "Charitable donations", "Dons de bienfaisance"),
    ("52", "Pension adjustment", "Facteur d'equivalence"),
    ("55", "Employee's PPIP premiums", "Cotisations de l'employe au RPAP"),
    ("56", "PPIP insurable earnings", "Gains assurables du RPAP"),
]

# T4 "Other information" coded boxes (real codes; the code numbers + amounts are decoys).
_T4_OTHER_CODES = ["40", "42", "66", "67", "71", "77", "85", "87"]

_QC_PROVINCE = "QC"


# ---------------- layout A: RL-1 (Quebec, lettered boxes A-W) ----------------

def _layout_rl1(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="tax_slip", lang=lang)
    year = random.choice(["2023", "2024", "2025"])

    # masthead: form code + title + year -> all DECOYS
    d.decoy("RL-1"); d.add("  ")
    d.add("RELEVE 1\n" if fr else "RELEVE 1 (RL-1 slip)\n")
    d.add("Revenus d'emploi et revenus divers\n" if fr
          else "Employment and other income\n")
    d.add("Annee " if fr else "Year "); d.decoy(year)
    d.add("   Code du releve  R   No du dernier releve transmis " if fr
          else "   Releve code  R   Last slip number ")
    d.decoy(str(random.randint(1000000, 9999999))); d.add("\n\n")

    # lettered box grid -> every box number AND amount is a DECOY
    for letter, name_fr in _RL1_BOXES:
        d.decoy(letter); d.add("- " + name_fr + "  ")
        d.decoy(_box_amount()); d.add("\n")
    d.add("Renseignements complementaires\n\n" if fr else "Additional information\n\n")

    # identity block (the ONLY positives + the employer-address decoy)
    # SIN cue: the formal field label OR -- as a ~30% alternative -- an inline-prose cue (some employer
    # cover notes / amended-slip memos word it as a sentence rather than the boxed label). Either way the
    # value is V.sin(valid=True) fielded as government_id; only the surrounding cue text changes.
    if random.random() < 0.30:
        if fr:
            d.add("Le numero d'assurance sociale figurant a votre dossier est le ")
            d.field(V.sin(valid=True), "government_id")
            d.add("; veuillez le verifier.\n")
        else:
            d.add("The social insurance number on file for this individual is ")
            d.field(V.sin(valid=True), "government_id")
            d.add("; please verify it.\n")
    else:
        d.add("Numero d'assurance sociale du particulier: " if fr
              else "Individual's social insurance number: ")
        d.field(V.sin(valid=True), "government_id"); d.add("\n")

    # reference number (facultatif) -> a Luhn-INVALID 9-digit look-alike DECOY
    d.add("Numero de reference (facultatif): " if fr else "Reference number (optional): ")
    d.decoy(V.sin(valid=False)); d.add("\n")

    d.add("Nom et adresse de l'employeur ou du payeur:\n" if fr
          else "Name and address of the employer or payer:\n")
    d.field(_employer_name(lang), "organization"); d.add("\n")
    d.decoy(_employer_address(lang)); d.add("\n")          # employer ADDRESS -> decoy
    # tax_id cue (~30% alternative): the RL-1 slip FACE carries no employer identification box, but employer
    # cover notes / payer correspondence accompanying the slip routinely print the payer's QST (TQ) or
    # GST/HST (RT) registration number ("numero d'inscription TVQ/TPS du payeur"). When present it is an
    # employer registry/business number -> tax_id (collision rule 3: RT/TQ registry form, never a bare run).
    # The SIN above remains the only government_id; the Luhn-invalid reference number stays the SIN decoy.
    if random.random() < 0.30:
        tid, kind = _employer_tax_id()
        if kind == "TQ":
            d.add("Numero d'inscription TVQ du payeur: " if fr
                  else "Payer's QST registration number: ")
        else:
            d.add("Numero d'inscription TPS du payeur: " if fr
                  else "Payer's GST/HST registration number: ")
        d.field(tid, "tax_id"); d.add("\n")

    # account_number cue (~30% alternative, coverage parity with the held-out T4 Box 54): employer
    # remittance / cover-note correspondence accompanying the RL-1 routinely prints the employer's NUMERIC
    # payroll bank/deposit account number ("numero de compte de l'employeur"), the account remittances draw
    # from. This is a bare/hyphenated digit run (V.bank_account, the same numeric account value shape the
    # held-out slip's account_number carries) -> account_number (collision rule 1: numeric run, never the
    # RT/TQ tax_id nor the Luhn SIN government_id). Co-present with the SIN above so the bare-numeric-account
    # vs Luhn-government-id contrast is taught in-distribution on this train layout.
    if random.random() < 0.30:
        d.add("Numero de compte de l'employeur: " if fr
              else "Employer's account number: ")
        d.field(_employer_account(lang), "account_number"); d.add("\n")

    d.add("Nom de famille, prenom et adresse du particulier:\n" if fr
          else "Individual's last name, first name and address:\n")
    d.field(V.person(lang, caps=False), "person"); d.add("\n")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + " (QC) ")                              # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    d.add("Releve officiel - Revenu Quebec\nFormulaire prescrit\n" if fr
          else "Official slip - Revenu Quebec\nPrescribed form\n")
    return d.row()


# ---------------- layout B (HELD-OUT): T4 (federal, numbered boxes 10-56 + Other information) ----------

def _layout_t4(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="tax_slip", lang=lang)
    year = random.choice(["2023", "2024", "2025"])

    # masthead: form code + title + year -> all DECOYS
    d.decoy("T4"); d.add("  ")
    d.add("Etat de la remuneration payee\n" if fr else "Statement of Remuneration Paid\n")
    d.add(("Agence du revenu du Canada\n" if fr else "Canada Revenue Agency\n"))
    d.add("Annee / Year " if fr else "Year ")
    d.decoy(year); d.add("\n")

    # Box 10 province + Box 12 SIN are at the top of the federal slip
    d.add("Box 10 - Province of employment / Province d'emploi: ")
    d.add(_QC_PROVINCE + "\n")                              # province code alone -> NEGATIVE
    d.add("Box 12 - Social insurance number / Numero d'assurance sociale\n")
    d.field(V.sin(valid=True), "government_id"); d.add("\n")

    # numbered box grid -> every box number AND amount is a DECOY
    for num, name_en, name_fr in _T4_BOXES:
        d.add("Box " if not fr else "Case ")
        d.decoy(num); d.add(" - " + (name_fr if fr else name_en) + "  ")
        d.decoy(_box_amount()); d.add("\n")

    # "Other information" coded boxes -> the codes + amounts are decoys
    d.add("Other information / Autres renseignements\n")
    for code in random.sample(_T4_OTHER_CODES, k=random.randint(2, 4)):
        d.add("Code "); d.decoy(code); d.add("  "); d.decoy(_box_amount()); d.add("\n")

    # employer block: NAME positive, address decoy, and the single real employer identifier on the slip face:
    # Box 54 "Employer's account number" = the 15-char payroll PROGRAM account number (BN(9)+RP+4). This is the
    # ONLY employer number field on the real T4 slip; there is NO separate "Business number" line distinct from
    # box 54, so do not fabricate one. Per collision rule 1 the BN+RP payroll account -> account_number.
    d.add("Employer's name / Nom de l'employeur:\n")
    d.field(_employer_name(lang), "organization"); d.add("\n")
    d.decoy(_employer_address(lang)); d.add("\n")          # employer ADDRESS -> decoy
    # Box 54 "Employer's account number" = the 15-char payroll PROGRAM account number (BN(9)+RP+4). Per the
    # RC4120 guide this is the ONLY employer number field on the real T4 slip face; there is NO separate
    # "Business number" line distinct from box 54, so we do NOT fabricate one. Per collision rule 1 the
    # BN+RP payroll account -> account_number (NOT tax_id; tax_id is the NEQ/RT/TQ register doctype's field).
    d.add("Box 54 - Employer's account number / Numero de compte de l'employeur: ")
    d.field(_payroll_account(), "account_number"); d.add("\n")

    # employee block: name LAST-FIRST all-caps (per CRA guide) + address + postal
    d.add("Employee's name and address / Nom et adresse de l'employe:\n")
    d.field(_t4_name_lastfirst(lang), "person"); d.add("\n")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + " " + _QC_PROVINCE + " ")             # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    return d.row()


LAYOUTS = [_layout_rl1, _layout_t4]   # T4 (suffix) = held-out structure (numbered boxes vs lettered)


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
