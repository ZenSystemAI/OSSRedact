#!/usr/bin/env python3
"""tax_notice generator: synthetic Quebec/Canada tax assessment notices in the REAL document structure.

Grounded on the two hand-built scaffolds (datasets/scaffolds/handbuilt/):
 - qc-avis-de-cotisation.md : Revenu Quebec "Avis de cotisation" (FR primary).
 - cra-noa.md               : Canada Revenue Agency "Notice of Assessment" (bilingual header, EN/FR).

The product is faithful layout + correct 20-scheme labels + explicit hard-negative decoys. Per the v11
contract section 4 (identity-only redaction) the SUBJECT identity is the positive; every transaction-level
datum (tax-year, issue/limit dates, all dollar amounts, line numbers) and both agency identities (Revenu
Quebec / Canada Revenue Agency, tax-centre + return addresses, the public 1-800 enquiry lines) are DECOYS.

KEY CONTRASTS this doctype teaches:
 - FULL SIN (V.sin valid=True, Luhn-pass, QC first digit 2/3) under a NAS / Social-insurance cue
   -> government_id ; the CRA-style MASKED SIN last-4 ("XXX XX4 286") -> NEGATIVE decoy (never labeled).
 - Assessment / notice number (^[QM][A-Z0-9]{10}$, the QC avis number) -> sensitive_account_id.
 - QC "Numero de reference (paiement)" grouped opaque ref -> sensitive_account_id.
 - CRA NETFILE access code (8-char alnum, top-right of the NOA) -> sensitive_account_id, NOT password and
   NOT secret (it is an opaque access reference, the single most look-alike credential on the doc).
 - The depot-direct / direct-deposit account number (compte / account-ending) -> account_number ; the LONE
   institution (3-digit) and transit (5-digit) fragments -> NEGATIVE decoys (collision rule 1/2).

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix per layouts.split_pools):
 - _layout_qc_avis : Revenu Quebec avis de cotisation, FR-primary "Label : valeur" prose + SOMMAIRE.   [train]
 - _layout_cra_noa : CRA Notice of Assessment, bilingual header, top-right NETFILE code, masked SIN,
                     NOTICE DETAILS / ACCOUNT SUMMARY / TAX ASSESSMENT line-number table, RRSP block. [heldout]
The two structures differ in issuer, language frame, the SIN treatment (full vs masked), the credential
present (payment ref vs NETFILE code), and the body shape (prose summary vs line-number assessment table).

gen(lang, split) -> one offset-true row dict. Caller seeds `random`. ~65% FR / 35% EN.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import cue_helpers as C         # noqa: E402
import layouts                  # noqa: E402

_ALNUM_UP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# Public Revenu Quebec institutional return address (PUBLIC fact, NOT PII -> filler, never labeled).
_RQ_ADDR = ["3800, rue de Marly\nQuebec (Quebec)  G1X 4A5",
            "C. P. 3000, succursale Place-Desjardins\nMontreal (Quebec)  H5B 1A4"]
# Public CRA tax-centre addresses (PUBLIC fact, NOT PII -> filler, never labeled).
_CRA_CENTRE = [("Jonquiere Tax Centre", "2251 boulevard Rene-Levesque", "Jonquiere QC  G7S 5J2"),
               ("Sudbury Tax Centre", "1050 Notre Dame Avenue", "Sudbury ON  P3A 5C1"),
               ("Winnipeg Tax Centre", "66 Stapon Road", "Winnipeg MB  R3C 3M2")]
# Public agency enquiry lines (PUBLIC, NOT PII -> filler).
_RQ_PHONE = ["1 800 267-6299", "514 864-6299", "418 659-6299"]
_CRA_PHONE = ["1-800-959-8281", "1-866-426-1527", "613-940-8495"]


# ---------------- inline doctype-specific value shapes ----------------

def _notice_number() -> str:
    """QC avis-de-cotisation number: ^[QM][A-Z0-9]{10}$ (11 chars, M/Q prefix). -> sensitive_account_id."""
    return random.choice("MQ") + "".join(random.choice(_ALNUM_UP) for _ in range(10))


def _payment_ref() -> str:
    """QC 'Numero de reference (paiement)': a 12-digit opaque ref, grouped 4-4-4. -> sensitive_account_id.
    Opaque/structured reference (not a bare bank-account run) -> sensitive_account_id, never account_number."""
    digits = "".join(random.choice("0123456789") for _ in range(12))
    return f"{digits[:4]} {digits[4:8]} {digits[8:]}"


def _netfile_code() -> str:
    """CRA NETFILE access code: a unique 8-character access code of numbers AND letters, top-right of the NOA
    (cra-noa.md / canada.ca 'Understand sections of your notice'). -> sensitive_account_id (opaque access
    ref, NOT password / NOT secret). Forced to mix >=1 letter and >=1 digit so it never looks alphabetic."""
    body = [random.choice("ABCDEFGHJKLMNPRSTUVWXYZ"), random.choice("23456789")]
    body += [random.choice("ABCDEFGHJKLMNPRSTUVWXYZ23456789") for _ in range(6)]
    random.shuffle(body)
    return "".join(body)


def _masked_sin() -> str:
    """CRA-style MASKED SIN showing only the last 4 ('XXX XX4 286'). A partial look-alike of the full SIN ->
    NEGATIVE decoy (emitted via d.decoy(), NEVER labeled). Several real masking shapes."""
    last4 = "".join(random.choice("0123456789") for _ in range(4))
    style = random.random()
    if style < 0.45:
        return f"XXX XX{last4[0]} {last4[1:]}"        # XXX XX4 286
    if style < 0.75:
        return f"XXX-XX-{last4}"                       # XXX-XX-1286
    return f"*** ** {last4}"                           # *** ** 4286


def _compte_number() -> str:
    """Direct-deposit account (the 'compte' on the QC avis): a bare 6-9 digit run. -> account_number."""
    return "".join(random.choice("0123456789") for _ in range(random.randint(6, 9)))


def _acct_ending() -> str:
    """CRA 'account ending NNNN': the last 4 digits of the direct-deposit account. -> account_number."""
    return "".join(random.choice("0123456789") for _ in range(4))


def _tax_id_train() -> str:
    """Business/registry number for a Revenu Quebec business avis de cotisation -> tax_id. Uses the shared
    V.tax_id() family (GST #########RT####, QST ##########TQ####, bare-10-digit NEQ). When the sampled value
    is the pure-digit NEQ, ~45% of the time it is printed in the spaced registry form via C.group_digits(
    (3,3,4)) (e.g. '881 147 1049') -- the spacing the register really prints. group_digits is applied ONLY to
    the all-digit NEQ (RT/TQ carry letters, which group_digits would strip -> not a substring), so the fielded
    string always stays a real substring of the rendered text (offset-truth preserved)."""
    v = V.tax_id()
    if v.isdigit() and random.random() < 0.45:        # bare-10-digit NEQ -> spaced (3,3,4) registry form
        return C.group_digits(v, (3, 3, 4))
    return v


def _money_en(v: float) -> str:
    """English/CRA dollar form '$1,204.55' (amount -> always a DECOY)."""
    return f"${v:,.2f}"


def _money_fr(v: float) -> str:
    """OQLF dollar form '58 420,00 $' (amount -> always a DECOY)."""
    return f"{int(v):,}".replace(",", " ") + f",{int(round((v - int(v)) * 100)):02d} $"


def _line_amount(v: float) -> str:
    """A bare line-amount on the CRA assessment table '61,300.00' (no $ sign; amount -> DECOY)."""
    return f"{v:,.2f}"


def _issue_date(lang: str) -> str:
    """Notice issue date (NOT a birth date) -> NEGATIVE decoy. Long month-name form, no clock time."""
    d = random.randint(1, 28); m = random.randint(1, 12); y = random.randint(2023, 2026)
    months_fr = ["janvier", "fevrier", "mars", "avril", "mai", "juin", "juillet", "aout",
                 "septembre", "octobre", "novembre", "decembre"]
    months_en = ["January", "February", "March", "April", "May", "June", "July", "August",
                 "September", "October", "November", "December"]
    if lang == "fr":
        return f"{d} {months_fr[m-1]} {y}"
    return f"{months_en[m-1]} {d}, {y}"


def _tax_year() -> str:
    return str(random.randint(2020, 2025))


# ---------------- layout A (TRAIN): Revenu Quebec avis de cotisation (FR-primary prose) ----------------

def _layout_qc_avis(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="tax_notice", lang=lang)

    # --- issuer return address: PUBLIC institutional fact -> filler (never labeled) ---
    d.add("Revenu Quebec\n")
    d.add(random.choice(_RQ_ADDR) + "\n\n")

    # --- addressee identity block (the subject: name + address + postal) ---
    d.add("                                         ")
    d.field(V.person(lang, caps=(random.random() < 0.7)), "person"); d.add("\n")
    d.add("                                         ")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add("                                         ")
    d.add(V.city() + " (Quebec)  ")                          # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    reassess = random.random() < 0.3
    if reassess:
        d.add("AVIS DE NOUVELLE COTISATION\n\n" if fr else "NOTICE OF REASSESSMENT\n\n")
    else:
        d.add("AVIS DE COTISATION\n\n" if fr else "NOTICE OF ASSESSMENT\n\n")

    # --- field lines: tax-year + dates are DECOYS; notice/payment refs + full SIN are POSITIVES ---
    d.add(("Annee d'imposition : " if fr else "Tax year: ")); d.decoy(_tax_year()); d.add("\n")
    d.add(("Date de l'avis : " if fr else "Notice date: ")); d.decoy(_issue_date(lang)); d.add("\n")

    d.add(("Numero d'avis de cotisation : " if fr else "Assessment notice number: "))
    d.field(_notice_number(), "sensitive_account_id"); d.add("\n")

    # full SIN shown on the QC avis -> government_id (Luhn-valid). Paired masked decoy some of the time.
    d.add(("Numero d'assurance sociale : " if fr else "Social insurance number: "))
    d.field(V.sin(valid=True), "government_id"); d.add("\n")
    if random.random() < 0.35:
        d.add(("(version abregee au dossier : " if fr else "(masked on file: "))
        d.decoy(_masked_sin()); d.add(")\n")                 # masked last-4 -> NEGATIVE decoy

    # --- business-account assessment: a Revenu Quebec avis can cover a registered enterprise's tax account
    # (GST/HST RT, QST TQ, or NEQ) -> the business/registry number is a tax_id POSITIVE. Emitted ~32% of the
    # time as an ALTERNATIVE alongside the personal-only avis. Per occurrence we teach BOTH cue styles the
    # held-out search/inline layouts use: a FORMAL labeled cue OR a TERSE inline cue (no 'Label : ' colon
    # frame, the number tucked into a prose clause / bare brand-style tag). FR and EN forms for each. The SIN
    # government_id above + every decoy + the collision rules are untouched. ----
    if random.random() < 0.32:
        tid = _tax_id_train()                                # V.tax_id() RT/TQ/NEQ, sometimes (3,3,4) spaced
        if random.random() < 0.62:
            # FORMAL labeled cue (the 'Numero d'entreprise (NE)' / 'Numero d'identification' line)
            lab_fr = random.choice(["Numero d'entreprise (NE) : ",
                                    "Numero d'identification de l'entreprise : ",
                                    "Numero de compte d'entreprise : "])
            lab_en = random.choice(["Business number (BN): ",
                                    "Business identification number: ",
                                    "Business account number: "])
            d.add(lab_fr if fr else lab_en)
            d.field(tid, "tax_id"); d.add("\n")
        else:
            # TERSE inline cue: number tucked into a prose clause or a bare 'NE/BN' tag, no colon frame
            if fr:
                clause = random.choice([
                    "Cette cotisation vise le compte d'entreprise NE ",
                    "Etabli pour l'entreprise enregistree sous le NE ",
                    "Compte vise : NE "])
            else:
                clause = random.choice([
                    "This assessment relates to business account BN ",
                    "Issued for the enterprise registered under BN ",
                    "Account concerned: BN "])
            d.add(clause)
            d.field(tid, "tax_id"); d.add(".\n")

    d.add(("Numero de reference (paiement) : " if fr else "Payment reference number: "))
    d.field(_payment_ref(), "sensitive_account_id"); d.add("\n\n")

    # --- SOMMAIRE: every figure is a DECOY (transaction-level) ---
    revenu = random.uniform(28000, 96000)
    d.add("SOMMAIRE\n" if fr else "SUMMARY\n")
    d.add(("  Revenu total ............................... " if fr
           else "  Total income ............................... "))
    d.decoy(_money_fr(revenu) if fr else _money_en(revenu)); d.add("\n")
    imposable = revenu * random.uniform(0.78, 0.95)
    d.add(("  Revenu imposable ........................... " if fr
           else "  Taxable income ............................. "))
    d.decoy(_money_fr(imposable) if fr else _money_en(imposable)); d.add("\n")
    impot = imposable * random.uniform(0.10, 0.20)
    d.add(("  Impot du Quebec ............................ " if fr
           else "  Quebec income tax .......................... "))
    d.decoy(_money_fr(impot) if fr else _money_en(impot)); d.add("\n")
    credits = impot * random.uniform(0.8, 1.4)
    d.add(("  Credits d'impot et retenues ............... " if fr
           else "  Tax credits and deductions ................ "))
    d.decoy(_money_fr(credits) if fr else _money_en(credits)); d.add("\n")
    d.add("  -----------------------------------------------------\n")

    owing = credits < impot
    net = abs(impot - credits)
    if owing:
        d.add(("  Solde a payer .............................. " if fr
               else "  Balance owing .............................. "))
        d.decoy(_money_fr(net) if fr else _money_en(net)); d.add("\n")
        d.add(("  Date limite de paiement : " if fr else "  Payment due date: "))
        d.decoy(_issue_date(lang)); d.add("\n\n")
    else:
        d.add(("  Remboursement .............................. " if fr
               else "  Refund ..................................... "))
        d.decoy(_money_fr(net) if fr else _money_en(net)); d.add("\n\n")

        # --- depot direct: institution + transit are LONE fragments (decoys); compte is account_number ---
        d.add(("Le remboursement sera depose dans le compte bancaire enregistre\n(depot direct) : "
               if fr else "The refund will be deposited to the registered bank account\n(direct deposit): "))
        d.add(("institution " if fr else "institution "))
        d.decoy(f"{random.choice(['001','002','003','004','006','010','614','815'])}")   # lone institution -> NEGATIVE
        d.add(", transit "); d.decoy(f"{random.randint(0, 99999):05d}")                  # lone transit -> NEGATIVE
        d.add(", " + ("compte " if fr else "account "))
        d.field(_compte_number(), "account_number"); d.add(".\n\n")

    # --- footer: public service line + portal note (PUBLIC -> filler) ---
    d.add(("Pour consulter cet avis en tout temps : Mon dossier pour les citoyens.\n"
           if fr else "To view this notice anytime: My Account for citizens.\n"))
    d.add(("Service a la clientele : " if fr else "Client services: "))
    d.add(random.choice(_RQ_PHONE) + "\n")
    return d.row()


# ---------------- layout B (HELD-OUT): CRA Notice of Assessment (bilingual, line-number table) ----------

def _layout_cra_noa(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="tax_notice", lang=lang)

    # --- bilingual issuer header + tax-centre address: PUBLIC institutional fact -> filler ---
    d.add("Canada Revenue Agency             Agence du revenu du Canada\n")
    centre = random.choice(_CRA_CENTRE)
    d.add(centre[0] + "\n" + centre[1] + "\n" + centre[2] + "\n\n")

    # --- taxpayer name (left) + NETFILE access code (top-right) ---
    d.field(V.person(lang, caps=(random.random() < 0.7)), "person")
    d.add(("                                   Code d'acces NETFILE : " if fr
           else "                                   NETFILE access code: "))
    d.field(_netfile_code(), "sensitive_account_id"); d.add("\n")          # opaque access ref, NOT password
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + " QC  ")                                               # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    reassess = random.random() < 0.3
    d.add(("DETAILS DE L'AVIS\n" if fr else "NOTICE DETAILS\n"))
    # masked SIN last-4 -> NEGATIVE decoy (the contrast against the QC avis full SIN)
    d.add(("  Numero d'assurance sociale ......... " if fr
           else "  Social insurance number ............ "))
    d.decoy(_masked_sin()); d.add("\n")
    d.add(("  Annee d'imposition ................. " if fr else "  Tax year ........................... "))
    d.decoy(_tax_year()); d.add("\n")
    d.add(("  Date d'emission .................... " if fr else "  Date issued ........................ "))
    d.decoy(_issue_date(lang)); d.add("\n\n")

    # --- ACCOUNT SUMMARY: refund / amount due / nil -> all amounts are DECOYS ---
    d.add(("RESUME DU COMPTE\n" if fr else "ACCOUNT SUMMARY\n"))
    outcome = random.random()
    refund = random.uniform(50, 4200)
    if outcome < 0.45:
        d.add(("  Remboursement : " if fr else "  Refund: ")); d.decoy(_money_en(refund)); d.add("\n\n")
        getting_refund = True
    elif outcome < 0.8:
        d.add(("  Montant du : " if fr else "  Amount due: ")); d.decoy(_money_en(refund)); d.add("\n\n")
        getting_refund = False
    else:
        d.add(("  Solde : Nul\n\n" if fr else "  Balance: Nil\n\n"))
        getting_refund = False

    # --- TAX ASSESSMENT: CRA line-number table -> line numbers + amounts are DECOYS ---
    d.add(("EVALUATION FISCALE\n" if fr else "TAX ASSESSMENT\n"))
    total_income = random.uniform(30000, 110000)
    for line, label_fr, label_en, base in [
        ("15000", "Revenu total", "Total income", total_income),
        ("26000", "Revenu imposable", "Taxable income", total_income * random.uniform(0.8, 0.95)),
        ("43500", "Total a payer", "Total payable", total_income * random.uniform(0.1, 0.2)),
        ("43700", "Impot total retenu", "Total income tax deducted", total_income * random.uniform(0.12, 0.22)),
    ]:
        lab = label_fr if fr else label_en
        d.add("  Ligne " + line + "  " if fr else "  Line " + line + "  ")
        d.add(lab.ljust(30, ".") + " "); d.decoy(_line_amount(base)); d.add("\n")
    # the refund/owing line
    d.add(("  Ligne 48400  " if fr else "  Line 48400  "))
    d.add(("Remboursement".ljust(30, ".") if fr else "Refund".ljust(30, ".")) + " ")
    d.decoy(_line_amount(refund)); d.add("\n")

    # direct-deposit account ending (last 4) -> account_number ; cheque-by-mail otherwise
    if getting_refund and random.random() < 0.7:
        d.add(("  Depot direct au compte se terminant par " if fr
               else "  Direct deposit to account ending "))
        d.field(_acct_ending(), "account_number"); d.add("\n\n")
    else:
        d.add(("  Cheque poste a l'adresse au dossier\n\n" if fr
               else "  Cheque mailed to the address on file\n\n"))

    # --- RRSP / FHSA statement block: extra amounts, all DECOYS (appears on many notices) ---
    if random.random() < 0.7:
        d.add(("RELEVE DE LA LIMITE DE COTISATION REER\n" if fr
               else "RRSP DEDUCTION LIMIT STATEMENT\n"))
        limit = random.uniform(2000, 31000)
        d.add(("  Limite de deduction REER ........... " if fr
               else "  RRSP deduction limit ............... "))
        d.decoy(_line_amount(limit)); d.add("\n")
        d.add(("  Cotisations inutilisees ............ " if fr
               else "  Unused RRSP contributions .......... "))
        d.decoy(_line_amount(random.uniform(0, 1500))); d.add("\n")
        d.add(("  Marge de cotisation disponible ..... " if fr
               else "  Available contribution room ........ "))
        d.decoy(_line_amount(limit)); d.add("\n\n")

    # --- footer: public CRA enquiry line + access-code note (PUBLIC -> filler) ---
    d.add(("Pour toute question, ouvrez une session dans votre compte de l'ARC ou composez le "
           if fr else "If you have questions, sign in to your CRA account or call "))
    d.add(random.choice(_CRA_PHONE) + ".\n")
    return d.row()


LAYOUTS = [_layout_qc_avis, _layout_cra_noa]   # CRA NoA (suffix) = held-out structure


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
