#!/usr/bin/env python3
"""tax_return generator: synthetic Quebec/Canada tax-return forms in the REAL Revenu Quebec layout.

Grounded on two genuinely-distinct real form structures (the scaffolds under datasets/scaffolds):
 - TP-1.D (Declaration de revenus du Quebec): the PERSONAL income return. A numbered field-cell layout:
   "Renseignements sur vous" (Nom de famille / Prenom -> person, NAS -> government_id (SIN), Date de
   naissance -> date_of_birth cued by the label, Sexe), an "Adresse" block (Appartement / Numero / Rue ->
   address, Ville + Province QC -> NEGATIVE, Code postal -> postal_code), then "Situation"/"Revenu" line
   rows. Every cell carries a small LINE NUMBER (1, 2, 11, 6, 7, 8, 9, 12, 101, 199 ...) and the income
   lines carry $ AMOUNTS -- those line numbers, amounts, the tax YEAR, the form code (TP-1.D (2025-12)) and
   the prescribed-form barcode (Y501 ZZ 89534849) are ALL decoys. A second "conjoint(e)" (spouse) block
   repeats Nom/Prenom/NAS/DOB for the spouse (more person/government_id/date_of_birth positives).
 - FP-500 (TPS/TVH et TVQ): the BUSINESS GST/QST remittance. A DIFFERENT structure: a tax-account header
   (Numero de compte TPS/TVH -> tax_id (GST #########RT####), NEQ -> tax_id (10-digit) -- the real FP-500
   header order, which has NO dedicated QST-account cell -- then the QST account under its real
   Revenu Quebec label "Numero d'inscription au fichier de la TVQ" -> tax_id (QST ##########TQ####),
   Nom = business name -> organization,
   Numero d'identification / Dossier -> account_number), reporting-period date ranges (decoys), then the
   line-101..213 detailed-calculation table (all amounts/line numbers = decoys), then a "Signature" part
   with Nom de la personne autorisee -> person, Titre, Date. Institutional service phone numbers in the
   general-info text are decoys. The three tax-account shapes (GST RT / QST TQ / NEQ) are exactly the
   V.tax_id() family (contract section 6), but each is pinned to its real cell here so the GST cell never
   gets a NEQ-shaped value, etc. This is the HELD-OUT structure (the suffix of LAYOUTS).

20-scheme labels emitted: person, address, postal_code, government_id, date_of_birth, phone_number,
account_number, organization, tax_id. Everything else (line numbers, line amounts, the year, form codes,
barcodes, instalment amounts, reporting-period dates, institutional phones, Sexe codes, the QC province
token, the city name) is a NEGATIVE decoy -- per the identity-only redaction policy.

LAYOUTS (>=2 distinct real structures; held-out = the suffix):
 - _layout_tp1_basic   : TP-1 personal return, taxpayer block only.                                  [train]
 - _layout_tp1_spouse  : TP-1 personal return + conjoint(e) block + income lines (denser). v11 r3: a    [train]
                         fraction of sole-proprietor rows now carry a business-REGISTRATION-EXTRACT
                         block (tax_id RT/TQ/NEQ + account_number numeric id run + organization
                         business-name header) -- closing the label-coverage gap vs the FP-500 held-out
                         while staying distinct from the FP-500 form skeleton (no form code / calc table /
                         reporting-period header).
 - _layout_fp500       : FP-500 GST/QST business remittance (tax_id + organization header, no SIN/DOB). [heldout]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402
import cue_helpers as C         # noqa: E402


# ---------------- inline doctype-specific value shapes ----------------

def _line_amount() -> str:
    """A tax-return line amount in OQLF style ('12 345,67') WITHOUT a trailing $ (the TP-1/FP-500 cells
    print the bare number; the $ sits in the column header). Always a DECOY."""
    val = random.randint(0, 99999)
    cents = random.randint(0, 99)
    grouped = f"{val:,}".replace(",", " ")
    return f"{grouped},{cents:02d}"


def _barcode() -> str:
    """The TP-1 prescribed-form barcode token, e.g. 'Y501 ZZ 89534849'. Always a DECOY (form metadata)."""
    return f"Y{random.randint(500, 599)} ZZ {random.randint(80000000, 89999999)}"


def _form_code_tp1() -> str:
    return f"TP-1.D ({random.choice(['2024-12', '2025-12'])})"


def _identifier_no() -> str:
    """Revenu Quebec 'Numero d'identification' / 'Dossier' on FP-500: a bare numeric run, NO Luhn ->
    account_number (NOT a SIN, NOT a tax_id). Distinct from the GST/QST/NEQ tax_id."""
    return "".join(random.choice("0123456789") for _ in range(random.choice([10, 10, 11])))


def _dossier_no() -> str:
    return "".join(random.choice("0123456789") for _ in range(4))


def _service_phone() -> str:
    """An institutional Revenu Quebec service line printed in the general-info text -> NEGATIVE decoy
    (not the SUBJECT's phone). Real numbers on FP-500: 418 659-4692 / 514 873-4692 / 1 800 567-4692."""
    return random.choice(["418 659-4692", "514 873-4692", "1 800 567-4692"])


def _period_range(fr: bool) -> str:
    """A reporting-period date range 'Du AAAA-MM-JJ au AAAA-MM-JJ' -> all DECOY dates (not DOB)."""
    return f"{V.iso_date()} {'au' if fr else 'to'} {V.iso_date()}"


def _sexe(fr: bool) -> str:
    return random.choice(["1", "2"])     # masculin / feminin checkbox code -> DECOY


# ---------------- v11 r2 cue: business number on a TP-1 self-employment workpaper (train) ----------------

def _taxid_workpaper_cue(d: Doc, fr: bool) -> None:
    """Append a single self-employment / business-number workpaper line to a TP-1 return -> tax_id.

    WHY (recall-first, catastrophic tier): the train TP-1 layouts emit NO tax_id, yet a real TP-1 with
    self-employment income (line 164 'Revenus nets d'entreprise') is filed alongside a sole-proprietor
    business number -- NEQ / numero de TVQ / numero d'identification RT. The held-out FP-500 teaches
    tax_id only under a formal two-cell tabbed GST/QST header; here we teach the SAME V.tax_id() entity
    under a TERSE INLINE PROSE cue on one line, a presentation the held-out never uses (no copied
    structure). value via V.tax_id(); a fraction of NEQ runs print spaced (C.group_digits, digits
    identical so the fielded span is a real substring). Offset-true via d.field(value, 'tax_id')."""
    tid = V.tax_id()
    # the three real cue families from the spec, bilingual; pick by which V.tax_id() shape was drawn so the
    # cue word matches the value (RT account -> RT cue, TQ account -> TVQ cue, bare 10-digit -> NEQ cue).
    if "RT" in tid:
        cue = ("Numero d'identification - RT : " if fr else "Identification number - RT: ")
    elif "TQ" in tid:
        cue = ("numero de TVQ : " if fr else "QST number: ")
    else:
        cue = ("Numero d'entreprise du Quebec (NEQ) : " if fr else "Quebec enterprise number (NEQ): ")
        if random.random() < 0.5:                       # spaced NEQ variant; digits unchanged
            tid = C.group_digits(tid, (3, 3, 4))
    d.add(("Travail autonome - " if fr else "Self-employment - ") + cue)
    d.field(tid, "tax_id"); d.add("\n")


# ---------------- v11 r3 block: sole-proprietor business-registration extract on a TP-1 (train) ----------------

def _business_registration_block(d: Doc, fr: bool, lang: str) -> None:
    """Append a sole-proprietor business-registration extract to a TP-1 self-employment return, teaching the
    THREE business-return labels the FP-500 held-out exercises -- tax_id (GST RT / QST TQ / NEQ),
    account_number (the numeric 'Numero d'identification' / 'Dossier' run) and organization (the labeled
    business-name header) -- which the personal TP-1 layouts otherwise never produce (a label-coverage gap:
    train emitted almost no tax_id and no account_number / organization).

    WHY a separate block, not the FP-500 skeleton: this is a registration-confirmation extract attached to a
    sole-proprietor return (line 164 self-employment income), NOT the FP-500 remittance form -- no FP-500
    form code, no Part-1 calculation table, no reporting-period header. It reuses the held-out's exact VALUE
    helpers so the fielded shapes match (_gst_account RT, _qst_account TQ, _neq 10-digit -> tax_id;
    _identifier_no bare numeric run -> account_number; V.company labeled -> organization), under the same
    real Revenu Quebec cue vocabulary ('Numero de compte TPS/TVH', 'TVQ', 'NEQ', 'Numero d'identification'),
    bilingual -- but composed in a presentation the held-out never emits (no copied structure). This also
    sharpens the tax_id-vs-account_number-vs-organization contrast on a single page: the RT/TQ/NEQ accounts
    must route to tax_id while the bare numeric identification run routes to account_number (round-2 confused
    tax_id -> sensitive_account_id; co-locating the numeric run keeps the boundary crisp).

    Offset-true: every positive via d.field(value, label); the dossier ref + the cue text are decoy / filler.
    """
    d.add(("Inscription au registre des entreprises - travailleur autonome\n" if fr
           else "Business registration extract - sole proprietor\n"))

    # business name header -> organization (the labeled 'Nom' business-name cell, V.company like FP-500)
    d.add(("Nom de l'entreprise : " if fr else "Business name: "))
    d.field(V.company(lang), "organization"); d.add("\n")

    # GST/HST account (RT) and QST (TVQ) accounts -> tax_id, reusing the FP-500 RT / TQ value helpers + cues
    d.add(("Numero de compte TPS/TVH : " if fr else "GST/HST account number: "))
    d.field(_gst_account(), "tax_id"); d.add("\n")
    d.add(("Numero d'inscription au fichier de la TVQ : " if fr else "QST registration number: "))
    d.field(_qst_account(), "tax_id"); d.add("\n")

    # NEQ -> tax_id, reusing the FP-500 NEQ value helper + cue
    d.add(("Numero d'entreprise du Quebec (NEQ) : " if fr else "Quebec enterprise number (NEQ): "))
    d.field(_neq(), "tax_id"); d.add("\n")

    # numeric 'Numero d'identification' / 'Dossier' run -> account_number (NUMERIC, no Luhn), the SAME
    # _identifier_no helper the held-out routes to account_number -- contrasted against the RT/TQ/NEQ tax_ids
    # above so the model learns the bare numeric run is account_number, not a tax_id / sensitive_account_id.
    d.add(("Numero d'identification : " if fr else "Identification number: "))
    d.field(_identifier_no(), "account_number")
    d.add(("  Dossier : " if fr else "  File: ")); d.decoy(_dossier_no()); d.add("\n")


# ---------------- layout A: TP-1 personal return, taxpayer block (train) ----------------

def _layout_tp1_basic(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="tax_return", lang=lang)

    # form header / year (all decoy metadata)
    d.add(("DECLARATION DE REVENUS" if fr else "INCOME TAX RETURN") + "\t")
    d.decoy(_form_code_tp1()); d.add("\t")
    d.decoy(str(random.choice([2024, 2025]))); d.add("\n")           # tax YEAR -> decoy

    d.add(("Renseignements sur vous\n" if fr else "Information about you\n"))

    # Nom de famille (1) / Prenom (2) -> one person value; line numbers 1, 2 are decoys
    d.add(("Nom de famille" if fr else "Last name") + " \t")
    d.add(("Prenom" if fr else "First name") + "\n")
    d.add("1 \t"); d.field(V.person(lang, caps=(random.random() < 0.5)), "person"); d.add("\t2\n")

    # NAS (11) -> government_id (SIN) ; Date de naissance (6) -> date_of_birth (CUED) ; Sexe (4) decoy
    d.add(("Numero d'assurance sociale (NAS)" if fr else "Social insurance number (SIN)") + " \t")
    d.add(("Date de naissance" if fr else "Date of birth") + "\n")
    d.add("11 \t"); d.field(V.sin(), "government_id"); d.add(" \t")
    d.add("6 \t"); d.field(V.dob(lang), "date_of_birth")
    d.add(("  Sexe : " if fr else "  Sex: ")); d.decoy(_sexe(fr)); d.add("  4\n")

    # Adresse block: Appartement (7) / Numero / Rue -> address ; Ville + Province QC -> NEGATIVE ;
    # Code postal (9) -> postal_code
    d.add(("Adresse\n" if fr else "Address\n"))
    d.add(("Appartement \tNumero \tRue, case postale\n" if fr
           else "Apartment \tNumber \tStreet, PO box\n"))
    d.add("7 \t"); d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(("Ville, village ou municipalite \tProvince \tCode postal\n" if fr
           else "City, town or municipality \tProvince \tPostal code\n"))
    d.add("8 \t" + V.city() + " \tQC \t9 \t")                         # city + province QC -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    # Situation line (12) -> all decoy line numbers / checkbox codes
    d.add(("Situation\n" if fr else "Marital status\n"))
    d.add(("Votre situation le 31 decembre : " if fr else "Your status on December 31: "))
    d.decoy(str(random.choice([1, 2]))); d.add("  12\n")

    # prescribed-form barcode footer -> decoy
    d.add("\t\t"); d.decoy(_barcode()); d.add(("\tFormulaire prescrit\n" if fr else "\tPrescribed form\n"))
    return d.row()


# ---------------- layout B: TP-1 personal return + spouse block + income lines (train) ----------------

def _layout_tp1_spouse(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="tax_return", lang=lang)

    d.add(("DECLARATION DE REVENUS" if fr else "INCOME TAX RETURN") + "\t")
    d.decoy(_form_code_tp1()); d.add("\t"); d.decoy(str(random.choice([2024, 2025]))); d.add("\n")

    # --- taxpayer block ---
    d.add(("Renseignements sur vous\n" if fr else "Information about you\n"))
    d.add(("Nom de famille \tPrenom\n" if fr else "Last name \tFirst name\n"))
    d.add("1 \t"); d.field(V.person(lang, caps=(random.random() < 0.5)), "person"); d.add("\t2\n")

    d.add(("Numero d'assurance sociale (NAS) \tDate de naissance\n" if fr
           else "Social insurance number (SIN) \tDate of birth\n"))
    d.add("11 \t"); d.field(V.sin(), "government_id"); d.add(" \t6 \t")
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")

    # optional subject phone + email-free TP-1 (TP-1 has no email cell; phone appears on some workpapers)
    if random.random() < 0.5:
        d.add(("Telephone : " if fr else "Phone: ")); d.field(V.phone(), "phone_number"); d.add("\n")

    d.add(("Adresse\n" if fr else "Address\n"))
    d.add(("Appartement \tNumero \tRue, case postale\n" if fr
           else "Apartment \tNumber \tStreet, PO box\n"))
    d.add("7 \t"); d.field(V.street_address(lang), "address"); d.add("\n")
    d.add("8 \t" + V.city() + " \tQC \t9 \t"); d.field(V.postal_code(), "postal_code"); d.add("\n")

    # --- conjoint(e) / spouse block: repeats Nom/Prenom/NAS/DOB (more positives) ---
    d.add(("Renseignements sur votre conjoint(e) au 31 decembre\n" if fr
           else "Information about your spouse on December 31\n"))
    d.add(("Nom de famille \tPrenom\n" if fr else "Last name \tFirst name\n"))
    d.add("31 \t"); d.field(V.person(lang, caps=(random.random() < 0.5)), "person"); d.add("\t32\n")
    d.add(("Numero d'assurance sociale (NAS) \tDate de naissance\n" if fr
           else "Social insurance number (SIN) \tDate of birth\n"))
    d.add("41 \t"); d.field(V.sin(), "government_id"); d.add(" \t36 \t")
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")

    # --- income lines: line numbers + bare amounts, ALL decoys ---
    d.add(("Revenu total\n" if fr else "Total income\n"))
    _income_lines(d, fr)

    # ~33% of these returns carry self-employment income -> a sole-proprietor business number (tax_id)
    # printed inline on the self-employment workpaper. Terse inline-prose cue, not the FP-500 header cell.
    if random.random() < 0.33:
        _taxid_workpaper_cue(d, fr)

    # ~30% of these returns are sole-proprietor filings accompanied by a business-registration extract,
    # which closes the train label-coverage gap vs the FP-500 held-out: tax_id (RT/TQ/NEQ) + account_number
    # (numeric identification run) + organization (business-name header), under the real Revenu Quebec cues
    # but in a registration-extract presentation distinct from the FP-500 form skeleton.
    if random.random() < 0.30:
        _business_registration_block(d, fr, lang)

    d.add("\t\t"); d.decoy(_barcode()); d.add(("\tFormulaire prescrit\n" if fr else "\tPrescribed form\n"))
    return d.row()


def _income_lines(d: Doc, fr: bool) -> None:
    """Append a block of TP-1 income lines: each = a label + a bare line number + a bare $ amount, all
    DECOYS. This is the volume that teaches the model NOT to redact line numbers / amounts."""
    rows_fr = ["Revenus d'emploi, releve 1, case A", "Autres revenus d'emploi",
               "Prestations d'assurance emploi, feuillet T4E", "Interets et autres revenus de placement",
               "Gains en capital imposables", "Revenus nets d'entreprise", "Revenu total"]
    rows_en = ["Employment income, RL-1 box A", "Other employment income",
               "Employment insurance benefits, T4E", "Interest and other investment income",
               "Taxable capital gains", "Net business income", "Total income"]
    nums = ["101", "107", "111", "130", "139", "164", "199"]
    rows = rows_fr if fr else rows_en
    for label, ln in zip(rows, nums):
        d.add(label + " \t"); d.decoy(ln); d.add(" \t"); d.decoy(_line_amount()); d.add("\n")


# ---------------- layout C (HELD-OUT): FP-500 GST/QST business remittance ----------------

def _layout_fp500(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="tax_return", lang=lang)

    # title block
    d.add(("Taxe sur les produits et services (TPS/TVH) et taxe de vente du Quebec (TVQ)\n" if fr
           else "Goods and services tax (GST/HST) and Quebec sales tax (QST)\n"))
    d.add(("Protege B une fois rempli\t" if fr else "Protected B when completed\t"))
    d.decoy("FP-500 (2019-05)"); d.add("\n")                          # form code -> decoy

    # tax-account header (REAL FP-500 order): "Numero de compte TPS/TVH" then "Numero d'entreprise du
    # Quebec (NEQ)" -- the real form has NO dedicated QST-account cell in this header. The GST/HST account
    # (GST RT) and NEQ are both tax_id. The QST account (QST TQ) is carried under its real Revenu Quebec
    # QST-registration label "Numero d'inscription au fichier de la TVQ" on the next line (also tax_id),
    # so all three V.tax_id() shapes appear but each sits under a label that really exists on Revenu Quebec
    # QST/GST correspondence -- not a fabricated "compte TVQ" cell wedged into the header row.
    d.add(("Numero de compte TPS/TVH \tNumero d'entreprise du Quebec (NEQ)\n" if fr
           else "GST/HST account number \tQuebec enterprise number (NEQ)\n"))
    d.field(_gst_account(), "tax_id"); d.add(" \t")
    d.field(_neq(), "tax_id"); d.add("\n")
    d.add(("Numero d'inscription au fichier de la TVQ\n" if fr
           else "QST registration number\n"))
    d.field(_qst_account(), "tax_id"); d.add("\n")

    # Numero d'identification / Dossier -> account_number (bare numeric, no Luhn) -- NOT a tax_id, NOT a SIN
    d.add(("Numero d'identification \tDossier\n" if fr else "Identification number \tFile\n"))
    d.field(_identifier_no(), "account_number"); d.add(" \t"); d.decoy(_dossier_no()); d.add("\n")

    # Nom = the BUSINESS NAME, labeled -> organization (NOT a person here)
    d.add(("Nom \t" if fr else "Name \t")); d.field(V.company(lang), "organization"); d.add("\n")

    # reporting periods -> date ranges = DECOYS (not DOB)
    d.add(("Periode de declaration - TPS/TVH \tPeriode de declaration - TVQ\n" if fr
           else "Reporting period - GST/HST \tReporting period - QST\n"))
    d.add(("Du " if fr else "From ")); d.decoy(_period_range(fr)); d.add(" \t")
    d.add(("Du " if fr else "From ")); d.decoy(_period_range(fr)); d.add("\n")

    # Part 1: detailed calculation lines -> line numbers + bare amounts, ALL decoys
    d.add(("1  Calculs detailles de la TPS/TVH et de la TVQ\n" if fr
           else "1  Detailed GST/HST and QST calculations\n"))
    d.add("\t\tTPS/TVH\tTVQ\n" if fr else "\t\tGST/HST\tQST\n")
    _fp500_lines(d, fr)

    # an institutional service phone in the general-info text -> NEGATIVE decoy (not the subject's phone)
    d.add(("Pour obtenir des renseignements, composez le " if fr
           else "For information, call ")); d.decoy(_service_phone()); d.add("\n")

    # Part 3: Signature -> authorized person's NAME = person ; Titre + Date = decoys
    d.add(("3  Signature\n" if fr else "3  Signature\n"))
    d.add(("Nom de la personne autorisee (en majuscules) \tTitre ou fonction \tDate\n" if fr
           else "Name of authorized person (in capitals) \tTitle or position \tDate\n"))
    d.field(V.person(lang, caps=True), "person"); d.add(" \t")
    d.decoy(random.choice(["President", "Directrice", "Comptable", "Tresorier", "Controleur"]
                          if fr else ["President", "Director", "Accountant", "Treasurer", "Controller"]))
    d.add(" \t"); d.decoy(V.iso_date()); d.add("\n")                  # signature date -> decoy
    return d.row()


def _gst_account() -> str:
    """A GST/HST business number account: 9 digits + 'RT' + 4-digit program ref (BN-style). The GST RT
    member of the V.tax_id() family, pinned to the 'Numero de compte TPS/TVH' cell so this cell always
    carries the RT shape (never a NEQ or QST look-alike)."""
    n9 = "".join(random.choice("0123456789") for _ in range(9))
    return f"{n9}RT{random.randint(0, 9999):04d}"


def _qst_account() -> str:
    """A Quebec QST registration number: 10 digits + 'TQ' + 4-digit file ref (#########T####). The QST TQ
    member of the V.tax_id() family, pinned to the 'Numero de compte TVQ' cell. tax_id shape, distinct from
    both the GST RT account and the bare NEQ."""
    n10 = "".join(random.choice("0123456789") for _ in range(10))
    return f"{n10}TQ{random.randint(0, 9999):04d}"


def _neq() -> str:
    """Quebec enterprise number (NEQ): a 10-digit run. The bare-NEQ member of the V.tax_id() family, pinned
    to the NEQ cell (distinct from the GST RT and QST TQ accounts)."""
    return "".join(random.choice("0123456789") for _ in range(10))


def _fp500_lines(d: Doc, fr: bool) -> None:
    """Append FP-500 part-1 calculation lines: label + line number + two bare amounts (GST col, QST col),
    all DECOYS."""
    rows_fr = ["Total des fournitures (chiffre d'affaires)", "TPS/TVH exigible - TVQ exigible",
               "Redressements", "CTI - RTI", "TPS/TVH nette - TVQ nette",
               "TPS/TVH a verser ou remboursement demande"]
    rows_en = ["Total supplies (revenue)", "GST/HST collectible - QST collectible",
               "Adjustments", "ITC - ITR", "Net GST/HST - Net QST", "GST/HST to remit or refund claimed"]
    nums = [("101", ""), ("103", "203"), ("104", "204"), ("106", "206"), ("109", "209"), ("113", "213")]
    rows = rows_fr if fr else rows_en
    for label, (a, b) in zip(rows, nums):
        d.add(label + " \t"); d.decoy(a); d.add(" \t"); d.decoy(_line_amount())
        if b:
            d.add(" \t"); d.decoy(b); d.add(" \t"); d.decoy(_line_amount())
        d.add("\n")


LAYOUTS = [_layout_tp1_basic, _layout_tp1_spouse, _layout_fp500]   # FP-500 (suffix) = held-out structure


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
