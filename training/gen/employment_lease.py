#!/usr/bin/env python3
"""employment_lease generator: synthetic Quebec employment/income letters + TAL residential leases.

Grounded on two REAL, structurally distinct Quebec document families (no scaffold PDF; built faithfully
from the standard structures + the v11 contract conventions):

 (a) EMPLOYMENT / INCOME VERIFICATION LETTER -- free PROSE on employer letterhead. The employer name sits
     in a LABELED header field (Employeur: / Employer: / De: / From:) -> organization (positive). The
     SUBJECT employee's identity is PII: person, civic address, postal_code, phone, email, and a direct
     deposit account_number. The SALARY amount and the employment / issue DATES are DECOYS (transaction
     level / amount data per the identity-only redaction policy).

 (b) TAL BAIL / RESIDENTIAL LEASE -- a tabular FORM (Regie du logement / TAL bail de logement). HELD-OUT
     structure (the suffix). Two PERSONS (locataire/tenant + locateur/landlord), two ADDRESSES (the leased
     dwelling + the landlord's party address), postal_code, phone, email, and an account_number for the
     pre-authorized rent debit. The RENT amount and the lease term DATES are DECOYS.

The org-as-positive vs org-as-decoy contrast (contract rule 3): the employer in the letter header is a
LABELED organization positive; an org-shaped name appearing in a free-text mention (a benefits provider, a
payroll processor line) is a NEGATIVE decoy. Both modes are emitted so the contrast is in-distribution.

The 7 collision rules taught here: account_number (bare/hyphenated numeric, institution-first) vs a
sensitive_account_id-shaped employee file UUID kept as a DECOY (rule 1) -- this doc has NO sensitive_account_id
positive, the opaque file ref stays a hard negative so the model never routes a bare payroll account there;
amount + every non-birth date are decoys (date rule); city / province QC / postal-shaped folio = NEGATIVE.

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix):
 - _layout_letter_hr    : prose income-verification letter, HR-officer voice, deposit account inline.   [train]
 - _layout_letter_bank  : prose letter addressed to a lender (mortgage/credit), salary + tenure block.  [train]
 - _layout_lease_form   : TAL residential lease FORM (tenant + landlord parties, dwelling section).     [heldout]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402
import cue_helpers as C         # noqa: E402

# inline synthetic org-name pieces (generic, NOT real companies) -- employer / payroll processor / provider
_ORG_WORDS = ["Boreal", "Cascade", "Cedre", "Granit", "Horizon", "Lumiere", "Meridien", "Nordik", "Polaris",
              "Saphir", "Vertex", "Zephyr", "Quartz", "Atelier", "Sommet", "Riviere", "Pinacle", "Aurore"]
_ORG_SUFFIX_FR = ["Solutions inc.", "Technologies", "Conseil", "Groupe", "Services", "Industries",
                  "Logistique", "Construction", "Distribution ltee", "Gestion", "Manufacturier"]
_ORG_SUFFIX_EN = ["Solutions Inc.", "Technologies", "Consulting", "Group", "Services", "Industries",
                  "Logistics", "Construction", "Distribution Ltd.", "Holdings", "Manufacturing"]
# org-shaped names that show up in a NON-header mention (benefits/payroll provider) -> always a decoy
_PROVIDER = ["Sun Life", "Manuvie", "Beneva", "iA Groupe financier", "ADP Canada", "Nethris", "Employeur D",
             "Desjardins Assurances", "Croix Bleue"]
_JOB_FR = ["analyste principal", "technicienne comptable", "charge de projet", "preposee aux beneficiaires",
           "developpeur logiciel", "coordonnatrice marketing", "mecanicien industriel", "adjointe administrative"]
_JOB_EN = ["senior analyst", "accounting technician", "project lead", "patient care attendant",
           "software developer", "marketing coordinator", "industrial mechanic", "administrative assistant"]
_HR_TITLE_FR = ["Directrice des ressources humaines", "Conseiller en remuneration", "Chef de la paie",
                "Gestionnaire RH"]
_HR_TITLE_EN = ["Human Resources Director", "Compensation Advisor", "Payroll Manager", "HR Manager"]
_LEASE_KIND_FR = ["3 1/2", "4 1/2", "5 1/2", "6 1/2", "studio", "maison unifamiliale"]
_LEASE_KIND_EN = ["1-bedroom", "2-bedroom", "3-bedroom", "4-bedroom", "studio", "single-family home"]


def _employer_name(fr: bool) -> str:
    """A generic synthetic employer / company name (labeled-header -> organization positive)."""
    suf = random.choice(_ORG_SUFFIX_FR if fr else _ORG_SUFFIX_EN)
    return f"{random.choice(_ORG_WORDS)} {suf}"


def _provider_name() -> str:
    """An org-shaped name in a free-text benefits/payroll mention -> always a DECOY (no header label)."""
    return random.choice(_PROVIDER)


def _salary(fr: bool) -> str:
    """Annual / hourly salary -> ALWAYS a decoy (amount-level data, never PII). Carries '$'."""
    if random.random() < 0.7:
        gross = random.randint(38, 145) * 1000
        if fr:
            return f"{gross:,}".replace(",", " ") + " $ par annee"
        return f"${gross:,} per year"
    rate = random.randint(18, 65) + random.choice([0.0, 0.25, 0.50, 0.75])
    if fr:
        return f"{rate:.2f} $ l'heure".replace(".", ",")
    return f"${rate:.2f} per hour"


def _rent(fr: bool) -> str:
    """Monthly rent -> ALWAYS a decoy (amount-level data). Carries '$'."""
    val = random.randint(650, 2950)
    if fr:
        return f"{val:,}".replace(",", " ") + " $ par mois"
    return f"${val:,} per month"


def _lease_no() -> str:
    """A TAL lease / folio reference -> bare numeric folio kept as a DECOY (postal-shaped/account-shaped
    look-alike: never lift a form folio to account_number or postal_code)."""
    return random.choice(["TAL-", "Bail no ", "Dossier ", "Folio "]) + str(random.randint(100000, 999999))


def _file_uuid() -> str:
    """An opaque employee-file ref (UUID-shaped). Rule 1: this would LOOK like a sensitive_account_id, but in
    a payroll/HR file context it is a NEGATIVE decoy here -- the model must not route opaque HR refs there."""
    return V.uuid4()


# ---- v11 round-2 recall-first cue vocabulary (TRAIN-only helpers; ~30% alternatives) ----
# These teach the catastrophic-tier IDs (government_id SIN, employer tax_id) and phone under the TERSE /
# INLINE-PROSE cues the held-out layouts use, WITHOUT copying any held-out STRUCTURE. Each is called only
# from the train layouts below, gated at ~30% so the formal-labeled forms still dominate.

def _sin_inline_prose(d, fr: bool):
    """INLINE-PROSE government_id (full Luhn-valid SIN) -> POSITIVE. The SIN is embedded mid-sentence rather
    than on a 'NAS:' label line, so the model learns the entity under prose cueing (rule 3: government_id =
    V.sin(valid=True)). Bilingual."""
    if fr:
        d.add("Aux fins de la verification, le numero d'assurance sociale de l'employe(e) est le ")
        d.field(V.sin(valid=True), "government_id")
        d.add(", tel qu'inscrit a son dossier de paie.\n\n")
    else:
        d.add("For verification purposes, the employee's social insurance number is ")
        d.field(V.sin(valid=True), "government_id")
        d.add(", as recorded in their payroll file.\n\n")


def _employer_business_number(d, fr: bool):
    """Employer's business/registry number as tax_id (V.tax_id -> RT/TQ/NEQ forms) -> POSITIVE, with a
    realistic cue (NEQ / NE / Business Number). ~50% of the time print the spaced (3,3,4) variant via
    C.group_digits (digits identical -> still a real substring). Rule 3: tax_id = business/registry number."""
    raw = V.tax_id()
    val = C.group_digits(raw, (3, 3, 4)) if random.random() < 0.5 else raw
    if fr:
        cue = random.choice(["Numero d'entreprise du Quebec (NEQ): ", "NE: ", "No d'entreprise de l'employeur: "])
    else:
        cue = random.choice(["Business Number: ", "NE: ", "Employer business number: "])
    d.add(cue); d.field(val, "tax_id"); d.add("\n")


def _phone_terse(d, fr: bool, value: str = None):
    """TERSE phone cue (no full 'Telephone:' label) -> phone_number POSITIVE. Teaches the abbreviated /
    inline phone cueing the held-out layouts use. Bilingual."""
    val = value or V.phone()
    cue = random.choice(["Tel.: ", "Tel ", "T ", "Tel: "] if fr else ["Tel.: ", "Ph: ", "T ", "Tel: "])
    d.add(cue); d.field(val, "phone_number"); d.add("\n")


# ---------------- layout A (train): prose income-verification letter, HR voice ----------------

def _layout_letter_hr(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="employment_lease", lang=lang)
    emp = _employer_name(fr)

    # letterhead: employer is the LABELED header organization positive
    d.add("Employeur: " if fr else "Employer: ")
    d.field(emp, "organization"); d.add("\n")
    if random.random() < 0.3:                                                         # ~30% alt: employer NEQ/NE -> tax_id positive
        _employer_business_number(d, fr)
    d.add("Date: " if fr else "Date: "); d.decoy(V.iso_date()); d.add("\n")           # issue date -> decoy
    d.add(("Reference du dossier: " if fr else "File reference: "))
    d.decoy(_file_uuid()); d.add("\n\n")                                              # HR file UUID -> decoy

    d.add(("OBJET: Attestation d'emploi et de revenu\n\n" if fr
           else "RE: Employment and income verification\n\n"))
    d.add(("A qui de droit,\n\n" if fr else "To whom it may concern,\n\n"))

    job = random.choice(_JOB_FR if fr else _JOB_EN)
    if fr:
        d.add("Par la presente, nous confirmons que ")
        d.field(V.person(lang, caps=False), "person")
        d.add(f" occupe le poste de {job} au sein de notre entreprise depuis le ")
        d.decoy(V.iso_date())                                                         # hire date -> decoy
        d.add(". Sa remuneration brute est de ")
        d.decoy(_salary(True)); d.add(".\n\n")                                         # salary -> decoy
    else:
        d.add("This letter confirms that ")
        d.field(V.person(lang, caps=False), "person")
        d.add(f" holds the position of {job} at our company since ")
        d.decoy(V.iso_date())
        d.add(". Their gross compensation is ")
        d.decoy(_salary(False)); d.add(".\n\n")

    if random.random() < 0.3:                                                         # ~30% alt: inline-prose SIN -> government_id positive
        _sin_inline_prose(d, fr)

    # employee contact identity block (positives)
    d.add(("Adresse du domicile: " if fr else "Home address: "))
    d.field(V.street_address(lang), "address")
    d.add(", " + V.city() + " QC ")                                                   # city + QC -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    if random.random() < 0.3:                                                         # ~30% alt: terse phone cue
        _phone_terse(d, fr)
    else:
        d.add(("Telephone: " if fr else "Phone: ")); d.field(V.phone(), "phone_number"); d.add("\n")
    d.add(("Courriel: " if fr else "Email: ")); d.field(V.email(), "email"); d.add("\n")
    d.add(("Compte de depot direct: " if fr else "Direct deposit account: "))
    d.field(V.bank_account(), "account_number"); d.add("\n\n")                         # payroll account -> positive

    # a benefits provider mention: org-shaped name WITHOUT a header label -> NEGATIVE decoy
    if fr:
        d.add("Les avantages sociaux sont administres par ")
        d.decoy(_provider_name()); d.add(".\n\n")
    else:
        d.add("Group benefits are administered by ")
        d.decoy(_provider_name()); d.add(".\n\n")

    title = random.choice(_HR_TITLE_FR if fr else _HR_TITLE_EN)
    d.add(("Veuillez agreer nos salutations distinguees.\n\n" if fr else "Sincerely,\n\n"))
    d.add(title + ", " + emp + "\n")                                                  # org in sign-off line -> NEGATIVE
    return d.row()


# ---------------- layout B (train): prose letter addressed to a lender ----------------

def _layout_letter_bank(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="employment_lease", lang=lang)
    emp = _employer_name(fr)

    d.add(emp + "\n")                                                                 # letterhead name (no label) -> NEGATIVE
    d.add(("De: " if fr else "From: ")); d.field(emp, "organization"); d.add("\n")    # labeled sender -> organization positive
    if random.random() < 0.3:                                                         # ~30% alt: employer NEQ/NE -> tax_id positive
        _employer_business_number(d, fr)
    d.add(("Emis le: " if fr else "Issued on: ")); d.decoy(V.request_datetime(lang)); d.add("\n\n")  # datetime -> decoy

    d.add(("A l'attention du service de credit hypothecaire,\n\n" if fr
           else "Attention: Mortgage credit department,\n\n"))

    job = random.choice(_JOB_FR if fr else _JOB_EN)
    if fr:
        d.add("Nous attestons que notre employe(e), ")
        d.field(V.person(lang, caps=False), "person")
        d.add(f", est a notre emploi a titre de {job}. La date d'embauche est le ")
        d.decoy(V.iso_date()); d.add(" et le salaire annuel s'eleve a ")               # tenure date -> decoy
        d.decoy(_salary(True)); d.add(".\n\n")                                         # salary -> decoy
    else:
        d.add("We hereby attest that our employee, ")
        d.field(V.person(lang, caps=False), "person")
        d.add(f", is employed with us as {job}. The hire date is ")
        d.decoy(V.iso_date()); d.add(" and the annual salary is ")
        d.decoy(_salary(False)); d.add(".\n\n")

    if random.random() < 0.3:                                                         # ~30% alt: inline-prose SIN -> government_id positive
        _sin_inline_prose(d, fr)

    # employee identity block, slightly different field order from layout A (postal before address line)
    d.add(("Coordonnees de l'employe(e):\n" if fr else "Employee contact information:\n"))
    d.add(("  Courriel: " if fr else "  Email: ")); d.field(V.email(), "email"); d.add("\n")
    if random.random() < 0.3:                                                         # ~30% alt: terse phone cue (indented)
        d.add("  "); _phone_terse(d, fr)
    else:
        d.add(("  Telephone: " if fr else "  Phone: ")); d.field(V.phone(), "phone_number"); d.add("\n")
    d.add(("  Adresse: " if fr else "  Address: "))
    d.field(V.street_address(lang), "address")
    d.add(", " + V.city() + " QC ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    d.add(("  Compte de paie: " if fr else "  Payroll account: "))
    d.field(V.bank_account(form="hyphen"), "account_number"); d.add("\n\n")

    title = random.choice(_HR_TITLE_FR if fr else _HR_TITLE_EN)
    d.add((f"Pour toute verification, contactez le service de la paie.\n\n{title}\n" if fr
           else f"For verification, please contact the payroll department.\n\n{title}\n"))
    return d.row()


# ---------------- layout C (HELD-OUT): TAL residential lease FORM ----------------

def _layout_lease_form(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="employment_lease", lang=lang)

    # form title + folio (the folio is a postal/account look-alike kept as a DECOY)
    d.add(("BAIL DE LOGEMENT (Tribunal administratif du logement)\n" if fr
           else "RESIDENTIAL LEASE (Administrative Housing Tribunal)\n"))
    d.add(("No de dossier: " if fr else "File no.: ")); d.decoy(_lease_no()); d.add("\n")
    d.add(("Date du bail: " if fr else "Lease date: ")); d.decoy(V.iso_date()); d.add("\n\n")  # date -> decoy

    # SECTION 1 -- parties: landlord (locateur) is a PERSON here
    d.add(("SECTION 1 - PARTIES\n" if fr else "SECTION 1 - PARTIES\n"))
    d.add(("Locateur (proprietaire): " if fr else "Landlord (owner): "))
    d.field(V.person(lang, caps=False), "person"); d.add("\n")
    d.add(("  Adresse du locateur: " if fr else "  Landlord address: "))
    d.field(V.street_address(lang), "address")
    d.add(", " + V.city() + " QC ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    d.add(("  Telephone du locateur: " if fr else "  Landlord phone: "))
    d.field(V.phone(), "phone_number"); d.add("\n\n")

    d.add(("Locataire: " if fr else "Tenant: "))
    d.field(V.person(lang, caps=False), "person"); d.add("\n")
    d.add(("  Courriel du locataire: " if fr else "  Tenant email: "))
    d.field(V.email(), "email"); d.add("\n")
    d.add(("  Telephone du locataire: " if fr else "  Tenant phone: "))
    d.field(V.phone(), "phone_number"); d.add("\n\n")

    # SECTION 2 -- dwelling (a SECOND distinct address)
    kind = random.choice(_LEASE_KIND_FR if fr else _LEASE_KIND_EN)
    d.add(("SECTION 2 - LOGEMENT LOUE\n" if fr else "SECTION 2 - LEASED DWELLING\n"))
    d.add((f"  Type de logement: {kind}\n" if fr else f"  Dwelling type: {kind}\n"))
    d.add(("  Adresse du logement: " if fr else "  Dwelling address: "))
    d.field(V.street_address(lang), "address")
    d.add(", " + V.city() + " QC ")
    d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    # SECTION 3 -- term + rent (ALL decoys: lease dates + rent amount)
    d.add(("SECTION 3 - DUREE ET LOYER\n" if fr else "SECTION 3 - TERM AND RENT\n"))
    d.add(("  Debut du bail: " if fr else "  Lease start: ")); d.decoy(V.iso_date()); d.add("\n")
    d.add(("  Fin du bail: " if fr else "  Lease end: ")); d.decoy(V.iso_date()); d.add("\n")
    d.add(("  Loyer: " if fr else "  Rent: ")); d.decoy(_rent(fr)); d.add("\n")
    d.add(("  Depot / paiement par debit preautorise au compte: " if fr
           else "  Deposit / payment via pre-authorized debit to account: "))
    d.field(V.bank_account(), "account_number"); d.add("\n\n")                         # PAD account -> positive

    # signature block: a property-management org mention WITHOUT a header label -> NEGATIVE decoy
    if fr:
        d.add("Gestion immobiliere assuree par ")
    else:
        d.add("Property management provided by ")
    d.decoy(_provider_name()); d.add("\n")
    d.add(("Signe a " if fr else "Signed at ")); d.add(V.city())
    d.add((" le " if fr else " on ")); d.decoy(V.iso_date()); d.add("\n")              # signature date -> decoy
    return d.row()


LAYOUTS = [_layout_letter_hr, _layout_letter_bank, _layout_lease_form]   # lease form (suffix) = held-out


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
