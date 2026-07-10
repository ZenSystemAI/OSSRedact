#!/usr/bin/env python3
"""insurance generator: synthetic Quebec insurance declarations pages (Conditions particulieres) in the
REAL FPQ1-auto + BAC-home structure (FR/EN). 100% SYNTHETIC values, real document STRUCTURE only.

Grounded on the two Quebec standard-form scaffolds:
 - F.P.Q. No 1 (formulaire des proprietaires, Autorite des marches financiers / Desjardins; form code 933 000):
   the auto policy. The PII never lives in the contract WORDING (Chapitre A/B garanties, exclusions); it lives
   on the "Conditions particulieres" / declarations page the wording references -- assure designe, address,
   vehicules assures (VIN + plaque), garanties principales + montants, prime, prise d'effet / expiration.
 - BAC 1503Q (formule tous risques, proprietaire occupant): the home policy. Same shape: a declarations page
   with the Assure, the lieux assures (civil address), garanties A-H habitation + montants d'assurance, prime.

The product (training data) is: the SUBJECT identity labeled correctly + the contract machinery (coverage
limits, premiums, dates, the insurer/broker names, the VIN, the plate, the form code) left as explicit
hard-negative DECOYS. Per the contract's identity-only redaction policy + the 7 collision rules.

POSITIVES (cued, labeled): person (assure designe / co-titulaire), address, postal_code, phone_number,
 sensitive_account_id (alphanumeric/opaque police number), account_number (purely-numeric police number),
 email (home variant), date_of_birth (assure's DOB, cued -- distinct from the policy dates).
DECOYS (in text, never labeled): VIN, licence plate, premium amounts, coverage limits (Chapitre A/B montants,
 Garanties A-H montants), effective/expiry/issue dates (NON-cued -> never date_of_birth), insurer name,
 broker/courtier name, the AMF form code (933 000 / BAC 1503Q), policy "groupe/avenant" numeric codes,
 city + province QC, a Luhn-invalid SIN look-alike, a postal-shaped product/territory code.

LAYOUTS (>=2 genuinely-distinct REAL structures; held-out = the suffix):
 - _layout_fpq1_decl   : FPQ1 auto Conditions particulieres, tabular vehicule block (VIN/plaque).      [train]
 - _layout_fpq1_renew  : FPQ1 auto renewal NOTICE, prose multi-vehicule, courtier block, numeric police. [train]
 - _layout_bac_home    : BAC 1503Q HOME declarations -- lieux assures, Garanties A-H, NO vehicule/VIN.   [heldout]

The held-out HOME structure has no vehicule/VIN/plaque block at all (a different decoy family) and adds the
habitation Garanties A-H + a montant d'assurance habitation + an email line the auto layouts never produce --
a genuinely different real structure, not a reworded near-duplicate.

gen(lang, split) -> one offset-true row dict. Caller seeds `random`. ~65% FR / 35% EN.
"""
from __future__ import annotations
import sys, os, random, string
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402
import cue_helpers as C         # noqa: E402

# synthetic insurer names (generic; NOT real -- the real scaffolds name AMF-approved insurers, we don't reuse).
_INSURERS = ["Boreal Assurances generales inc.", "Assurances Cascade inc.", "Groupe Meridien Assurances",
             "Polaris Assurance inc.", "Mutuelle Nordik Assurances", "Vertex Assurances generales",
             "Saphir Assurances inc.", "Horizon Assurance habitation et auto"]
_BROKERS = ["Cabinet Quartz Services financiers", "Courtage Sommet inc.", "Aurore Assurances - cabinet",
            "Groupe-conseil Riviere", "Pinacle Courtage d'assurance", "Lumiere Services-conseils"]
# AMF standard-form codes (public form identifiers, NOT PII -> decoys). The form code is the document's
# identity marker, so keep the families separate: FPQ1 codes appear on AUTO pages, BAC 1503Q on HOME pages
# (the real ones are 933 000 for FPQ1 auto, BAC 1503Q for the home formule tous risques).
_FORM_CODES_AUTO = ["933 000 (2025-01)", "933 000", "F.P.Q. No 1", "F.P.Q. 1", "F.P.Q. No 1 (933 000)"]
_FORM_CODES_HOME = ["B.A.C. 1503Q", "BAC 1503Q (2009)", "BAC 1503Q", "B.A.C. 1503Q (2009)"]
# vehicle make/model pieces for the auto declarations table (all decoy context)
_MAKES = ["Toyota Corolla", "Honda Civic", "Mazda CX-5", "Ford F-150", "Hyundai Elantra", "Kia Forte",
          "Subaru Outback", "Nissan Rogue", "Volkswagen Jetta", "Chevrolet Equinox", "RAV4 Hybride"]
# auto garanties (FPQ1 Chapitre A = responsabilite, Chapitre B = dommages) -- labels are decoy context
_AUTO_GARANTIES_FR = [("Chapitre A - Responsabilite civile", "2 000 000 $"),
                      ("Chapitre B1 - Tous risques", "Franchise 500 $"),
                      ("Chapitre B2 - Collision et versement", "Franchise 250 $"),
                      ("Chapitre B3 - Accidents sans collision ni versement", "Franchise 50 $"),
                      ("Avenant F.A.Q. 20 - Vehicule de remplacement", "Inclus")]
_AUTO_GARANTIES_EN = [("Chapter A - Civil liability", "$2,000,000"),
                      ("Chapter B1 - All perils", "Deductible $500"),
                      ("Chapter B2 - Collision and upset", "Deductible $250"),
                      ("Chapter B3 - All perils other than collision", "Deductible $50"),
                      ("Endorsement Q.E.F. 20 - Replacement vehicle", "Included")]
# home garanties (BAC A-H habitation) -- labels + montants are decoy context
_HOME_GARANTIES_FR = [("Garantie A - Batiment d'habitation", "385 000 $"),
                      ("Garantie B - Dependances", "38 500 $"),
                      ("Garantie C - Biens meubles (contenu)", "192 500 $"),
                      ("Garantie D - Frais de subsistance supplementaires", "77 000 $"),
                      ("Garantie E - Responsabilite civile", "2 000 000 $"),
                      ("Garantie F - Frais medicaux", "5 000 $")]
_HOME_GARANTIES_EN = [("Coverage A - Dwelling building", "$385,000"),
                      ("Coverage B - Detached private structures", "$38,500"),
                      ("Coverage C - Personal property (contents)", "$192,500"),
                      ("Coverage D - Additional living expenses", "$77,000"),
                      ("Coverage E - Personal liability", "$2,000,000"),
                      ("Coverage F - Voluntary medical payments", "$5,000")]


# ---------------- inline doctype-specific value shapes ----------------

def _money_fr() -> str:
    """OQLF-style premium amount '1 234,56 $' -> always a DECOY (premium/coverage figure, never PII)."""
    whole = random.randint(300, 4800)
    return f"{whole:,}".replace(",", " ") + f",{random.randint(0,99):02d} $"


def _money_en() -> str:
    return f"${random.randint(300, 4800):,}.{random.randint(0,99):02d}"


def _policy_number(numeric: bool = None) -> tuple[str, str]:
    """A Quebec auto/home policy number. Returns (value, label).

    Collision rule 1: an OPAQUE alphanumeric reference (letters+digits, AUTO-2024-..., AAA0000000) is
    sensitive_account_id; a PURELY-NUMERIC run with no letters is a bare account number -> account_number.
    Never route a bare numeric policy to sensitive_account_id."""
    if numeric is None:
        numeric = random.random() < 0.45
    if numeric:
        # purely-numeric policy reference -> account_number (8-11 digits, no Luhn, hyphen-grouped sometimes)
        digits = "".join(random.choice("0123456789") for _ in range(random.randint(8, 11)))
        if random.random() < 0.4:
            return f"{digits[:4]}-{digits[4:]}", "account_number"
        return digits, "account_number"
    # opaque alphanumeric reference -> sensitive_account_id
    style = random.random()
    letters = "".join(random.choice("ABCDEFGHJKLMNPRSTVWXYZ") for _ in range(random.choice([2, 3])))
    digits = "".join(random.choice("0123456789") for _ in range(random.choice([6, 7, 8])))
    if style < 0.4:
        prefix = random.choice(["AUTO", "HAB", "POL", "QC"])
        return f"{prefix}-{random.randint(2022, 2026)}-{digits}", "sensitive_account_id"
    if style < 0.7:
        return f"{letters}{digits}", "sensitive_account_id"
    return f"{letters}-{digits[:3]}-{digits[3:]}", "sensitive_account_id"


def _vin() -> str:
    """A 17-char VIN -> DECOY (NOT in the 20-scheme). Excludes I/O/Q like real VINs."""
    chars = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
    return "".join(random.choice(chars) for _ in range(17))


def _plate() -> str:
    """A Quebec licence plate -> DECOY (NOT in the 20-scheme). Common QC formats e.g. 'F12 ABC', '123 ABC'."""
    if random.random() < 0.5:
        return f"{random.choice(string.ascii_uppercase)}{random.randint(10,99)} {''.join(random.choice(string.ascii_uppercase) for _ in range(3))}"
    return f"{random.randint(100,999)} {''.join(random.choice(string.ascii_uppercase) for _ in range(3))}"


def _group_code() -> str:
    """A policy 'groupe / avenant / lot' numeric code -> DECOY (a bare 3-5 digit code, NOT an account)."""
    return str(random.randint(100, 99999))


def _territory_code() -> str:
    """A rating-territory / product code that LOOKS postal-shaped -> DECOY (collision: postal only with a
    delivery/address cue; a product/territory code with no address context is a negative)."""
    return f"T{random.randint(0,9)}{random.choice('ABCEGHJKLMNPRSTVXY')}-{random.randint(10,99)}"


def _veh_year() -> str:
    return str(random.randint(2012, 2026))   # vehicle model year -> DECOY (not a DOB, no birth cue)


# ---------------- v11 round-2 cue-vocabulary helpers (TRAIN layouts only) -------------------------------
# These add the INLINE-PROSE government_id (SIN), the insurer business/registration number as tax_id, and a
# TERSE phone cue the formal-labeled train layouts never taught -- as ALTERNATIVES (~30% of occurrences),
# bilingual FR/EN, offset-true via Doc. Collision rules held: a FULL Luhn-valid SIN -> government_id; the
# masked/partial form stays a DECOY. The insurer's registry number (RT/TQ/NEQ) -> tax_id.

def _emit_sin_inline_prose(d: Doc, fr: bool) -> None:
    """INLINE-PROSE government_id cue: a full Luhn-valid SIN embedded in a running declaration sentence the
    underwriting/identity-verification note carries -- NOT a 'Field:' label. The full SIN -> government_id;
    a masked tail printed alongside stays a DECOY (collision rule 2)."""
    sin = V.sin(valid=True)
    if fr:
        openers = [
            "Aux fins de verification d'identite, l'assure declare que son numero d'assurance sociale est le ",
            "Le titulaire confirme que son NAS au dossier est ",
            "Pour la verification au dossier de credit, le numero d'assurance sociale fourni est ",
        ]
        d.add(random.choice(openers)); d.field(sin, "government_id")
        if random.random() < 0.45:
            d.add(", et les quatre derniers chiffres ("); d.decoy("XXX XX " + sin.replace(" ", "").replace("-", "")[-3:])
            d.add(") figurent au releve.")
        else:
            d.add(".")
        d.add("\n")
    else:
        openers = [
            "For identity verification, the insured states that their social insurance number is ",
            "The policyholder confirms the SIN on file is ",
            "For the credit-file check, the social insurance number provided is ",
        ]
        d.add(random.choice(openers)); d.field(sin, "government_id")
        if random.random() < 0.45:
            d.add(", with the last digits ("); d.decoy("XXX XX " + sin.replace(" ", "").replace("-", "")[-3:])
            d.add(") shown on the statement.")
        else:
            d.add(".")
        d.add("\n")


def _emit_insurer_tax_id(d: Doc, fr: bool) -> None:
    """The INSURER's business/registration number -> tax_id, with a realistic Quebec registry cue (NEQ /
    no d'entreprise / TPS-TVQ inscription). Occasionally spaced via C.group_digits (spaces only -- digits
    identical, so the fielded span is a real substring of the text)."""
    raw = V.tax_id()
    val = C.group_digits(raw, (3, 3, 4)) if random.random() < 0.45 else raw
    if fr:
        cue = random.choice([
            "Numero d'entreprise (NEQ) de l'assureur: ",
            "Assureur inscrit au registre, no d'inscription TPS/TVQ: ",
            "No d'entreprise de l'assureur (a des fins fiscales): ",
        ])
    else:
        cue = random.choice([
            "Insurer business number (NEQ): ",
            "Insurer registered, GST/QST registration no.: ",
            "Insurer business number (tax purposes): ",
        ])
    d.add(cue); d.field(val, "tax_id"); d.add("\n")


def _emit_phone_terse(d: Doc, fr: bool) -> None:
    """TERSE / positional phone cue (Tel. / T. / Cell. / a bare number with a trailing '(cell)' tag) instead
    of the formal 'Telephone:' label, so the model learns phone_number under a clipped cue."""
    style = random.random()
    if fr:
        if style < 0.45:
            d.add(random.choice(["Tel. ", "Tel: ", "T. "])); d.field(V.phone(), "phone_number")
        elif style < 0.7:
            d.add("Cell. "); d.field(V.phone(), "phone_number")
        else:
            d.field(V.phone(), "phone_number"); d.add(" (cell.)")
    else:
        if style < 0.45:
            d.add(random.choice(["Tel. ", "Tel: ", "T. "])); d.field(V.phone(), "phone_number")
        elif style < 0.7:
            d.add("Cell. "); d.field(V.phone(), "phone_number")
        else:
            d.field(V.phone(), "phone_number"); d.add(" (cell)")
    d.add("\n")


# ---------------- layout A (train): FPQ1 auto Conditions particulieres, tabular vehicule block ----------

def _layout_fpq1_decl(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="insurance", lang=lang)
    insurer = random.choice(_INSURERS)

    # masthead: insurer + AMF form code (both decoys)
    d.decoy(insurer); d.add("\n")
    d.add("Police d'assurance automobile du Quebec\n" if fr else "Quebec automobile insurance policy\n")
    d.add(("F.P.Q. No 1 - Formulaire des proprietaires  " if fr
           else "Q.P.F. No 1 - Owner's form  "))
    d.decoy(random.choice(_FORM_CODES_AUTO)); d.add("\n")
    d.add("CONDITIONS PARTICULIERES\n\n" if fr else "DECLARATIONS PAGE\n\n")

    # policy number (collision rule 1: alphanumeric -> sensitive_account_id, numeric -> account_number)
    pol, pol_lab = _policy_number()
    d.add("Numero de police: " if fr else "Policy number: "); d.field(pol, pol_lab); d.add("    ")
    d.add("Groupe: " if fr else "Group: "); d.decoy(_group_code()); d.add("\n")

    # effective / expiry dates -> DECOYS (NON-cued dates, never date_of_birth)
    d.add("Prise d'effet: " if fr else "Effective date: "); d.decoy(V.iso_date())
    d.add("    Expiration: " if fr else "    Expiry: "); d.decoy(V.iso_date()); d.add("\n\n")

    # assure designe -> person, with cued DOB -> date_of_birth
    d.add("Assure designe: " if fr else "Named insured: "); d.field(V.person(lang), "person"); d.add("\n")
    d.add("Date de naissance: " if fr else "Date of birth: "); d.field(V.dob(lang), "date_of_birth"); d.add("\n")
    d.add("Adresse: " if fr else "Address: ")
    d.field(V.street_address(lang), "address"); d.add(", ")
    d.add(V.city() + (" QC " if random.random() < 0.85 else " Quebec "))     # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    # phone: ~30% terse cue (Tel. / Cell. / positional), else the formal 'Telephone:' label
    if random.random() < 0.30:
        _emit_phone_terse(d, fr)
    else:
        d.add("Telephone: " if fr else "Phone: "); d.field(V.phone(), "phone_number"); d.add("\n")
    # ~50% insured's email (same cue + value shape the held-out home layout uses) -> email
    if random.random() < 0.50:
        d.add("Courriel: " if fr else "Email: "); d.field(V.email(), "email"); d.add("\n")
    d.add("\n")

    # ~30% INLINE-PROSE government_id (full Luhn-valid SIN cued in a running sentence, not a 'Field:' label)
    if random.random() < 0.30:
        _emit_sin_inline_prose(d, fr); d.add("\n")

    # optional second insured (co-titulaire) -> person
    if random.random() < 0.4:
        d.add("Conducteur additionnel: " if fr else "Additional driver: ")
        d.field(V.person(lang), "person"); d.add("\n\n")

    # vehicules assures table: VIN + plaque are DECOYS (not in the scheme); year is a decoy date-like
    d.add("VEHICULES ASSURES\n" if fr else "INSURED VEHICLES\n")
    d.add(("Annee  Marque/Modele               No de serie (NIV)        Plaque\n" if fr
           else "Year   Make/Model                   VIN                      Plate\n"))
    for _ in range(random.randint(1, 2)):
        d.decoy(_veh_year()); d.add("   ")
        d.decoy(random.choice(_MAKES)); d.add("     ")
        d.decoy(_vin()); d.add("    ")
        d.decoy(_plate()); d.add("\n")
    d.add("\n")

    # garanties + montants + prime -> ALL decoys (coverage machinery)
    d.add("GARANTIES ET MONTANTS\n" if fr else "COVERAGES AND LIMITS\n")
    for name, lim in (_AUTO_GARANTIES_FR if fr else _AUTO_GARANTIES_EN):
        d.add(name + "   "); d.decoy(lim); d.add("\n")
    d.add(("Prime totale: " if fr else "Total premium: "))
    d.decoy(_money_fr() if fr else _money_en()); d.add("\n")

    # broker line -> decoy (org-shaped, but a counterparty firm, not the subject's identity)
    d.add(("Courtier: " if fr else "Broker: ")); d.decoy(random.choice(_BROKERS)); d.add("\n")
    # ~30% insurer business/registration number -> tax_id (registry cue, occasionally spaced)
    if random.random() < 0.30:
        _emit_insurer_tax_id(d, fr)
    return d.row()


# ---------------- layout B (train): FPQ1 auto RENEWAL NOTICE, prose multi-vehicule, courtier block ------

def _layout_fpq1_renew(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="insurance", lang=lang)
    insurer = random.choice(_INSURERS)

    d.add(("Avis de renouvellement - Assurance automobile\n" if fr
           else "Renewal notice - Automobile insurance\n"))
    d.decoy(insurer); d.add("  -  "); d.decoy(random.choice(_FORM_CODES_AUTO)); d.add("\n")
    # courtier block first (prose), name is a decoy
    d.add(("Emis par le cabinet " if fr else "Issued by the brokerage "))
    d.decoy(random.choice(_BROKERS))
    d.add((" le " if fr else " on ")); d.decoy(V.iso_date()); d.add(".\n\n")

    # subject identity in a prose sentence
    d.add(("La presente atteste que " if fr else "This confirms that "))
    d.field(V.person(lang), "person")
    d.add((", residant au " if fr else ", residing at "))
    d.field(V.street_address(lang), "address"); d.add(", ")
    d.add(V.city() + " QC ")
    d.field(V.postal_code(), "postal_code")
    d.add((", est assure pour la periode du " if fr else ", is insured for the term from "))
    d.decoy(V.iso_date()); d.add((" au " if fr else " to ")); d.decoy(V.iso_date()); d.add(".\n")
    # phone: ~30% terse cue (Tel. / Cell. / positional), else the existing prose 'Joignable au' line
    if random.random() < 0.30:
        _emit_phone_terse(d, fr); d.add("\n")
    else:
        d.add(("Joignable au " if fr else "Reachable at ")); d.field(V.phone(), "phone_number"); d.add(".\n\n")

    # ~30% INLINE-PROSE government_id (full Luhn-valid SIN cued in a running sentence, not a 'Field:' label)
    if random.random() < 0.30:
        _emit_sin_inline_prose(d, fr); d.add("\n")

    # numeric-only policy in this variant (collision rule 1: bare numeric -> account_number) + decoy SIN-lookalike
    pol, pol_lab = _policy_number(numeric=True)
    d.add(("Numero de contrat: " if fr else "Contract number: ")); d.field(pol, pol_lab); d.add("\n")
    if random.random() < 0.5:
        # an INVALID 9-digit SIN look-alike printed as a "reference" -> hard negative, NEVER labeled
        d.add(("Reference dossier (a valider): " if fr else "File reference (to verify): "))
        d.decoy(V.sin(valid=False)); d.add("\n")
    d.add(("Territoire de tarification: " if fr else "Rating territory: "))
    d.decoy(_territory_code()); d.add("\n\n")     # postal-shaped product code -> NEGATIVE

    # multi-vehicule, prose lines: VIN + plaque decoys
    d.add("Vehicules au contrat:\n" if fr else "Vehicles on contract:\n")
    for _ in range(random.randint(2, 3)):
        d.add("  - "); d.decoy(_veh_year()); d.add(" "); d.decoy(random.choice(_MAKES))
        d.add(", NIV " if fr else ", VIN "); d.decoy(_vin())
        d.add((", plaque " if fr else ", plate ")); d.decoy(_plate()); d.add("\n")
    d.add("\n")

    # garanties summary + premium (decoys)
    for name, lim in (_AUTO_GARANTIES_FR if fr else _AUTO_GARANTIES_EN)[:3]:
        d.add(name + " : "); d.decoy(lim); d.add("\n")
    d.add(("Prime annuelle a payer: " if fr else "Annual premium due: "))
    d.decoy(_money_fr() if fr else _money_en()); d.add("\n")
    # ~30% insurer business/registration number -> tax_id (registry cue, occasionally spaced)
    if random.random() < 0.30:
        _emit_insurer_tax_id(d, fr)
    return d.row()


# ---------------- layout C (HELD-OUT): BAC 1503Q HOME declarations -- lieux assures, Garanties A-H -------

def _layout_bac_home(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="insurance", lang=lang)
    insurer = random.choice(_INSURERS)

    d.decoy(insurer); d.add("\n")
    d.add("Formulaire d'assurance habitation du Quebec\n" if fr else "Quebec home insurance policy\n")
    d.add(("Proprietaire occupant - Formule tous risques  " if fr
           else "Owner-occupant - All-risks form  "))
    d.decoy(random.choice(_FORM_CODES_HOME)); d.add("\n")
    d.add("CONDITIONS PARTICULIERES\n\n" if fr else "DECLARATIONS PAGE\n\n")

    # home policy number -- bias toward opaque alphanumeric (HAB- prefix) -> sensitive_account_id
    pol, pol_lab = _policy_number(numeric=(random.random() < 0.3))
    d.add("Numero de police: " if fr else "Policy number: "); d.field(pol, pol_lab); d.add("    ")
    d.add("Avenant: " if fr else "Endorsement: "); d.decoy(_group_code()); d.add("\n")
    d.add("Prise d'effet: " if fr else "Effective date: "); d.decoy(V.iso_date())
    d.add("    Echeance: " if fr else "    Expiry: "); d.decoy(V.iso_date()); d.add("\n\n")

    # assure + email (the auto layouts never emit email -> distinct structure) + phone
    d.add("Assure: " if fr else "Insured: "); d.field(V.person(lang), "person"); d.add("\n")
    if random.random() < 0.5:
        d.add("Co-assure: " if fr else "Co-insured: "); d.field(V.person(lang), "person"); d.add("\n")
    d.add("Courriel: " if fr else "Email: "); d.field(V.email(), "email"); d.add("\n")
    d.add("Telephone: " if fr else "Phone: "); d.field(V.phone(), "phone_number"); d.add("\n\n")

    # lieux assures -> address + postal (the dwelling) ; city + QC decoy
    d.add("LIEUX ASSURES\n" if fr else "INSURED PREMISES\n")
    d.add("Adresse du risque: " if fr else "Risk address: ")
    d.field(V.street_address(lang), "address"); d.add(", ")
    d.add(V.city() + " QC ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    d.add(("Annee de construction: " if fr else "Year built: ")); d.decoy(_veh_year()); d.add("\n\n")

    # Garanties A-H habitation + montants d'assurance -> ALL decoys (NO vehicule/VIN/plaque block at all)
    d.add("GARANTIES ET MONTANTS D'ASSURANCE\n" if fr else "COVERAGES AND AMOUNTS OF INSURANCE\n")
    for name, lim in (_HOME_GARANTIES_FR if fr else _HOME_GARANTIES_EN):
        d.add(name + "   "); d.decoy(lim); d.add("\n")
    d.add(("Franchise: " if fr else "Deductible: ")); d.decoy("1 000 $" if fr else "$1,000"); d.add("\n")
    d.add(("Prime totale: " if fr else "Total premium: "))
    d.decoy(_money_fr() if fr else _money_en()); d.add("\n")
    d.add(("Courtier: " if fr else "Broker: ")); d.decoy(random.choice(_BROKERS)); d.add("\n")
    return d.row()


LAYOUTS = [_layout_fpq1_decl, _layout_fpq1_renew, _layout_bac_home]   # bac_home (suffix) = held-out structure


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
