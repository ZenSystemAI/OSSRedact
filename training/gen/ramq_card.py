#!/usr/bin/env python3
"""ramq_card generator: synthetic RAMQ health insurance cards (carte soleil) + RAMQ correspondence.

GROUNDED on the REAL RAMQ "Liste des numeros d'assurance maladie (NAM) fictifs" training scaffold
(datasets/scaffolds/liste-de-nam-fictifs.pdf) and the physical carte soleil layout. The defining PII is the
NAM (numero d'assurance maladie) = 4 letters + 8 digits, encoding the holder's name initials + birth date
with the +50-female-month rule (V.ramq_nam). The card also carries the holder name + the cued birth date
(both PII) and a cluster of card-administration DECOYS that look like IDs but are NOT the subject identity:
the M/F sex marker, the card issue date, the card expiry date, and the issuer org
"Regie de l'assurance maladie du Quebec".

Per the contract section 5 collision rules + the date rule + the identity-only policy:
 - NAM (4 alpha + 8 digit) -> government_id. The 6 OFFICIAL fictitious NAMs (SZUM23031416, ANAS95510510,
   TAGL23540717, JEAE79611518, GAUC69020712, LERC75111217) appear in bulk (the list layout) and as sparse
   anchors (the card layout), interleaved with fresh V.ramq_nam() values so the model learns the SHAPE not
   the literals.
 - holder name -> person ; the cued birth date (date de naissance / date of birth / ne(e) le) ->
   date_of_birth, encoded to MATCH the NAM's YYMMDD by construction.
 - DECOYS (never labeled): the sex marker M/F ; the card EXPIRY date (date with no birth cue) ; the card
   ISSUE date ; the issuer "Regie de l'assurance maladie du Quebec" / "RAMQ" (transaction/issuer org, not the
   subject) ; a card sequence number (a bare numeric run that is NOT an account_number) ; the bare province
   QC and city name.

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix):
 - _layout_card  : the physical card-face block (NAM + name + DOB + sex + expiry + issue date).      [train]
 - _layout_list  : the REAL training-document tabular list (a column of NAMs + service-year columns,
                   the actual scaffold structure).                                                    [train]
 - _layout_letter: a RAMQ renewal / correspondence LETTER that cites the NAM in running prose
                   (renewal notice, address block, no card grid) = HELD-OUT structure.               [heldout]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`. ~65% FR / 35% EN.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402

# The 6 OFFICIAL fictitious NAMs from the real RAMQ training scaffold (carry them verbatim as anchors).
_OFFICIAL_NAMS = ["SZUM23031416", "ANAS95510510", "TAGL23540717", "JEAE79611518",
                  "GAUC69020712", "LERC75111217"]

_ISSUER_FR = "Regie de l'assurance maladie du Quebec"
_ISSUER_EN = "Regie de l'assurance maladie du Quebec"   # the issuer org is French-named on every card


# ---------------- inline doctype-specific value shapes ----------------

def _nam_with_dob(lang: str):
    """Return (nam, dob_string, sex) where the cued DOB MATCHES the NAM's encoded YY MM(+50 F) DD by
    construction. Faithful to the real card: the NAM literally encodes the birth date shown beside it."""
    sex = random.choice("MF")
    yy = random.randint(30, 99)               # 2-digit birth year on the card
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    nam = V.ramq_nam(sex=sex, year=yy, month=month, day=day)
    # build the human birth date from the SAME yy/mm/dd the NAM encodes (full 19xx/20xx year)
    full_year = 1900 + yy if yy >= 30 else 2000 + yy
    dob = _dob_from(day, month, full_year, lang)
    return nam, dob, sex


def _dob_from(day: int, month: int, year: int, lang: str) -> str:
    """A cued birth date in a real card shape (YYYY-MM-DD / DD/MM/YYYY / long month form)."""
    style = random.random()
    if style < 0.45:
        return f"{year}-{month:02d}-{day:02d}"          # the RAMQ card prints ISO birth dates
    if style < 0.7:
        return f"{day:02d}/{month:02d}/{year}"
    months_fr = ["janvier", "fevrier", "mars", "avril", "mai", "juin", "juillet", "aout",
                 "septembre", "octobre", "novembre", "decembre"]
    months_en = ["January", "February", "March", "April", "May", "June", "July", "August",
                 "September", "October", "November", "December"]
    if lang == "fr":
        return f"{day} {months_fr[month-1]} {year}"
    return f"{months_en[month-1]} {day}, {year}"


def _card_date() -> str:
    """A card issue / expiry date (MM/AAAA on a real carte soleil) -> always a DECOY (no birth cue)."""
    mm = random.randint(1, 12)
    yyyy = random.randint(2024, 2031)
    return f"{mm:02d}/{yyyy}" if random.random() < 0.6 else f"{yyyy}-{mm:02d}"


def _card_seq() -> str:
    """The small sequence/control number on the card face (a bare numeric run) -> NEGATIVE decoy: it is NOT
    an account_number and NOT the NAM. Teaches: a bare short numeric run with no account cue stays O."""
    return f"{random.randint(0, 99):02d}"


def _sex_marker(sex: str) -> str:
    return sex                                  # 'M' / 'F' on the card -> DECOY (never government_id)


def _nam_value() -> str:
    """A NAM for a positive span: mostly fresh-sampled SHAPE, sometimes an official anchor. Always emitted
    UNSPACED here (the 6 official ones are unspaced; mixing fresh spaced/unspaced still flows through
    V.ramq_nam in the list layout)."""
    if random.random() < 0.30:
        return random.choice(_OFFICIAL_NAMS)
    return V.ramq_nam().replace(" ", "")        # collapse to the card-printed compact form


# ---------------- layout A: physical card face (carte soleil) ----------------

def _layout_card(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="ramq_card", lang=lang)
    nam, dob, sex = _nam_with_dob(lang)

    # issuer header band -> DECOY org (the issuer, not the subject identity)
    d.add(("Carte d'assurance maladie\n" if fr else "Health Insurance Card\n"))
    d.decoy(_ISSUER_FR if fr else _ISSUER_EN); d.add("\n\n")

    # holder name (printed LAST, FIRST on the card) -> person
    d.add(("Nom \t") if fr else ("Name \t"))
    d.field(V.person(lang, caps=(random.random() < 0.7)), "person"); d.add("\n")

    # cardholder mailing address block (on the card-carrier / personalized record) ->
    # street part = address ; city + province stay NEGATIVE ; the FSA postal code -> postal_code
    d.add(("Adresse \t" if fr else "Address \t"))
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(("\t"))
    d.add(V.city() + (" (Quebec)  " if fr else " (Quebec)  "))          # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    # the NAM -> government_id (the headline field)
    d.add(("No d'assurance maladie \t" if fr else "Health Insurance No. \t"))
    d.field(nam, "government_id"); d.add("  ")
    d.decoy(_card_seq()); d.add("\n")                       # trailing card sequence -> NEGATIVE

    # birth date (cued) -> date_of_birth ; sex marker -> DECOY
    d.add(("Date de naissance \t" if fr else "Date of Birth \t"))
    d.field(dob, "date_of_birth"); d.add("   ")
    d.add(("Sexe \t" if fr else "Sex \t")); d.decoy(_sex_marker(sex)); d.add("\n")

    # issue + expiry -> DECOY dates (no birth cue lifts these)
    d.add(("Date d'emission \t" if fr else "Issue Date \t"))
    d.decoy(_card_date()); d.add("   ")
    d.add(("Date d'expiration \t" if fr else "Expiry Date \t"))
    d.decoy(_card_date()); d.add("\n")
    return d.row()


# ---------------- layout B: the real fictitious-NAM training list (tabular) ----------------

def _layout_list(lang: str) -> dict:
    """The actual scaffold structure: a heading, a column-header row, then N rows each = a NAM (government_id)
    followed by service-year cells (all DECOY years/words). This is the document the parser must redact: a
    BULK list of NAMs interleaved with non-PII service metadata."""
    fr = lang == "fr"
    d = Doc(doctype="ramq_card", lang=lang)

    d.add(("Utilisation de l'environnement de formation du Visualiseur\n\n" if fr
           else "Training environment usage for the Viewer\n\n"))
    d.add(("Liste des numeros d'assurance maladie (NAM) fictifs et situations representees\n" if fr
           else "List of fictitious health insurance numbers (NAM) and represented situations\n"))
    d.add(("NAM \tMedicament \tLaboratoire \tImagerie \tConsentement\n" if fr
           else "NAM \tDrug \tLab \tImaging \tConsent\n"))

    _years = ["2012", "2015", "2012 et 2013", "2017 a 2019", "2007 a 2017", "2008 a 2011",
              "2018 et 2019", "2012 a 2019", "2013"]
    _consent = (["Participe", "Refus", "Participe"] if fr else ["Participating", "Declined", "Participating"])

    for _ in range(random.randint(6, 12)):
        d.field(_nam_value(), "government_id"); d.add(" \t")
        d.decoy(random.choice(_years)); d.add(" \t")           # service-year cells -> NEGATIVE
        d.decoy(random.choice(_years)); d.add(" \t")
        d.decoy(random.choice(_years)); d.add(" \t")
        d.decoy(random.choice(_consent)); d.add("\n")          # consent word -> NEGATIVE

    d.add(("\nGere par la " if fr else "\nAdministered by the "))
    d.decoy(_ISSUER_FR if fr else _ISSUER_EN); d.add("\n")     # issuer org -> NEGATIVE decoy
    return d.row()


# ---------------- layout C (HELD-OUT): RAMQ renewal / correspondence letter (prose) ----------------

def _layout_letter(lang: str) -> dict:
    """A RAMQ renewal/correspondence LETTER citing the NAM in RUNNING PROSE (no card grid, no tabular list).
    Structurally distinct: an issuer letterhead, a mailing address block (address + postal_code), a salutation
    with the holder name, and a sentence embedding the NAM + the renewal/expiry date in text. This is the
    held-out structure the model never trains on."""
    fr = lang == "fr"
    d = Doc(doctype="ramq_card", lang=lang)
    nam, dob, sex = _nam_with_dob(lang)

    # issuer letterhead -> DECOY org
    d.decoy(_ISSUER_FR if fr else _ISSUER_EN); d.add("\n")
    d.add(("Avis de renouvellement de la carte d'assurance maladie\n\n" if fr
           else "Health insurance card renewal notice\n\n"))

    # date of the letter (NOT a birth date) -> DECOY
    d.add(("Date de l'avis : " if fr else "Notice date: "))
    d.decoy(_card_date()); d.add("\n\n")

    # mailing block: holder name + address + postal code
    d.field(V.person(lang), "person"); d.add("\n")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + ((" (Quebec) \t" if fr else " (Quebec) \t")))      # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    # the body: salutation + NAM + DOB cited in prose
    d.add(("Madame, Monsieur,\n\n" if fr else "Dear cardholder,\n\n"))
    if fr:
        d.add("Votre carte d'assurance maladie, associee au numero d'assurance maladie ")
        d.field(nam, "government_id")
        d.add(", arrivera bientot a echeance. Nos dossiers indiquent que vous etes ne(e) le ")
        d.field(dob, "date_of_birth")
        d.add(". La carte doit etre renouvelee avant le ")
        d.decoy(_card_date())                                            # renewal/expiry date -> NEGATIVE
        d.add(".\n")
    else:
        d.add("Your health insurance card, linked to health insurance number ")
        d.field(nam, "government_id")
        d.add(", will expire soon. Our records show that you were born on ")
        d.field(dob, "date_of_birth")
        d.add(". The card must be renewed before ")
        d.decoy(_card_date())                                            # renewal/expiry date -> NEGATIVE
        d.add(".\n")

    # closing line cites the sex marker + a control number, both decoys
    d.add(("\nSexe au dossier : " if fr else "\nSex on file: "))
    d.decoy(_sex_marker(sex)); d.add(("   No de sequence : " if fr else "   Sequence no.: "))
    d.decoy(_card_seq()); d.add("\n")
    return d.row()


LAYOUTS = [_layout_card, _layout_list, _layout_letter]   # letter (suffix) = held-out prose structure


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
