#!/usr/bin/env python3
"""saaq_licence generator: synthetic Quebec SAAQ driver's licences (permis de conduire) in the REAL
numbered-field layout from the SAAQ "Presentation of Quebec driver's licences" specimen sheets
(presentation-quebec-driver-licences.pdf + presentation-licence-plus.pdf).

RE-GROUNDED (v11) on the actual specimen structure. The licence card is a numbered-field list where the
human-readable identity block is the PII and everything physical/administrative is a hard negative:

  Permis de conduire
  4d   L1531-171274-08                          <- driver's licence number  -> government_id
  1    LAPOINTE                                 <- last name (ALL-CAPS)      -> person
  2    ANNE-MARIE                               <- first name(s) (ALL-CAPS)  -> person
  3    Date de naissance (A-M-J) : 1974-12-17   <- CUED birth date           -> date_of_birth
  8    333, BOULEVARD JEAN-LESAGE               <- holder address            -> address
       APP. 432
       QUEBEC (QC) G1K 8J6                      <- city + (QC) + postal      -> postal_code (city/QC NEGATIVE)
       15 Sexe : F                              <- sex                       -> DECOY
  9    Classe(s) : 1 2 3 4A 4B 4C 5 6A          <- licence classes           -> DECOY
  12   Cond. : A C        16 Taille (cm) : 168  <- conditions / height       -> DECOY
  9a   Mention(s) : F M T 18 Yeux : BLEU        <- endorsements / eye colour -> DECOY
  5    No de reference : P B M H 9 2 V 7 0      <- reference number          -> DECOY
  4a   Valide le : 2015-08-21 4b Expire le : 2022-12-17   <- issue/expiry dates -> DECOY (NOT DOB)
  Societe de l'assurance automobile du Quebec   <- the SAAQ org              -> DECOY (issuer, not subject id)

POSITIVES (identity-only redaction policy): government_id (the permis number), person (last + first name,
ALL-CAPS), date_of_birth (only the CUED 'Date de naissance' line), address, postal_code.
The SAAQ permis number is the official hyphenated shape L1531-171274-08 (1 letter + 4 + 6 + 2 digits): the
digit source is V.saaq_permis() (1 letter + 12 digits), regrouped INLINE here so text[s:e] stays exact.

DECOYS (the false-positive moat; emitted via d.decoy(), NEVER labeled):
 - sex (Sexe : F/M), licence class(es), condition(s), endorsement(s)/mention(s), height (Taille cm),
   eye colour (Yeux), reference number (No de reference), the issue date (Valide le / Date of issue) and
   expiry date (Expire le / Date of expiry) -> per the date rule, ONLY a cued birth date is date_of_birth;
   every other date on the card is a NEGATIVE.
 - the SAAQ organization itself (Societe de l'assurance automobile du Quebec / SAAQ) -> issuer header, not
   the subject's identity -> NEGATIVE decoy (collision rule 3: an org names the subject only as a labeled
   employer/clinic header; the document issuer is not the subject).
 - city name + province (QC) + street-type words alone -> NEGATIVE.
 - government_id collision rule 2: a real SAAQ card carries NO SIN, so the hyphenated permis number is the
   only government_id on it. We deliberately do NOT print a bare 9-digit SIN look-alike here (it would be
   unfaithful to the scaffold); the permis-vs-SIN-vs-account contrast is taught by the doctypes that really
   do carry a SIN (kyc / tax_slip / insurance / sin_letter emit V.sin(valid=False) as the look-alike decoy).
 - Permis Plus only: the ICAO machine-readable zone (MRZ) two-row strip is emitted as ONE decoy block; its
   sub-fields (the encoded name/dob/permis) are NOT labeled (the human-readable lines above are the
   positives). Also Plus-only: 'Plus' indicator + 'CAN' citizenship indicator -> NEGATIVE.

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix):
 - _layout_standard : the standard plastic licence card, numbered-field block.               [train]
 - _layout_specimen : the SAAQ specimen presentation sheet -- same identity fields but each line carries the
                      bilingual numbered legend ('Last name (1)', 'Date of birth (3)') and the back-of-card
                      classes/conditions legend, a structurally different document layout.    [train]
 - _layout_plus     : Permis de conduire Plus -- adds 'Plus' + 'CAN' indicators AND the ICAO MRZ
                      decoy strip the standard card never has -> genuinely distinct structure. [HELD-OUT]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`. ~65% FR / 35% EN.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402

# ---- card-decoy value pools (all NEGATIVE: physical/administrative, never the subject's identity) ----
_CLASSES = ["1 2 3 4A 4B 4C 5 6A", "5 6A 6B", "5", "1 2 3 5 6A", "5 6A", "4B 5 6A 6B 8", "3 5 6A"]
_CONDS = ["A", "A C", "A B", "C", "A C J", "B", "A J"]
_MENTIONS = ["F M T", "F M", "F", "M T", "F T", "M"]
_EYES_FR = ["BRUN", "BLEU", "VERT", "NOISETTE", "GRIS", "PERS"]
_EYES_EN = ["BROWN", "BLUE", "GREEN", "HAZEL", "GREY"]
_SEX = ["F", "M"]


def _permis() -> str:
    """The official hyphenated SAAQ permis shape L1531-171274-08 (1 letter + 4 + 6 + 2 digits). The digit
    source is V.saaq_permis() (1 letter + 12 digits); we only regroup it -> text[s:e] is exact, no find()."""
    raw = V.saaq_permis()                       # e.g. 'E914177763170'  (1 letter + 12 digits)
    letter, digits = raw[0], raw[1:]
    return f"{letter}{digits[0:4]}-{digits[4:10]}-{digits[10:12]}"


def _ref_number() -> str:
    """A spaced single-char reference number, real 'No de reference : P B M H 9 2 V 7 0' style. NEGATIVE."""
    alnum = "ABCDEFGHJKLMNPRSTVWXYZ0123456789"
    return " ".join(random.choice(alnum) for _ in range(random.choice([8, 9, 10])))


def _eye(fr: bool) -> str:
    return random.choice(_EYES_FR if fr else _EYES_EN)


def _height() -> str:
    return str(random.randint(150, 198))


def _names(lang: str) -> tuple[str, str]:
    """Real SAAQ cards print last name (field 1) and first name(s) (field 2) on SEPARATE ALL-CAPS lines.
    Returns (last, first) each ALL-CAPS, drawn from the shared name pools (V.person caps then split)."""
    last = random.choice(V._LAST)
    # first name: sometimes a hyphenated compound like ANNE-MARIE / JEAN-PHILIPPE (real on the specimen)
    pool = V._FIRST_FR if lang == "fr" else V._FIRST_EN
    first = random.choice(pool)
    if random.random() < 0.30:
        first = f"{first}-{random.choice(pool)}"
    return V._fold(last).upper(), V._fold(first).upper()


def _addr_lines(d: Doc, lang: str) -> None:
    """Field 8: street (positive address) on line 1, optional APP. line, then 'CITY (QC) POSTAL' line where
    only the postal code is the positive (city name + province (QC) -> NEGATIVE)."""
    d.field(V.street_address(lang), "address"); d.add("\n")
    if random.random() < 0.55:
        d.add(f"     APP. {random.randint(1, 480)}\n")
    d.add("     "); d.add(V.city().upper()); d.add(" (QC) ")   # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")


def _icao_mrz() -> str:
    """An ICAO machine-readable zone block (Permis Plus). Emitted as ONE decoy: the encoded identity is NOT
    re-labeled (the human-readable permis/name/dob lines above are the positives). Two 30-char rows of the
    A-Z0-9< alphabet, structurally MRZ-shaped (filler '<', document code 'D1', issuing state 'CAN')."""
    az = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    def fill(s, n):
        return (s + "<" * n)[:n]
    surname = "".join(random.choice(az) for _ in range(random.randint(4, 8)))
    given = "".join(random.choice(az) for _ in range(random.randint(4, 7)))
    line1 = fill(f"D1CAN{surname}<<{given}", 30)
    body = "".join(random.choice(az + "0123456789") for _ in range(15))
    line2 = fill(f"CAN{body}", 30)
    return f"{line1}\n{line2}"


# ---------------- layout A: standard plastic licence card (numbered-field block) ----------------

def _layout_standard(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="saaq_licence", lang=lang)
    last, first = _names(lang)

    d.add("Permis de conduire\n" if fr else "Driver's licence\n")
    d.add("4d   "); d.field(_permis(), "government_id"); d.add("\n")
    d.add("1    "); d.field(last, "person"); d.add("\n")
    d.add("2    "); d.field(first, "person"); d.add("\n")
    d.add("3    Date de naissance (A-M-J) : " if fr else "3    Date of birth (Y-M-D) : ")
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")
    d.add("8    "); _addr_lines(d, lang)

    # physical / administrative block -> all DECOYS
    d.add("15   Sexe : " if fr else "15   Sex : "); d.decoy(random.choice(_SEX)); d.add("\n")
    d.add("9    Classe(s) : " if fr else "9    Class(es) : "); d.decoy(random.choice(_CLASSES)); d.add("\n")
    d.add("12   Cond. : " if fr else "12   Cond. : "); d.decoy(random.choice(_CONDS))
    d.add("   16 Taille (cm) : " if fr else "   16 Height (cm) : "); d.decoy(_height()); d.add("\n")
    d.add("9a   Mention(s) : " if fr else "9a   Endorsement(s) : "); d.decoy(random.choice(_MENTIONS))
    d.add("   18 Yeux : " if fr else "   18 Eyes : "); d.decoy(_eye(fr)); d.add("\n")
    d.add("5    No de reference : " if fr else "5    Reference number : "); d.decoy(_ref_number()); d.add("\n")
    d.add("4a   Valide le : " if fr else "4a   Date of issue : "); d.decoy(V.iso_date())
    d.add(" 4b Expire le : " if fr else " 4b Date of expiry : "); d.decoy(V.iso_date()); d.add("\n")
    d.add("Paiement exige chaque annee a votre date anniversaire de naissance\n" if fr
          else "Payment required each year on your birthday\n")
    # issuer org -> NEGATIVE (document issuer, not the subject's identity)
    d.decoy("Societe de l'assurance automobile du Quebec" if fr
            else "Societe de l'assurance automobile du Quebec")
    d.add("   saaq.gouv.qc.ca\n")
    return d.row()


# ---------------- layout B: SAAQ specimen presentation sheet (bilingual numbered legend) -------------

def _layout_specimen(lang: str) -> dict:
    """The 'Presentation of Quebec driver's licences' specimen sheet: the same identity fields, but each
    line is captioned with the bilingual numbered legend ('Last name (1)', 'Date of birth (3)') and a
    back-of-card classes/conditions legend block. A structurally different document from the plain card."""
    fr = lang == "fr"
    d = Doc(doctype="saaq_licence", lang=lang)
    last, first = _names(lang)

    d.add("Presentation of Quebec driver's licences\n")
    d.add("Permis de conduire\n" if fr else "Driver's licence\n")
    d.add("Driver's licence number (4d)   "); d.field(_permis(), "government_id"); d.add("\n")
    d.add("Last name (1)   "); d.field(last, "person"); d.add("\n")
    d.add("First name(s) (2)   "); d.field(first, "person"); d.add("\n")
    d.add("Date of birth (3)   Date de naissance (A-M-J) : " if fr
          else "Date of birth (3)   Date of birth (Y-M-D) : ")
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")
    d.add("Licence holder's address (8)   "); _addr_lines(d, lang)

    # the legend captions each decoy field by its number (back-of-card legend)
    d.add("Sex (15)   "); d.decoy(random.choice(_SEX)); d.add("\n")
    d.add("Driver's licence class(es) (9)   "); d.decoy(random.choice(_CLASSES)); d.add("\n")
    d.add("Condition(s) (12)   "); d.decoy(random.choice(_CONDS)); d.add("\n")
    d.add("Height (cm) (16)   "); d.decoy(_height()); d.add("\n")
    d.add("Eye colour (18)   "); d.decoy(_eye(fr)); d.add("\n")
    d.add("Endorsement(s) (9a)   "); d.decoy(random.choice(_MENTIONS)); d.add("\n")
    d.add("Reference number (5)   "); d.decoy(_ref_number()); d.add("\n")
    d.add("Date of expiry (4b)   "); d.decoy(V.iso_date()); d.add("\n")
    d.add("Date of issue (4a)   "); d.decoy(V.iso_date()); d.add("\n")
    # back-of-card legend block + issuer (all NEGATIVE)
    d.add("Definitions of licence classes, conditions and endorsements\n")
    d.add("CLASSE(S): Tous les types de vehicules routiers. Toute motocyclette.\n")
    d.add("CONDITION(S): A: Lunettes ou lentilles corneennes, C: Appareil auditif.\n")
    d.decoy("Societe de l'assurance automobile du Quebec"); d.add("   saaq.gouv.qc.ca\n")
    return d.row()


# ---------------- layout C (HELD-OUT): Permis de conduire Plus + ICAO MRZ strip ----------------

def _layout_plus(lang: str) -> dict:
    """Permis de conduire Plus: adds the Plus + CAN citizenship indicators AND the ICAO machine-readable
    zone (MRZ) strip that the standard card never carries. The MRZ is ONE decoy block (its encoded
    sub-fields are NOT re-labeled); the human-readable permis/name/dob lines remain the positives."""
    fr = lang == "fr"
    d = Doc(doctype="saaq_licence", lang=lang)
    last, first = _names(lang)

    d.add("Permis de conduire Plus\n" if fr else "Driver's licence Plus\n")
    d.add("Plus   ")  # Licence Plus indicator -> NEGATIVE
    d.decoy("Plus"); d.add("   ")
    d.decoy("CAN"); d.add("   ")  # citizenship indicator -> NEGATIVE
    d.add("(citoyennete)\n" if fr else "(citizenship)\n")
    d.add("4d   "); d.field(_permis(), "government_id"); d.add("\n")
    d.add("1    "); d.field(last, "person"); d.add("\n")
    d.add("2    "); d.field(first, "person"); d.add("\n")
    d.add("3    Date de naissance (A-M-J) : " if fr else "3    Date of birth (Y-M-D) : ")
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")
    d.add("8    "); _addr_lines(d, lang)

    d.add("15   Sexe : " if fr else "15   Sex : "); d.decoy(random.choice(_SEX)); d.add("\n")
    d.add("9    Classe(s) : " if fr else "9    Class(es) : "); d.decoy(random.choice(_CLASSES)); d.add("\n")
    d.add("12   Cond. : " if fr else "12   Cond. : "); d.decoy(random.choice(_CONDS))
    d.add("   16 Taille (cm) : " if fr else "   16 Height (cm) : "); d.decoy(_height()); d.add("\n")
    d.add("18   Yeux : " if fr else "18   Eyes : "); d.decoy(_eye(fr)); d.add("\n")
    d.add("4a   Valide le : " if fr else "4a   Date of issue : "); d.decoy(V.iso_date())
    d.add(" 4b Expire le : " if fr else " 4b Date of expiry : "); d.decoy(V.iso_date()); d.add("\n")

    # ICAO machine-readable zone -> ONE decoy block (sub-fields NOT labeled)
    d.add("Machine readable zone (MRZ)\n")
    d.decoy(_icao_mrz()); d.add("\n")
    d.decoy("Societe de l'assurance automobile du Quebec"); d.add("   saaq.gouv.qc.ca\n")
    return d.row()


LAYOUTS = [_layout_standard, _layout_specimen, _layout_plus]   # _layout_plus (suffix) = held-out structure


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
