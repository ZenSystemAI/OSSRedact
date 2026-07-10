#!/usr/bin/env python3
"""void_cheque generator: synthetic Quebec/Canada VOID / SPECIMEN cheques in the REAL cheque layout (FR/EN).

A void cheque is the artifact people upload to set up a pre-authorized debit / direct deposit, so it is a
dense PII carrier: the account holder's identity (top-left), their civic address + postal code, and the MICR
line at the bottom -- transit(5) + institution(3) + account(7-12) -- which IS the bank account number.

Grounded on the real cheque structure (no scaffold PDF for this doctype; built from the MICR spec + the v11
contract + Canadian cheque conventions):

POSITIVES (the SUBJECT's identity -- redact):
 - person            : the payer / account holder printed top-left (the cheque owner). A personal cheque has
                       one; a joint cheque has two ('ET'/'AND').
 - address           : the holder's civic address line printed under the name.
 - postal_code       : the holder's Quebec FSA postal code (G/H/J).
 - account_number    : the MICR triplet. Rendered two real ways:
                         (a) the raw MICR glyph line as ASCII "*TRANSIT* INST ACCOUNT*"  (the bottom-of-cheque
                             encoded line), OR
                         (b) the institution-first hyphenated form III-TTTT(T)-AAAAAAAAA via V.bank_account()
                             printed in a "Transit / Institution / Account" field block.
 - payee (person)    : "Pay to the order of <PERSON>" / "Payez a l'ordre de <PERSON>" ONLY when the payee is
                       a PERSON -> person. A COMPANY payee is a DECOY (transaction counterparty, not the
                       subject's identity).

DECOYS (present in the text, NEVER labeled -- the false-positive fix; contract section 5 + the date/identity
rules):
 - cheque date        : V.iso_date() / long-form date -> NEGATIVE (only a CUED birth date is date_of_birth,
                        and a cheque carries no birth date).
 - amount (words+fig) : "1 234,56 $" figures + the written-out words line -> NEGATIVE.
 - memo / for line    : "Memo: loyer aout" free text -> NEGATIVE.
 - cheque number      : the 3-4 digit top-right serial -> NEGATIVE (a bare 3-digit also collides with CVV /
                        institution number; rule 6 -- no CVV cue, so never lifted).
 - bank name + branch : "Banque Royale du Canada, succursale ..." -> NEGATIVE (the issuing institution, not
                        the holder).
 - company payee      : an org-shaped payee name -> NEGATIVE (counterparty, identity-only policy).
 - lone institution # : a bare 3-digit institution code printed alone -> NEGATIVE (only the full MICR run is
                        account_number; collision rule 1/2).

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix per layouts.split_pools):
 - _layout_personal     : a standard PERSONAL cheque -- holder block top-left, raw ASCII MICR glyph line at
                          the bottom, "Pay to the order of" usually a PERSON.                       [train]
 - _layout_personal_alt : a PERSONAL cheque with the account printed as an institution-first hyphenated
                          Transit/Institution/Account field block (no glyph line), single holder.   [train]
 - _layout_business     : a BUSINESS cheque -- a company letterhead at the top (org DECOY, the business is
                          NOT the protected subject's identity here), an AUTHORIZED SIGNATORY who is the
                          PERSON positive, two signature lines, and the raw MICR line. Structurally distinct
                          (org header + signatory block) -> the genuinely-unseen held-out structure. [heldout]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`. ~65% FR / 35% EN.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402

# institution codes (authoritative, contract section 6) -> the public bank names that print on the cheque
_INSTITUTIONS = {"001": "BMO", "002": "Scotiabank", "003": "RBC", "004": "TD", "006": "Banque Nationale",
                 "010": "CIBC", "614": "Tangerine", "815": "Desjardins"}
_BANK_FR = {"001": "Banque de Montreal", "002": "Banque Scotia", "003": "Banque Royale du Canada",
            "004": "Banque TD Canada Trust", "006": "Banque Nationale du Canada",
            "010": "Banque CIBC", "614": "Tangerine", "815": "Caisse Desjardins"}
_BRANCH_FR = ["succursale Centre-Ville", "succursale du Plateau", "succursale Sainte-Foy",
              "succursale Vieux-Longueuil", "centre de services Laurier", "succursale Wellington"]
_BRANCH_EN = ["Downtown branch", "Plateau branch", "Sainte-Foy branch", "Westmount branch",
              "Laurier service centre", "Wellington branch"]

# inline synthetic company-name pieces for a company PAYEE / a business letterhead (generic, never real)
_CO_WORDS = ["Boreal", "Cascade", "Cedre", "Granit", "Horizon", "Lumiere", "Meridien", "Nordik", "Polaris",
             "Saphir", "Vertex", "Zephyr", "Quartz", "Atelier", "Sommet", "Riviere", "Pinacle", "Aurore"]
_CO_SUFFIX_FR = ["Solutions inc.", "Technologies", "Conseil", "Groupe", "Services", "Industries",
                 "Logistique", "Construction", "Distribution ltee", "Gestion"]
_CO_SUFFIX_EN = ["Solutions Inc.", "Technologies", "Consulting", "Group", "Services", "Industries",
                 "Logistics", "Construction", "Distribution Ltd.", "Holdings"]

# written-out amount words (the "amount in words" line is a DECOY)
_UNITS_FR = ["zero", "un", "deux", "trois", "quatre", "cinq", "six", "sept", "huit", "neuf", "dix",
             "onze", "douze", "treize", "quatorze", "quinze", "seize", "vingt", "trente", "quarante",
             "cinquante", "soixante", "cent", "deux cents", "trois cents", "mille"]
_UNITS_EN = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
             "eleven", "twelve", "thirteen", "fifteen", "twenty", "thirty", "forty", "fifty", "sixty",
             "hundred", "two hundred", "three hundred", "one thousand"]

_MEMO_FR = ["loyer", "loyer aout", "remboursement", "facture 0042", "depot direct", "cotisation",
            "frais de service", "don", "salaire", "honoraires"]
_MEMO_EN = ["rent", "rent August", "reimbursement", "invoice 0042", "direct deposit", "membership",
            "service fee", "donation", "salary", "fees"]


# ---------------- inline doctype-specific value shapes ----------------

def _micr_line() -> tuple[str, str, str]:
    """Build a cheque MICR line and return (full_micr_ascii, institution_code, hyphenated_account).

    The bottom-of-cheque MICR is transit(5) + institution(3) + account(7-12), printed with the special E-13B
    glyphs (the transit symbol, on-us symbol). Rendered to plain text those glyphs come through as a marker
    -- we use '*' (the common ASCII stand-in). Canadian cheque order: cheque-no, transit-institution, account.
    The whole encoded run is the account_number positive (the MICR triplet)."""
    inst = random.choice(list(_INSTITUTIONS))
    transit = "".join(random.choice("0123456789") for _ in range(5))
    # raw MICR account fields run 7-12 digits; the hyphenated/parser form stays within \d{6,9}
    acct_micr = "".join(random.choice("0123456789") for _ in range(random.randint(7, 12)))
    acct_hyph = "".join(random.choice("0123456789") for _ in range(random.randint(6, 9)))
    # ASCII MICR: "*TRANSIT* INST ACCOUNT*"  (transit symbol = *, on-us symbol = trailing *)
    full = f"*{transit}* {inst} {acct_micr}*"
    hyph = f"{inst}-{transit}-{acct_hyph}"     # institution-first hyphenated form (parser regex shape)
    return full, inst, hyph


def _cheque_no() -> str:
    """The top-right cheque serial number: a bare 3-4 digit run -> always a DECOY. A bare 3-digit also
    collides with a CVV / institution number (collision rule 6); with no CVV cue it is NEVER lifted."""
    return f"{random.randint(1, 9999):0{random.choice([3, 4])}d}"


def _amount_words(lang: str) -> str:
    """The hand-written 'amount in words' line on a cheque -> a DECOY (transaction data, never identity)."""
    units = _UNITS_FR if lang == "fr" else _UNITS_EN
    cents = random.randint(0, 99)
    body = " ".join(random.choice(units) for _ in range(random.randint(2, 4)))
    if lang == "fr":
        return f"{body} dollars et {cents:02d}/100"
    return f"{body} dollars and {cents:02d}/100"


def _amount_fig(lang: str) -> str:
    """Numeric amount in the $-box -> a DECOY."""
    dollars = random.randint(20, 9999)
    cents = random.randint(0, 99)
    if lang == "fr":
        return f"{dollars:,}".replace(",", " ") + f",{cents:02d} $"
    return f"${dollars:,}.{cents:02d}"


def _company(lang: str) -> str:
    suf = random.choice(_CO_SUFFIX_FR if lang == "fr" else _CO_SUFFIX_EN)
    return f"{random.choice(_CO_WORDS)} {suf}"


def _cheque_date(lang: str) -> str:
    """The cheque date -> a DECOY (no birth-date cue on a cheque). Mix ISO + DD/MM/YYYY + long-form."""
    style = random.random()
    if style < 0.45:
        return V.iso_date()
    d = random.randint(1, 28); m = random.randint(1, 12); y = random.randint(2024, 2026)
    if style < 0.7:
        return f"{d:02d}/{m:02d}/{y}"
    months_fr = ["janvier", "fevrier", "mars", "avril", "mai", "juin", "juillet", "aout",
                 "septembre", "octobre", "novembre", "decembre"]
    months_en = ["January", "February", "March", "April", "May", "June", "July", "August",
                 "September", "October", "November", "December"]
    return f"{d} {months_fr[m-1]} {y}" if lang == "fr" else f"{months_en[m-1]} {d}, {y}"


# ---------------- shared cheque pieces ----------------

def _void_stamp(fr: bool) -> str:
    return random.choice(["VOID / NUL", "SPECIMEN", "ANNULE", "VOID", "NUL"]) if not fr else \
        random.choice(["NUL", "SPECIMEN", "ANNULE", "VOID / NUL", "CHEQUE NUL"])


def _holder_block(d: Doc, lang: str, joint: bool = False) -> None:
    """Top-left holder identity block: name(s) + civic address + city/QC + postal code.
    name(s) -> person positive(s); address -> address; postal -> postal_code; city + 'QC' -> NEGATIVE."""
    fr = lang == "fr"
    d.field(V.person(lang, caps=(random.random() < 0.4)), "person")
    if joint:
        d.add(" ET " if fr else " AND ")
        d.field(V.person(lang, caps=(random.random() < 0.4)), "person")
    d.add("\n")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + (" QC  " if random.random() < 0.85 else " Quebec  "))   # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")


def _payee_line(d: Doc, lang: str) -> None:
    """'Pay to the order of <X>' -- a PERSON payee -> person positive; a COMPANY payee -> DECOY (counterparty,
    identity-only policy). Both modes appear so the contrast is in-distribution."""
    fr = lang == "fr"
    d.add("Payez a l'ordre de  " if fr else "Pay to the order of  ")
    if random.random() < 0.55:
        d.field(V.person(lang), "person")          # a person payee IS protected
    else:
        d.decoy(_company(lang))                    # a company payee is a transaction counterparty -> NEGATIVE
    d.add("    "); d.decoy(_amount_fig(lang)); d.add("\n")     # the $-box figure -> DECOY
    d.decoy(_amount_words(lang)); d.add("\n")                  # amount-in-words line -> DECOY


def _date_and_chqno(d: Doc, lang: str) -> None:
    fr = lang == "fr"
    d.add("No  " if fr else "No.  "); d.decoy(_cheque_no()); d.add("\n")    # cheque serial -> DECOY
    d.add("Date  "); d.decoy(_cheque_date(lang)); d.add("\n")              # cheque date -> DECOY


def _bank_branch(d: Doc, lang: str, inst: str) -> None:
    fr = lang == "fr"
    bank = _BANK_FR[inst] if fr else _INSTITUTIONS[inst]
    branch = random.choice(_BRANCH_FR if fr else _BRANCH_EN)
    d.decoy(bank); d.add(", "); d.decoy(branch); d.add("\n")               # issuing bank + branch -> DECOY


def _memo(d: Doc, lang: str) -> None:
    fr = lang == "fr"
    d.add("Note: " if fr else "Memo: "); d.decoy(random.choice(_MEMO_FR if fr else _MEMO_EN)); d.add("\n")


# ---------------- layout A: standard PERSONAL cheque, raw ASCII MICR glyph line ----------------

def _layout_personal(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="void_cheque", lang=lang)
    full_micr, inst, _ = _micr_line()

    d.add(_void_stamp(fr) + "\n")
    _holder_block(d, lang, joint=(random.random() < 0.2))
    d.add("\n")
    _date_and_chqno(d, lang)
    _bank_branch(d, lang, inst)
    _payee_line(d, lang)
    _memo(d, lang)
    d.add(("Signature  " if fr else "Signature  ") + "_______________________\n")
    # bottom-of-cheque MICR glyph line: cheque-no, then *transit* inst account*  -> the run is the account
    d.add("|" + _cheque_no() + "|  ")                       # leading cheque-no in MICR band -> DECOY
    d.field(full_micr, "account_number"); d.add("\n")
    return d.row()


# ---------------- layout B: PERSONAL cheque, hyphenated Transit/Institution/Account field block -----------

def _layout_personal_alt(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="void_cheque", lang=lang)
    _, inst, hyph = _micr_line()

    d.add(_void_stamp(fr) + "\n")
    _bank_branch(d, lang, inst)
    _holder_block(d, lang, joint=False)
    d.add("\n")
    _date_and_chqno(d, lang)
    _payee_line(d, lang)
    # account printed as an institution-first hyphenated field block (no glyph line) -> account_number
    if fr:
        d.add("Renseignements bancaires (institution-transit-compte):\n")
        d.add("Compte: ")
    else:
        d.add("Banking details (institution-transit-account):\n")
        d.add("Account: ")
    d.field(hyph, "account_number"); d.add("\n")
    # a lone institution code printed alone -> NEGATIVE (only the full run is the account; rule 1/2)
    d.add("Institution: " if fr else "Institution: "); d.decoy(inst); d.add("\n")
    _memo(d, lang)
    return d.row()


# ---------------- layout C (HELD-OUT): BUSINESS cheque -- company letterhead + authorized signatory ----

def _layout_business(lang: str) -> dict:
    """Genuinely-distinct held-out structure: a company LETTERHEAD at the top (org-shaped name -> DECOY, the
    business is the account-holding ENTITY, not the protected natural person), then an explicit AUTHORIZED
    SIGNATORY block where a PERSON is named + their civic address + postal code (the protected subject), two
    signature lines, and the bottom MICR. Neither train layout has a company letterhead or a signatory block,
    so the model never trained on this skeleton."""
    fr = lang == "fr"
    d = Doc(doctype="void_cheque", lang=lang)
    full_micr, inst, _ = _micr_line()

    d.add(_void_stamp(fr) + "\n")
    # company LETTERHEAD: the business name is the account-holding entity, NOT the protected subject's
    # identity (identity-only policy) -> DECOY. Its business address line is also a letterhead decoy.
    d.decoy(_company(lang)); d.add("\n")
    d.decoy(V.street_address(lang)); d.add("  ")
    d.decoy(V.city()); d.add(" QC\n")                      # business letterhead address -> NEGATIVE
    _bank_branch(d, lang, inst)
    d.add("\n")
    _date_and_chqno(d, lang)
    _payee_line(d, lang)

    # AUTHORIZED SIGNATORY: the protected natural person + their personal civic address + postal code.
    d.add(("Signataire autorise: " if fr else "Authorized signatory: "))
    d.field(V.person(lang), "person"); d.add("\n")
    d.add(("Adresse du signataire: " if fr else "Signatory address: "))
    d.field(V.street_address(lang), "address"); d.add("  ")
    d.add(V.city() + (" QC  " if random.random() < 0.85 else " Quebec  "))   # city + prov -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    _memo(d, lang)
    d.add(("Signature 1  " if fr else "Signature 1  ") + "____________________   ")
    d.add(("Signature 2  " if fr else "Signature 2  ") + "____________________\n")
    # bottom-of-cheque MICR glyph line: cheque-no, then *transit* inst account* -> the run is the account
    d.add("|" + _cheque_no() + "|  ")                      # leading cheque-no in MICR band -> DECOY
    d.field(full_micr, "account_number"); d.add("\n")
    return d.row()


LAYOUTS = [_layout_personal, _layout_personal_alt, _layout_business]   # business (suffix) = held-out


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
