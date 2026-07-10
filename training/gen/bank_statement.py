#!/usr/bin/env python3
"""bank_statement generator: synthetic Quebec/Canada consumer chequing / savings statements in the REAL
big-five (RBC eStatement) layout.

GROUNDED on datasets/scaffolds/eStatement.pdf (RBC "Your personal chequing account statement"):
 - a BANK ISSUER block at the top: "Royal Bank of Canada" + P.O. Box + city/province/postal of the bank +
   the statement period ("From <date> to <date>") -> ALL DECOYS (the issuer is not the subject).
 - the long mailing barcode line ("RBCPDA0001-123456789-01-000001-1-0001 ...") -> DECOY.
 - the HOLDER identity block (the only PII): holder name (ALL-CAPS in the real doc), a street line, an
   optional "ADDRESS LINE #2", then "CITY, PROVINCE A1B 2C3" (city + province are NEGATIVE; only the postal
   code is the positive).
 - "Your account number: 02782-5094431" (transit-account form) -> account_number.
 - "How to reach us:" toll-free numbers ("1-800 ROYAL", "1-800-769-2511") + a www URL -> DECOYS (issuer
   contact info, not the holder's phone).
 - the account-summary block: a BRANCH address ("5879 ROULE JEAN-BAPTISTE, MONTREAL, PQ H3C 3B8") = the
   bank's address, a DECOY (NOT the holder's); opening/closing balances + total deposits/withdrawals ($)
   -> DECOYS.
 - the "Details of your account activity" grid (Date / Description / Withdrawals ($) / Deposits ($) /
   Balance ($)) + cheque numbers ("Cheque #30") -> ALL DECOYS. This transaction volume is the moat for
   false-positive control.

What is PII (positive) per the identity-only redaction policy (the HOLDER identity block ONLY):
 - person        : the account holder name (often ALL-CAPS via V.person(caps=True); joint via ' ET '/' AND ').
 - address       : the holder's civic street line. The bank's branch/issuer address -> NEGATIVE decoy.
 - postal_code   : the holder's delivery postal code (Quebec G/H/J FSA). The bank's postal -> NEGATIVE decoy.
 - account_number: the transit-account form (02782-5094431) or the institution-first V.bank_account() form.
 - phone_number  : ONLY a holder contact line ("Telephone du titulaire") when present -> positive; the
   bank's toll-free "How to reach us" numbers are DECOYS.

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix):
 - _layout_personal_chequing : the RBC eStatement classic -- issuer block + mailing block + account-number
   line + summary block (branch address + balances) + the Details transaction grid.              [train]
 - _layout_savings_everyday  : a savings / everyday-account big-five skeleton -- masthead, an account-info
   panel keyed by account number + interest, a separate "Account holder details" block carrying a holder
   contact phone line (phone_number positive), and a deposit/withdrawal ledger.                    [train]
 - _layout_joint_statement   : a JOINT-HOLDER big-five skeleton -- two holders on the mailing line
   (' ET '/' AND '), a combined-statement header, per-holder summary, and the activity grid. The joint
   structure + the two-name mailing line are unseen in training.                                  [HELD-OUT]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402

# Big-five issuer names. The issuer string is an ORGANIZATION NEGATIVE on a statement (the bank that issued
# the document is not the subject); used only as the masthead the model must learn NOT to redact.
_ISSUERS = ["Royal Bank of Canada", "TD Canada Trust", "Banque Scotia", "BMO Banque de Montreal",
            "CIBC", "Banque Nationale du Canada", "Tangerine", "Desjardins"]
# The issuer's own mailing PO box / processing centre lines -> DECOYS (bank address, not holder).
_ISSUER_PO = ["P.O. Box 4047 Terminal A", "C.P. 6300 Succursale Centre-ville", "P.O. Box 1 Station A",
              "C.P. 4047 Terminal A", "P.O. Box 600 Station Centre-Ville"]
_ISSUER_CITY = ["Toronto, ON M5W 1L5", "Montreal, QC H3B 4W8", "Toronto, ON M5J 2J5",
                "Montreal, QC H2L 4Y9"]
# Branch / processing-centre addresses printed in the summary block -> DECOYS (the BANK's address).
_BRANCH_STREETS = ["5879 ROULE JEAN-BAPTISTE, MONTREAL, PQ H3C 3B8",
                   "1 PLACE VILLE-MARIE, MONTREAL, QC H3B 3A9",
                   "200 BAY STREET, TORONTO, ON M5J 2J5",
                   "150 RUE SAINT-JACQUES, MONTREAL, QC H2Y 1L6"]
_ACCT_TYPE = ["Signature Plus", "Personal chequing", "Compte cheques personnel", "RBC Day to Day Banking",
              "Compte courant", "Everyday Chequing", "Compte avec interets", "High Interest Savings",
              "Compte epargne Avantages"]
# Transaction descriptions -> ALL DECOYS (merchant/vendor/company names + amounts inside stay negatives).
_TXN_DESC = ["Opening balance", "Interest paid", "ATM withdrawal", "Overdraft interest", "Transfer",
             "Monthly fee", "Direct deposit", "Online Banking transfer", "Solde d'ouverture",
             "Interets verses", "Retrait GAB", "Frais mensuels", "Depot direct", "Virement"]
_MERCH = ["Nasr Foods Inc.", "The Bay", "Highland Farms", "Costco Wholesale", "Petro-Canada", "IGA",
          "Metro", "Tim Hortons", "Amazon.ca", "Hydro-Quebec", "Videotron", "SAQ"]


# ---------------- inline doctype-specific value shapes ----------------

def _money(v: float = None) -> str:
    """A statement amount / balance. Always a DECOY on a statement. Real RBC style '$3,664.79' and the OQLF
    '3 664,79 $' both appear; signed '- 727.50' / '+ 145.15' summary lines too."""
    val = abs(v) if v is not None else (random.randint(1, 9000) + random.random())
    val = round(val, 2)                                                    # avoid cents carry (,100 $) artifacts
    r = random.random()
    if r < 0.5:
        s = f"${val:,.2f}"                                                  # RBC EN style $3,664.79
    else:
        whole = int(val)                                                   # round() already carried into whole
        cents = int(round((val - whole) * 100))
        s = f"{whole:,}".replace(",", " ") + f",{cents:02d} $"             # OQLF 3 664,79 $
    if v is not None and v < 0:
        return "- " + s
    return s


def _account_no() -> str:
    """A consumer statement account number. Two real big-five shapes:
     - the RBC transit-account form 'TTTTT-AAAAAAA' (5-digit transit + 6-9 account), e.g. 02782-5094431;
     - the canonical institution-first V.bank_account() form (III-TTTT(T)-AAA or a bare run).
    Both stay account_number (collision rule 1: a bare/hyphenated NUMERIC run -> account_number, never
    sensitive_account_id). NOT Luhn (collision rule 2: an account is not a card)."""
    if random.random() < 0.5:
        transit = "".join(random.choice("0123456789") for _ in range(5))
        acct = "".join(random.choice("0123456789") for _ in range(random.randint(6, 9)))
        return f"{transit}-{acct}"
    return V.bank_account()


def _barcode() -> str:
    """The long machine mailing barcode line (RBCPDA0001-123456789-01-000001-1-0001 ...) -> DECOY. Looks
    like a hyphenated id but is print/mail routing metadata, not the holder's account."""
    return ("RBCPDA" + "".join(random.choice("0123456789") for _ in range(4)) + "-"
            + "".join(random.choice("0123456789") for _ in range(9)) + "-"
            + "-".join(f"{random.randint(0, 9999):0{n}d}" for n in (2, 6, 1, 4))
            + "   " + str(random.randint(10000, 99999)))


def _toll_free() -> str:
    """A bank 'How to reach us' toll-free number -> DECOY (issuer contact, not the holder's phone)."""
    return random.choice(["1-800-769-2511", "1-800-769-2555", "1 800 769-2555", "1-866-222-3456",
                          "1-800-465-2422", "1-888-826-4374"])


def _holder(lang: str) -> str:
    # real statement mailing blocks carry the holder name in ALL-CAPS most of the time
    return V.person(lang, caps=(random.random() < 0.75))


# Terse / abbreviated account-number cues seen on real big-five statements (account-info panels and
# transit-account stubs print 'Cpte', 'Compte', 'No', 'Acct' instead of the full formal label).
_ACCT_TERSE_FR = ["Cpte ", "Cpte: ", "Cpte no ", "Compte ", "Compte: ", "No ", "No: ", "No de cpte "]
_ACCT_TERSE_EN = ["Acct ", "Acct: ", "Acct no ", "Acct # ", "No ", "No: ", "Account "]


def _emit_account_no(d: Doc, lang: str, formal_fr: str, formal_en: str) -> None:
    """Emit ONE account_number positive under a varied presentation, then a trailing newline.

    Real big-five layouts present the account number three ways; teach all three so a BARE numeric run
    (no field label, e.g. the held-out ACROFILE) is still learned as account_number:
      - formal label (the original cue, ~62%): 'Numero de compte: ' / 'Your account number: '
      - terse abbreviated cue (~20%):          'Cpte ' / 'Compte ' / 'No ' / 'Acct '
      - BARE positional run on its own indented line, NO field label (~18%).
    Value stays a NUMERIC run via _account_no() (collision rule 1: bare/hyphenated numeric -> account_number,
    never sensitive_account_id; never Luhn -> not a card)."""
    r = random.random()
    if r < 0.62:                                              # formal label (original)
        d.add(formal_fr if lang == "fr" else formal_en)
        d.field(_account_no(), "account_number"); d.add("\n")
    elif r < 0.82:                                            # terse abbreviated cue
        d.add(random.choice(_ACCT_TERSE_FR if lang == "fr" else _ACCT_TERSE_EN))
        d.field(_account_no(), "account_number"); d.add("\n")
    else:                                                     # BARE positional run, no label, indented
        d.add("    ")                                         # positional indent, no cue word
        d.field(_account_no(), "account_number"); d.add("\n")


def _statement_period(lang: str) -> str:
    """The 'From <date> to <date>' statement period line -> a single DECOY string (two issue dates)."""
    a, b = V.iso_date(), V.iso_date()
    if lang == "fr":
        return f"Du {a} au {b}"
    return f"From {a} to {b}"


def _issuer_block(d: Doc, lang: str) -> None:
    """The top issuer/mailing-house block: issuer name + PO box + bank city/province + statement period +
    barcode. EVERYTHING here is a DECOY (the bank, not the subject)."""
    d.decoy(random.choice(_ISSUERS)); d.add("\n")
    d.decoy(random.choice(_ISSUER_PO)); d.add("\n")
    d.decoy(random.choice(_ISSUER_CITY)); d.add("\n")
    d.add(("Releve de compte cheques personnel\n" if lang == "fr"
           else "Your personal chequing account statement\n"))
    d.decoy(_statement_period(lang)); d.add("\n")
    d.decoy(_barcode()); d.add("\n")


def _mailing_holder_block(d: Doc, lang: str) -> None:
    """The holder mailing block (the PII): name, street line(s), then 'CITY, PROVINCE postal'. City and
    province are NEGATIVE; only the postal code is a positive."""
    d.field(_holder(lang), "person"); d.add("\n")
    d.field(V.street_address(lang), "address"); d.add("\n")
    if random.random() < 0.4:
        d.add(("App. " if lang == "fr" else "SUITE ") + str(random.randint(100, 5999)) + "\n")  # line #2 filler
    d.add(V.city() + (", QC " if random.random() < 0.7 else ", PQ "))    # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")


def _reach_us(d: Doc, lang: str) -> None:
    """'How to reach us' contact column -> all DECOYS (issuer toll-free + URL)."""
    d.add(("Pour nous joindre: " if lang == "fr" else "How to reach us: "))
    d.decoy(_toll_free()); d.add("  ")
    d.decoy(random.choice(["www.rbcroyalbank.com/depots", "www.rbcbanqueroyale.com", "www.td.com",
                           "www.banquescotia.com", "www.cibc.com"])); d.add("\n")


def _txn_desc() -> str:
    """A realistic statement transaction description -> always a DECOY. Merchant/company names + cheque
    numbers + amounts inside stay negatives (collision rule 3: a merchant in a transaction line is NEGATIVE;
    collision rule 6: a bare 'Cheque #NN' number is not a card_cvv)."""
    r = random.random()
    if r < 0.30:
        return random.choice(_TXN_DESC)
    if r < 0.55:
        return f"Interac purchase - {random.randint(1000, 9999)} - {random.choice(_MERCH)}"
    if r < 0.70:
        return f"Cheque #{random.randint(1, 499)}"                       # cheque number -> NEGATIVE
    if r < 0.85:
        return f"Paiement preautorise {random.choice(_MERCH)}"
    return f"Depot {random.choice(_MERCH)}"


def _activity_grid(d: Doc, lang: str, npages: int = 2) -> None:
    """The 'Details of your account activity' table: header + 8-26 rows, ALL decoys (transaction dates,
    descriptions, withdrawals/deposits/balances). The transaction volume is the false-positive moat."""
    d.add(("\nDetails de l'activite de votre compte\n" if lang == "fr"
           else "\nDetails of your account activity\n"))
    d.add(("Date          Description                       Retraits ($)      Depots ($)        Solde ($)\n"
           if lang == "fr"
           else "Date          Description                       Withdrawals ($)   Deposits ($)      Balance ($)\n"))
    bal = random.uniform(-2000, 9000)
    for _ in range(random.randint(8, 26)):
        amt = round(random.uniform(0.15, 2800), 2)
        bal = round(bal + (amt if random.random() < 0.5 else -amt), 2)
        d.decoy(V.iso_date()); d.add("   ")
        d.decoy(_txn_desc()); d.add("   ")
        d.decoy(_money(amt)); d.add("   ")
        d.decoy(_money(bal)); d.add("\n")
    d.add(f"-- 1 of {npages} --\n")


# ---------------- layout A: classic personal chequing summary + transaction grid (RBC eStatement) ----

def _layout_personal_chequing(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="bank_statement", lang=lang)

    _issuer_block(d, lang)

    # mailing/holder block (the PII), alongside the account number + reach-us column. The account number is
    # presented with the formal label OR a terse cue OR a bare positional run (see _emit_account_no).
    _mailing_holder_block(d, lang)
    _emit_account_no(d, lang, "Numero de compte: ", "Your account number: ")
    _reach_us(d, lang)

    # account-summary block: account type + BRANCH address (the bank's address = DECOY) + balances (DECOYS)
    d.add(("\nSommaire de votre compte pour cette periode\n" if fr
           else "\nSummary of your account for this period\n"))
    d.decoy(random.choice(_ACCT_TYPE)); d.add(" ")
    d.decoy(_account_no()); d.add("\n")                                  # re-printed account no -> here a decoy run
    d.decoy(random.choice(_ISSUERS)); d.add("\n")
    d.decoy(random.choice(_BRANCH_STREETS)); d.add("\n")                 # the BANK branch address -> DECOY
    d.add(("Solde d'ouverture " if fr else "Your opening balance ")); d.decoy(_money()); d.add("\n")
    d.add(("Total des depots " if fr else "Total deposits into your account ")); d.decoy(_money(random.uniform(1, 900))); d.add("\n")
    d.add(("Total des retraits " if fr else "Total withdrawals from your account ")); d.decoy(_money(-random.uniform(1, 900))); d.add("\n")
    d.add(("Solde de fermeture " if fr else "Your closing balance ")); d.decoy(_money()); d.add("\n")

    _activity_grid(d, lang, npages=2)
    return d.row()


# ---------------- layout B: savings / everyday account, holder contact phone present ----------------

def _layout_savings_everyday(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="bank_statement", lang=lang)

    # masthead: issuer ORG NEGATIVE + savings statement title
    d.decoy(random.choice(_ISSUERS))
    d.add(("\nReleve - Compte epargne\n" if fr else "\nStatement - Savings Account\n"))
    d.decoy(_statement_period(lang)); d.add("\n")

    # account-info panel keyed by the account number + type + interest (amounts are decoys)
    d.add(("\nRenseignements sur le compte\n" if fr else "\nAccount information\n"))
    d.add(("Type de compte: " if fr else "Account type: ")); d.decoy(random.choice(_ACCT_TYPE)); d.add("\n")
    _emit_account_no(d, lang, "Numero de compte: ", "Account number: ")
    d.add(("Taux d'interet annuel: " if fr else "Annual interest rate: "))
    d.decoy(f"{random.uniform(0.5, 4.5):.2f} %"); d.add("\n")
    d.add(("Interets verses cette periode " if fr else "Interest paid this period "))
    d.decoy(_money(random.uniform(0.1, 80))); d.add("\n")

    # a SEPARATE "account holder details" block carrying a holder CONTACT phone line (phone_number positive)
    d.add(("\nCoordonnees du titulaire\n" if fr else "\nAccount holder details\n"))
    d.add(("Titulaire: " if fr else "Account holder: ")); d.field(_holder(lang), "person"); d.add("\n")
    d.add(("Adresse: " if fr else "Address: ")); d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + (", QC " if random.random() < 0.7 else ", Quebec "))   # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    d.add(("Telephone du titulaire: " if fr else "Account holder phone: "))
    d.field(V.phone(), "phone_number"); d.add("\n")                          # the HOLDER's phone -> positive

    # bank "How to reach us" toll-free -> DECOY (so the holder phone and the bank toll-free coexist)
    _reach_us(d, lang)

    # deposit / withdrawal ledger -> ALL decoys
    _activity_grid(d, lang, npages=1)
    return d.row()


# ---------------- layout C (HELD-OUT): joint-holder big-five skeleton -------------------------------

def _layout_joint_statement(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="bank_statement", lang=lang)

    _issuer_block(d, lang)

    # JOINT mailing line: two holders on one line (' ET '/' AND ') -> two person positives. The structure
    # (combined statement, two-name mailing line, per-holder summary) is unseen in training.
    d.field(_holder(lang), "person"); d.add(" ET " if fr else " AND ")
    d.field(_holder(lang), "person"); d.add("\n")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + (", QC " if random.random() < 0.7 else ", PQ "))    # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    d.add(("\nReleve combine - Compte conjoint\n" if fr else "\nCombined statement - Joint account\n"))
    d.add(("Numero de compte conjoint: " if fr else "Joint account number: "))
    d.field(_account_no(), "account_number"); d.add("\n")
    _reach_us(d, lang)

    # per-holder summary block: branch address (bank's = DECOY) + balances (DECOYS)
    d.add(("\nSommaire du compte pour cette periode\n" if fr else "\nSummary of your account for this period\n"))
    d.decoy(random.choice(_ACCT_TYPE)); d.add("\n")
    d.decoy(random.choice(_BRANCH_STREETS)); d.add("\n")                 # the BANK branch address -> DECOY
    d.add(("Solde d'ouverture conjoint " if fr else "Joint opening balance ")); d.decoy(_money()); d.add("\n")
    d.add(("Solde de fermeture conjoint " if fr else "Joint closing balance ")); d.decoy(_money()); d.add("\n")

    _activity_grid(d, lang, npages=random.randint(2, 4))
    return d.row()


LAYOUTS = [_layout_personal_chequing, _layout_savings_everyday, _layout_joint_statement]  # joint = held-out


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
