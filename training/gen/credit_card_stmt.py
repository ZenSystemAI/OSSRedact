#!/usr/bin/env python3
"""credit_card_stmt generator: synthetic Quebec/Canada credit-card / revolving-credit statements in REAL
issuer layouts (Desjardins Accord D FR specimen + a generic bank Visa/Mastercard statement + an Amex-style
rewards charge-card statement as the held-out structure).

GROUNDED on the Desjardins "Votre releve de compte explique" scaffold
(datasets/scaffolds/b10-releve-compte-f.pdf), which fixes the real Accord D revolving-credit vocabulary:
"Solde total de votre releve", "Paiement minimum du", "Limite de credit", "Solde de votre financement
Accord D", numbered financing plans ("plan 007 D"), the OQLF money format "1 504,59 $", and the table
"Sommaire des transactions courantes" / "Detail des operations". The generic-bank and Amex layouts follow
the standard North-American card-statement anatomy (account summary block + transaction list).

What is PII (positive) on a card statement, per the identity-only redaction policy:
 - person          : the cardholder / titulaire name.
 - address         : the mailing civic address (street line). City + province QC alone -> NEGATIVE.
 - postal_code     : the delivery postal code (Quebec G/H/J FSA).
 - payment_card    : the FULL PAN on the "card on file" / "Carte" line (Luhn-valid, V.payment_card()).
 - account_number  : the folio / numero de compte / membership number (the inline _folio() shape).

What is a DECOY (present, never labeled) -- the contrast the model MUST learn:
 - the MASKED card tail in every transaction line ("**** **** **** 1234", Amex "**** ****** *1234"):
   NEVER payment_card. This is the headline contrast of this doctype -- full-PAN(positive) vs masked-tail
   (decoy). The masked tail carries asterisks + only 4 visible digits, so it can never be a PAN.
 - every amount: credit limit, available credit, previous/new balance, minimum payment, every transaction
   amount, interest charged, the OQLF "1 234,56 $" totals.
 - every date: statement date, statement period, payment due date, every transaction/posting date.
 - the annual interest rate (e.g. "19,90 %") and reward points / Membership Rewards balances.
 - merchant / vendor names on transaction lines (the carrier of the charge, not the subject).

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix):
 - _layout_desjardins_accord_d : Desjardins Accord D FR revolving-credit statement -- Solde total /
   Paiement minimum / Limite de credit block, numbered financing plans, "Sommaire des transactions
   courantes" table with masked tails.                                                          [train]
 - _layout_bank_visa           : generic bank Visa/Mastercard statement -- "Numero de compte / Account
   number" + account-summary block (previous balance, payments, purchases, new balance, credit limit,
   available credit, interest rate) + transaction list with 4-group masked tails.               [train]
 - _layout_amex_rewards        : Amex-style rewards charge-card statement -- a Membership Number (not a
   bank account), a Membership Rewards points block, NO preset-credit-limit phrasing, a 15-digit Amex
   full PAN on file, and the distinct Amex masked-tail format ("**** ****** *1234"). The rewards-charge
   structure + the Amex masked format are unseen in training.                                   [HELD-OUT]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402
import cue_helpers as C         # noqa: E402

# Merchant names on transaction lines -> DECOYS (the charge's vendor, not the subject's identity).
_MERCH = ["IGA #88", "METRO #341", "COSTCO WHOLESALE", "AMAZON.CA", "TIM HORTONS #2231", "SAQ #234",
          "COUCHE-TARD #55", "WALMART #3012", "PHARMAPRIX #44", "UBER EATS", "NETFLIX.COM", "SHELL #9921",
          "RONA #102", "DOLLARAMA #91", "PETRO-CANADA #44", "BUREAU EN GROS", "DECATHLON MONTREAL",
          "SPOTIFY P2C8K", "APPLE.COM/BILL", "RESTAURANT LE GRILL"]
# Card-product names -> DECOYS (the product line, never PII).
_PRODUCTS_FR = ["Carte Visa Desjardins Or", "Visa Affaires Desjardins", "Carte Visa Classique",
                "Mastercard Mondiale BNC", "Carte Visa Infinite Privilege"]
_PRODUCTS_EN = ["Desjardins Visa Gold", "World Mastercard", "Visa Classic Card", "Visa Infinite Card",
                "Cashback Mastercard"]


# ---------------- inline doctype-specific value shapes (decoys + the folio positive) ----------------

def _money(v: float, oqlf: bool = None) -> str:
    """A statement amount -> always a DECOY. OQLF '1 234,56 $' or anglo '$1,234.56'. The '$' is the canary
    the test keys on (no labeled span may contain '$')."""
    oqlf = (random.random() < 0.6) if oqlf is None else oqlf
    if oqlf:
        whole = f"{int(abs(v)):,}".replace(",", " ")
        cents = f"{int(round((abs(v) - int(abs(v))) * 100)):02d}"
        s = f"{whole},{cents} $"
    else:
        s = f"${abs(v):,.2f}"
    return ("-" + s) if v < 0 else s


def _masked_tail(form: str = "grouped") -> str:
    """The MASKED card tail shown on transaction lines -> a DECOY, NEVER payment_card. Asterisks + only the
    last 4 digits visible. 'grouped' = Visa/MC '**** **** **** 1234'; 'amex' = '**** ****** *1234';
    'compact' = 'XXXX-1234'. By construction it can never be a valid PAN (it is mostly asterisks)."""
    tail = "".join(random.choice("0123456789") for _ in range(4))
    if form == "amex":
        return f"**** ****** *{tail}"
    if form == "compact":
        return random.choice(["XXXX", "xxxx", "****"]) + random.choice(["-", " "]) + tail
    return f"**** **** **** {tail}"


def _folio() -> str:
    """A credit-card folio / account number -> account_number positive. A grouped numeric run distinct from
    a PAN (not Luhn-bound) and from a bank transit account: '4540 12## ##### ####' style folio or a bare
    9-12 digit member/account run. Never asterisk-masked (that is the decoy)."""
    style = random.random()
    if style < 0.45:
        groups = [str(random.randint(1000, 9999)) for _ in range(random.choice([3, 4]))]
        return " ".join(groups)
    if style < 0.75:
        return "".join(random.choice("0123456789") for _ in range(random.randint(9, 12)))
    return f"{random.randint(100,999)}-{random.randint(100000,999999)}-{random.randint(10,99)}"


def _amex_membership() -> str:
    """Amex membership number -> account_number positive. Distinct grouped shape '3759 ###### #####'."""
    return f"3759 {random.randint(100000,999999)} {random.randint(10000,99999)}"


def _amex_pan() -> str:
    """A FULL Amex PAN on file -> payment_card positive. Forces the 15-digit Amex shape (34/37 prefix,
    '**** ****** *####' grouping) so the Amex rewards-charge layout actually carries an Amex card, not a
    16-digit Visa/MC PAN. Reuses the frozen V.payment_card() Luhn-valid sampler (re-draws until Amex)."""
    import re as _re
    while True:
        pan = V.payment_card(valid=True)
        if len(_re.sub(r"\D", "", pan)) == 15:
            return pan


def _rate() -> str:
    """Annual interest rate -> DECOY. OQLF percent '19,90 %' or anglo '19.90%'."""
    whole = random.choice([11, 12, 18, 19, 20, 21, 22])
    frac = random.choice([0, 9, 90, 99, 49, 75])
    if random.random() < 0.6:
        return f"{whole},{frac:02d} %"
    return f"{whole}.{frac:02d}%"


def _points() -> str:
    """A reward-points / Membership Rewards balance -> DECOY (loyalty figure, not money, not PII)."""
    n = random.randint(1200, 489000)
    return f"{n:,}".replace(",", " ") if random.random() < 0.6 else f"{n:,}"


def _txn_table(d: Doc, fr: bool, mask_form: str = "grouped", n: tuple = (8, 22)) -> None:
    """Append the transaction list: header row + 8-22 lines, ALL decoys (posting date, transaction date,
    merchant, the MASKED card tail, amount). This volume + the masked-tail contrast is the false-positive
    moat for this doctype."""
    if fr:
        d.add("Date  Date transac.  Description  Carte  Montant\n")
    else:
        d.add("Posting  Trans. date  Description  Card  Amount\n")
    for _ in range(random.randint(*n)):
        d.decoy(V.iso_date()); d.add("  ")
        d.decoy(V.iso_date()); d.add("  ")
        d.decoy(random.choice(_MERCH)); d.add("  ")
        d.decoy(_masked_tail(mask_form)); d.add("  ")        # masked tail -> NEVER payment_card
        d.decoy(_money(round(random.uniform(2, 1900), 2))); d.add("\n")


def _name(lang: str) -> str:
    # Real card-statement holder lines are frequently ALL-CAPS embossed-style; let caps vary.
    return V.person(lang, caps=(random.random() < 0.55))


# ---------------- v11 r2 cue-diversification helpers (TRAIN layouts only) ----------------
# These add the BRAND-CUED full-PAN and BARE/positional account_number presentations the held-out real
# layouts use but the formal-labeled train layouts never taught. ~30% of occurrences switch to the new
# cue; the rest keep the existing formal label. Offset-true via d.field by construction.

def _emit_card_line(d: Doc, fr: bool, formal_label: str) -> None:
    """Emit the FULL-PAN payment_card line. ~30%: a BRAND-CUED form -- print the network brand (matched to
    the PAN's IIN via C.brand_label) then the full PAN, e.g. 'Paiement par VISA <pan>' /
    'Regle par MASTERCARD <pan>' / 'Paid by VISA <pan>'. The remaining ~70%: the existing formal label.
    Either way the full PAN is the payment_card positive; masked tails in the txn table stay decoys."""
    pan = V.payment_card(valid=True)
    if random.random() < 0.30:
        brand = C.brand_label(pan)
        if fr:
            lead = random.choice([
                f"Paiement par {brand} ",
                f"Regle par {brand} ",
                f"Porte sur la carte {brand} ",
                f"{brand} se terminant -- carte ",
            ])
        else:
            lead = random.choice([
                f"Paid by {brand} ",
                f"Charged to {brand} ",
                f"Posted to {brand} card ",
                f"{brand} card ending -- ",
            ])
        d.add(lead); d.field(pan, "payment_card"); d.add("\n")
    else:
        d.add(formal_label); d.field(pan, "payment_card"); d.add("\n")


def _emit_account_line(d: Doc, fr: bool, formal_label: str) -> None:
    """Emit the account_number (folio) line. ~30%: a BARE/positional form -- a terse inline cue or a bare
    'No.'/'#'/'Cpte' tag rather than the full 'Numero de compte:' label, e.g. 'Cpte 4540 1212 ...' /
    'No 4540...' / 'Acct# ...' / 'Ref. 4540...'. The remaining ~70%: the existing formal label. The folio
    is a NUMERIC bare/grouped run (V via _folio) -> account_number positive (never the opaque/masked form)."""
    folio = _folio()
    if random.random() < 0.30:
        if fr:
            tag = random.choice(["Cpte ", "No ", "No. ", "Cpte no ", "Ref. ", "Compte "])
        else:
            tag = random.choice(["Acct ", "Acct# ", "No. ", "A/C ", "Ref. ", "# "])
        d.add(tag); d.field(folio, "account_number"); d.add("\n")
    else:
        d.add(formal_label); d.field(folio, "account_number"); d.add("\n")


# ---------------- layout A: Desjardins Accord D revolving-credit statement (FR specimen) ----------------

def _layout_desjardins_accord_d(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="credit_card_stmt", lang=lang)
    plan = f"{random.randint(1, 99):03d} {random.choice('ABCDEFG')}"   # financing plan no. ('007 D') -> decoy

    d.add("Desjardins\n")
    d.add("Releve de compte Accord D\n" if fr else "Accord D Account Statement\n")
    d.add(("Date du releve: " if fr else "Statement date: ")); d.decoy(V.iso_date()); d.add("\n")

    d.add(("Titulaire: " if fr else "Cardholder: ")); d.field(_name(lang), "person"); d.add("\n")
    _emit_account_line(d, fr, "Numero de compte: " if fr else "Account number: ")
    _emit_card_line(d, fr, "Carte enregistree au dossier: " if fr else "Card on file: ")  # FULL PAN positive

    d.add(("Adresse: " if fr else "Address: ")); d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + ("  QC  " if fr else ", QC  "))                   # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    # the Accord D summary block -- every figure here is a DECOY
    d.add(("Solde total de votre releve: " if fr else "Total statement balance: "))
    d.decoy(_money(round(random.uniform(80, 4200), 2))); d.add("\n")
    d.add(("Paiement minimum du: " if fr else "Minimum payment due: "))
    d.decoy(_money(round(random.uniform(15, 220), 2))); d.add("\n")
    d.add(("Date limite de paiement: " if fr else "Payment due date: ")); d.decoy(V.iso_date()); d.add("\n")
    d.add(("Limite de credit (achats courants): " if fr else "Credit limit (current purchases): "))
    d.decoy(_money(round(random.uniform(2000, 25000), 2))); d.add("\n")
    d.add(("Solde de votre financement Accord D (plan " if fr else "Accord D financing balance (plan ")
          + plan + "): ")
    d.decoy(_money(round(random.uniform(100, 3500), 2))); d.add("\n")
    d.add(("Taux d'interet annuel: " if fr else "Annual interest rate: ")); d.decoy(_rate()); d.add("\n\n")

    d.add("Sommaire des transactions courantes\n" if fr else "Summary of current transactions\n")
    _txn_table(d, fr, mask_form="grouped")
    return d.row()


# ---------------- layout B: generic bank Visa / Mastercard statement ----------------

def _layout_bank_visa(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="credit_card_stmt", lang=lang)
    product = random.choice(_PRODUCTS_FR if fr else _PRODUCTS_EN)

    d.add(random.choice(["Banque Nationale", "Mouvement Desjardins", "BMO", "CIBC"]) + "\n")
    d.add(product + "\n")
    d.add(("Periode du releve: " if fr else "Statement period: "))
    d.decoy(V.iso_date()); d.add(" au " if fr else " to "); d.decoy(V.iso_date()); d.add("\n\n")

    # address block first (envelope window position on the real statement)
    d.field(_name(lang), "person"); d.add("\n")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + ("  QC  " if fr else ", QC  "))
    d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    _emit_account_line(d, fr, "Numero de compte " if fr else "Account number ")
    _emit_card_line(d, fr, "Numero de carte " if fr else "Card number ")   # FULL PAN -> payment_card
    d.add("\n")

    # account-summary block -- all decoys
    d.add(("Solde anterieur " if fr else "Previous balance ")); d.decoy(_money(round(random.uniform(0, 3000), 2))); d.add("\n")
    d.add(("Paiements et credits " if fr else "Payments and credits "))
    d.decoy(_money(-round(random.uniform(50, 2000), 2))); d.add("\n")
    d.add(("Achats et avances " if fr else "Purchases and advances "))
    d.decoy(_money(round(random.uniform(50, 2800), 2))); d.add("\n")
    d.add(("Interets " if fr else "Interest charged ")); d.decoy(_money(round(random.uniform(0, 90), 2))); d.add("\n")
    d.add(("Nouveau solde " if fr else "New balance ")); d.decoy(_money(round(random.uniform(0, 4200), 2))); d.add("\n")
    d.add(("Paiement minimum " if fr else "Minimum payment ")); d.decoy(_money(round(random.uniform(10, 180), 2))); d.add("\n")
    d.add(("Date d'echeance " if fr else "Due date ")); d.decoy(V.iso_date()); d.add("\n")
    d.add(("Limite de credit " if fr else "Credit limit ")); d.decoy(_money(round(random.uniform(3000, 30000), 2))); d.add("\n")
    d.add(("Credit disponible " if fr else "Available credit ")); d.decoy(_money(round(random.uniform(0, 20000), 2))); d.add("\n")
    d.add(("Taux annuel " if fr else "Annual rate ")); d.decoy(_rate()); d.add("\n\n")

    d.add("Detail des transactions\n" if fr else "Transaction details\n")
    _txn_table(d, fr, mask_form=random.choice(["grouped", "compact"]))
    return d.row()


# ---------------- layout C (HELD-OUT): Amex-style rewards charge-card statement ----------------

def _layout_amex_rewards(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="credit_card_stmt", lang=lang)

    d.add("American Express\n")
    d.add(("Releve de carte Rewards " if fr else "Rewards Card Statement ") + "\n")
    d.add(("Date de cloture: " if fr else "Closing date: ")); d.decoy(V.iso_date()); d.add("\n\n")

    # Amex prepares the holder block differently: name, then a Membership Number (NOT a bank account),
    # then the full 15-digit Amex PAN on file.
    d.add(("Membre: " if fr else "Member: ")); d.field(_name(lang), "person"); d.add("\n")
    d.add(("Numero de membre: " if fr else "Membership number: "))
    d.field(_amex_membership(), "account_number"); d.add("\n")          # membership no. -> account_number
    d.add(("Carte: " if fr else "Card: "))
    d.field(_amex_pan(), "payment_card"); d.add("\n")                   # FULL 15-digit Amex PAN -> payment_card

    d.add(("Adresse postale: " if fr else "Mailing address: "))
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + ("  QC  " if fr else ", QC  "))
    d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    # Rewards charge-card summary: NO preset credit limit, a Membership Rewards points block instead.
    d.add(("Solde precedent " if fr else "Previous balance ")); d.decoy(_money(round(random.uniform(0, 2500), 2))); d.add("\n")
    d.add(("Nouvelles charges " if fr else "New charges ")); d.decoy(_money(round(random.uniform(80, 5200), 2))); d.add("\n")
    d.add(("Solde total du " if fr else "Total balance due ")); d.decoy(_money(round(random.uniform(80, 6000), 2))); d.add("\n")
    d.add(("Paiement minimum " if fr else "Minimum payment ")); d.decoy(_money(round(random.uniform(35, 320), 2))); d.add("\n")
    d.add(("Date d'echeance " if fr else "Payment due ")); d.decoy(V.iso_date()); d.add("\n")
    d.add(("Solde Membership Rewards: " if fr else "Membership Rewards balance: "))
    d.decoy(_points()); d.add(" pts\n")
    d.add(("Points gagnes ce mois: " if fr else "Points earned this period: ")); d.decoy(_points()); d.add("\n\n")

    d.add("Detail des operations\n" if fr else "Detail of charges\n")
    _txn_table(d, fr, mask_form="amex")                                 # distinct Amex masked-tail format
    return d.row()


LAYOUTS = [_layout_desjardins_accord_d, _layout_bank_visa, _layout_amex_rewards]  # Amex (suffix) = held-out


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
