#!/usr/bin/env python3
"""telecom_bill generator: synthetic Quebec telecom / internet / mobility bills in the REAL
TELUS / Videotron invoice layouts.

GROUNDED on the firecrawl scaffolds of the real support pages that describe each bill's anatomy:
 - datasets/scaffolds/firecrawl/telus-qc-residential-bill.md  (TELUS Home Services / residential bill:
   account number, bill summary = balance carried forward + total account balance + payment due + payment
   options, charges by product + 911 fees + taxes, mailing address on file, bill date / billing cycle).
 - datasets/scaffolds/firecrawl/videotron-understanding-invoice.md  (Videotron Helix "My Account" invoice:
   the 4 basics = Account number top-right + Invoice date + Invoice period + Current invoice due date /
   pre-authorized payment date; Current Services / Invoice Details / Pay-per-use fees / One-time fees;
   Previous invoice -> Payment rec'd line).
 - datasets/scaffolds/firecrawl/telus-mobility-bill-terms.md  (TELUS Mobility bill terms 01-10: Bill Date,
   Account number, Savings Box, Balance owing from last bill, New charges, Total due, Partial charges,
   Monthly and other charges = rate plan, Add-ons, Usage charges; per-SUBSCRIBER charges keyed by the
   subscriber's own service number; Device Balance / Easy Payment).

What is PII (positive) on a telecom bill, per the identity-only redaction policy:
 - person       : the account holder name.
 - address      : the service/billing civic address (street line). City + province QC alone -> NEGATIVE.
 - postal_code  : the delivery postal code (Quebec G/H/J FSA).
 - account_number: the customer / account number (the inline customer_number() shape).
 - phone_number : the subscriber's OWN mobility/home service number (the line being billed) -> positive.

What is a DECOY (present, never labeled), the false-positive moat for billing docs:
 - every amount (monthly charges, taxes, 911 fee, total due, balance carried forward, partial charges).
 - every date (bill date, invoice date, invoice period, due date, pre-authorized payment date).
 - usage figures (GB of data, minutes, texts) and plan names / product names.
 - the PROVIDER name (TELUS / Videotron) -> an organization NEGATIVE (a billing-header issuer, not the
   subject; the model must not redact the carrier on every invoice).
 - call-detail-record numbers (numbers the subscriber CALLED = third-party phones) -> phone-shaped NEGATIVE.

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix):
 - _layout_telus_residential : TELUS Home Services bill -- prose-ish bill-summary block, charges by
   product, no per-subscriber phone keying.                                                    [train]
 - _layout_videotron_helix   : Videotron Helix "My Account" invoice -- the tight 4-basics block
   (account no top-right / invoice date / invoice period / due date) + Invoice Details table.   [train]
 - _layout_telus_mobility     : TELUS Mobility bill -- numbered terms, per-SUBSCRIBER section keyed by the
   billed service number (phone_number positive) + a call-detail-record table of CALLED numbers
   (phone-shaped DECOYS). The mobility structure + the CDR table are unseen in training.       [HELD-OUT]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402

# Provider names are ORGANIZATION NEGATIVES on a bill (the issuer/carrier, not the subject). Real carriers,
# used only as the masthead/issuer string the model must learn NOT to redact on every invoice.
_PROVIDERS = ["TELUS", "Videotron", "Bell", "Fido", "Koodo", "Virgin Plus", "Rogers"]
# Plan / product names -> DECOYS (billing line items, never PII).
_MOBILITY_PLANS = ["Peace of Mind Connect 50GB", "Forfait Tranquillite 75 Go", "5G Premium 100GB",
                   "Essential 20GB", "Forfait Essentiel 30 Go", "Unlimited Canada-US 60GB"]
_HOME_PRODUCTS = ["Internet 1 Gbps", "Internet illimite 940 Mbit/s", "Optik TV Essentials",
                  "Telephonie residentielle", "Helix Internet 1 Gbit/s", "Helix Tele", "PureFibre 750"]
_DEVICES = ["Apple iPhone 15", "Samsung Galaxy S24", "Google Pixel 8", "Apple iPhone 14",
            "Samsung Galaxy A55", "Motorola Edge"]


# ---------------- inline doctype-specific value shapes ----------------

def _money() -> str:
    """A billing amount. Always a DECOY on a telecom bill. FR (1 234,56 $) + EN ($1,234.56) shapes."""
    val = random.randint(0, 380) + random.random()
    if random.random() < 0.55:
        return f"{int(val):,}".replace(",", " ") + f",{random.randint(0,99):02d} $"   # OQLF 1 234,56 $
    return f"${val:,.2f}"                                                              # EN $1,234.56


def _customer_number() -> str:
    """A telecom customer / account number. NOT a bank account (no institution-first format), NOT Luhn.
    Real shapes: a bare 9-13 digit run, or a grouped run, or a 'C'/'A'-prefixed account ref. Stays an
    account_number (collision rule 1: a bare/grouped numeric run -> account_number, never
    sensitive_account_id; a telecom customer no is operational, not a UUID/opaque ref)."""
    r = random.random()
    if r < 0.4:
        return "".join(random.choice("0123456789") for _ in range(random.randint(9, 13)))   # bare run
    if r < 0.7:
        a = "".join(random.choice("0123456789") for _ in range(random.choice([2, 3])))
        b = "".join(random.choice("0123456789") for _ in range(random.choice([7, 8])))
        return f"{a}-{b}"                                                                     # grouped
    pre = random.choice(["C", "A", "BC"])
    return pre + "".join(random.choice("0123456789") for _ in range(random.randint(8, 10)))   # prefixed


def _customer_number_numeric() -> str:
    """A telecom customer / account number, NUMERIC-ONLY shapes (bare run or hyphenated group). Used for the
    TERSE/BARE account_number cue variants where there is no formal label to disambiguate -- a numeric run
    keeps it an account_number (collision rule 1: a bare/grouped numeric run -> account_number, never a
    prefixed/opaque ref). Intentionally excludes the 'C'/'A'/'BC'-prefixed alphanumeric branch."""
    if random.random() < 0.55:
        return "".join(random.choice("0123456789") for _ in range(random.randint(9, 13)))   # bare run
    a = "".join(random.choice("0123456789") for _ in range(random.choice([2, 3])))
    b = "".join(random.choice("0123456789") for _ in range(random.choice([7, 8])))
    return f"{a}-{b}"                                                                         # grouped


def _emit_account_number(d: "Doc", fr: bool) -> None:
    """Append an account_number POSITIVE under one of several cues. ~30% of the time use a TERSE/BARE
    NUMERIC cue (held-out layouts carry account numbers under terse 'Compte <num>' / bare positional runs
    that the formal 'Numero de compte:' label never teaches); otherwise the formal labeled inline form.
    NUMERIC values only on the terse path (do NOT introduce alphanumeric account numbers)."""
    r = random.random()
    if r < 0.15:
        # terse 'Compte' / 'Account' cue, no colon, numeric only
        d.add(("Compte " if fr else "Account "))
        d.field(_customer_number_numeric(), "account_number")
        d.add("\n")
    elif r < 0.22:
        # abbreviated cue: 'No de compte' / 'Acct No' (terse), numeric only
        d.add(("No de compte " if fr else "Acct No "))
        d.field(_customer_number_numeric(), "account_number")
        d.add("\n")
    elif r < 0.30:
        # BARE positional numeric run on its own line (no cue word) -- pure positional account number
        d.field(_customer_number_numeric(), "account_number")
        d.add("\n")
    else:
        # formal labeled inline form (the original presentation, kept as the majority case)
        d.add(("Numero de compte: " if fr else "Account number: "))
        d.field(_customer_number(), "account_number")
        d.add(("  (requis pour vos paiements)\n" if fr else "  (needed for bill payments)\n"))


def _emit_one_subject_phone(d: "Doc", fr: bool) -> None:
    """Append ONE subscriber service number as a phone_number POSITIVE under a TERSE cue. Train layouts
    never carried a subject phone, so terse-context phones (held-out 'Numero de service:' / 'Tel' / bare) go
    unlearned -- this adds them. The OWN service line is the subject (positive); CALLED numbers stay decoys.
    Reuses V.phone() (same value shape the held-out layout uses for its labeled service number)."""
    r = random.random()
    if r < 0.40:
        d.add(("Numero de service: " if fr else "Service number: "))
        d.field(V.phone(), "phone_number"); d.add("\n")
    elif r < 0.62:
        d.add(("Tel " if fr else "Tel "))
        d.field(V.phone(), "phone_number"); d.add("\n")
    elif r < 0.80:
        # additional terse cue variety (mobile / cell number on file) -- same positive, same value shape
        d.add(("Numero mobile: " if fr else "Mobile no: "))
        d.field(V.phone(), "phone_number"); d.add("\n")
    else:
        # bare positional phone on its own line (no cue word)
        d.field(V.phone(), "phone_number"); d.add("\n")


def _emit_subject_phone(d: "Doc", fr: bool) -> None:
    """Append the subscriber's OWN service number(s) as phone_number POSITIVE(s). Emits one terse-cued service
    number, and ~50% of the time a SECOND household/service line under a distinct terse cue ('Ligne
    secondaire' / 'Second line') -- a realistic multi-line account. The 1-2 count + cue variety raises train's
    phone_number frequency toward the held-out rate while every emitted number stays a subject positive."""
    _emit_one_subject_phone(d, fr)
    if random.random() < 0.5:
        d.add(("Ligne secondaire: " if fr else "Second line: "))
        d.field(V.phone(), "phone_number"); d.add("\n")


def _called_number() -> str:
    """A number the subscriber CALLED (a call-detail-record entry = a THIRD PARTY's phone). Phone-shaped,
    but a NEGATIVE decoy (only the subscriber's OWN service number is the positive)."""
    return V.phone()


def _usage() -> str:
    """A usage figure (data / minutes / texts). A DECOY (billing metric, never PII)."""
    r = random.random()
    if r < 0.45:
        return f"{random.randint(1, 99)}.{random.randint(0, 9)} Go" if random.random() < 0.5 \
               else f"{random.randint(1, 99)}.{random.randint(0, 9)} GB"
    if r < 0.75:
        return f"{random.randint(0, 1200)} min"
    return f"{random.randint(0, 500)} textos" if random.random() < 0.5 else f"{random.randint(0, 500)} texts"


def _holder(lang: str) -> str:
    # bill headers often carry the holder name in caps (mailing block) but mixed-case is common too
    return V.person(lang, caps=(random.random() < 0.4))


# ---------------- layout A: TELUS Home Services / residential bill ----------------

def _layout_telus_residential(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="telecom_bill", lang=lang)
    prov = random.choice(["TELUS", "Bell"])

    # masthead: provider name is an ORG NEGATIVE (issuer, not subject)
    d.decoy(prov); d.add(("\nFacture des services a domicile\n" if fr else "\nHome Services bill\n"))

    # account holder + mailing address block
    d.add("Titulaire du compte: " if fr else "Account holder: ")
    d.field(_holder(lang), "person"); d.add("\n")
    # the home/residential service number(s) appear under TERSE cues (phone_number positive), 1-2 lines per
    # bill -- raises train's phone_number frequency toward the held-out rate
    _emit_subject_phone(d, fr)
    d.add("Adresse de facturation: " if fr else "Billing address: ")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + (" QC " if random.random() < 0.8 else " Quebec "))   # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    # account-number block: ~30% terse/bare NUMERIC cue ('Compte <num>' / bare run), else formal inline label
    _emit_account_number(d, fr)

    # bill dates -> ALL decoys
    d.add(("Date de facturation: " if fr else "Bill date: ")); d.decoy(V.iso_date())
    d.add(("   Cycle de facturation: " if fr else "   Billing cycle: ")); d.decoy(V.iso_date())
    d.add(("   Date d'echeance: " if fr else "   Payment due date: ")); d.decoy(V.iso_date()); d.add("\n")

    # charges by product -> product names + amounts all decoys
    d.add(("\nFrais mensuels par produit\n" if fr else "\nMonthly charges by product\n"))
    for _ in range(random.randint(3, 6)):
        d.decoy(random.choice(_HOME_PRODUCTS)); d.add("   "); d.decoy(_money()); d.add("\n")
    d.add(("Frais 911 " if fr else "911 fee ")); d.decoy(_money()); d.add("\n")
    d.add(("Taxes (TPS/TVQ) " if fr else "Taxes (GST/QST) ")); d.decoy(_money()); d.add("\n")

    # bill summary block (balance carried forward / total account balance / payment due)
    d.add(("\nSommaire de la facture\n" if fr else "\nBill summary\n"))
    d.add(("Solde reporte du mois dernier " if fr else "Balance carried forward from last month "))
    d.decoy(_money()); d.add("\n")
    d.add(("Solde total du compte " if fr else "Total account balance ")); d.decoy(_money()); d.add("\n")
    d.add(("Paiement du " if fr else "Payment due ")); d.decoy(_money()); d.add("\n")

    return d.row()


# ---------------- layout B: Videotron Helix "My Account" invoice ----------------

def _layout_videotron_helix(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="telecom_bill", lang=lang)

    # masthead: provider is an ORG NEGATIVE
    d.decoy("Videotron"); d.add(("  Facture Helix\n" if fr else "  Helix invoice\n"))

    # the "4 invoice basics" block -- account number (~30% terse/bare NUMERIC cue), then the 3 dates (decoys)
    _emit_account_number(d, fr)
    d.add(("Date de la facture: " if fr else "Invoice date: ")); d.decoy(V.iso_date()); d.add("\n")
    d.add(("Periode de facturation: " if fr else "Invoice period: "))
    d.decoy(V.iso_date()); d.add(" au " if fr else " to "); d.decoy(V.iso_date()); d.add("\n")
    d.add(("Date d'echeance / prelevement preautorise: " if fr
           else "Current invoice due date / pre-authorized payment date: "))
    d.decoy(V.iso_date()); d.add("\n")

    # subscriber block: holder + service address
    d.add(("\nAbonne: " if fr else "\nSubscriber: ")); d.field(_holder(lang), "person"); d.add("\n")
    # the subscriber's OWN service number(s) appear under TERSE cues (phone_number positive), 1-2 lines per
    # bill -- raises train's phone_number frequency toward the held-out rate
    _emit_subject_phone(d, fr)
    d.add(("Adresse du service: " if fr else "Service address: "))
    d.field(V.street_address(lang), "address"); d.add(", ")
    d.add(V.city() + " QC ")                                  # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    # Invoice Details / Current Services table -> product names + amounts decoys
    d.add(("\nDetails de la facture - Services actuels\n" if fr else "\nInvoice Details - Current Services\n"))
    for _ in range(random.randint(2, 4)):
        d.decoy(random.choice(_HOME_PRODUCTS)); d.add("   "); d.decoy(_money()); d.add("\n")

    # Pay-per-use / One-time fees section -> usage + amount decoys
    d.add(("Frais a l'usage\n" if fr else "Pay-per-use fees\n"))
    if random.random() < 0.7:
        d.add(("Depassement de donnees " if fr else "Data overage ")); d.decoy(_usage())
        d.add("  "); d.decoy(_money()); d.add("\n")
    d.add(("Frais ponctuels\n" if fr else "One-time fees\n"))
    d.decoy(random.choice(["Activation", "Installation", "Frais de mise en service", "Setup fee"]))
    d.add("  "); d.decoy(_money()); d.add("\n")

    # Previous invoice -> Payment rec'd line (date + amount decoys)
    d.add(("\nFacture precedente - Paiement recu " if fr else "\nPrevious invoice - Payment rec'd "))
    d.decoy(V.iso_date()); d.add("  "); d.decoy(_money()); d.add("\n")
    d.add(("Total a payer " if fr else "Total due ")); d.decoy(_money()); d.add("\n")

    return d.row()


# ---------------- layout C (HELD-OUT): TELUS Mobility bill, per-subscriber + CDR table ----------------

def _layout_telus_mobility(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="telecom_bill", lang=lang)

    # masthead: provider ORG NEGATIVE
    d.decoy("TELUS"); d.add(("  Facture Mobilite\n" if fr else "  Mobility bill\n"))

    # account holder + mailing address
    d.add(("Titulaire: " if fr else "Account holder: ")); d.field(_holder(lang), "person"); d.add("\n")
    d.add(("Numero de compte: " if fr else "Account number: "))
    d.field(_customer_number(), "account_number")
    d.add(("  (requis pour les paiements et inscriptions My Account)\n" if fr
           else "  (needed to make a payment and to register for My Account)\n"))
    d.add(("Adresse postale: " if fr else "Mailing address: "))
    d.field(V.street_address(lang), "address"); d.add(", ")
    d.add(V.city() + " QC ")                                 # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    # numbered mobility-bill terms (01..06) -> dates + amounts decoys
    d.add(("\n01 Date de facturation: " if fr else "\n01 Bill date: ")); d.decoy(V.iso_date()); d.add("\n")
    d.add(("03 Economies " if fr else "03 Savings box "))            # Savings Box
    d.decoy(_money()); d.add("\n")
    d.add(("04 Solde reporte de la derniere facture " if fr else "04 Balance owing from your last bill "))
    d.decoy(_money()); d.add("\n")
    d.add(("05 Nouveaux frais " if fr else "05 New charges ")); d.decoy(_money()); d.add("\n")
    d.add(("06 Total du " if fr else "06 Total due ")); d.decoy(_money()); d.add("\n")

    # PER-SUBSCRIBER section keyed by the billed SERVICE number -> phone_number POSITIVE.
    # (1-2 subscribers; the held-out structure the train layouts never produce.)
    for _ in range(random.randint(1, 2)):
        d.add(("\nAbonne - Numero de service: " if fr else "\nSubscriber - Service number: "))
        d.field(V.phone(), "phone_number"); d.add("\n")           # the OWN service line = positive
        d.add(("  08 Forfait mensuel: " if fr else "  08 Monthly rate plan: "))
        d.decoy(random.choice(_MOBILITY_PLANS)); d.add("   "); d.decoy(_money()); d.add("\n")
        d.add(("  Appareil: " if fr else "  Device: ")); d.decoy(random.choice(_DEVICES))
        d.add(("   Solde de l'appareil " if fr else "   Device Balance ")); d.decoy(_money()); d.add("\n")
        d.add(("  09 Options " if fr else "  09 Add-ons ")); d.decoy(_money()); d.add("\n")
        d.add(("  10 Frais d'utilisation " if fr else "  10 Usage charges "))
        d.decoy(_usage()); d.add("  "); d.decoy(_money()); d.add("\n")

        # call-detail-record table: numbers CALLED are THIRD-PARTY phones -> phone-shaped DECOYS.
        d.add(("  Detail des appels\n" if fr else "  Call detail record\n"))
        d.add(("  Date         Numero compose      Duree    Frais\n" if fr
               else "  Date         Number called       Duration Charge\n"))
        for _ in range(random.randint(3, 8)):
            d.decoy(V.iso_date()); d.add("  ")
            d.decoy(_called_number()); d.add("  ")            # called number = decoy (not the subject)
            d.decoy(f"{random.randint(0, 59)}:{random.randint(0, 59):02d}"); d.add("  ")
            d.decoy(_money()); d.add("\n")

    d.add(("Taxes (TPS/TVQ) " if fr else "Taxes (GST/QST) ")); d.decoy(_money()); d.add("\n")
    return d.row()


LAYOUTS = [_layout_telus_residential, _layout_videotron_helix, _layout_telus_mobility]   # mobility = held-out


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
