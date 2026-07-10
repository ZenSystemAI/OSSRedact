#!/usr/bin/env python3
"""restaurant_facture generator: synthetic Quebec MANDATORY restaurant invoices (facture obligatoire,
MEV/WEB-SRM) in the REAL Revenu Quebec mandated layout.

GROUNDED on the Revenu Quebec scaffold (datasets/scaffolds/firecrawl/restaurant-exemple-facture.md +
restaurant-preparation-factures.md): the legally mandated field order of a facture produced by a certified
SEV / MEV. The defining structural feature is the "suite de signes d'egalite" (===) rule: a run of '=' before
the tax/total block, the amounts presented in a MANDATED ORDER (Montant de la TPS -> Montant de la TVQ ->
Montant total de la fourniture, then adjusted / due / installments / balance / tip), a mandatory mention
("PAIEMENT RECU" / "FACTURE ORIGINALE"), a QR + 'Consulter la transaction en ligne' web link, the WEB-SRM
processing echo (Moment du traitement + Numero de transaction transmis + Identifiant de l'appareil), and a
SECOND === run.

This is a MOSTLY-NEGATIVE doctype. The moat is teaching the model NOT to over-redact the mandatory invoice
skeleton (the operator's false-positive fix): the whole === block, every tax amount / total / tip / balance,
every item line + price, the transaction numbers, the device id (no de l'appareil), the QR web link, the
restaurant name (org decoy), the restaurant phone, and all dates/times are DECOYS.

POSITIVES (sparse):
 - tax_id  : the restaurant's GST/TPS registration number (RT...) and QST/TVQ registration number (TQ...) in
             the header. ALWAYS present (legally mandatory >= 500 $ and emitted here every doc).
 - person  : ONLY a named customer line (note de credit / document complementaire 'Nom du client') if present.
 - phone_number : a CUSTOMER phone (delivery contact) if present; the RESTAURANT phone in the header = DECOY.
 - payment_card : ONLY a full PAN if printed (rare); the usual masked tail ('**** **** **** 4242') = DECOY.

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix):
 - _layout_dinein   : dine-in reception receipt (recu de fermeture), table service, no customer identity. [train]
 - _layout_takeout  : takeout / delivery facture with a named customer + delivery address + delivery phone
                      (the 'document complementaire' >= 500 $ identity path) -> person/phone positives.   [heldout]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402
import cue_helpers as C         # noqa: E402

# ---- inline synthetic restaurant names (generic, NOT real businesses; org decoys) ----
_RESTO_PREFIX = ["Restaurant", "Bistro", "Brasserie", "Cafe", "Casse-croute", "Rotisserie", "Taverne",
                 "Pizzeria", "Resto-Bar", "Creperie"]
_RESTO_NAME = ["Le Chasseur", "Chez Mathilde", "L'Ardoise", "du Vieux-Port", "Saint-Denis", "La Fabrique",
               "Le Lampadaire", "des Erables", "L'Entrecote", "Le Charbon", "La Tablee", "du Marche",
               "Le Quai 17", "L'Atelier", "La Cantine"]

# ---- menu items (description detaillee). Always decoys. ----
_ITEMS_FR = [
    ("Soupe aux legumes", 6.50), ("Buffet de salades", 14.95), ("Menu du jour no 1", 21.00),
    ("Verre de vin rouge", 9.00), ("Service de vestiaire", 3.00), ("Tartare de saumon", 18.50),
    ("Poutine maison", 11.25), ("Cote de boeuf 12 oz", 38.00), ("Pates carbonara", 19.75),
    ("Cafe au lait", 4.25), ("Tarte au sucre", 7.50), ("Pichet de sangria", 24.00),
    ("Plateau de fromages", 16.00), ("Bavette de boeuf", 27.50), ("Fish and chips", 17.95),
]
_ITEMS_EN = [
    ("Vegetable soup", 6.50), ("Salad bar", 14.95), ("Daily special no. 1", 21.00),
    ("Glass of red wine", 9.00), ("Coat check service", 3.00), ("Salmon tartare", 18.50),
    ("House poutine", 11.25), ("12 oz prime rib", 38.00), ("Carbonara pasta", 19.75),
    ("Cafe latte", 4.25), ("Sugar pie", 7.50), ("Sangria pitcher", 24.00),
    ("Cheese platter", 16.00), ("Beef flank steak", 27.50), ("Fish and chips", 17.95),
]


def _money(v: float) -> str:
    """OQLF / Quebec money string. ALWAYS contains '$' -> a DECOY by construction. Round to cents FIRST so
    the cents field is always exactly 2 digits (never a .995 -> ',100 $' carry artifact)."""
    cents = int(round(v * 100))
    dollars, c = divmod(cents, 100)
    if random.random() < 0.5:
        return f"{dollars:,}".replace(",", " ") + f",{c:02d} $"   # 1 234,56 $ (OQLF)
    return f"{dollars:,}.{c:02d} $"                               # 1,234.56 $


def _txn_no() -> str:
    """SEV transaction number (Numero de transaction) -> DECOY. Short alnum SEV ref, not a PII id."""
    return "".join(random.choice("0123456789") for _ in range(random.choice([4, 6]))) \
        + "-" + "".join(random.choice("0123456789ABCDEF") for _ in range(4))


def _device_id() -> str:
    """Identifiant de l'appareil (WEB-SRM device id) -> DECOY. Hyphen-grouped uppercase alnum block."""
    g = lambda n: "".join(random.choice("0123456789ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(n))
    return f"{g(4)}-{g(4)}-{g(4)}"


def _resto_name() -> str:
    return f"{random.choice(_RESTO_PREFIX)} {random.choice(_RESTO_NAME)}"


def _masked_pan() -> str:
    """The usual masked card tail on a payment line -> a DECOY (NOT payment_card)."""
    brand = random.choice(["VISA", "MC", "MASTERCARD", "AMEX", "DEBIT", "Interac"])
    last4 = "".join(random.choice("0123456789") for _ in range(4))
    style = random.random()
    if style < 0.5:
        return f"{brand} **** **** **** {last4}"
    if style < 0.8:
        return f"{brand} XXXXXXXXXXXX{last4}"
    return f"{brand} ...{last4}"


def _eq_run() -> str:
    """A 'suite de signes d'egalite' -> DECOY filler that anchors the mandated block."""
    return "=" * random.randint(16, 40)


def _qr_url() -> str:
    """The WEB-SRM 'Consulter la transaction en ligne' link -> DECOY (transaction metadata, not PII)."""
    tok = "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(22))
    return "https://transaction.mev.revenuquebec.ca/t/" + tok


def _resto_phone() -> str:
    """The RESTAURANT's own phone in the header -> DECOY (org contact, not the subject)."""
    return V.phone()


def _tps_reg() -> str:
    """GST/TPS registration number: a 9-digit BN + RTxxxx program account (V.tax_id GST shape)."""
    n9 = "".join(random.choice("0123456789") for _ in range(9))
    return f"{n9} RT {random.randint(0,9999):04d}"


def _tvq_reg() -> str:
    """QST/TVQ registration number: a 10-digit + TQxxxx Quebec file number (V.tax_id QST shape)."""
    n10 = "".join(random.choice("0123456789") for _ in range(10))
    return f"{n10} TQ {random.randint(0,9999):04d}"


def _header(d: Doc, fr: bool) -> None:
    """Nom commercial + adresse de l'etablissement (org/address/phone DECOYS) + transmission moment +
    transaction number (DECOYS). This is the top of every mandatory facture."""
    d.decoy(_resto_name()); d.add("\n")                                  # org decoy (restaurant name)
    d.decoy(V.street_address("fr"))                                      # restaurant street -> DECOY
    d.add(", " + V.city() + " (QC) ")
    d.decoy(V.postal_code()); d.add("\n")                                # restaurant postal -> DECOY
    if random.random() < 0.7:
        d.add(("Tel.: " if fr else "Tel.: ")); d.decoy(_resto_phone()); d.add("\n")   # resto phone = DECOY
    d.add(("Moment de la transmission: " if fr else "Transmission time: "))
    d.decoy(V.request_datetime("fr" if fr else "en")); d.add("\n")       # transmission datetime -> DECOY
    d.add(("Numero de transaction: " if fr else "Transaction number: "))
    d.decoy(_txn_no()); d.add("\n")


def _items(d: Doc, fr: bool) -> float:
    """Item lines: description detaillee + taxes appliquees [F]/[P] + price. All DECOYS. Returns subtotal."""
    items = _ITEMS_FR if fr else _ITEMS_EN
    d.add(("\nDescription                              Taxes   Prix\n" if fr
           else "\nDescription                              Taxes   Price\n"))
    subtotal = 0.0
    for _ in range(random.randint(2, 6)):
        name, price = random.choice(items)
        qty = random.randint(1, 3)
        line = round(price * qty, 2)
        subtotal += line
        taxcode = random.choice(["[F][P]", "[F]", "[P]", "[F][P][S]"])   # federal/provincial/supplementary
        d.decoy(name); d.add("   " + taxcode + "   "); d.decoy(_money(line)); d.add("\n")
    subtotal = round(subtotal, 2)
    d.add(("Sous-total: " if fr else "Subtotal: ")); d.decoy(_money(subtotal)); d.add("\n")
    return subtotal


def _tax_registration(d: Doc, fr: bool) -> None:
    """The two MANDATORY tax registration numbers -> the only header tax_id POSITIVES.
    No d.field() value straddles the label; numbers are fielded as single strings."""
    d.add(("No d'inscription TPS: " if fr else "GST registration no.: "))
    d.field(_tps_reg(), "tax_id"); d.add("\n")
    d.add(("No d'inscription TVQ: " if fr else "QST registration no.: "))
    d.field(_tvq_reg(), "tax_id"); d.add("\n")


def _eq_total_block(d: Doc, fr: bool, subtotal: float) -> None:
    """The MANDATED '===' block: a run of '=' then, IN ORDER, Montant de la TPS, Montant de la TVQ, Montant
    total de la fourniture, then (if any) adjusted / due / installments / balance / tip. EVERY value here is
    a DECOY (transaction-level amounts, never PII)."""
    tps = round(subtotal * 0.05, 2)
    tvq = round(subtotal * 0.09975, 2)
    total = round(subtotal + tps + tvq, 2)
    d.add("\n"); d.add(_eq_run()); d.add("\n")
    d.add(("Montant de la TPS: " if fr else "GST amount: ")); d.decoy(_money(tps)); d.add("\n")
    d.add(("Montant de la TVQ: " if fr else "QST amount: ")); d.decoy(_money(tvq)); d.add("\n")
    d.add(("Montant total de la fourniture: " if fr else "Total amount of the supply: "))
    d.decoy(_money(total)); d.add("\n")
    if random.random() < 0.6:                                            # optional tip / balance lines
        tip = round(total * random.choice([0.10, 0.15, 0.18]), 2)
        d.add(("Pourboire: " if fr else "Tip: ")); d.decoy(_money(tip)); d.add("\n")
        d.add(("Solde: " if fr else "Balance: ")); d.decoy(_money(round(total + tip, 2))); d.add("\n")
    if random.random() < 0.4:
        d.add(("Montant du: " if fr else "Amount due: ")); d.decoy(_money(total)); d.add("\n")
        d.add(("Versement actuel: " if fr else "Current installment: ")); d.decoy(_money(total)); d.add("\n")


def _customer_identity(d: Doc, fr: bool, lang: str) -> None:
    """TRAIN-ONLY customer-identity strip for the dine-in layout (closing-receipt with a named account /
    house-tab customer >= 500 $). Reuses the SAME value helpers + 'Nom du client' / 'Telephone du client'
    cues the held-out takeout layout uses, so the dine-in TRAIN layout covers the person/address/postal_code/
    phone_number labels the held-out tests -- WITHOUT copying the held-out delivery skeleton (no order ref,
    no delivery wording; a plain 'Adresse:' line, not 'Adresse de livraison:'). Called ONLY by the train fn."""
    d.add(("Nom du client: " if fr else "Customer name: "))
    d.field(V.person(lang, caps=False), "person"); d.add("\n")
    # customer address: the subject's street -> address positive; city + QC province = NEGATIVE;
    # the customer postal -> postal_code positive (same value shapes as the held-out customer block).
    d.add(("Adresse: " if fr else "Address: "))
    d.field(V.street_address(lang), "address")
    d.add(", " + V.city() + " (QC) ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    # customer contact phone -> phone_number positive (contrast vs the restaurant header phone decoy).
    d.add(("Telephone du client: " if fr else "Customer phone: "))
    d.field(V.phone(), "phone_number"); d.add("\n")


def _mention(d: Doc, fr: bool) -> None:
    """Mandatory mention -> DECOY filler."""
    if fr:
        d.add(random.choice(["PAIEMENT RECU", "FACTURE ORIGINALE", "DUPLICATA", "RECU DE FERMETURE"]) + "\n")
    else:
        d.add(random.choice(["PAYMENT RECEIVED", "ORIGINAL INVOICE", "DUPLICATE", "CLOSING RECEIPT"]) + "\n")


def _websrm_echo(d: Doc, fr: bool) -> None:
    """The WEB-SRM processing echo: QR web link + Moment du traitement + Numero de transaction transmis +
    Identifiant de l'appareil, then the SECOND === run. ALL DECOYS (the device id especially -- it is the
    appareil id, NOT a subject account)."""
    d.add(("Code QR: " if fr else "QR code: ")); d.decoy(_qr_url()); d.add("\n")
    d.add(("Consulter la transaction en ligne\n" if fr else "View the transaction online\n"))
    d.add(("Moment du traitement: " if fr else "Processing time: "))
    d.decoy(V.request_datetime("fr" if fr else "en")); d.add("\n")
    d.add(("Numero de transaction transmis: " if fr else "Transmitted transaction number: "))
    d.decoy(_txn_no()); d.add("\n")
    d.add(("Identifiant de l'appareil: " if fr else "Device identifier: "))
    d.decoy(_device_id()); d.add("\n")
    d.add(_eq_run()); d.add("\n")


# ---------------- layout A: dine-in reception receipt (recu de fermeture, table service) ----------------

def _layout_dinein(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="restaurant_facture", lang=lang)

    _header(d, fr)
    if random.random() < 0.6:
        d.add(("Table " if fr else "Table ")); d.decoy(str(random.randint(1, 60)))
        d.add(("  Couverts: " if fr else "  Guests: ")); d.decoy(str(random.randint(1, 8))); d.add("\n")

    # named-account / house-tab customer-identity strip (>= 500 $ path) -> person/address/postal_code/
    # phone_number positives. ~55% of dine-in receipts: covers the labels the held-out tests WITHOUT
    # copying the held-out delivery skeleton.
    if random.random() < 0.55:
        _customer_identity(d, fr, lang)

    subtotal = _items(d, fr)
    _tax_registration(d, fr)                                             # tax_id positives

    # mode de paiement: usually a masked tail (DECOY); ~30% of the time a full PAN is printed on the slip,
    # cued by the network BRAND that matches its IIN (C.brand_label) -> payment_card POSITIVE. This teaches
    # the brand-cue presentation in the train layout WITHOUT copying the held-out customer-identity structure.
    d.add(("Mode de paiement: " if fr else "Payment method: "))
    if random.random() < 0.3:
        pan = V.payment_card(valid=True)
        d.add(C.brand_label(pan) + " ")          # BRAND matches the PAN's IIN (VISA / MASTERCARD / AMEX)
        d.field(pan, "payment_card")
    else:
        d.decoy(_masked_pan())
    d.add("\n")

    _eq_total_block(d, fr, subtotal)
    _mention(d, fr)
    _websrm_echo(d, fr)
    d.add(("Merci de votre visite!\n" if fr else "Thank you for your visit!\n"))   # post-=== free text DECOY
    return d.row()


# ---------------- layout B (HELD-OUT): takeout / delivery facture with a NAMED CUSTOMER -------------
# The 'document complementaire' >= 500 $ identity path (Preparation des factures table): a named customer
# + delivery address + a delivery phone -> the only place person/phone become POSITIVES. Structurally
# distinct from dine-in: it carries a customer-identity block + a delivery block + occasionally a full PAN.

def _layout_takeout(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="restaurant_facture", lang=lang)

    _header(d, fr)
    d.add(("Commande pour emporter / livraison\n" if fr else "Takeout / delivery order\n"))
    d.add(("No de commande: " if fr else "Order no.: ")); d.decoy(V.order_ref()); d.add("\n")

    # ---- CUSTOMER IDENTITY block: the document-complementaire 'Nom du client' -> person POSITIVE ----
    d.add(("Nom du client: " if fr else "Customer name: "))
    d.field(V.person(lang, caps=False), "person"); d.add("\n")
    # delivery address: a real customer address here. The street is the subject's -> address positive;
    # city + province QC = NEGATIVE; the delivery postal = postal_code positive.
    d.add(("Adresse de livraison: " if fr else "Delivery address: "))
    d.field(V.street_address(lang), "address")
    d.add(", " + V.city() + " (QC) ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    # delivery CONTACT phone = the CUSTOMER's phone -> phone_number positive (contrast vs resto phone decoy)
    d.add(("Telephone du client: " if fr else "Customer phone: "))
    d.field(V.phone(), "phone_number"); d.add("\n")

    subtotal = _items(d, fr)
    _tax_registration(d, fr)                                             # tax_id positives

    # mode de paiement: occasionally a FULL PAN printed on the slip -> payment_card POSITIVE; else masked DECOY
    d.add(("Mode de paiement: " if fr else "Payment method: "))
    if random.random() < 0.5:
        d.add(random.choice(["VISA ", "MC ", "MASTERCARD ", ""]))
        d.field(V.payment_card(valid=True), "payment_card")
    else:
        d.decoy(_masked_pan())
    d.add("\n")

    _eq_total_block(d, fr, subtotal)
    _mention(d, fr)

    # note de credit path: a credit-note customer name -> person positive; the remittance date = DECOY
    if random.random() < 0.45:
        d.add(("Note de credit emise a: " if fr else "Credit note issued to: "))
        d.field(V.person(lang, caps=False), "person"); d.add("\n")
        d.add(("Date de remise: " if fr else "Remittance date: ")); d.decoy(V.iso_date()); d.add("\n")

    _websrm_echo(d, fr)
    d.add(("Merci et bon appetit!\n" if fr else "Thank you and enjoy!\n"))
    return d.row()


LAYOUTS = [_layout_dinein, _layout_takeout]   # takeout (suffix) = held-out structure (customer identity)


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
