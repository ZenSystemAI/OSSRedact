#!/usr/bin/env python3
"""email_receipt generator: synthetic Quebec/Canada transactional EMAILS + retail/POS RECEIPTS (FR/EN).

Two genuinely-distinct real structures share one doctype because they are the two faces of a "confirmation"
artifact: (a) the transactional email that announces the order, and (b) the till/POS receipt that closes it.
Built from the real RFC 5322 email envelope (From:/To:/Subject:/Date:/Message-ID: headers + greeting + body)
and a standard Quebec retail point-of-sale receipt (store header + item lines + GST/HST + QST + payment
tender + masked card tail), not from a scaffold PDF.

POSITIVES per layout:
 - (a) transactional EMAIL [train]:
     email   : the From: AND To: addresses (both real, both redacted)
     person  : the recipient name in the greeting / body
     phone_number : a support / callback phone in the body
     address : a shipping / billing street address
     account_number : the customer/account number referenced (bare or institution-first run)
     username : a bare login id / @handle the email refers to
     file_path : an attachment path (e.g. /home/<user>/factures/recu.pdf)
   DECOYS (NEVER labeled): the tracking / confirmation URL, the order reference (CMD-/REF-/ORD-), every
   amount ($), the Message-ID, all dates (Date: header, ISO body dates -> no cued DOB here), and the SENDER
   company name (an org decoy in the From line and the signature).

 - (b) retail/POS RECEIPT [HELD-OUT]:
     tax_id  : the store's GST/HST (RT) and QST (TQ) registration numbers (always present)
     person  : ONLY a named member/loyalty customer line if present
     address : the cardholder/billing street if printed
     phone_number : a CUSTOMER callback phone if printed (the STORE header phone = decoy)
     payment_card : ONLY a full PAN if printed (rare); the usual masked tail ('**** **** **** 4242') = DECOY
   DECOYS (NEVER labeled): every item + price, subtotal/taxes/total ($), the masked card tail, the till /
   transaction / approval numbers, the store name + store address + store phone, the loyalty points, the
   barcode, and all transaction dates/times.

The two layouts are structurally distinct: (a) is a prose email with RFC 5322 headers and a greeting; (b) is
a tabular till receipt with a store header, an item table, a tax block and a tender block. The held-out (POS
receipt) is the suffix of LAYOUTS, so the model is evaluated on a structure it never trained on.

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402
import cue_helpers as C         # noqa: E402

# ---- inline synthetic sender / store brand names (generic, NOT real businesses; org decoys) ----
_BRAND_WORD = ["Boreale", "Cascade", "Nordik", "Horizon", "Saphir", "Polaris", "Vertex", "Sommet",
               "Riviere", "Aurore", "Quartz", "Meridien", "Granit", "Cedre", "Pinacle", "Zephyr"]
_BRAND_SUFFIX = ["Boutique", "Marche", "Quincaillerie", "Pharmacie", "Librairie", "Mode", "Electronique",
                 "Sports", "Maison", "Cafe", "Epicerie", "Detail"]
_MAIL_SUBSYS = ["mg", "smtp", "mail", "relay", "mx1", "edm", "notify"]

# ---- retail item pools (description + unit price). Always decoys. ----
_ITEMS_FR = [
    ("Chandail coton ouate", 39.99), ("Piles AA paquet de 8", 12.49), ("Cafe moulu 908 g", 14.95),
    ("Ampoule DEL 9W", 6.99), ("Carnet de notes", 4.25), ("Cable USB-C 2 m", 19.99),
    ("Detergent a lessive", 21.50), ("Sac reutilisable", 1.99), ("Casque d'ecoute", 59.95),
    ("Bouteille isotherme", 27.99), ("Lot de stylos", 8.49), ("Tapis de souris", 11.99),
    ("Chargeur mural 20W", 24.99), ("Boite de mouchoirs", 3.79), ("Cle USB 64 Go", 17.49),
]
_ITEMS_EN = [
    ("Cotton fleece sweater", 39.99), ("AA batteries pack of 8", 12.49), ("Ground coffee 908 g", 14.95),
    ("LED bulb 9W", 6.99), ("Notebook", 4.25), ("USB-C cable 2 m", 19.99),
    ("Laundry detergent", 21.50), ("Reusable bag", 1.99), ("Headphones", 59.95),
    ("Insulated bottle", 27.99), ("Pen set", 8.49), ("Mouse pad", 11.99),
    ("20W wall charger", 24.99), ("Tissue box", 3.79), ("USB drive 64 GB", 17.49),
]


# ---------------- inline value shapes (doctype-specific; values.py is never edited) ----------------

def _brand() -> str:
    """A generic synthetic retailer / sender brand name -> ORG DECOY (sender line, store header, signature)."""
    return f"{random.choice(_BRAND_WORD)} {random.choice(_BRAND_SUFFIX)}"


def _brand_slug(name: str) -> str:
    """domain slug for the sender brand (ASCII, lowercase, no spaces)."""
    return name.lower().replace(" ", "").replace("'", "")


def _sender_email(brand: str) -> str:
    """A no-reply / transactional sender address at the brand domain -> the From: address (email positive)."""
    local = random.choice(["no-reply", "noreply", "commandes", "orders", "factures", "billing",
                           "service", "confirmation"])
    return f"{local}@{_brand_slug(brand)}.ca"


def _message_id(brand: str) -> str:
    """RFC 5322 Message-ID -> DECOY (mail-system metadata, never PII). <token@subsys.domain>."""
    tok = "".join(random.choice("0123456789abcdef") for _ in range(random.choice([16, 24, 32])))
    return f"<{tok}@{random.choice(_MAIL_SUBSYS)}.{_brand_slug(brand)}.ca>"


def _tracking_url(brand: str) -> str:
    """The confirmation / tracking link -> DECOY (transaction metadata, not PII)."""
    tok = "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(22))
    path = random.choice(["commande", "order", "suivi", "track", "recu", "receipt"])
    return f"https://{_brand_slug(brand)}.ca/{path}/{tok}"


def _money(v: float) -> str:
    """OQLF / Quebec money string. ALWAYS contains '$' -> a DECOY by construction. Round to cents FIRST so
    the cents field is exactly 2 digits (no .995 -> ',100 $' carry artifact)."""
    cents = int(round(v * 100))
    dollars, c = divmod(cents, 100)
    if random.random() < 0.5:
        return f"{dollars:,}".replace(",", " ") + f",{c:02d} $"   # 1 234,56 $ (OQLF)
    return f"{dollars:,}.{c:02d} $"                               # 1,234.56 $


def _order_ref() -> str:
    """An order reference (CMD-/REF-/ORD-) -> DECOY. Distinct from account_number: it carries a prefix."""
    return random.choice(["CMD-", "REF-", "ORD-", "CMD-W", "WEB-"]) + str(random.randint(100000, 99999999))


def _till_no() -> str:
    """A POS till / transaction / approval number -> DECOY. Short numeric run, not a subject account."""
    style = random.random()
    if style < 0.4:
        return "".join(random.choice("0123456789") for _ in range(random.choice([4, 5])))
    if style < 0.7:
        return "#" + "".join(random.choice("0123456789") for _ in range(6))
    return "".join(random.choice("0123456789") for _ in range(3)) + "-" \
        + "".join(random.choice("0123456789") for _ in range(4))


def _barcode() -> str:
    """A receipt-footer barcode digit run (UPC/loyalty) -> DECOY. 12-13 digits, no separators."""
    return "".join(random.choice("0123456789") for _ in range(random.choice([12, 13])))


def _masked_pan() -> str:
    """The usual masked card tail on a tender line -> a DECOY (NOT payment_card)."""
    brand = random.choice(["VISA", "MC", "MASTERCARD", "AMEX", "DEBIT", "Interac", "DEBIT INTERAC"])
    last4 = "".join(random.choice("0123456789") for _ in range(4))
    style = random.random()
    if style < 0.5:
        return f"{brand} **** **** **** {last4}"
    if style < 0.8:
        return f"{brand} XXXXXXXXXXXX{last4}"
    return f"{brand} ...{last4}"


def _handle() -> str:
    """A bare login id / @handle the email refers to -> username positive (NOT an email, NOT a path)."""
    u = V.username()
    return ("@" + u) if random.random() < 0.5 else u


def _attachment_path() -> str:
    """An attachment file path -> file_path positive. The embedded username is PART of the path span."""
    user = V.username()
    if random.random() < 0.6:
        leaf = random.choice(["recu.pdf", "facture.pdf", "confirmation.pdf", "releve.pdf", "commande.pdf"])
        sub = random.choice(["factures", "recus", "documents", "telechargements"])
        return f"/home/{user}/{sub}/{leaf}"
    leaf = random.choice(["Recu.pdf", "Facture.pdf", "Confirmation.pdf"])
    return rf"C:\\Users\\{user}\\Documents\\{leaf}"


def _email_payment_line(d: Doc, fr: bool) -> None:
    """Payment-method line in the confirmation email. ~35% of the time the merchant echoes the FULL PAN
    (a brand-cued payment_card POSITIVE); the brand prefix is the network that MATCHES the PAN's IIN via
    C.brand_label(pan). Otherwise the email shows the usual masked card tail -> DECOY. Teaches the model to
    catch a payment_card cued by its network brand, not only by a formal label."""
    d.add(("Mode de paiement: " if fr else "Payment method: "))
    if random.random() < 0.35:
        pan = V.payment_card(valid=True)                                       # full PAN -> positive
        d.add(C.brand_label(pan) + " ")                                        # network brand ALWAYS matches IIN
        d.field(pan, "payment_card")
    else:
        d.decoy(_masked_pan())                                                 # masked tail -> DECOY
    d.add("\n\n")


def _merchant_gst() -> str:
    """Merchant GST/HST (RT) registration for the email footer -> tax_id positive (GST shape). Reuses the
    same V.tax_id value source the held-out receipt's tax_id uses; resample until an RT-program number so the
    'TPS/TVH:' / 'GST/HST:' cue gets a GST-shaped value (n9 + RT + 4)."""
    while True:
        t = V.tax_id()
        if "RT" in t:
            return t


def _merchant_qst() -> str:
    """Merchant QST (TQ) registration for the email footer -> tax_id positive (QST shape). Same V.tax_id
    source; resample until a TQ Quebec file number so the 'TVQ:' / 'QST:' cue gets a QST-shaped value."""
    while True:
        t = V.tax_id()
        if "TQ" in t:
            return t


def _store_tps_reg() -> str:
    """Store GST/HST registration: a 9-digit BN + RTxxxx program account -> tax_id positive (GST shape)."""
    n9 = "".join(random.choice("0123456789") for _ in range(9))
    return f"{n9} RT {random.randint(0,9999):04d}"


def _store_tvq_reg() -> str:
    """Store QST registration: a 10-digit + TQxxxx Quebec file number -> tax_id positive (QST shape)."""
    n10 = "".join(random.choice("0123456789") for _ in range(10))
    return f"{n10} TQ {random.randint(0,9999):04d}"


# ---------------- layout A: transactional EMAIL (RFC 5322 envelope + prose body) [train] ----------------

def _layout_email(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="email_receipt", lang=lang)
    brand = _brand()

    # ---- RFC 5322 headers. From/To emails -> positives; sender brand, Date, Message-ID -> decoys. ----
    d.add("From: ")
    d.decoy(brand); d.add(" <")                                  # sender brand name in From -> ORG DECOY
    d.field(_sender_email(brand), "email"); d.add(">\n")         # From: address -> email positive
    d.add("To: ")
    recipient = V.person(lang, caps=False)
    d.decoy(recipient); d.add(" <")                              # display name repeats in greeting (decoy here)
    d.field(V.email(), "email"); d.add(">\n")                    # To: address -> email positive
    d.add(("Subject: " if not fr else "Objet: ")
          + (random.choice(["Confirmation de votre commande ", "Votre recu ", "Commande expediee "])
             if fr else random.choice(["Order confirmation ", "Your receipt ", "Order shipped "])))
    d.decoy(_order_ref()); d.add("\n")                           # order ref in subject -> DECOY
    d.add("Date: "); d.decoy(V.request_datetime(lang)); d.add("\n")            # Date header -> DECOY
    d.add("Message-ID: "); d.decoy(_message_id(brand)); d.add("\n\n")          # Message-ID -> DECOY

    # ---- greeting (recipient person -> positive) ----
    d.add(("Bonjour " if fr else "Hello "))
    d.field(recipient, "person"); d.add(",\n\n")

    d.add(("Merci pour votre commande. Voici les details de votre confirmation.\n\n" if fr
           else "Thank you for your order. Here are your confirmation details.\n\n"))

    # ---- body: order ref (decoy) + account number (positive) + amounts (decoys) ----
    d.add(("Numero de commande: " if fr else "Order number: "))
    d.decoy(_order_ref()); d.add("\n")                                         # order ref -> DECOY
    d.add(("Numero de compte client: " if fr else "Customer account number: "))
    acct_form = random.choice(["hyphen", "bare", "bare10", "bare11"])
    d.field(V.bank_account(form=acct_form), "account_number"); d.add("\n")     # account -> positive
    d.add(("Total facture: " if fr else "Total charged: "))
    d.decoy(_money(random.uniform(12, 980))); d.add("\n\n")                    # amount -> DECOY

    # ---- payment method: brand-cued full PAN (~35%) -> positive; masked tail otherwise -> DECOY ----
    _email_payment_line(d, fr)

    # ---- shipping / billing address -> positive ----
    d.add(("Adresse de livraison:\n" if fr else "Shipping address:\n"))
    d.field(V.street_address(lang), "address")
    d.add(", " + V.city() + " (QC) ")                                          # city + QC -> NEGATIVE
    d.decoy(V.postal_code()); d.add("\n\n")                                    # shipping postal -> DECOY here

    # ---- account / login the email refers to -> username positive ----
    d.add(("Connectez-vous avec votre identifiant " if fr else "Sign in with your username "))
    d.field(_handle(), "username")
    d.add((" pour suivre votre commande.\n" if fr else " to track your order.\n"))

    # ---- tracking link -> DECOY ----
    d.add(("Suivez votre colis ici: " if fr else "Track your package here: "))
    d.decoy(_tracking_url(brand)); d.add("\n\n")

    # ---- attachment path -> file_path positive (embedded username is part of the span) ----
    d.add(("Piece jointe: " if fr else "Attachment: "))
    d.field(_attachment_path(), "file_path"); d.add("\n\n")

    # ---- support contact: a phone -> positive; the sender brand recurs as an ORG DECOY ----
    d.add(("Pour toute question, appelez notre service a la clientele au " if fr
           else "For any questions, call our customer service at "))
    d.field(V.phone(), "phone_number"); d.add(".\n\n")

    # signature: sender brand again -> ORG DECOY; a second order/ship ISO date -> DECOY
    d.add(("Cordialement,\nL'equipe " if fr else "Best regards,\nThe team at "))
    d.decoy(brand); d.add("\n")
    d.add(("Date d'expedition prevue: " if fr else "Estimated ship date: "))
    d.decoy(V.iso_date()); d.add("\n")

    # ---- merchant footer block: the sender's own street/postal + GST/QST registrations. This is the
    # commercial-confirmation footer many Quebec retailers print; it gives the TRAIN layout in-doctype
    # signal for postal_code (merchant address) and tax_id (merchant GST/QST), reusing the same value
    # sources the held-out receipt uses for those labels. ----
    d.add("\n"); d.decoy(brand); d.add(", ")                                   # brand recurs -> ORG DECOY
    d.decoy(V.street_address(lang))                                            # merchant street -> DECOY
    d.add(", " + V.city() + " (QC) ")                                          # city + QC -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")                       # merchant postal -> positive
    d.add(("TPS/TVH: " if fr else "GST/HST: ")); d.field(_merchant_gst(), "tax_id"); d.add("   ")
    d.add(("TVQ: " if fr else "QST: ")); d.field(_merchant_qst(), "tax_id"); d.add("\n")
    return d.row()


# ---------------- layout B (HELD-OUT): retail / POS RECEIPT (tabular till receipt) ----------------
# Structurally distinct from the email: a store header, an item TABLE, a tax block and a tender block. The
# only positives are the store's tax_id registrations (always) plus the optional member-identity path
# (named member + billing address + callback phone + a rare full PAN).

def _store_header(d: Doc, fr: bool) -> str:
    """Store name + store address + store phone (all DECOYS) + the till/transaction line (DECOY)."""
    brand = _brand()
    d.decoy(brand); d.add("\n")                                              # store name -> ORG DECOY
    d.decoy(V.street_address("fr"))                                          # store street -> DECOY
    d.add(", " + V.city() + " (QC) ")
    d.decoy(V.postal_code()); d.add("\n")                                    # store postal -> DECOY
    d.add(("Tel.: " if fr else "Tel.: ")); d.decoy(V.phone()); d.add("\n")   # store phone -> DECOY
    d.add(("Caisse " if fr else "Till ")); d.decoy(_till_no())
    d.add(("  Transaction " if fr else "  Transaction ")); d.decoy(_till_no()); d.add("\n")
    d.add(("Date: " if fr else "Date: ")); d.decoy(V.request_datetime(lang="fr" if fr else "en")); d.add("\n")
    return brand


def _item_table(d: Doc, fr: bool) -> float:
    """Item lines: description + price. ALL DECOYS. Returns subtotal."""
    items = _ITEMS_FR if fr else _ITEMS_EN
    d.add(("\nArticle                                 Prix\n" if fr
           else "\nItem                                    Price\n"))
    subtotal = 0.0
    for _ in range(random.randint(2, 7)):
        name, price = random.choice(items)
        qty = random.randint(1, 3)
        line = round(price * qty, 2)
        subtotal += line
        if qty > 1:
            d.decoy(f"{qty} x {name}")
        else:
            d.decoy(name)
        d.add("   "); d.decoy(_money(line)); d.add("\n")
    return round(subtotal, 2)


def _tax_block(d: Doc, fr: bool, subtotal: float) -> None:
    """Subtotal / GST / QST / total -> all DECOYS (amounts), then the store's tax registrations -> tax_id
    POSITIVES (always present, the defining positive of the receipt)."""
    tps = round(subtotal * 0.05, 2)
    tvq = round(subtotal * 0.09975, 2)
    total = round(subtotal + tps + tvq, 2)
    d.add(("Sous-total: " if fr else "Subtotal: ")); d.decoy(_money(subtotal)); d.add("\n")
    d.add(("TPS (5%): " if fr else "GST (5%): ")); d.decoy(_money(tps)); d.add("\n")
    d.add(("TVQ (9,975%): " if fr else "QST (9.975%): ")); d.decoy(_money(tvq)); d.add("\n")
    d.add(("TOTAL: " if fr else "TOTAL: ")); d.decoy(_money(total)); d.add("\n")
    # the store's registration numbers -> the always-present tax_id positives
    d.add(("No TPS: " if fr else "GST no.: ")); d.field(_store_tps_reg(), "tax_id"); d.add("  ")
    d.add(("No TVQ: " if fr else "QST no.: ")); d.field(_store_tvq_reg(), "tax_id"); d.add("\n")


def _tender_block(d: Doc, fr: bool) -> None:
    """Payment tender: the masked card tail is the common case -> DECOY; a rare full PAN -> payment_card
    positive. The approval number -> DECOY."""
    d.add(("Paiement: " if fr else "Payment: "))
    if random.random() < 0.5:
        d.add(random.choice(["VISA ", "MC ", "MASTERCARD ", ""]))
        d.field(V.payment_card(valid=True), "payment_card")                  # rare full PAN -> positive
    else:
        d.decoy(_masked_pan())                                               # usual masked tail -> DECOY
    d.add("\n")
    d.add(("No d'approbation: " if fr else "Approval no.: ")); d.decoy(_till_no()); d.add("\n")


def _layout_receipt(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="email_receipt", lang=lang)

    _store_header(d, fr)
    subtotal = _item_table(d, fr)
    _tax_block(d, fr, subtotal)
    _tender_block(d, fr)

    # ---- optional MEMBER / LOYALTY identity path: the only place person/address/phone become positives ----
    if random.random() < 0.7:
        d.add(("\nMembre: " if fr else "\nMember: "))
        d.field(V.person(lang, caps=False), "person"); d.add("\n")           # named member -> person positive
        if random.random() < 0.6:
            d.add(("Adresse de facturation: " if fr else "Billing address: "))
            d.field(V.street_address(lang), "address")
            d.add(", " + V.city() + " (QC) ")                                # city + QC -> NEGATIVE
            d.field(V.postal_code(), "postal_code"); d.add("\n")             # billing postal -> positive
        if random.random() < 0.6:
            d.add(("Telephone du membre: " if fr else "Member phone: "))
            d.field(V.phone(), "phone_number"); d.add("\n")                  # member callback phone -> positive
        d.add(("Points fidelite: " if fr else "Loyalty points: "))
        d.decoy(str(random.randint(0, 9999))); d.add("\n")                   # loyalty points -> DECOY

    # ---- footer: barcode + thank-you (DECOYS) ----
    d.add(("\nCode-barres: " if fr else "\nBarcode: ")); d.decoy(_barcode()); d.add("\n")
    d.add(("Merci de votre achat!\n" if fr else "Thank you for your purchase!\n"))
    return d.row()


LAYOUTS = [_layout_email, _layout_receipt]   # receipt (suffix) = held-out structure (POS till receipt)


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
