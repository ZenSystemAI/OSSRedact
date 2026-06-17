#!/usr/bin/env python3
"""kyc / loan_app generator: synthetic Quebec/Canada KYC forms + loan applications (FR/EN).

This is the CATASTROPHIC-ID carrier doctype: the IDs that bank statements never expose. The form/application
collects, in clearly cued fields, the full identity stack -> the model must learn to redact ALL of it:
 - government_id: a MIX of SIN (V.sin valid=True, Luhn-pass, QC first digit 2/3), RAMQ NAM (V.ramq_nam,
   +50-female month), and SAAQ permis (V.saaq_permis). Cues: FR NAS / numero d'assurance sociale,
   numero d'assurance maladie / RAMQ, permis de conduire / SAAQ; EN SIN / health card / driver licence.
 - payment_card (V.payment_card valid=True, Luhn-pass) with its adjacent card_cvv (V.cvv) and
   card_expiry (V.card_expiry), each lifted only by an explicit CVV / expiry cue (research section 7 rules 6).
 - tax_id (V.tax_id, GST/QST/NEQ) under a numero d'entreprise / business-number cue.
 - person, date_of_birth (cued, NOT an ISO transaction date), address, postal_code, phone_number, email.

DECOYS (research section 8 kyc checklist; emitted via .decoy(), NEVER labeled -> the false-positive fix):
 - V.sin(valid=False)            : Luhn-INVALID 9-digit SIN look-alike (collision rule 2)
 - V.payment_card(valid=False)   : Luhn-INVALID PAN look-alike
 - V.order_ref()                 : CMD-/REF-/ORD- application reference
 - V.build_hash()                : 64-char hex (form/template build hash; secret-vs-hash collision rule 7)
 - a lone 3-digit institution number + a lone 5-digit transit (NEGATIVE standalone, only the full run is account)
 - V.amount()                    : requested loan amount / income figures
 - non-DOB V.iso_date()          : application date / signature date (ISO -> NEGATIVE, only cued birth date is DOB)

gen(lang) -> one offset-true row dict. Caller seeds `random`. ~65% FR / 35% EN.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import cue_helpers as C         # noqa: E402

_LENDERS = ["Pret Express", "Credit Rapide", "Financiere Boreale", "Cap Financement",
            "Solutions de Pret Nordique", "Prets Horizon", "Groupe Financier Cartier"]


# ---------------------------------------------------------------------------
# v11 round-2 (recall-first) TRAIN-ONLY cue diversification.
#
# kyc is split-agnostic (gen() ignores `split`; train and heldout run the SAME body), so the held-out render
# MUST stay byte-identical to the pre-edit baseline. We add new cue VOCABULARY ONLY on the train path, gated
# by `split == "train" and random.random() < P`: Python short-circuits `and`, so on any non-train split the
# random.random() call is NEVER evaluated -- zero extra draws, identical RNG stream, identical heldout bytes.
# The new presentations are ALTERNATIVES (~30%) to the existing formal-labeled forms; all decoys + collision
# rules are preserved. Held-out structures (the scaffold-grounded doctypes) are untouched.
# ---------------------------------------------------------------------------


def _emit_card_line(d: Doc, fr: bool, split: str):
    """FULL-PAN payment_card line. TRAIN ~30%: a BRAND-CUED form -- print the network brand matched to the
    PAN's IIN (C.brand_label) then the full PAN, e.g. 'Paiement par VISA <pan>' / 'Paid by MASTERCARD <pan>'.
    Otherwise (and ALWAYS on heldout): the existing 'No de carte:' / 'Card no:' formal label. Either way the
    full PAN is the payment_card positive (a masked tail elsewhere stays a decoy). On a non-train split the
    `and` short-circuits before random.random(), so the RNG stream matches the pre-edit baseline exactly."""
    if split == "train" and random.random() < 0.30:
        pan = V.payment_card(valid=True)                       # full PAN -> payment_card POSITIVE
        brand = C.brand_label(pan)                             # network brand MATCHES the PAN's IIN
        if fr:
            lead = random.choice([
                f"Paiement par {brand} ",
                f"Regle par {brand} ",
                f"Porte sur la carte {brand} ",
                f"Carte {brand}: ",
            ])
        else:
            lead = random.choice([
                f"Paid by {brand} ",
                f"Charged to {brand} ",
                f"Posted to {brand} card ",
                f"{brand} card: ",
            ])
        d.add(lead); d.field(pan, "payment_card"); d.add("\n")
    else:
        d.add("No de carte: " if fr else "Card no: ")
        d.field(V.payment_card(valid=True), "payment_card"); d.add("\n")


def _dob_value():
    """A cued birth date (NOT a bare ISO transaction date). Mirrors the flinks DOB styles."""
    d = random.randint(1, 28); m = random.randint(1, 12); y = random.randint(1955, 2003)
    style = random.random()
    if style < 0.4:
        return f"{d:02d}/{m:02d}/{y}"
    if style < 0.7:
        return f"{y}-{m:02d}-{d:02d}"
    months = ["janvier", "fevrier", "mars", "avril", "mai", "juin", "juillet", "aout",
              "septembre", "octobre", "novembre", "decembre"]
    return f"{d} {months[m-1]} {y}"


def _gov_id_block(d: Doc, fr: bool, split: str):
    """Emit the catastrophic-ID block: always SIN + RAMQ NAM + SAAQ permis, each cued, all government_id.

    SIN / NAS presentation. TRAIN ~30%: an INLINE-PROSE cue -- the NAS/SIN named inside a running sentence
    rather than as a labeled 'NAS:' field (the held-out terse/prose layouts cue it this way and the formal
    train layouts never do). Otherwise (and ALWAYS on heldout): the existing 'NAS:' / 'SIN:' labeled field.
    Both forms field the Luhn-valid V.sin -> government_id POSITIVE. On a non-train split the `and` short-
    circuits before random.random(), so V.sin(valid=True) is still the first draw -> heldout bytes unchanged."""
    # SIN / NAS (Luhn-valid positive); paired with a Luhn-invalid decoy look-alike some of the time
    if split == "train" and random.random() < 0.30:
        sin_val = V.sin(valid=True)
        if fr:
            lead, tail = random.choice([
                ("Le demandeur confirme que son numero d'assurance sociale est le ", "."),
                ("Aux fins de verification, le NAS fourni au dossier est ", " ."),
                ("Je certifie que mon numero d'assurance sociale (", ") est exact."),
            ])
        else:
            lead, tail = random.choice([
                ("The applicant confirms that their social insurance number is ", "."),
                ("For verification purposes, the SIN provided on file is ", " ."),
                ("I certify that my social insurance number (", ") is accurate."),
            ])
        d.add(lead); d.field(sin_val, "government_id"); d.add(tail + "\n")
    else:
        d.add("NAS: " if fr else "SIN: ")
        d.field(V.sin(valid=True), "government_id"); d.add("\n")
    if random.random() < 0.4:
        d.add("NAS du conjoint (a verifier): " if fr else "Co-applicant SIN (to verify): ")
        d.decoy(V.sin(valid=False)); d.add("\n")          # invalid -> hard negative, NEVER labeled

    # RAMQ NAM (carte soleil)
    d.add("Numero d'assurance maladie (RAMQ): " if fr else "Health card number (RAMQ): ")
    d.field(V.ramq_nam(), "government_id"); d.add("\n")

    # SAAQ permis de conduire
    d.add("Permis de conduire (SAAQ): " if fr else "Driver licence (SAAQ): ")
    d.field(V.saaq_permis(), "government_id"); d.add("\n")


def gen(lang: str = None, split: str = "train") -> dict:
    # `split` is accepted for the uniform corpus API. kyc varies by field composition (not by a held-out
    # real-document structure), and it is the sole carrier of several catastrophic IDs, so it contributes to
    # BOTH splits; the held-out distinctness comes from the scaffold-grounded doctypes.
    lang = lang or ("fr" if random.random() < 0.65 else "en")
    fr = lang == "fr"
    d = Doc(doctype="kyc", lang=lang)

    d.add(random.choice(_LENDERS) + "\n")
    d.add(("Demande de pret / Formulaire KYC\n" if fr else "Loan application / KYC form\n"))
    d.add(("Numero de dossier: " if fr else "File reference: "))
    d.decoy(V.order_ref()); d.add("\n")
    d.add(("Date de la demande: " if fr else "Application date: "))
    d.decoy(V.iso_date()); d.add("\n")                    # application date is ISO -> NEGATIVE

    # ---- applicant identity ----
    d.add(("\n-- Identite du demandeur --\n" if fr else "\n-- Applicant identity --\n"))
    d.add("Nom complet: " if fr else "Full name: ")
    d.field(V.person(lang), "person"); d.add("\n")

    d.add("Date de naissance: " if fr else "Date of birth: ")
    d.field(_dob_value(), "date_of_birth"); d.add("\n")

    d.add("Adresse: " if fr else "Address: ")
    d.field(V.street_address(lang), "address")
    d.add(", " + V.city() + (" QC " if random.random() < 0.8 else " Quebec "))   # city + prov = NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    d.add("Telephone: " if fr else "Phone: ")
    d.field(V.phone(), "phone_number"); d.add("\n")
    d.add("Courriel: " if fr else "Email: ")
    d.field(V.email(), "email"); d.add("\n")

    # ---- catastrophic government IDs ----
    d.add(("\n-- Pieces d'identite --\n" if fr else "\n-- Identification --\n"))
    _gov_id_block(d, fr, split)

    # ---- tax id (self-employed / business applicant) ----
    d.add("Numero d'entreprise: " if fr else "Business number: ")
    d.field(V.tax_id(), "tax_id"); d.add("\n")

    # ---- payment / pre-authorized debit details ----
    d.add(("\n-- Mode de paiement --\n" if fr else "\n-- Payment method --\n"))
    _emit_card_line(d, fr, split)                         # formal 'No de carte:' OR (train ~30%) brand-cued PAN
    # CVV cue lifts the 3-digit to card_cvv (collision rule 6)
    d.add("CVV: " if fr else "CVV: ")
    d.field(V.cvv(), "card_cvv"); d.add("   ")
    d.add("Date d'expiration: " if fr else "Expiry date: ")
    d.field(V.card_expiry(), "card_expiry"); d.add("\n")

    if random.random() < 0.45:                            # a discarded/invalid card on file -> hard negative
        d.add("Carte refusee (au dossier): " if fr else "Declined card (on file): ")
        d.decoy(V.payment_card(valid=False)); d.add("\n")

    if random.random() < 0.30:                            # occasional international funding source -> IBAN
        d.add("Compte international (IBAN): " if fr else "International account (IBAN): ")
        d.field(V.iban(), "iban"); d.add("\n")

    # ---- loan terms: all decoys (lone bank fragments + amounts) ----
    d.add(("\n-- Conditions du pret --\n" if fr else "\n-- Loan terms --\n"))
    d.add("Institution (3 chiffres): " if fr else "Institution (3-digit): ")
    d.decoy(f"{random.randint(0, 999):03d}"); d.add("   ")          # lone 3-digit institution -> NEGATIVE
    d.add("Transit (5 chiffres): " if fr else "Transit (5-digit): ")
    d.decoy(f"{random.randint(0, 99999):05d}"); d.add("\n")          # lone 5-digit transit -> NEGATIVE
    d.add("Montant demande: " if fr else "Amount requested: ")
    d.decoy(V.amount()); d.add("\n")
    d.add("Revenu annuel declare: " if fr else "Declared annual income: ")
    d.decoy(V.amount()); d.add("\n")

    # ---- footer decoys ----
    d.add(("\nGabarit du formulaire (hash): " if fr else "\nForm template (hash): "))
    d.decoy(V.build_hash()); d.add("\n")
    d.add(("Signe le " if fr else "Signed on "))
    d.decoy(V.iso_date())                                  # signature date is ISO -> NEGATIVE
    d.add(f"   -- page {random.randint(1,3)} de {random.randint(3,5)} --\n")
    return d.row()


if __name__ == "__main__":
    random.seed(0)
    for _ in range(2):
        r = gen()
        t = r["input"]
        print("=" * 70, r["meta"]["lang"], r["meta"]["doctype"])
        print(t[:500])
        print("POSITIVES:", [(lab, t[s:e]) for s, e, lab in r["output"]["spans"]])
        print()
