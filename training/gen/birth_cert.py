#!/usr/bin/env python3
"""birth_cert generator: synthetic Quebec birth-certificate paperwork (Directeur de l'etat civil), FR/EN.

RE-GROUNDED (v11) on the REAL DCCA-Naissance form structure (scaffold DCCA-Naissance.pdf,
"Demande de certificat ou de copie d'acte de NAISSANCE", form code FO-11-13, version 2026-2027):
 Section 1 -- Renseignements sur la personne qui fait la demande (the REQUESTER): nom/prenom, adresse de
   domicile + appartement + ville + province + code postal + pays, indicatif + telephone, courriel.
 Section 2 -- Renseignements sur la personne concernee par la demande (the SUBJECT child): nom/prenom,
   autres prenoms, mention du sexe (Masculin/Feminin/Non binaire X), date de naissance (Annee/Mois/Jour),
   lieu de naissance (ville), lieu de l'inscription.
 Parents block -- nom de famille et prenom usuel du parent + de l'autre parent (FATHER + MOTHER) + lien.
 Section 3 -- documents demandes + tarification (55,00 $ / 64,25 $ / 82,25 $) + total case 27.
 Section 5 -- modes de paiement: carte de credit (numero + date d'expiration Mois/Annee).

RICH RELATIONAL PII -- up to 4 person spans: the REQUESTER (Section 1), the SUBJECT child (Section 2),
the FATHER and the MOTHER (Parents block). Plus the subject's date_of_birth (cued "Date de naissance"),
the requester's address / postal_code / phone_number / email, an application-fee payment_card with its
adjacent card_cvv (CVV cue) and card_expiry, and a registration/document number -> sensitive_account_id.

DECOYS (emitted via .decoy(), NEVER labeled -> the false-positive fix):
 - lieu de naissance / lieu de l'inscription CITY (V.city())                 -> NEGATIVE (place, not address)
 - mention du sexe (Masculin/Feminin/Non binaire X)                          -> NEGATIVE
 - the fee amounts + total (V.amount(), 55,00 $, etc.)                       -> NEGATIVE
 - the form code FO-11-13 + version stamp                                    -> NEGATIVE
 - every NON-DOB date: request/signature date (V.iso_date())                 -> NEGATIVE (only cued DOB is DOB)
 - province QC / street-type word alone                                      -> NEGATIVE (per date/postal rule)
 - V.payment_card(valid=False) declined card on file (collision rule 2)      -> NEGATIVE

LAYOUTS (>=2 GENUINELY-distinct real structures; held-out = the suffix):
 - _layout_application : the DCCA-Naissance demande form (requester + subject + parents + payment). [train]
 - _layout_extract     : the ISSUED certificate / acte de naissance content-list extract -- a different
                         real structure (registry extract, no requester/payment, no parents-as-lien block;
                         the subject + parents are presented as registered FACTS with a registration number
                         heading the document).                                                   [heldout]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`. ~65% FR / 35% EN.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402

# Form-version stamps + code from the real header -> always DECOYS (document metadata, not PII).
_FORM_CODES = ["FO-11-13", "FO-11-13", "FO-11-14", "FO-11-21"]
_VERSIONS = ["2026-2027", "2025-2026", "2027-2028"]
_COUNTRIES_FR = ["Canada", "Canada", "Canada", "France", "Haiti", "Maroc"]
_COUNTRIES_EN = ["Canada", "Canada", "Canada", "France", "Haiti", "Morocco"]
_FEE_FR = ["55,00 $", "64,25 $", "82,25 $"]
_FEE_EN = ["$55.00", "$64.25", "$82.25"]


def _sex(fr: bool) -> str:
    """Mention du sexe checkbox value -> always a DECOY (sex marker is a hard negative, not redacted PII)."""
    if fr:
        return random.choice(["Masculin", "Feminin", "Non binaire (X)"])
    return random.choice(["Male", "Female", "Non-binary (X)"])


def _form_code() -> str:
    return random.choice(_FORM_CODES) + " " + "".join(random.choice("0123456789") for _ in range(8))


def _given_names() -> str:
    """'Autres prenoms' -- a comma-separated list of extra given names (per the real field 14)."""
    pool = ["Marie", "Joseph", "Anne", "Louis", "Rose", "Paul", "Claire", "Charles", "Jeanne", "Olivier"]
    n = random.randint(1, 3)
    return ", ".join(random.sample(pool, n))


def _reg_number() -> str:
    """Registration / document number on the issued acte -> sensitive_account_id (opaque alphanumeric ref).
    Real Quebec acte references are an opaque code, not a bare numeric run (so it is NOT account_number)."""
    style = random.random()
    if style < 0.45:                                  # opaque dash-grouped alphanumeric (e.g. 2019-A-0837461)
        yr = random.randint(1950, 2024)
        ltr = random.choice("ABCDEFGHJKLMNPRSTVWXYZ")
        return f"{yr}-{ltr}-{random.randint(1000000, 9999999)}"
    if style < 0.75:                                  # NAISS / ACTE prefixed opaque ref
        pre = random.choice(["NAISS", "ACTE", "REG"])
        return f"{pre}-{random.choice('QC')}{random.choice('QC')}-" + \
               "".join(random.choice("0123456789ABCDEFGHJKLMNP") for _ in range(9))
    return V.uuid4()                                  # UUID-shaped registry record id


# ----------------- shared identity sub-blocks -----------------

def _phone_block(d: Doc, fr: bool) -> None:
    """Field 8/9: indicatif regional + telephone. The phone() value already carries the NPA, so the whole
    number is one phone_number span; we do NOT split the area code into a separate fragment."""
    d.add("8. Ind. reg. / Telephone (domicile): " if fr else "8. Area code / Phone (home): ")
    d.field(V.phone(), "phone_number"); d.add("\n")


# ----------------- layout A: the DCCA-Naissance application form (TRAIN) -----------------

def _layout_application(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="birth_cert", lang=lang)
    country = random.choice(_COUNTRIES_FR if fr else _COUNTRIES_EN)

    # ---- header: title + version stamp + form code (all DECOYS) ----
    d.add("Directeur de l'etat civil\n" if fr else "Directeur de l'etat civil (Quebec)\n")
    d.add("NAISSANCE -- Demande de certificat ou de copie d'acte\n" if fr
          else "BIRTH -- Application for a certificate or a copy of an act\n")
    d.add("Version "); d.decoy(random.choice(_VERSIONS)); d.add("   No ")
    d.decoy(_form_code()); d.add("\n")

    # ---- Section 1: the REQUESTER ----
    d.add(("\nSection 1 : Renseignements sur la personne qui fait la demande\n" if fr
           else "\nSection 1: Information about the person making the application\n"))
    d.add("1. Nom de famille et prenom usuel: " if fr else "1. Last name and usual first name: ")
    d.field(V.person(lang), "person"); d.add("\n")
    d.add("3. Adresse de domicile (numero, rue): " if fr else "3. Home address (number, street): ")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add("4. Ville: " if fr else "4. City: ")
    d.decoy(V.city())                                              # city alone -> NEGATIVE
    d.add("   5. Province: "); d.decoy("QC")                        # province QC alone -> NEGATIVE
    d.add("   7. Pays: " if fr else "   7. Country: "); d.decoy(country)   # country -> NEGATIVE
    d.add("\n6. Code postal: " if fr else "\n6. Postal code: ")
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    _phone_block(d, fr)
    d.add("Courriel: " if fr else "Email: ")
    d.field(V.email(), "email"); d.add("\n")

    # ---- Section 2: the SUBJECT child ----
    d.add(("\nSection 2 : Renseignements sur la personne concernee par la demande\n" if fr
           else "\nSection 2: Information about the person concerned by the application\n"))
    d.add("12. Nom de famille et prenom usuel: " if fr else "12. Last name and usual first name: ")
    d.field(V.person(lang), "person"); d.add("\n")
    d.add("14. Autres prenoms: " if fr else "14. Other given names: ")
    d.decoy(_given_names())                                        # other given names list -> NEGATIVE
    d.add("\n15. Mention du sexe: " if fr else "\n15. Sex marker: ")
    d.decoy(_sex(fr)); d.add("\n")                                  # sex marker -> NEGATIVE
    d.add("16. Date de naissance: " if fr else "16. Date of birth: ")
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")             # the ONLY DOB-cued date
    d.add("17. Lieu de naissance: " if fr else "17. Place of birth: ")
    d.decoy(V.city())                                              # place of birth city -> NEGATIVE
    d.add(", " + country + "\n")
    d.add("18. Lieu de l'inscription: " if fr else "18. Place of registration: ")
    d.decoy(V.city()); d.add("\n")                                  # registration place city -> NEGATIVE
    # Existing acte being ordered carries its own registration / document number -> sensitive_account_id
    # (opaque alphanumeric ref via _reg_number(), the SAME helper + cues the issued-extract layout uses).
    if random.random() < 0.90:
        d.add("No d'inscription au registre: " if fr else "Registration number: ")
        d.field(_reg_number(), "sensitive_account_id"); d.add("\n")
        d.add("No du document delivre: " if fr else "Issued document number: ")
        d.field(_reg_number(), "sensitive_account_id"); d.add("\n")

    # ---- Parents block: FATHER + MOTHER (2 more person spans) ----
    d.add(("\n19. Nom de famille et prenom usuel du parent: " if fr
           else "\n19. Last name and usual first name of parent: "))
    d.field(V.person(lang), "person")
    d.add("   20. Lien de parente: " if fr else "   20. Relationship: ")
    d.decoy("Pere" if fr else "Father"); d.add("\n")               # relationship marker -> NEGATIVE
    d.add("21. Nom de famille et prenom usuel de l'autre parent: " if fr
          else "21. Last name and usual first name of the other parent: ")
    d.field(V.person(lang), "person")
    d.add("   22. Lien de parente: " if fr else "   22. Relationship: ")
    d.decoy("Mere" if fr else "Mother"); d.add("\n")               # relationship marker -> NEGATIVE

    # ---- Section 3: documents + tarification (all DECOYS) ----
    d.add(("\nSection 3 : Documents demandes -- Tarification en vigueur jusqu'au 31 mars 2027\n" if fr
           else "\nSection 3: Documents requested -- pricing in effect until March 31, 2027\n"))
    d.add("23. Certificat: " if fr else "23. Certificate: ")
    d.decoy(random.choice(_FEE_FR if fr else _FEE_EN))
    d.add("   24. Copie d'acte: " if fr else "   24. Copy of act: ")
    d.decoy(random.choice(_FEE_FR if fr else _FEE_EN))
    d.add("\n27. Total a payer: " if fr else "\n27. Total payable: ")
    d.decoy(V.amount()); d.add("\n")                                # fee amount -> NEGATIVE

    # ---- Section 4: declaration + signature date (ISO date -> DECOY) ----
    d.add(("\nSection 4 : Declaration -- 29. Date de la demande: " if fr
           else "\nSection 4: Declaration -- 29. Application date: "))
    d.decoy(V.iso_date()); d.add("\n")                              # signature/request date -> NEGATIVE

    # ---- Section 5: payment by credit card ----
    d.add(("\nSection 5 : Modes de paiement\n" if fr else "\nSection 5: Methods of payment\n"))
    d.add("31. Carte de credit -- Numero de la carte de credit: " if fr
          else "31. Credit card -- Credit card number: ")
    d.field(V.payment_card(valid=True), "payment_card"); d.add("\n")
    d.add("CVV: ")
    d.field(V.cvv(), "card_cvv")                                    # CVV cue lifts the 3-digit (rule 6)
    d.add("   Date d'expiration (Mois/Annee): " if fr else "   Expiry date (Month/Year): ")
    d.field(V.card_expiry(), "card_expiry"); d.add("\n")

    if random.random() < 0.4:                                       # declined card on file -> hard negative
        d.add("Carte refusee (au dossier): " if fr else "Declined card (on file): ")
        d.decoy(V.payment_card(valid=False)); d.add("\n")

    d.add("Ministere de l'Emploi et de la Solidarite sociale\n" if fr
          else "Ministere de l'Emploi et de la Solidarite sociale\n")
    return d.row()


# ----------------- layout B (HELD-OUT): the issued acte / certificate content-list extract -----------------

def _layout_extract(lang: str) -> dict:
    """The ISSUED document: a registry extract / certificate content list -- structurally distinct from the
    application form (no requester, no payment, no Section-numbered checkboxes, no parents-as-lien block).
    The subject + parents appear as REGISTERED FACTS, headed by a registration/document number."""
    fr = lang == "fr"
    d = Doc(doctype="birth_cert", lang=lang)
    country = random.choice(_COUNTRIES_FR if fr else _COUNTRIES_EN)

    d.add("DIRECTEUR DE L'ETAT CIVIL DU QUEBEC\n" if fr else "REGISTRAR OF CIVIL STATUS OF QUEBEC\n")
    d.add("CERTIFICAT DE NAISSANCE -- Extrait du registre de l'etat civil\n" if fr
          else "BIRTH CERTIFICATE -- Extract from the register of civil status\n")

    # registration/document number heads the issued document -> sensitive_account_id
    d.add("No d'inscription au registre: " if fr else "Registration number: ")
    d.field(_reg_number(), "sensitive_account_id"); d.add("\n")
    d.add("No du document delivre: " if fr else "Issued document number: ")
    d.field(_reg_number(), "sensitive_account_id"); d.add("\n")
    d.add("Date de delivrance: " if fr else "Date of issue: ")
    d.decoy(V.iso_date()); d.add("\n")                              # issue date -> NEGATIVE

    # the registered facts about the SUBJECT (prose-style key/value, not numbered form fields)
    d.add(("\nRenseignements inscrits au registre\n" if fr else "\nInformation entered in the register\n"))
    d.add("Nom de l'enfant: " if fr else "Name of the child: ")
    d.field(V.person(lang, caps=True), "person"); d.add("\n")       # acte names are natively ALL-CAPS
    d.add("Sexe: " if fr else "Sex: ")
    d.decoy(_sex(fr)); d.add("\n")                                  # sex marker -> NEGATIVE
    d.add("Date de naissance: " if fr else "Date of birth: ")
    d.field(V.dob(lang), "date_of_birth"); d.add("\n")             # cued DOB
    d.add("Lieu de naissance: " if fr else "Place of birth: ")
    d.decoy(V.city())                                              # place of birth city -> NEGATIVE
    d.add(" (" + ("province de Quebec, " if fr else "province of Quebec, ") + country + ")\n")

    # registered parentage -> 2 person spans (no 'lien' checkbox -- a content list, structurally different)
    d.add(("\nFiliation inscrite au registre\n" if fr else "\nParentage entered in the register\n"))
    d.add("Pere: " if fr else "Father: ")
    d.field(V.person(lang, caps=True), "person"); d.add("\n")
    d.add("Mere: " if fr else "Mother: ")
    d.field(V.person(lang, caps=True), "person"); d.add("\n")

    # contact of record on the extract (the subject-as-adult requesting their own act)
    if random.random() < 0.6:
        d.add(("\nCoordonnees au dossier\n" if fr else "\nContact information on file\n"))
        d.add("Adresse: " if fr else "Address: ")
        d.field(V.street_address(lang), "address")
        d.add(", "); d.decoy(V.city()); d.add(" "); d.decoy("QC"); d.add(" ")
        d.field(V.postal_code(), "postal_code"); d.add("\n")
        d.add("Courriel: " if fr else "Email: ")
        d.field(V.email(), "email"); d.add("\n")

    d.add(("\nCe certificat est delivre conformement au registre de l'etat civil du Quebec.\n" if fr
           else "\nThis certificate is issued in accordance with the Quebec register of civil status.\n"))
    d.add("Reference du formulaire: "); d.decoy(_form_code()); d.add("\n")   # form code -> NEGATIVE
    return d.row()


LAYOUTS = [_layout_application, _layout_extract]   # extract (suffix) = held-out structure


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
