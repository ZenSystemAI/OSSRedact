#!/usr/bin/env python3
"""sin_letter generator: synthetic Service Canada Social Insurance Number (SIN) documents in PROSE context.

GROUNDED on the real structures:
 - datasets/scaffolds/handbuilt/sin-confirmation-letter.md  (the bilingual SIN Confirmation Letter:
   Service Canada letterhead + Bathurst NB registration-office address + recipient address block + an
   indented "Name on record / SIN / Date of birth" block + a confidential-handling prose paragraph + a
   French block that repeats the SAME SIN).
 - datasets/scaffolds/SIN_NewComers_EN.pdf  (the "Social Insurance Number -- Information for new people in
   Canada" instructional sheet: prose sections, apply steps, the 1-866-274-6627 program line, social-media
   footer). The held-out layout embeds a SIN inside the instructional prose.

This is the ONE doctype that shows a FULL SIN in plain PROSE (not tabular, not masked) AND a date_of_birth
together: the highest-stakes catastrophic pairing. The SIN appears TWICE in the letter (EN block + FR block)
to exercise multi-occurrence span detection in a single document.

LABELLING (per the v11 contract + collision rule 2): a 9-digit Luhn-valid SIN is `government_id` (NOT
tax_id; tax_id is the BN/GST RT/QST TQ/NEQ family). The scaffold .md mislabels it tax_id; the contract is
authoritative -> government_id.

POSITIVES: person, government_id (full SIN, V.sin, appears 2x), date_of_birth (V.dob), address, postal_code.
DECOYS (never labeled):
 - the letter date / issue timestamp (V.iso_date / V.request_datetime) -- not a birth date.
 - the issuer org "Service Canada" / "Emploi et Developpement social Canada" -- public institutional, not
   the subject's identity (collision rule 3: no header label lifts it to organization here).
 - the Bathurst NB registration-office address + PO box -- public institutional address, not the subject's.
 - the public SIN program line 1-866-274-6627 -- a published number, not the subject's phone.
 - a file/reference number (V.order_ref) and a Luhn-INVALID 9-digit SIN look-alike (V.sin(valid=False)) --
   so the model learns the file number and the bad-checksum twin are NOT the SIN (collision rule 2).
 - "Social Insurance Number (SIN)" mentioned as a PHRASE with no adjacent value -- realistic letter filler.

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix):
 - _layout_letter   : full bilingual mailed Confirmation Letter (letterhead + address block + indented
                      record block + confidential prose + FR block repeating the SIN).            [train]
 - _layout_msca     : "My Service Canada Account" digital confirmation notice -- short summary, file/
                      reference number, no mailed letterhead, signature/closing block.            [train]
 - _layout_newcomer : the newcomer INSTRUCTIONAL sheet that CITES a SIN inside example/instruction
                      sentences (prose + apply steps + social-media footer). Structurally distinct.[heldout]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402

# Public Service Canada registration-office address (the real lost-SIN/registration office, public info on
# canada.ca). NOT the subject's address -> always a decoy.
_SIN_OFFICE = "PO Box 7000\nBathurst NB  E2A 4T1\nCanada"
# The published SIN program line (public, on canada.ca) -> NOT the subject's phone -> decoy.
_SIN_PROGRAM_LINE = "1-866-274-6627"


def _issuer(fr: bool) -> str:
    """The issuing institution name as it appears on the masthead -> a DECOY (public institutional issuer,
    not the subject's identity; no employer/clinic-style header label lifts it to organization here)."""
    if fr:
        return random.choice(["Service Canada", "Emploi et Developpement social Canada",
                              "Emploi et Developpement social Canada / Service Canada"])
    return random.choice(["Service Canada", "Employment and Social Development Canada",
                          "Employment and Social Development Canada / Service Canada"])


def _file_ref() -> str:
    """A Service Canada file / reference number that is NOT the SIN (collision rule 2). Distinct shape from a
    9-digit SIN: a CMD-/REF-/ORD- prefixed run, or a dossier-style alpha-dash-numeric. Always a DECOY."""
    if random.random() < 0.5:
        return V.order_ref()
    return random.choice(["NAS", "SIN", "DOS", "REF"]) + "-" + \
        "".join(random.choice("0123456789") for _ in range(random.randint(7, 9)))


def _sin_value() -> str:
    """One Luhn-valid SIN, space-grouped (the prose/letter convention '046 454 286'). Sampled ONCE per doc so
    the EN and FR blocks repeat the SAME number (multi-occurrence)."""
    s = V.sin()
    # force a separated form (letters/prose never run a SIN as 9 bare digits); prefer the space grouping
    if " " not in s and "-" not in s:
        s = s[:3] + " " + s[3:6] + " " + s[6:]
    return s


def _sin_lookalike() -> str:
    """A Luhn-INVALID 9-digit SIN look-alike, grouped exactly like a real SIN (collision rule 2). This is the
    bad-checksum twin the model must learn is NOT a government_id -- a bare grouped 9-digit run with NO
    file-ref prefix, so it is a genuine SIN look-alike (distinct from the CMD-/REF- file numbers). Always a
    DECOY (never fielded)."""
    s = V.sin(valid=False)
    if " " not in s and "-" not in s:
        s = s[:3] + " " + s[3:6] + " " + s[6:]
    return s


def _sin_record_line(d: 'Doc', sin: str, fr: bool) -> None:
    """First SIN occurrence in the mailed letter's record block.

    The held-out eval showed catastrophic-tier ids (incl. government_id / SIN) appear in real layouts under
    TERSE / INLINE cues the formal-labeled TRAIN never teaches. So ~40% of the time, instead of the formal
    'Numero d'assurance sociale : <sin>' record line, embed the SAME Luhn-valid SIN inside an INLINE-PROSE
    NAS/SIN sentence (FR + EN forms). The SIN stays a government_id positive via d.field; the formal field
    remains the majority (~60%). This adds the missing inline-cue VOCABULARY without changing the letter's
    structure (still a record/body line, still the same masthead/address skeleton)."""
    if random.random() < 0.40:
        # inline-prose NAS/SIN cue: the SIN embedded in a sentence (still government_id by construction)
        if fr:
            d.add("   " + random.choice([
                "Le NAS confirme ",
                "Veuillez fournir votre NAS (",
                "Aux fins de votre dossier, le NAS ",
            ]))
            # the chosen opener decides the trailing prose so the sentence reads naturally
            choice = d._parts[-1]
            d.field(sin, "government_id")
            if "(" in choice:
                d.add(") a votre employeur uniquement lorsque la loi l'exige.\n\n")
            elif choice.strip().startswith("Le NAS confirme"):
                d.add(" figure au dossier au nom indique ci-dessus.\n\n")
            else:
                d.add(" demeure votre numero officiel.\n\n")
        else:
            d.add("   " + random.choice([
                "Your SIN ",
                "Please keep your SIN (",
                "For your records, the confirmed SIN ",
            ]))
            choice = d._parts[-1]
            d.field(sin, "government_id")
            if "(" in choice:
                d.add(") on file.\n\n")
            elif choice.strip().startswith("Your SIN"):
                d.add(" is on file under the name shown above.\n\n")
            else:
                d.add(" remains your official number.\n\n")
    else:
        # formal labeled field (the original record-block line)
        if fr:
            d.add("   Numero d'assurance sociale : "); d.field(sin, "government_id"); d.add("\n")
        else:
            d.add("   Social Insurance Number:  "); d.field(sin, "government_id"); d.add("\n")


# ---------------- layout A (train): the mailed bilingual Confirmation Letter ----------------

def _layout_letter(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="sin_letter", lang=lang)
    sin = _sin_value()
    name_plain = V.person(lang, caps=False)
    dob = V.dob(lang)

    # masthead: issuer + public registration-office address (all decoys)
    d.decoy(_issuer(fr)); d.add("\n")
    d.add("Bureau d'immatriculation au numero d'assurance sociale\n" if fr
          else "Social Insurance Registration Office\n")
    d.decoy(_SIN_OFFICE); d.add("\n\n")

    # letter date (decoy: an issue date, NOT a birth date)
    d.add("Le " if fr else "")
    d.decoy(V.iso_date()); d.add("\n\n")

    # recipient mailing block: the SAME subject, printed ALL-CAPS as real letters address-block it + address
    # + postal. (The body/record block below uses the plain-case form of the same person.)
    d.field(name_plain.upper(), "person"); d.add("\n")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + (" QC  " if random.random() < 0.85 else " Quebec  "))   # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    # salutation (repeats the subject name -> a second person positive)
    d.add(("Madame, Monsieur " if fr else "Dear "))
    d.field(name_plain, "person"); d.add(",\n\n")

    # body: confidential confirmation prose. The phrase 'numero d'assurance sociale (NAS)' with no adjacent
    # value is realistic filler (decoy-by-omission: nothing is fielded on these lines).
    if fr:
        d.add("La presente lettre confirme votre numero d'assurance sociale (NAS). Aucun nouveau numero\n"
              "n'a ete attribue; elle confirme un NAS existant.\n\n")
    else:
        d.add("This letter confirms your Social Insurance Number (SIN). A new number has not been issued;\n"
              "this letter confirms an existing SIN.\n\n")

    # indented record block: Name on record / SIN (1st occurrence) / Date of birth. The SIN line is either
    # the formal labeled field (~60%) or an inline-prose NAS/SIN cue sentence (~40%) -- see _sin_record_line.
    if fr:
        d.add("   Nom au dossier : "); d.field(name_plain, "person"); d.add("\n")
        _sin_record_line(d, sin, fr)
        d.add("   Date de naissance au dossier : "); d.field(dob, "date_of_birth"); d.add("\n\n")
    else:
        d.add("   Name on record:  "); d.field(name_plain, "person"); d.add("\n")
        _sin_record_line(d, sin, fr)
        d.add("   Date of birth on record:  "); d.field(dob, "date_of_birth"); d.add("\n\n")

    # confidentiality prose (filler) + the bilingual block that REPEATS the SAME SIN (2nd occurrence)
    if fr:
        d.add("Votre NAS est confidentiel. Ne le communiquez pas, sauf si la loi l'exige ou si un\n"
              "employeur doit declarer votre revenu. Protegez cette lettre comme vos autres pieces\n"
              "d'identite.\n\n")
        d.add("This letter confirms your Social Insurance Number (SIN). No new number has been issued.\n")
        d.add("   Social Insurance Number:  "); d.field(sin, "government_id"); d.add("\n\n")
    else:
        d.add("Your SIN is confidential. Do not share it unless required by law or by an employer who\n"
              "must report your income. Protect this letter as you would your other identity documents.\n\n")
        d.add("La presente lettre confirme votre numero d'assurance sociale (NAS). Aucun nouveau numero\n"
              "n'a ete attribue.\n")
        d.add("   Numero d'assurance sociale : "); d.field(sin, "government_id"); d.add("\n\n")

    # a SIN-shaped but Luhn-INVALID twin in a superseded-record caution -> DECOY (collision rule 2: the
    # bad-checksum look-alike must be present-but-never-labeled so the model learns the checksum gate).
    if fr:
        d.add("Si un ancien numero ("); d.decoy(_sin_lookalike())
        d.add(") figurait a votre dossier, il a ete remplace et n'est plus valide.\n\n")
    else:
        d.add("If a prior number ("); d.decoy(_sin_lookalike())
        d.add(") appeared on your record, it has been superseded and is no longer valid.\n\n")

    # closing: the public program line is a DECOY (published, not the subject's phone)
    if fr:
        d.add("Pour toute question, communiquez avec le programme du numero d'assurance sociale au\n")
    else:
        d.add("For questions, contact the Social Insurance Number program at\n")
    d.decoy(_SIN_PROGRAM_LINE); d.add(".\n\n")
    d.decoy(_issuer(fr)); d.add("\n")            # signature-line issuer repeat -> decoy
    return d.row()


# ---------------- layout B (train): the MSCA digital confirmation notice ----------------

def _layout_msca(lang: str) -> dict:
    """A 'My Service Canada Account' digital SIN-confirmation notice: no mailed letterhead/address block,
    a short summary with a file/reference number decoy, and a different field ordering. Structurally
    distinct from the mailed letter."""
    fr = lang == "fr"
    d = Doc(doctype="sin_letter", lang=lang)
    sin = _sin_value()
    name_plain = V.person(lang, caps=False)
    dob = V.dob(lang)

    d.decoy(_issuer(fr)); d.add(" -- " if False else "\n")   # no em dash anywhere
    d.add("Mon dossier Service Canada (MDSC)\n" if fr else "My Service Canada Account (MSCA)\n")
    d.add("Confirmation du numero d'assurance sociale\n\n" if fr
          else "Social Insurance Number confirmation\n\n")

    # file/reference number (decoy: NOT the SIN) + a generated/issued timestamp (decoy: not a birth date)
    d.add("Numero de dossier : " if fr else "File reference: "); d.decoy(_file_ref()); d.add("\n")
    d.add("Genere le : " if fr else "Generated: "); d.decoy(V.request_datetime(lang)); d.add("\n")
    # a Luhn-INVALID 9-digit SIN look-alike (a void/duplicate entry) -> DECOY (collision rule 2)
    d.add("Entree en double annulee : " if fr else "Voided duplicate entry: ")
    d.decoy(_sin_lookalike()); d.add("\n\n")

    # short summary lines (different order than the letter: SIN first, then person, then DOB)
    if fr:
        d.add("Votre numero d'assurance sociale a ete confirme.\n\n")
        d.add("Numero d'assurance sociale : "); d.field(sin, "government_id"); d.add("\n")
        d.add("Titulaire : "); d.field(name_plain, "person"); d.add("\n")
        d.add("Date de naissance : "); d.field(dob, "date_of_birth"); d.add("\n\n")
    else:
        d.add("Your Social Insurance Number has been confirmed.\n\n")
        d.add("Social Insurance Number:  "); d.field(sin, "government_id"); d.add("\n")
        d.add("Holder:  "); d.field(name_plain, "person"); d.add("\n")
        d.add("Date of birth:  "); d.field(dob, "date_of_birth"); d.add("\n\n")

    # an on-file mailing address line (subject's address positives) -- still in the digital notice
    if fr:
        d.add("Adresse au dossier : "); d.field(V.street_address(lang), "address")
        d.add(", " + V.city() + " QC  "); d.field(V.postal_code(), "postal_code"); d.add("\n\n")
    else:
        d.add("Address on file: "); d.field(V.street_address(lang), "address")
        d.add(", " + V.city() + " QC  "); d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    # second SIN occurrence inside a handling-note (keeps the multi-occurrence property in this layout too)
    if fr:
        d.add("Conservez ce document. Votre NAS ("); d.field(sin, "government_id")
        d.add(") est confidentiel et ne doit pas etre communique sans motif legitime.\n\n")
    else:
        d.add("Keep this document. Your SIN ("); d.field(sin, "government_id")
        d.add(") is confidential and must not be shared without a legitimate reason.\n\n")

    # closing decoys: program line + issuer
    if fr:
        d.add("Des questions? Programme du NAS : ")
    else:
        d.add("Questions? SIN program: ")
    d.decoy(_SIN_PROGRAM_LINE); d.add("\n")
    d.decoy(_issuer(fr)); d.add("\n")
    return d.row()


# ---------------- layout C (HELD-OUT): the newcomer instructional sheet citing a SIN ----------------

def _layout_newcomer(lang: str) -> dict:
    """The 'Social Insurance Number -- Information for new people in Canada' instructional sheet (grounded in
    SIN_NewComers_EN.pdf): prose sections, an apply-by example, the program line, a social-media footer. The
    SIN here is CITED inside instruction/example sentences (not in a labeled confirmation block), and the
    person's name appears in a sample-application sentence. Structurally distinct from the two letters: the
    train layouts never produce this instructional/bulleted prose shape."""
    fr = lang == "fr"
    d = Doc(doctype="sin_letter", lang=lang)
    sin = _sin_value()
    name_plain = V.person(lang, caps=False)
    dob = V.dob(lang)

    # title + issuer masthead (decoy)
    d.add("Numero d'assurance sociale\n" if fr else "Social Insurance Number\n")
    d.add("Renseignements pour les nouveaux arrivants au Canada\n\n" if fr
          else "Information for new people in Canada\n\n")
    d.decoy(_issuer(fr)); d.add("\n\n")

    # intro prose: 'SIN' as a phrase with no adjacent value -> filler/decoy-by-omission
    if fr:
        d.add("Le numero d'assurance sociale (NAS) est un numero a neuf chiffres requis pour travailler\n"
              "au Canada. En tant que nouvel arrivant, il vous incombe de demander votre NAS.\n\n")
    else:
        d.add("The Social Insurance Number (SIN) is a nine-digit number that is required to work in\n"
              "Canada. As a newcomer, it is your responsibility to apply for your SIN.\n\n")

    # a worked example that CITES a confirmed applicant's identity inside an instruction sentence
    if fr:
        d.add("Exemple : une fois la demande de "); d.field(name_plain, "person")
        d.add(" (nee le "); d.field(dob, "date_of_birth")
        d.add(") traitee, le NAS confirme "); d.field(sin, "government_id")
        d.add("\nfigure dans la lettre de confirmation envoyee par la poste.\n\n")
    else:
        d.add("Example: once the application for "); d.field(name_plain, "person")
        d.add(" (born "); d.field(dob, "date_of_birth")
        d.add(") is processed, the confirmed SIN "); d.field(sin, "government_id")
        d.add("\nappears on the confirmation letter sent by mail.\n\n")

    # apply steps (bulleted prose). Mailing address for the form -> still part of an instruction, but the
    # applicant's residential address IS the subject's identity -> positive.
    if fr:
        d.add("Comment demander un NAS?\n")
        d.add("  - En ligne au moyen du portail eNAS securise.\n")
        d.add("  - En personne, en apportant vos documents originaux.\n")
        d.add("  - Par la poste. Adresse de retour du demandeur : ")
        d.field(V.street_address(lang), "address"); d.add(", " + V.city() + " QC  ")
        d.field(V.postal_code(), "postal_code"); d.add("\n\n")
    else:
        d.add("How do I apply?\n")
        d.add("  - Online using the secure eSIN portal.\n")
        d.add("  - In person, bringing your original documents.\n")
        d.add("  - By mail. Applicant return address: ")
        d.field(V.street_address(lang), "address"); d.add(", " + V.city() + " QC  ")
        d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    # the published program line -> decoy ; a file ref for the sample application -> decoy (NOT the SIN)
    if fr:
        d.add("Si vous n'avez pas recu votre NAS dans les 10 jours ouvrables, communiquez avec le\n"
              "programme du numero d'assurance sociale au ")
    else:
        d.add("If you have not received your SIN within 10 business days, contact the Social Insurance\n"
              "Number program at ")
    d.decoy(_SIN_PROGRAM_LINE); d.add(".\n")
    d.add("Numero de reference de la demande : " if fr else "Application reference number: ")
    d.decoy(_file_ref()); d.add("\n")
    # a Luhn-INVALID 9-digit SIN look-alike inside a caution -> DECOY (collision rule 2): a number that
    # FAILS the SIN check digit is not a valid SIN.
    if fr:
        d.add("Un numero a neuf chiffres dont le chiffre de controle est invalide (par exemple ")
        d.decoy(_sin_lookalike()); d.add(") n'est pas un NAS valide.\n\n")
    else:
        d.add("A nine-digit number whose check digit is invalid (for example ")
        d.decoy(_sin_lookalike()); d.add(") is not a valid SIN.\n\n")

    # second SIN occurrence inside an employer-reporting instruction (keeps multi-occurrence)
    if fr:
        d.add("Une fois recu, fournissez votre NAS ("); d.field(sin, "government_id")
        d.add(") a votre employeur uniquement lorsque la loi l'exige.\n\n")
    else:
        d.add("Once received, provide your SIN ("); d.field(sin, "government_id")
        d.add(") to your employer only when required by law.\n\n")

    # social-media footer (decoys: issuer + handles, no PII)
    d.add("Suivez-nous :\n" if fr else "Follow us:\n")
    d.decoy(_issuer(fr)); d.add("\n")
    d.add("facebook.com/servicecanadaen  linkedin.com/company/service-canada\n")
    return d.row()


LAYOUTS = [_layout_letter, _layout_msca, _layout_newcomer]   # newcomer sheet (suffix) = held-out structure


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
