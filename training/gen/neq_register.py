#!/usr/bin/env python3
"""neq_register generator: synthetic Quebec enterprise register statements (etat des renseignements,
Registraire des entreprises) in the REAL register layout (FR/EN).

GROUNDED on the official quebec.ca field schema (datasets/scaffolds/firecrawl/neq-register-fields.md +
neq-number.md). The register is a PUBLIC document, but it carries identity PII the gateway must redact:
the registered enterprise NAME, the NEQ, and -- the catastrophic part -- the NAMES and personal HOME
ADDRESSES of directors / officers / shareholders / ultimate beneficiaries (the register is legally required
to publish "the names and home addresses of their shareholders, directors, partners and officers").

The hard problem this doctype teaches: ORGANIZATION vs PERSON contrast in the SAME document.
 - the enterprise name (Nom) + other-name versions + establishment names -> organization (POSITIVE).
 - the director / officer / shareholder / ultimate-beneficiary NATURAL-PERSON names -> person (POSITIVE),
   with their personal home addresses -> address + postal_code (POSITIVE).
 - the NEQ (ten-digit, first two digits = legal form 11/22/33/88) -> tax_id (POSITIVE, via _neq()).
 - the establishment number (Numero de l'etablissement) -> account_number (POSITIVE, cued).

POSITIVES emitted: organization, person, address, postal_code, tax_id, account_number.

DECOYS (in the text, NEVER labeled -- the false-positive fix). The register is DENSE with date / code /
status / count fields that look label-worthy but are not identity:
 - registration / constitution / update / declaration dates -> V.iso_date()                 (NEGATIVE)
 - CAE economic-activity code (4-digit) + SCIAN (6-digit)                                     (NEGATIVE)
 - nombre de salaries (employee count)                                                        (NEGATIVE)
 - document index entries (type + filing date) + document/name-index reference numbers        (NEGATIVE)
 - statut ("immatriculee" / "radiee d'office"), forme juridique, regime constitutif/courant   (NEGATIVE)
 - city name + province "QC" / "Quebec" + street-type word alone                              (NEGATIVE)
 - a bare 3-digit-shaped CAE / a postal-shaped CAE has NO delivery context                     (NEGATIVE)

LAYOUTS (>=2 genuinely-distinct real structures; held-out = the suffix):
 - _layout_full   : the full multi-section etat des renseignements (identification + domicile + forme
                    juridique + activites + administrateurs/actionnaires + etablissements + index).   [train]
 - _layout_search : the compact NEQ search-result summary -- the few-line hit card the public search
                    returns (NEQ, nom, statut, adresse domicile) with NO director list, NO index.   [HELDOUT]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`. ~65% FR / 35% EN.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402
import cue_helpers as C         # noqa: E402

# legal-form prefixes for the NEQ first two digits (neq-number.md): 11 legal persons, 22 sole prop,
# 33 partnerships/associations, 88 public authorities.
_NEQ_PREFIX = ["11", "22", "33", "88"]

_FORME_FR = ["Societe par actions (compagnie)", "Personne morale sans but lucratif",
             "Personne physique exploitant une entreprise individuelle",
             "Societe en nom collectif (SENC)", "Societe en commandite (SEC)", "Cooperative",
             "Syndicat de coproprietaires"]
_FORME_EN = ["Business corporation", "Non-profit legal person", "Natural person (sole proprietorship)",
             "General partnership (GP)", "Limited partnership (LP)", "Cooperative",
             "Syndicate of co-owners"]
_REGIME_FR = ["Loi sur les societes par actions (RLRQ, c. S-31.1)",
              "Loi canadienne sur les societes par actions", "Code civil du Quebec",
              "Loi sur les compagnies (partie IA)"]
_REGIME_EN = ["Business Corporations Act (CQLR, c. S-31.1)", "Canada Business Corporations Act",
              "Civil Code of Quebec", "Companies Act (Part IA)"]
_STATUT_FR = ["Immatriculee", "Radiee d'office", "Radiee sur demande"]
_STATUT_EN = ["Registered", "Cancelled ex officio", "Cancelled on request"]
_ACTIVITE_FR = ["Services-conseils en informatique", "Construction de batiments residentiels",
                "Commerce de detail d'alimentation", "Restauration a service complet",
                "Transport de marchandises par camion", "Services de comptabilite",
                "Fabrication de produits metalliques"]
_ACTIVITE_EN = ["Computer consulting services", "Residential building construction",
                "Food retail", "Full-service restaurants", "Freight trucking",
                "Accounting services", "Metal product manufacturing"]
_DOCTYPE_FR = ["Declaration de mise a jour annuelle", "Declaration de mise a jour courante",
               "Declaration d'immatriculation", "Declaration modificative", "Avis de revocation"]
_DOCTYPE_EN = ["Annual updating declaration", "Current updating declaration",
               "Registration declaration", "Amending declaration", "Notice of revocation"]
_ROLE_FR = ["President", "Vice-president", "Secretaire", "Tresorier", "Administrateur",
            "Administratrice", "Dirigeant", "Dirigeante"]
_ROLE_EN = ["President", "Vice-President", "Secretary", "Treasurer", "Director",
            "Officer", "Chair", "Member of the Board"]


# ---------------- inline doctype-specific value shapes ----------------

def _neq() -> str:
    """A Quebec enterprise number: ten digits, first two = legal-form prefix (11/22/33/88). Labeled tax_id
    (the contract groups NEQ with GST RT / QST TQ under tax_id). Spacing varies like the real document
    (1234567890 or 1234 5678 90)."""
    body = random.choice(_NEQ_PREFIX) + "".join(random.choice("0123456789") for _ in range(8))
    r = random.random()
    if r < 0.55:
        return body
    if r < 0.8:
        return f"{body[:4]} {body[4:8]} {body[8:]}"
    return f"{body[:3]} {body[3:6]} {body[6:]}"


def _neq_train() -> str:
    """TRAIN-layout NEQ presentation. Same value routes to tax_id, but ~40% of the time it is printed in the
    SPACED registry format via C.group_digits(neq, (3,3,4)) (e.g. '881 147 1049') -- the (3,3,4) grouping the
    real register prints and the held-out search card uses -- so the train layout teaches the spaced cue WITHOUT
    copying held-out structure. group_digits only inserts spaces, so the fielded string is still a real substring.
    The packed and (4,4,2) forms produced by _neq() are kept as the majority presentation."""
    if random.random() < 0.4:
        body = random.choice(_NEQ_PREFIX) + "".join(random.choice("0123456789") for _ in range(8))
        return C.group_digits(body, (3, 3, 4))     # '881 147 1049' spaced registry form -> tax_id
    return _neq()


def _company_name(lang: str) -> str:
    """A registered enterprise name -> organization. Generic synthetic (never a real company); reuse the
    shared company sampler so org-shape is consistent across the corpus."""
    return V.company(lang)


def _other_name(lang: str) -> str:
    """An 'autre nom utilise au Quebec' / other-language version of the name -> still organization."""
    base = V.company(lang)
    if random.random() < 0.4:
        return base + (" et Fils" if lang == "fr" else " and Sons")
    return base


def _establishment_no() -> str:
    """Establishment number: order of registration assigned by the Registraire. A short bare numeric run
    (cued by 'Numero de l'etablissement') -> account_number (NOT sensitive_account_id: it is a bare run,
    collision rule 1)."""
    return "".join(random.choice("0123456789") for _ in range(random.randint(7, 10)))


def _cae() -> str:
    """Code d'activite economique: a FOUR-digit code -> NEGATIVE decoy (an economic-activity code, never PII;
    also a postal/account look-alike that must stay unlabeled)."""
    return f"{random.randint(1000, 9999)}"


def _scian() -> str:
    """SCIAN/NAICS: a six-digit code -> NEGATIVE decoy."""
    return f"{random.randint(100000, 999999)}"


def _doc_ref() -> str:
    """A document-index reference number -> NEGATIVE decoy (looks account-shaped, but it is filing metadata)."""
    return f"{random.randint(100, 9999)}-{random.randint(10, 99)}"


def _person_addr(d: Doc, lang: str) -> None:
    """A natural person's home address line: street -> address (POSITIVE), city + 'QC' -> NEGATIVE,
    postal -> postal_code (POSITIVE). The register publishes director/shareholder HOME addresses."""
    d.field(V.street_address(lang), "address"); d.add(", ")
    d.add(V.city() + (" (QC) " if random.random() < 0.6 else " QC "))      # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code")


def _domicile_block(d: Doc, fr: bool, lang: str) -> None:
    """Adresse du domicile / siege: the enterprise's registered domicile address (street -> address,
    city+prov -> NEGATIVE, postal -> postal_code)."""
    d.add("Adresse du domicile : " if fr else "Address of domicile: ")
    d.field(V.street_address(lang), "address"); d.add(", ")
    d.add(V.city() + (" (QC) " if random.random() < 0.6 else " QC "))
    d.field(V.postal_code(), "postal_code"); d.add("\n")


# ---------------- layout A: full etat des renseignements ----------------

def _layout_full(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="neq_register", lang=lang)

    d.add("Registraire des entreprises\n")
    d.add("Etat des renseignements d'une personne morale au registre des entreprises\n"
          if fr else
          "Statement of information of a legal person in the enterprise register\n")
    d.add(("Date de mise a jour de l'etat des renseignements : " if fr
           else "Statement-of-information update date: "))
    d.decoy(V.iso_date()); d.add("\n\n")                       # update date -> NEGATIVE

    # ---- Identification de l'entreprise ----
    d.add("-- Identification de l'entreprise --\n" if fr else "-- Enterprise identification --\n")
    d.add("Numero d'entreprise du Quebec (NEQ) : " if fr else "Quebec enterprise number (NEQ): ")
    d.field(_neq_train(), "tax_id"); d.add("\n")               # NEQ -> tax_id (packed or (3,3,4) spaced)
    d.add("Nom : " if fr else "Name: ")
    d.field(_company_name(lang), "organization"); d.add("\n")  # enterprise name -> organization
    if random.random() < 0.6:
        d.add("Autre nom utilise au Quebec : " if fr else "Other name used in Quebec: ")
        d.field(_other_name(lang), "organization"); d.add("\n")   # other name -> still organization
    d.add("Statut : " if fr else "Status: ")
    d.add((random.choice(_STATUT_FR) if fr else random.choice(_STATUT_EN)) + "\n")   # statut -> NEGATIVE
    d.add("Date d'immatriculation : " if fr else "Registration date: ")
    d.decoy(V.iso_date()); d.add("\n")                         # registration date -> NEGATIVE
    d.add("Date de la derniere declaration de mise a jour annuelle : " if fr
          else "Last annual updating declaration date: ")
    d.decoy(V.iso_date()); d.add("\n\n")                       # declaration date -> NEGATIVE

    # ---- Forme juridique ----
    d.add("-- Forme juridique --\n" if fr else "-- Legal form --\n")
    d.add("Forme juridique : " if fr else "Legal form: ")
    d.add((random.choice(_FORME_FR) if fr else random.choice(_FORME_EN)) + "\n")     # forme -> NEGATIVE
    d.add("Date de constitution : " if fr else "Date of constitution: ")
    d.decoy(V.iso_date()); d.add("\n")                         # constitution date -> NEGATIVE
    d.add("Regime constitutif : " if fr else "Constituent regime: ")
    d.add((random.choice(_REGIME_FR) if fr else random.choice(_REGIME_EN)) + "\n\n")  # regime -> NEGATIVE

    # ---- Adresse du domicile ----
    d.add("-- Adresse du domicile --\n" if fr else "-- Address of domicile --\n")
    _domicile_block(d, fr, lang)
    if random.random() < 0.4:
        d.add("Adresse du domicile elu : " if fr else "Address of elected domicile: ")
        d.field(V.street_address(lang), "address"); d.add(", ")
        d.add(V.city() + " (QC) ")
        d.field(V.postal_code(), "postal_code"); d.add("\n")
    d.add("\n")

    # ---- Activites economiques et nombre de salaries ----
    d.add("-- Activites economiques et nombre de salaries --\n" if fr
          else "-- Economic activities and number of employees --\n")
    d.add("Code d'activite economique (CAE) : " if fr else "Economic activity code (CAE): ")
    d.decoy(_cae()); d.add("\n")                               # CAE 4-digit -> NEGATIVE
    d.add("Activite : " if fr else "Activity: ")
    d.add((random.choice(_ACTIVITE_FR) if fr else random.choice(_ACTIVITE_EN)) + "\n")
    if random.random() < 0.5:
        d.add("Code SCIAN : " if fr else "NAICS code: ")
        d.decoy(_scian()); d.add("\n")                         # SCIAN 6-digit -> NEGATIVE
    d.add("Nombre de salaries : " if fr else "Number of employees: ")
    d.decoy(str(random.randint(0, 250))); d.add("\n\n")        # employee count -> NEGATIVE

    # ---- Administrateurs / dirigeants / actionnaires / beneficiaires ultimes ----
    # the register publishes natural-person names + HOME addresses -> person + address + postal_code
    d.add("-- Liste des administrateurs --\n" if fr else "-- List of directors --\n")
    for _ in range(random.randint(2, 4)):
        d.add("Nom : " if fr else "Name: ")
        d.field(V.person(lang), "person")                      # director name -> person
        d.add("   " + (random.choice(_ROLE_FR) if fr else random.choice(_ROLE_EN)) + "\n")  # role -> NEGATIVE
        d.add("   Adresse du domicile : " if fr else "   Home address: ")
        _person_addr(d, lang); d.add("\n")

    if random.random() < 0.7:
        d.add("\n-- Dirigeants non membres du conseil d'administration --\n" if fr
              else "\n-- Officers not members of the Board --\n")
        for _ in range(random.randint(1, 2)):
            d.add("Nom : " if fr else "Name: ")
            d.field(V.person(lang), "person")
            d.add("   " + (random.choice(_ROLE_FR) if fr else random.choice(_ROLE_EN)) + "\n")
            d.add("   Adresse du domicile : " if fr else "   Home address: ")
            _person_addr(d, lang); d.add("\n")

    if random.random() < 0.6:
        d.add("\n-- Actionnaires --\n" if fr else "\n-- Shareholders --\n")
        for _ in range(random.randint(1, 3)):
            d.add("Nom : " if fr else "Name: ")
            # a shareholder may be a natural person OR a legal person (another enterprise)
            if random.random() < 0.75:
                d.field(V.person(lang), "person")              # natural-person shareholder -> person
                d.add("\n   Adresse du domicile : " if fr else "\n   Home address: ")
                _person_addr(d, lang); d.add("\n")
            else:
                d.field(_company_name(lang), "organization")   # legal-person shareholder -> organization
                d.add("\n")

    if random.random() < 0.5:
        d.add("\n-- Beneficiaires ultimes --\n" if fr else "\n-- Ultimate beneficiaries --\n")
        d.add("Nom : " if fr else "Name: ")
        d.field(V.person(lang), "person")
        d.add("\n   Adresse du domicile : " if fr else "\n   Home address: ")
        _person_addr(d, lang); d.add("\n")

    # ---- Etablissements ----
    d.add("\n-- Etablissements --\n" if fr else "\n-- Establishments --\n")
    d.add("Numero de l'etablissement : " if fr else "Establishment number: ")
    d.field(_establishment_no(), "account_number"); d.add("\n")   # establishment no -> account_number
    d.add("Nom de l'etablissement : " if fr else "Establishment name: ")
    d.field(_company_name(lang), "organization"); d.add("\n")     # establishment name -> organization
    d.add("CAE de l'etablissement : " if fr else "Establishment CAE: ")
    d.decoy(_cae()); d.add("\n\n")                                # CAE -> NEGATIVE

    # ---- Index des documents ----
    d.add("-- Index des documents --\n" if fr else "-- Document index --\n")
    for _ in range(random.randint(2, 5)):
        d.decoy(random.choice(_DOCTYPE_FR) if fr else random.choice(_DOCTYPE_EN)); d.add("   ")
        d.decoy(_doc_ref()); d.add("   ")                         # filing reference -> NEGATIVE
        d.decoy(V.iso_date()); d.add("\n")                        # filing date -> NEGATIVE
    return d.row()


# ---------------- layout B (HELD-OUT): compact NEQ search-result summary ----------------

def _layout_search(lang: str) -> dict:
    """The public search-result hit card: what the 'Rechercher une entreprise au registre' search returns
    BEFORE you open the full statement -- a tight summary block (NEQ, nom, statut, adresse). NO director
    list, NO index, NO forme-juridique section. Genuinely different structure (single result row + a couple
    of lines), so the held-out tests STRUCTURAL generalization, not a reworded full statement."""
    fr = lang == "fr"
    d = Doc(doctype="neq_register", lang=lang)

    d.add("Registraire des entreprises\n")
    d.add("Resultat de la recherche au registre des entreprises\n" if fr
          else "Enterprise register search result\n")
    d.add(("Recherche effectuee le " if fr else "Search performed on "))
    d.decoy(V.request_datetime(lang)); d.add("\n")               # search timestamp -> NEGATIVE
    d.add(("Nombre de resultats : 1\n\n" if fr else "Number of results: 1\n\n"))

    # the compact result row: NEQ | Nom | Statut | (domicile city)
    d.add("NEQ : " if fr else "NEQ: ")
    d.field(_neq(), "tax_id"); d.add("\n")                       # NEQ -> tax_id
    d.add("Nom de l'entreprise : " if fr else "Enterprise name: ")
    d.field(_company_name(lang), "organization"); d.add("\n")    # enterprise name -> organization
    d.add("Statut au registre : " if fr else "Register status: ")
    d.add((random.choice(_STATUT_FR) if fr else random.choice(_STATUT_EN)) + "\n")   # statut -> NEGATIVE
    d.add("Forme juridique : " if fr else "Legal form: ")
    d.add((random.choice(_FORME_FR) if fr else random.choice(_FORME_EN)) + "\n")     # forme -> NEGATIVE
    d.add("Date d'immatriculation : " if fr else "Registration date: ")
    d.decoy(V.iso_date()); d.add("\n")                           # registration date -> NEGATIVE

    # the summary shows the registered domicile (no personal director home addresses in the hit card)
    _domicile_block(d, fr, lang)

    # occasionally the summary surfaces one "autre nom" + a representative contact name
    if random.random() < 0.5:
        d.add("Autre nom utilise : " if fr else "Other name used: ")
        d.field(_other_name(lang), "organization"); d.add("\n")
    if random.random() < 0.45:
        # a single named contact (the declarant) appears on some summary cards -> person
        d.add("Personne-ressource : " if fr else "Contact person: ")
        d.field(V.person(lang), "person"); d.add("\n")

    d.add(("\nConsultez l'etat des renseignements pour la liste complete des administrateurs.\n" if fr
           else "\nView the statement of information for the full list of directors.\n"))
    return d.row()


LAYOUTS = [_layout_full, _layout_search]    # search-result summary (suffix) = held-out structure


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
