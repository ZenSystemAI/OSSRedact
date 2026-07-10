#!/usr/bin/env python3
"""org_contrast generator: teaches employer-as-org vs merchant-as-negative (FR/EN).

The operator's false-positive complaint (research doc 2026-06-14 section 7 rule 3): an organization name is
only PII when it identifies the SUBJECT, i.e. in a labeled HEADER field like `Employeur:` / `Employer:` /
`Clinique:` / `Mon entreprise:`. The SAME kind of org name appearing in a transaction-description / merchant
/ vendor line is a NEGATIVE (the model must NOT redact every company token, or every bank statement bleeds).

So each doc emits BOTH modes explicitly so the contrast is in-distribution:
 - HEADER block: one labeled employer/clinic/company -> organization (the positive), plus realistic
   person + email + address positives for context (a profile/intake card).
 - LEDGER block: several merchant/vendor lines whose org-shaped names are d.decoy() (NEGATIVE), alongside
   amount/date/ref decoys so the org name is the only thing the model could over-fire on.

Org names are generated INLINE here (generic synthetic companies: `<Word> Solutions Inc`, `Clinique <Place>`,
`<Name> Consultation`); never a real company. All other PII reuses values.py.

gen(lang) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402

# inline synthetic org-name pieces (generic, not real companies)
_ORG_WORDS = ["Boreal", "Cascade", "Cedre", "Granit", "Horizon", "Lumiere", "Meridien", "Nordik", "Polaris",
              "Saphir", "Vertex", "Zephyr", "Quartz", "Atelier", "Sommet", "Riviere", "Pinacle", "Aurore"]
_ORG_SUFFIX = ["Solutions Inc", "Solutions inc.", "Technologies", "Conseil", "Groupe", "Services",
               "Industries", "Logistique", "Construction", "Distribution Ltee", "Gestion", "Marketing"]
_PLACES = ["du Plateau", "Saint-Laurent", "Centre-Ville", "de la Capitale", "des Erables", "du Vieux-Port",
           "Riviere-Nord", "des Laurentides", "de l'Estrie", "du Domaine"]
_CLINIC_KIND = ["Clinique", "Clinique dentaire", "Clinique medicale", "Centre medical", "Centre dentaire",
                "Pharmacie", "Physio"]


def _company_name() -> str:
    return f"{random.choice(_ORG_WORDS)} {random.choice(_ORG_SUFFIX)}"


def _clinic_name() -> str:
    return f"{random.choice(_CLINIC_KIND)} {random.choice(_PLACES)}"


def _person_consult() -> str:
    # "<Last> Consultation" / "<Last> & Associes" style firm named after a person, still a generic org
    last = random.choice(["Tremblay", "Gagnon", "Roy", "Cote", "Bouchard", "Morin", "Lavoie", "Fortin"])
    tail = random.choice(["Consultation", "Consultants", "& Associes", "Notaires", "Comptables", "Avocats"])
    return f"{last} {tail}"


def _employer_name() -> str:
    r = random.random()
    if r < 0.5:
        return _company_name()
    if r < 0.8:
        return _clinic_name()
    return _person_consult()


def _vendor_name() -> str:
    """An org-shaped name for a merchant/vendor LEDGER line (always a decoy). Same generators as the header
    employer on purpose: only the CONTEXT (header label vs ledger line) decides positive vs negative."""
    r = random.random()
    if r < 0.55:
        return _company_name()
    if r < 0.8:
        return _clinic_name()
    return _person_consult()


def gen(lang: str = None, split: str = "train") -> dict:
    # `split` accepted for the uniform corpus API; the org affiliation-vs-merchant contrast is needed in BOTH splits.
    lang = lang or ("fr" if random.random() < 0.65 else "en")
    fr = lang == "fr"
    d = Doc(doctype="org_contrast", lang=lang)

    # ---- title ----
    d.add(("Fiche employe / Releve de depenses\n" if fr else "Employee profile / Expense report\n"))
    d.add(("Reference: " if fr else "Reference: ")); d.decoy(V.order_ref()); d.add("\n\n")

    # ---- HEADER block: org is a LABELED positive here ----
    # the employer/clinic/company field label is what lifts the org to a positive
    if fr:
        org_label = random.choice(["Employeur: ", "Mon entreprise: ", "Clinique: ", "Societe: ",
                                   "Raison sociale: ", "Lieu de travail: "])
    else:
        org_label = random.choice(["Employer: ", "My company: ", "Clinic: ", "Company: ",
                                   "Business name: ", "Workplace: "])
    d.add(org_label); d.field(_employer_name(), "organization"); d.add("\n")

    # person + email + address positives (intake context)
    d.add("Nom: " if fr else "Name: "); d.field(V.person(lang), "person"); d.add("\n")

    d.add("Courriel: " if fr else "Email: "); d.field(V.email(), "email"); d.add("\n")
    if random.random() < 0.6:
        d.add("Telephone: " if fr else "Phone: "); d.field(V.phone(), "phone_number"); d.add("\n")

    d.add("Adresse: " if fr else "Address: ")
    d.field(V.street_address(lang), "address")
    d.add(", " + V.city() + (" QC " if random.random() < 0.8 else " Quebec "))   # city + prov = NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")

    # occasionally a SECOND labeled org header (e.g. a clinic where the employee is referred / treated)
    if random.random() < 0.35:
        if fr:
            lbl2 = random.choice(["Clinique de suivi: ", "Fournisseur principal: ", "Filiale: "])
        else:
            lbl2 = random.choice(["Follow-up clinic: ", "Parent company: ", "Subsidiary: "])
        d.add(lbl2)
        d.field(_clinic_name() if "linic" in lbl2 or "linique" in lbl2 else _company_name(), "organization")
        d.add("\n")

    # ---- LEDGER block: org-shaped vendor/merchant names are ALL decoys (NEGATIVE) ----
    d.add(("\nReleve de transactions\n" if fr else "\nTransaction ledger\n"))
    d.add(("Date        Fournisseur / Marchand              Montant\n" if fr
           else "Date        Vendor / Merchant                   Amount\n"))
    for _ in range(random.randint(6, 16)):
        d.decoy(V.iso_date()); d.add("  ")
        # mix org-shaped vendor decoys with plain merchant decoys so the contrast is dense
        if random.random() < 0.6:
            d.decoy(_vendor_name())
        else:
            d.decoy(V.merchant())
        d.add("   "); d.decoy(V.amount()); d.add("\n")

    # a "paid to / payable to" line: still a ledger context -> org-shaped name is a decoy
    if random.random() < 0.5:
        d.add(("Paye a: " if fr else "Paid to: ")); d.decoy(_vendor_name())
        d.add("  "); d.decoy(V.amount()); d.add("\n")

    # ---- footer decoys ----
    d.add(("Approuve par le service " if fr else "Approved by department "))
    d.decoy(_company_name())          # an internal-dept org name in free text -> NEGATIVE (no header label)
    d.add("  "); d.add("Lot "); d.decoy(str(random.randint(1000, 9999))); d.add("\n")
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
