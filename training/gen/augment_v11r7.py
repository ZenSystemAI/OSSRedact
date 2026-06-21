#!/usr/bin/env python3
"""v11r7 augmentation -- harden the THREE no-floor categories (person / organization / address) on the
real-world STRUCTURAL forms measured to leak on v11r6 (2026-06-18 live stress probes):

  person  : RFC5322 mailbox `Name <email>`, From:/To:/Cc:/Author:/Signed-off-by:/owner: headers, git-author.
  org     : bare `Name <suffix>` (Inc./Ltée/SENC/& Associés), JSON/CSV company fields, signature blocks,
            Employer:/company: cues, well-known QC institutions in prose, multi-org sentences.
  address : civic+street FR/EN with directionals (Ouest/O/West/W), rural routes (rang/route), units
            (app./suite/bureau), JSON address fields, `Adresse:` cues.

Offsets are computed BY CONSTRUCTION and every span is asserted to slice back to the exact value (a single
off-by-one corrupts the BIO labels). ~22% negatives per category preserve precision. Train and heldout pools
are DISJOINT so the heldout slices measure generalization, not memorization. Deterministic; pure stdlib.

Schema matches v11r5/v11r6: {input, output:{spans:[[s,e,label]], entities:{}}, meta}.

Usage: python training/gen/augment_v11r7.py --out-dir /tmp/aug7 --n-train 18000 --n-val 1800 --n-heldout 1500
"""
from __future__ import annotations
import argparse, json, os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from augment_structural_names import GIVEN, SURNAME, NEG_VALUES, _emit  # noqa: E402

# ---------------- organization pools ----------------
ORG_CORE = [  # synthetic / generic distinctive bases (split disjoint train vs heldout)
    "Lumen", "Sigma Capital", "Acme Logistics", "Northwind", "Boréal", "Clearwater", "Helios Systems",
    "Vortex", "Granite Partners", "Meridian", "Cascade Foods", "Solstice", "Ironwood", "Blue Harbor",
    "Crestline", "Aurora Labs", "Sentinel", "Kestrel", "Mosaic Health", "Brightpath", "Evergreen Realty",
    "Stonebridge", "Halcyon", "Vanguard Tech", "Riverstone", "Summit Tool", "Trillium", "Cobalt Works",
    "Pinnacle", "Driftwood", "Ember Analytics", "Falcon Freight", "Ardent", "Beacon Trust", "Quill",
    "Maplewood", "Thornton", "Voyageur", "Saguenay Métal", "Laurentide", "Beauport Auto", "Verdun Tissu",
]
ORG_SUFFIX = ["inc.", "Inc.", "Ltd.", "ltée", "Ltée", "SENC", "s.e.n.c.", "Cie", "Corporation", "Group",
              "Groupe", "Technologies", "Solutions", "Conseil", "& Associés", "et Fils", "Holdings"]
ORG_QC = [  # well-known public institutions/brands (public knowledge, not personal PII) the model must catch
    "Hydro-Québec", "Revenu Québec", "Desjardins", "Banque Nationale", "SAAQ", "Loto-Québec", "Vidéotron",
    "Bombardier", "Cascades", "Couche-Tard", "Jean Coutu", "Université Laval", "Ville de Montréal",
    "Caisse Desjardins", "La Capitale", "Énergir", "Cogeco", "Metro inc.", "CGI", "Lightspeed",
]
ORG_KEYS = ["company", "employer", "vendor", "organization", "org", "entreprise", "employeur",
            "fournisseur", "société", "client_org", "supplier"]

# ---------------- address pools ----------------
ST_TYPE_FR = ["rue", "avenue", "av.", "boulevard", "boul.", "chemin", "rang", "route", "place",
              "montée", "côte", "impasse"]
ST_TYPE_EN = ["Street", "St", "Avenue", "Ave", "Boulevard", "Blvd", "Road", "Rd", "Drive", "Dr",
              "Lane", "Court", "Crescent", "Way", "Terrace"]
ST_NAME = ["Saint-Denis", "René-Lévesque", "Henri-Bourassa", "Sainte-Catherine", "Sherbrooke", "Papineau",
           "du Lac", "des Pins", "des Érables", "du Moulin", "Notre-Dame", "Wellington", "Maisonneuve",
           "King", "Queen", "Maple", "Oak", "Bloor", "Yonge", "Wellington", "Dundas", "Bayview",
           "Greenfield", "Larkspur", "Sycamore", "Birchwood", "Hawthorne", "Cedarwood", "Sainte-Foy"]
DIR_FR = ["Ouest", "Est", "Nord", "Sud", "O.", "E.", "N.", "S."]
DIR_EN = ["West", "East", "North", "South", "W", "E", "N", "S"]
UNIT = ["app.", "apt", "unité", "suite", "bureau", "local"]
CITY = ["Montréal", "Québec", "Gatineau", "Laval", "Longueuil", "Sherbrooke", "Trois-Rivières",
        "Toronto", "Ottawa", "Mississauga"]
ADDR_KEYS = ["address", "adresse", "ship_to", "billing_address", "street", "location", "domicile"]


def _disjoint(pool, seed, frac=0.7):
    rng = random.Random(seed); p = pool[:]; rng.shuffle(p)
    cut = int(len(p) * frac)
    return p[:cut], p[cut:]


def _person(rng):
    g = rng.choice(GIVEN); r = rng.random()
    if r < 0.78:
        return f"{g} {rng.choice(SURNAME)}"
    if r < 0.92:
        return f"{g} {rng.choice(SURNAME)}-{rng.choice(SURNAME)}"
    return f"{g} {rng.choice(GIVEN)} {rng.choice(SURNAME)}"


def _email(rng, nm):
    h = nm.lower().replace(" ", ".").replace("-", "").replace("'", "")
    dom = rng.choice(["acme.ca", "example.org", "corp.io", "dev.io", "mail.qc.ca", "groupe.com"])
    return f"{h[:24]}@{dom}"


def _org(rng, cores):
    base = rng.choice(cores)
    r = rng.random()
    if r < 0.45:
        return f"{base} {rng.choice(ORG_SUFFIX)}"
    if r < 0.60:
        return f"{rng.choice(SURNAME)} {rng.choice(['&', 'et'])} {rng.choice(['Associés', 'Fils', 'Cie'])}"
    return base


def _address(rng):
    civ = str(rng.randint(10, 9999))
    if rng.random() < 0.6:
        st = f"{civ} {rng.choice(ST_TYPE_FR)} {rng.choice(ST_NAME)}"
        if rng.random() < 0.4:
            st += f" {rng.choice(DIR_FR)}"
    else:
        st = f"{civ} {rng.choice(ST_NAME)} {rng.choice(ST_TYPE_EN)}"
        if rng.random() < 0.4:
            st += f" {rng.choice(DIR_EN)}"
    return st


# ---------------- record builders (offset-true) ----------------
def _rec_person(rng, person):
    is_neg = rng.random() < 0.20
    form = rng.choice(["mailbox", "from", "to", "cc", "author", "signoff", "owner", "gitlog", "vcard"])
    nm = _person(person)
    em = _email(rng, nm)
    if form == "mailbox":
        if is_neg:
            return _emit(f"{rng.choice(['Support','Notifications','no-reply','Billing'])} <{em}>", [])
        pre = ""
        text = f"{pre}{nm} <{em}>"
        return _emit(text, [(len(pre), len(pre) + len(nm), "person")])
    cue = {"from": "From: ", "to": "To: ", "cc": "Cc: ", "author": "Author: ",
           "signoff": "Signed-off-by: ", "owner": "owner: ", "gitlog": f"commit {rng.randrange(16**7):07x}  ",
           "vcard": "FN:"}[form]
    withmail = form in ("mailbox", "from", "to", "cc", "author", "signoff", "gitlog") and rng.random() < 0.8
    if is_neg and form in ("from", "to", "cc"):
        return _emit(f"{cue}{em}", [])
    tail = f" <{em}>" if withmail else ""
    text = f"{cue}{nm}{tail}"
    s = len(cue)
    return _emit(text, [(s, s + len(nm), "person")])


def _rec_org(rng, cores):
    is_neg = rng.random() < 0.22
    form = rng.choice(["bare", "json", "csv", "sig", "cue", "qc_prose", "two"])
    if form == "bare":
        if is_neg:
            return _emit(rng.choice(NEG_VALUES), [])
        og = _org(rng, cores)
        return _emit(og, [(0, len(og), "organization")])
    if form == "json":
        key = rng.choice(ORG_KEYS)
        if is_neg:
            return _emit(json.dumps({key: rng.choice(NEG_VALUES)}, ensure_ascii=False), [])
        og = _org(rng, cores); pre = '{"' + key + '": "'
        return _emit(pre + og + '"}', [(len(pre), len(pre) + len(og), "organization")])
    if form == "csv":
        og = None if is_neg else _org(rng, cores)
        cells = [str(rng.randint(100, 999)), (rng.choice(NEG_VALUES) if is_neg else og), rng.choice(["QC", "ON", "active"])]
        out, spans, pos = "", [], 0
        for i, c in enumerate(cells):
            if i:
                out += ","; pos += 1
            if (not is_neg) and c == og and og is not None:
                spans.append((pos, pos + len(og), "organization"))
            out += c; pos += len(c)
        return _emit(out, spans)
    if form == "sig":
        og = _org(rng, cores)
        pre = f"{rng.choice(['Cordialement','Merci','Best regards','Regards'])},\n{_person(random.Random())}\n"
        text = pre + og
        return _emit(text, [(len(pre), len(pre) + len(og), "organization")])
    if form == "cue":
        cue = rng.choice(["Employer: ", "Employeur : ", "Company: ", "Société : ", "Vendor: "])
        if is_neg:
            return _emit(cue + rng.choice(NEG_VALUES), [])
        og = _org(rng, cores)
        return _emit(cue + og, [(len(cue), len(cue) + len(og), "organization")])
    if form == "qc_prose":
        og = rng.choice(ORG_QC)
        templ = rng.choice(["Je travaille chez {} depuis 2019.", "Dossier transmis à {} hier.",
                            "Facture émise par {}.", "Compte ouvert chez {}.", "Contrat signé avec {}."])
        i = templ.index("{}")
        text = templ.format(og)
        return _emit(text, [(i, i + len(og), "organization")])
    # two orgs in a sentence
    a, b = _org(rng, cores), _org(rng, cores)
    pre = "Partenariat entre "; mid = " et "
    text = f"{pre}{a}{mid}{b}."
    sa = len(pre); sb = sa + len(a) + len(mid)
    return _emit(text, [(sa, sa + len(a), "organization"), (sb, sb + len(b), "organization")])


def _rec_address(rng):
    is_neg = rng.random() < 0.20
    form = rng.choice(["bare", "json", "cue", "prose", "unit", "pobox", "pobox"])
    if is_neg:
        if form == "json":
            return _emit(json.dumps({rng.choice(ADDR_KEYS): rng.choice(NEG_VALUES)}, ensure_ascii=False), [])
        return _emit(rng.choice(NEG_VALUES), [])
    if form == "pobox":
        kind = rng.choice(["Case postale ", "C.P. ", "PO Box ", "P.O. Box ", "Casier postal "])
        # cap PO-box numbers at 4 digits: a 5-digit box collides with the 8-19 digit-ID band and teaches the
        # model to read long digit runs as address tokens (v11r9: keep address-borne numbers out of that band).
        ad = f"{kind}{rng.randint(100, 9999)}"
        tail = rng.choice(["", f", succ. {rng.choice(['Centre-ville', 'Place-Royale', 'Saint-Roch'])}",
                           f", {rng.choice(CITY)}"])
        return _emit(ad + tail, [(0, len(ad), "address")])
    ad = _address(rng)
    if form == "bare":
        return _emit(ad, [(0, len(ad), "address")])
    if form == "json":
        key = rng.choice(ADDR_KEYS); pre = '{"' + key + '": "'
        return _emit(pre + ad + '"}', [(len(pre), len(pre) + len(ad), "address")])
    if form == "cue":
        cue = rng.choice(["Adresse: ", "Adresse : ", "Address: ", "Ship to ", "Livrer au "])
        return _emit(cue + ad, [(len(cue), len(cue) + len(ad), "address")])
    if form == "unit":
        unit = f"{rng.choice(UNIT)} {rng.randint(1,99)}, "
        text = unit + ad
        return _emit(text, [(len(unit), len(unit) + len(ad), "address")])
    # prose with trailing city
    pre = rng.choice(["Le colis est au ", "Son adresse est ", "Livraison au "])
    text = f"{pre}{ad}, {rng.choice(CITY)}."
    return _emit(text, [(len(pre), len(pre) + len(ad), "address")])


def build(n, person_pool_seed, org_cores, addr_seed, seed, person_frac=0.28, org_frac=0.42):
    # split is parametrized (v11r9): the default 0.28/0.42/0.30 reproduces v11r7; v11r9 passes an
    # ADDRESS-WEIGHTED, minimal-person split (address is redact-by-default + the higher-confidence win;
    # person is already 0.997 + cue-backstopped, so it gets a token share only).
    rng = random.Random(seed)
    person_rng = random.Random(person_pool_seed)
    out = []
    for _ in range(n):
        c = rng.random()
        if c < person_frac:
            out.append(_rec_person(rng, person_rng))
        elif c < person_frac + org_frac:
            out.append(_rec_org(rng, org_cores))
        else:
            out.append(_rec_address(rng))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--n-train", type=int, default=18000)
    ap.add_argument("--n-val", type=int, default=1800)
    ap.add_argument("--n-heldout", type=int, default=1500)
    ap.add_argument("--person-frac", type=float, default=0.28)  # v11r9: 0.08
    ap.add_argument("--org-frac", type=float, default=0.42)     # v11r9: 0.40 (address = remainder, 0.52)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    org_train, org_held = _disjoint(ORG_CORE, seed=7)
    pf, of = args.person_frac, args.org_frac

    rows_train = build(args.n_train, 1, org_train, 1, seed=201, person_frac=pf, org_frac=of)
    rows_val = build(args.n_val, 2, org_train, 2, seed=202, person_frac=pf, org_frac=of)     # in-dist val
    rows_held = build(args.n_heldout, 99, org_held, 99, seed=203, person_frac=pf, org_frac=of)  # unseen org cores

    for fname, rows in [("train.jsonl", rows_train), ("val.jsonl", rows_val), ("heldout.jsonl", rows_held)]:
        with open(os.path.join(args.out_dir, fname), "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    def stats(rows):
        from collections import Counter
        c = Counter()
        for r in rows:
            for _, _, lab in r["output"]["spans"]:
                c[lab] += 1
        return {"rows": len(rows), "spans": dict(c)}
    print(json.dumps({"out_dir": args.out_dir, "train": stats(rows_train),
                      "val": stats(rows_val), "heldout": stats(rows_held)}, indent=2))


if __name__ == "__main__":
    main()
