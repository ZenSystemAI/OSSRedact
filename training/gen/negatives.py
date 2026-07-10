#!/usr/bin/env python3
"""negatives generator: PURE-NEGATIVE documents with ZERO PII spans (FR/EN).

This is the clean_fp moat: documents that LOOK like they might carry PII but do not. Every row has
output.spans == [] and output.entities == {} by construction (this generator NEVER calls d.field).
Everything is either filler (d.add) or an explicit hard-negative look-alike (d.decoy) so the model sees
amounts, ISO dates, bare numbers, ports, version strings, private/loopback IPs, build hashes, city/province
names, and bank/merchant names IN CLEAN CONTEXT and learns to leave them alone.

Per research doc 2026-06-14 section 7 (collision rules) the look-alikes that earn their keep here:
 - amounts + ISO dates + bare numeric runs (look like account_number, never cued) -> NEGATIVE.
 - city name / province `QC` / street-type word alone (geography) -> NEGATIVE.
 - private/loopback/link-local IPs -> NEGATIVE (only routable public IP would be ip_address).
 - 64-hex build hash -> NEGATIVE (secret-vs-hash collision rule 7).
 - Stripe PUBLISHABLE key pk_live_/pk_test_ -> NEGATIVE (designed public, rule in section 5).
 - bank/merchant names in a non-account / catalog / news context -> NEGATIVE (org-in-description rule 3).
 - ports, version strings, ticket ids, EFT routing numbers, bare institution/transit fragments -> NEGATIVE.

Several content templates rotate so the negatives are not a single shape: product catalogs, news snippets,
FR/EN prose, code without secrets, tables of amounts/dates/ports/versions, geography blurbs, and
bank/merchant non-account blurbs.

gen(lang) -> one offset-true row dict with spans == []. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random, string
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402

_BANKS = ["Desjardins", "Banque Nationale", "RBC Banque Royale", "TD Canada Trust", "BMO", "Banque Scotia",
          "CIBC", "Tangerine"]
_GENERIC_ORG = ["Acme Logistique", "Boreal Solutions", "Cascade Media", "Atelier Nordique", "Groupe Vertex",
                "Studio Lumiere", "Coop Saint-Roch", "Quartz Analytics", "Maple Foundry", "Orbit Systemes"]
_PROVINCES = ["QC", "Quebec", "Ontario", "Nouveau-Brunswick", "Colombie-Britannique"]
_STREET_TYPES = ["rue", "avenue", "boulevard", "boul.", "chemin", "place"]


# ---- inline decoy value helpers (doctype-specific look-alikes; not in values.py) ----

def _port() -> str:
    return str(random.choice([22, 80, 443, 5432, 6379, 8080, 8001, 8084, 3000, 5173, 9100, 11434]))


def _version() -> str:
    a, b, c = random.randint(0, 24), random.randint(0, 30), random.randint(0, 40)
    pre = random.choice(["", "", "v"])
    suf = random.choice(["", "", "-rc1", "-beta", ".post1"])
    return f"{pre}{a}.{b}.{c}{suf}"


def _pk_live() -> str:
    alnum = string.ascii_letters + string.digits
    kind = random.choice(["pk_live_", "pk_test_"])
    return kind + "".join(random.choice(alnum) for _ in range(24))


def _ticket() -> str:
    return random.choice(["JIRA-", "TICKET-", "SUP-", "OPS-", "BUG-"]) + str(random.randint(100, 9999))


def _sku() -> str:
    return random.choice(["SKU-", "ITEM-", "PROD-", "REF-"]) + "".join(
        random.choice(string.ascii_uppercase) for _ in range(2)) + str(random.randint(1000, 99999))


def _eft_routing() -> str:
    # EFT routing 0 + inst(3) + transit(5) -> NEGATIVE on its own (research section 2)
    inst = f"{random.randint(1, 815):03d}"
    transit = "".join(random.choice("0123456789") for _ in range(5))
    return f"0{inst}{transit}"


def _bare_num() -> str:
    return "".join(random.choice("0123456789") for _ in range(random.randint(7, 11)))


def _pct() -> str:
    return f"{random.randint(1, 99)}{random.choice([' %', '%', ',5 %'])}"


# ---- content templates (each appends only filler + decoys; never a field) ----

def _t_product_catalog(d: Doc, fr: bool):
    d.add(("Catalogue produits " if fr else "Product catalogue ") + random.choice(_GENERIC_ORG) + "\n")
    d.add(("Trimestre " if fr else "Quarter ") + f"Q{random.randint(1,4)} "); d.decoy(str(random.randint(2024, 2027)))
    d.add("\n\n")
    d.add(("Code        Article                         Prix       Stock\n" if fr
           else "Code        Item                            Price      Stock\n"))
    for _ in range(random.randint(5, 14)):
        d.decoy(_sku()); d.add("  ")
        d.decoy(random.choice(["Cable HDMI 2m", "Clavier mecanique", "Souris sans fil", "Moniteur 27 po",
                               "Disque SSD 1 To", "Routeur Wi-Fi 6", "Webcam HD", "Casque audio",
                               "Chargeur USB-C", "Tapis de souris"]))
        d.add("  "); d.decoy(V.amount()); d.add("   "); d.decoy(str(random.randint(0, 480))); d.add("\n")
    d.add(("\nTotal lignes: " if fr else "\nTotal rows: ")); d.decoy(str(random.randint(5, 99)))
    d.add(("  Remise volume " if fr else "  Volume discount ")); d.decoy(_pct()); d.add("\n")


def _t_news(d: Doc, fr: bool):
    org = random.choice(_GENERIC_ORG)
    if fr:
        d.add(org + " ouvre un nouveau centre logistique a ")
        d.decoy(V.city()); d.add(" (" + random.choice(_PROVINCES) + ")\n\n")
        d.add("Publie le "); d.decoy(V.iso_date()); d.add("\n\n")
        d.add(f"L'entreprise prevoit creer "); d.decoy(str(random.randint(40, 600)))
        d.add(" emplois et investir "); d.decoy(V.amount())
        d.add(" sur "); d.decoy(str(random.randint(2, 9))); d.add(" ans. ")
        d.add("Selon la direction, la croissance du chiffre d'affaires a atteint ")
        d.decoy(_pct()); d.add(" au dernier trimestre. La nouvelle installation, situee pres de ")
        d.decoy(V.city()); d.add(", desservira tout le ")
        d.decoy(random.choice(_PROVINCES)) ; d.add(".\n")
    else:
        d.add(org + " opens a new logistics hub in ")
        d.decoy(V.city()); d.add(" (" + random.choice(_PROVINCES) + ")\n\n")
        d.add("Published "); d.decoy(V.iso_date()); d.add("\n\n")
        d.add("The company expects to create "); d.decoy(str(random.randint(40, 600)))
        d.add(" jobs and invest "); d.decoy(V.amount())
        d.add(" over "); d.decoy(str(random.randint(2, 9))); d.add(" years. ")
        d.add("Management said revenue grew "); d.decoy(_pct())
        d.add(" last quarter. The facility near "); d.decoy(V.city())
        d.add(" will serve all of "); d.decoy(random.choice(_PROVINCES)); d.add(".\n")


def _t_prose(d: Doc, fr: bool):
    if fr:
        d.add("Note interne sur la planification du sprint\n\n")
        d.add("L'equipe a revu la feuille de route et convenu de reporter la fonctionnalite ")
        d.add("d'export a la version "); d.decoy(_version()); d.add(". ")
        d.add("Le deploiement vise la semaine du "); d.decoy(V.iso_date()); d.add(". ")
        d.add("Le budget restant est de "); d.decoy(V.amount())
        d.add(" et la velocite moyenne tourne autour de "); d.decoy(str(random.randint(20, 60)))
        d.add(" points. Trois villes pilotes ont ete proposees: ")
        d.decoy(V.city()); d.add(", "); d.decoy(V.city()); d.add(" et "); d.decoy(V.city()); d.add(".\n")
    else:
        d.add("Internal note on sprint planning\n\n")
        d.add("The team reviewed the roadmap and agreed to defer the export feature to release ")
        d.decoy(_version()); d.add(". ")
        d.add("Deployment targets the week of "); d.decoy(V.iso_date()); d.add(". ")
        d.add("Remaining budget is "); d.decoy(V.amount())
        d.add(" and average velocity sits around "); d.decoy(str(random.randint(20, 60)))
        d.add(" points. Three pilot cities were proposed: ")
        d.decoy(V.city()); d.add(", "); d.decoy(V.city()); d.add(" and "); d.decoy(V.city()); d.add(".\n")


def _t_code(d: Doc, fr: bool):
    # code WITHOUT secrets: pk_live (publishable, public), ports, versions, private IPs, build hash, hashes
    d.add(("# Configuration applicative (aucun secret reel)\n" if fr
           else "# Application configuration (no real secrets)\n"))
    d.add("APP_VERSION="); d.decoy(_version()); d.add("\n")
    d.add("HTTP_PORT="); d.decoy(_port()); d.add("\n")
    d.add("REDIS_HOST="); d.decoy(V.private_ip()); d.add(":"); d.decoy(_port()); d.add("\n")
    d.add("DB_HOST="); d.decoy(V.private_ip()); d.add("\n")
    d.add("# Stripe publishable key is safe to expose\n")
    d.add("STRIPE_PUBLISHABLE_KEY="); d.decoy(_pk_live()); d.add("\n")
    d.add("BUILD_SHA="); d.decoy(V.build_hash()); d.add("\n")
    d.add("RELEASE_TICKET="); d.decoy(_ticket()); d.add("\n")
    d.add(("# Voir le ticket pour les details\n" if fr else "# See ticket for details\n"))
    d.add("def health():\n    return {\"status\": \"ok\", \"port\": "); d.decoy(_port())
    d.add(", \"sha\": \""); d.decoy(V.build_hash()[:12]); d.add("\"}\n")


def _t_metrics_table(d: Doc, fr: bool):
    d.add(("Rapport de metriques (" if fr else "Metrics report (")); d.decoy(V.iso_date()); d.add(")\n\n")
    d.add(("Service      Port   Version   Latence   Uptime\n" if fr
           else "Service      Port   Version   Latency   Uptime\n"))
    for name in random.sample(["api", "worker", "cache", "queue", "gateway", "indexer", "scheduler",
                               "auth-svc", "billing", "search"], k=random.randint(4, 8)):
        d.add(name.ljust(12) + " ")
        d.decoy(_port()); d.add("   "); d.decoy(_version()); d.add("   ")
        d.decoy(f"{random.randint(1, 480)} ms"); d.add("   "); d.decoy(_pct()); d.add("\n")
    d.add(("\nHote interne: " if fr else "\nInternal host: ")); d.decoy(V.private_ip())
    d.add("  loopback "); d.decoy("127.0.0.1"); d.add("\n")
    d.add(("Tickets ouverts: " if fr else "Open tickets: ")); d.decoy(_ticket())
    d.add(", "); d.decoy(_ticket()); d.add("\n")


def _t_geography(d: Doc, fr: bool):
    if fr:
        d.add("Guide des villes du "); d.decoy(random.choice(_PROVINCES)); d.add("\n\n")
        for _ in range(random.randint(4, 8)):
            d.decoy(V.city()); d.add(" est situee dans la province de ")
            d.decoy(random.choice(_PROVINCES)); d.add(", population estimee ")
            d.decoy(f"{random.randint(20, 1800)} 000"); d.add(". ")
        d.add("\nLes principaux axes routiers passent par la "); d.decoy(random.choice(_STREET_TYPES))
        d.add(" Principale et le "); d.decoy(random.choice(_STREET_TYPES)); d.add(" du Parc.\n")
    else:
        d.add("Cities guide for "); d.decoy(random.choice(_PROVINCES)); d.add("\n\n")
        for _ in range(random.randint(4, 8)):
            d.decoy(V.city()); d.add(" is located in the province of ")
            d.decoy(random.choice(_PROVINCES)); d.add(", estimated population ")
            d.decoy(f"{random.randint(20, 1800)},000"); d.add(". ")
        d.add("\nMain roads run along the Principale and du Parc corridors.\n")


def _t_bank_noaccount(d: Doc, fr: bool):
    bank = random.choice(_BANKS)
    if fr:
        d.add("Comparatif des frais bancaires\n\n")
        d.add(bank + " a annonce une mise a jour de ses forfaits le ")
        d.decoy(V.iso_date()); d.add(". Le forfait de base coute ")
        d.decoy(V.amount()); d.add(" par mois. ")
        d.add("Le numero de routage EFT publie pour les depots directs est ")
        d.decoy(_eft_routing()); d.add(" (information publique, aucun compte associe). ")
        d.add("Le code d'institution est "); d.decoy(f"{random.randint(1, 815):03d}")
        d.add(" et le transit de la succursale est "); d.decoy(f"{random.randint(0,99999):05d}")
        d.add(". Les marchands acceptes incluent ")
        d.decoy(V.merchant()); d.add(", "); d.decoy(V.merchant()); d.add(" et "); d.decoy(V.merchant())
        d.add(".\n")
    else:
        d.add("Banking fee comparison\n\n")
        d.add(bank + " announced a plan update on ")
        d.decoy(V.iso_date()); d.add(". The basic plan costs ")
        d.decoy(V.amount()); d.add(" per month. ")
        d.add("The published EFT routing number for direct deposits is ")
        d.decoy(_eft_routing()); d.add(" (public info, no account attached). ")
        d.add("The institution code is "); d.decoy(f"{random.randint(1, 815):03d}")
        d.add(" and the branch transit is "); d.decoy(f"{random.randint(0,99999):05d}")
        d.add(". Accepted merchants include ")
        d.decoy(V.merchant()); d.add(", "); d.decoy(V.merchant()); d.add(" and "); d.decoy(V.merchant())
        d.add(".\n")


def _t_invoice_summary(d: Doc, fr: bool):
    # an order/invoice summary that carries amounts, dates, refs, bare numbers but NO holder PII
    d.add(("Sommaire de commande " if fr else "Order summary ")); d.decoy(V.order_ref()); d.add("\n")
    d.add(("Date " if fr else "Date ")); d.decoy(V.iso_date())
    d.add(("  Statut: Complete\n\n" if fr else "  Status: Completed\n\n"))
    d.add(("Article                Qte    Prix\n" if fr else "Item                   Qty    Price\n"))
    for _ in range(random.randint(3, 9)):
        d.decoy(random.choice(["Abonnement annuel", "Frais de service", "Licence logicielle",
                               "Support premium", "Module export", "Stockage 100 Go", "Siege additionnel"]))
        d.add("  x"); d.decoy(str(random.randint(1, 12))); d.add("   "); d.decoy(V.amount()); d.add("\n")
    d.add(("\nSous-total " if fr else "\nSubtotal ")); d.decoy(V.amount())
    d.add(("  TPS " if fr else "  GST ")); d.decoy(V.amount())
    d.add(("  Total " if fr else "  Total ")); d.decoy(V.amount()); d.add("\n")
    d.add(("No de suivi: " if fr else "Tracking no: ")); d.decoy(_bare_num()); d.add("\n")


_TEMPLATES = [_t_product_catalog, _t_news, _t_prose, _t_code, _t_metrics_table,
              _t_geography, _t_bank_noaccount, _t_invoice_summary]


def gen(lang: str = None, split: str = "train") -> dict:
    # `split` accepted for the uniform corpus API; clean-negative FP coverage is needed in BOTH splits.
    lang = lang or ("fr" if random.random() < 0.65 else "en")
    fr = lang == "fr"
    d = Doc(doctype="negatives", lang=lang)
    tmpl = random.choice(_TEMPLATES)
    tmpl(d, fr)
    # optional second block (different template) ~40% of the time, for length variety
    if random.random() < 0.4:
        d.add("\n" + ("=" * random.randint(20, 50)) + "\n\n")
        other = random.choice([t for t in _TEMPLATES if t is not tmpl])
        other(d, fr)
    return d.row()


if __name__ == "__main__":
    random.seed(0)
    for _ in range(2):
        r = gen()
        t = r["input"]
        print("=" * 70, r["meta"]["lang"], r["meta"]["doctype"])
        print(t[:500])
        print("POSITIVES:", [(lab, t[s:e]) for s, e, lab in r["output"]["spans"]])
        print("n_decoys:", r["meta"]["n_decoys"])
        print()
