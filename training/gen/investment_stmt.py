#!/usr/bin/env python3
"""investment_stmt generator: synthetic Quebec/Canada investment / portfolio account statements in the REAL
issuer layouts (Banque Nationale Reseau Independant "BNRI" portfolio statement + BMO Ligne d'action /
ConseilDirect "Comment lire votre releve" InvestorLine insert).

GROUNDED on the two scaffold PDFs (datasets/scaffolds/):
 - pdf-comprendre-releve-portefeuille.pdf : the BNRI "Releve de portefeuille d'investissement" sample. A
   left-aligned identity block ("M. MARC SAMPLE / 123 N'IMPORTE QUELLE RUE / TOUTE VILLE PROVINCE Z1Z 1Z1"),
   an "Information sur ce releve / Identification client #" client-number field, a "Duplicata du releve de
   MM. ELVIRA SAMPLE" second-holder line, a "Votre gestionnaire de portefeuille: <firm>" advisor block with
   a firm phone, then a "Sommaire du portefeuille" holdings grid (account types CAD REER/CELI/FERR, encaisse
   / placements / valeur marchande amounts, % asset-allocation), a "Repartition de l'actif" grid, FX rates,
   and "En date du <date>".
 - Statement_Insert_AD_F.pdf : the BMO Ligne d'action / ConseilDirect "Comment lire votre releve de compte"
   insert. A STRUCTURALLY DIFFERENT bilingual numbered-section narrative (1 Sommaire du compte, 2 Changements
   apportes, 3 Votre taux de rendement, ... 9 Sommaire des frais) with an inline support phone
   ("1-844-274-3762, entre 8 h et 20 h"). This is the HELD-OUT structure (the model never trains on it).

POSITIVES (subject identity only):
 person (account holder; a joint / duplicata holder is also a person), address, postal_code,
 account_number (the "Identification client #" / "No de compte" account-or-client number, via V.bank_account
 or an inline client-number shape), phone_number (the CLIENT's contact phone only).

DECOYS (the false-positive moat): the holdings grid (ticker symbols, quantities, book cost, market value),
 every amount / portfolio total / encaisse / placement / valeur marchande ($), the statement / period /
 "En date du" dates, rates of return (%), the fund / security names (org-shaped -> negative), the
 dealer / advisor firm name + the advisor/support phone (third-party org + third-party phone -> negative),
 the city + province "QC" token, period labels, FX rates, transaction reference ids.

LAYOUTS (>=2 genuinely distinct real structures; held-out = the suffix):
 - _layout_bnri    : BNRI portfolio-summary identity block + holdings grid (CAD REER/CELI/FERR).   [train]
 - _layout_bmo     : BMO Ligne d'action / ConseilDirect numbered-section narrative insert.         [heldout]

gen(lang, split) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402
import layouts                  # noqa: E402

# Dealer / advisor firm names (third party). In the "gestionnaire de portefeuille" / firm line these are
# NEGATIVE decoys (the issuer/advisor, not the subject's identity). Mirrors org_contrast rule 3: an org name
# is only PII in a labeled SUBJECT header, never as the dealer/issuer of the statement.
_DEALERS = ["Boreal Gestion de patrimoine", "Cascade Valeurs mobilieres inc.", "Meridien Conseil financier",
            "Polaris Investissements ltee", "Sommet Gestion privee", "Horizon Capital inc.",
            "Vertex Patrimoine", "Quartz Gestion d'actifs", "Pinacle Valeurs mobilieres",
            "Aurore Conseil en placement", "Granit Gestion de portefeuille", "Nordik Capital"]

# Fund / security names that populate the holdings grid -> ALWAYS decoys (the security held, not the
# subject's identity). Org-shaped on purpose: the model must NOT redact every fund token.
_FUNDS = ["Fonds equilibre Boreal", "FNB indiciel Cascade S&P 500", "Fonds obligataire Meridien",
          "Fonds d'actions canadiennes Polaris", "FNB Sommet dividendes", "Fonds du marche monetaire Horizon",
          "Fonds croissance Vertex", "Fonds revenu fixe Quartz", "FNB Pinacle actions mondiales",
          "Fonds equilibre Aurore", "Obligations du Canada 2,75%", "Fonds technologie Nordik"]

# Holdings-grid registered-account types (real BNRI rows: "CAD REER", "CAD CELI", "CAD FERR").
_ACCT_KINDS = ["CAD REER", "CAD CELI", "CAD FERR", "CAD CRI", "USD REER", "CAD REEE", "CAD compte au comptant"]

# Ticker symbols on the holdings grid -> decoys (security identifiers, never the subject's account).
_TICKERS = ["XIU", "VFV", "ZAG", "XBB", "TDB902", "RBF1018", "NBC450", "VCN", "ZSP", "XEF", "HXT", "VRE"]


def _money(v: float, oqlf: bool = True) -> str:
    """A holdings/portfolio amount in CAD. Real BNRI prints OQLF '56 350,80' (space thousands, comma decimal)
    and a trailing ' $' in some columns. ALWAYS a decoy."""
    if oqlf:
        whole = f"{int(abs(v)):,}".replace(",", " ")
        s = f"{whole},{int(round((abs(v) - int(abs(v))) * 100)):02d}"
    else:
        s = f"{abs(v):,.2f}"
    s = s + " $" if random.random() < 0.5 else s
    return ("-" + s) if v < 0 else s


def _pct() -> str:
    """A rate-of-return / asset-allocation percentage -> decoy. OQLF comma decimal."""
    return f"{random.randint(0, 99)},{random.randint(0, 9)}"


def _client_no() -> str:
    """A brokerage 'Identification client #' / 'No de compte' value -> account_number. Per COLLISION RULE 1
    (account_number = a numeric/bare/hyphenated run; an opaque ALPHANUMERIC ref is sensitive_account_id), we
    emit only NUMERIC forms here. v11 round-1 routed a short alphanumeric branch ('2YTEST'-style) to
    account_number, which contradicted the sensitive_account_id supervision elsewhere and drove the
    account_number<->sensitive_account_id confusion; numeric-only restores scheme consistency."""
    if random.random() < 0.6:
        return V.bank_account(form=random.choice(["hyphen", "bare", "bare10"]))
    # numeric account number with a dash group
    return f"{random.randint(100,999)}-{random.randint(100000,999999)}"


def _fx_line(fr: bool) -> str:
    """An FX rate line ('1,00 USD = 1,357220 CAD') -> decoy."""
    rate = f"{random.uniform(1.2, 1.45):.6f}".replace(".", ",")
    return f"1,00 USD = {rate} CAD"


def _ticker() -> str:
    return random.choice(_TICKERS)


def _qty() -> str:
    """A quantity of units/shares held -> decoy."""
    return f"{random.randint(1, 4000):,}".replace(",", " ") + ("," + f"{random.randint(0,999):03d}"
                                                                if random.random() < 0.4 else "")


# ---------------- layout A: BNRI portfolio summary + holdings grid (train) ----------------

def _layout_bnri(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="investment_stmt", lang=lang)
    dealer = random.choice(_DEALERS)

    # ---- masthead + statement metadata (all decoys) ----
    d.add("Releve de portefeuille d'investissement\n" if fr else "Investment portfolio statement\n")
    d.add(("En date du " if fr else "As of "))
    d.decoy(V.request_datetime(lang)); d.add("\n\n")     # statement date (date WITH time) -> decoy

    # ---- left identity block (the only identity PII) ----
    title = random.choice(["M.", "Mme", "Me"] if fr else ["Mr.", "Mrs.", "Ms."])
    d.add(title + " ")
    d.field(V.person(lang, caps=(random.random() < 0.7)), "person"); d.add("\n")
    d.field(V.street_address(lang), "address"); d.add("\n")
    d.add(V.city() + " QC ")                              # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n\n")

    # ---- "Information sur ce releve" client-number block ----
    # cue diversity (recall-first): the account/client number is sometimes formally labeled, sometimes
    # terse, sometimes a BARE positional run with no 'Field:' cue -- teaches the model that a bare numeric
    # run in the identity strip is an account_number, not only a label-prefixed one (the v11 round-1 gap).
    d.add(("Information sur ce releve\n" if fr else "About this statement\n"))
    _ac = random.random()
    if _ac < 0.45:
        d.add(("Identification client #  " if fr else "Client identification #  "))
        d.field(_client_no(), "account_number"); d.add("\n")
    elif _ac < 0.75:
        d.add(("No de compte  " if fr else "Account no.  "))
        d.field(_client_no(), "account_number"); d.add("\n")
    else:
        d.add("   "); d.field(_client_no(), "account_number"); d.add("\n")   # bare positional run

    # duplicata / joint holder (a second person positive) -- real sample: "Ceci est un duplicata du releve
    # de MM. ELVIRA SAMPLE"
    if random.random() < 0.55:
        d.add(("Ceci est un duplicata du releve de " if fr else "This is a duplicate of the statement of "))
        d.add(random.choice(["MM.", "M.", "Mme"] if fr else ["Mr.", "Mrs.", "Ms."]) + " ")
        d.field(V.person(lang, caps=(random.random() < 0.7)), "person"); d.add("\n")

    # client contact phone (a CLIENT phone positive) -- distinct from the advisor firm phone below
    if random.random() < 0.6:
        d.add(("Telephone du titulaire: " if fr else "Account holder phone: "))
        d.field(V.phone(), "phone_number"); d.add("\n")
    d.add("\n")

    # ---- advisor / dealer block: firm name + firm phone are THIRD-PARTY -> decoys ----
    d.add(("Pour nous joindre\n" if fr else "Contact us\n"))
    d.add(("Votre gestionnaire de portefeuille: " if fr else "Your portfolio manager: "))
    d.decoy(dealer); d.add("\n")
    d.decoy(V.phone()); d.add("\n\n")                     # advisor firm phone -> NEGATIVE (third party)

    # ---- "Sommaire du portefeuille" holdings grid (dense decoys) ----
    d.add(("Sommaire du portefeuille\n" if fr else "Portfolio summary\n"))
    d.add(("Periode precedente: " if fr else "Previous period: ")); d.decoy(V.iso_date()); d.add("  ")
    d.add(("Periode en cours: " if fr else "Current period: ")); d.decoy(V.iso_date()); d.add("\n")
    if fr:
        d.add("Type de compte        Encaisse ($)   Placements ($)   Total ($)   %\n")
    else:
        d.add("Account type          Cash ($)       Investments ($)  Total ($)   %\n")
    total = 0.0
    for kind in random.sample(_ACCT_KINDS, k=random.randint(2, 4)):
        cash = random.uniform(0, 9000); inv = random.uniform(0, 80000); tot = cash + inv
        total += tot
        d.add(kind + "   ")
        d.decoy(_money(cash)); d.add("   "); d.decoy(_money(inv)); d.add("   ")
        d.decoy(_money(tot)); d.add("   "); d.decoy(_pct()); d.add("\n")
    d.add(("Total   " if fr else "Total   ")); d.decoy(_money(total)); d.add("   ")
    d.decoy("100,0"); d.add("\n\n")

    # ---- "Repartition de l'actif" + holdings detail (ticker / qty / market value -> decoys) ----
    d.add(("Repartition de l'actif du portefeuille\n" if fr else "Portfolio asset allocation\n"))
    if fr:
        d.add("Placement                      Symbole   Quantite   Valeur marchande ($)   Rendement %\n")
    else:
        d.add("Holding                        Symbol    Quantity   Market value ($)       Return %\n")
    for _ in range(random.randint(4, 10)):
        d.decoy(random.choice(_FUNDS)); d.add("   ")     # fund/security name -> NEGATIVE
        d.decoy(_ticker()); d.add("   ")                 # ticker symbol -> NEGATIVE
        d.decoy(_qty()); d.add("   ")                    # quantity -> NEGATIVE
        d.decoy(_money(random.uniform(50, 40000))); d.add("   ")
        d.decoy(_pct()); d.add("\n")

    # ---- FX + footer (decoys) ----
    d.add(("Taux de change: " if fr else "Exchange rate: ")); d.decoy(_fx_line(fr)); d.add("\n")
    d.add(("Ref. operation: " if fr else "Transaction ref.: ")); d.decoy(V.order_ref()); d.add("\n")
    d.add(("Le present releve vous est emis par " if fr else "This statement is issued to you by "))
    d.decoy(dealer)                                       # issuer firm in free text -> NEGATIVE (no header)
    d.add(("." if fr else "."))
    return d.row()


# ---------------- layout B (HELD-OUT): BMO Ligne d'action / ConseilDirect numbered-section insert ----

def _layout_bmo(lang: str) -> dict:
    fr = lang == "fr"
    d = Doc(doctype="investment_stmt", lang=lang)
    dealer = random.choice(["BMO Ligne d'action", "ConseilDirect de BMO Ligne d'action",
                            "BMO Gestion de patrimoine", "BMO Ligne d'action Inc."])

    # ---- insert masthead (decoys) ----
    d.add(dealer + "   12/16 INSERT AD F\n")
    d.add(("Comment lire votre releve de compte de BMO Ligne d'action\n\n" if fr
           else "How to read your BMO InvestorLine account statement\n\n"))

    # ---- small subject identity strip (the only PII) -- the insert is mailed with the holder's statement ----
    if fr:
        d.add("Titulaire du compte: ")
    else:
        d.add("Account holder: ")
    d.field(V.person(lang, caps=(random.random() < 0.4)), "person"); d.add("\n")
    if fr:
        d.add("No de compte: ")
    else:
        d.add("Account no.: ")
    d.field(_client_no(), "account_number"); d.add("\n")
    d.field(V.street_address(lang), "address"); d.add(", ")
    d.add(V.city() + " QC ")                              # city + province -> NEGATIVE
    d.field(V.postal_code(), "postal_code"); d.add("\n")
    if random.random() < 0.5:
        d.add(("Tel.: " if fr else "Tel.: ")); d.field(V.phone(), "phone_number"); d.add("\n")
    d.add("\n")

    # ---- numbered narrative sections (the structural signature of this insert) ----
    secs_fr = [
        ("1", "Le Sommaire du compte vous donne un apercu de vos placements. Il comprend les placements "
              "effectues dans des titres canadiens, americains ou etrangers, leur valeur a l'ouverture et a "
              "la cloture ainsi que le solde de votre compte pour le mois couvert par le releve."),
        ("2", "La section Changements apportes a votre compte presente un sommaire de tous les depots et "
              "retraits effectues dans votre compte ainsi que le changement de la valeur marchande de vos "
              "placements."),
        ("3", "La section Votre taux de rendement comprend les rendements ponderes en fonction des capitaux "
              "investis et en fonction de la duree, calcules une fois par an."),
        ("4", "La section propre aux Comptes enregistres et CELI affiche les renseignements specifiques a ces "
              "types de comptes, soit vos cotisations et les beneficiaires figurant a votre compte."),
        ("5", "Le Sommaire de vos placements en dollars canadiens contient des renseignements sur la "
              "repartition de l'actif pour l'ensemble des placements detenus dans votre compte."),
        ("6", "La section Revenu que vous avez recu presente la repartition de chaque source de revenus pour "
              "votre compte, notamment les interets, les dividendes et les distributions."),
        ("7", "La section Details sur vos placements affiche les elements contenus dans chacune des categories "
              "de placement, notamment la quantite de parts detenues, le cout et la valeur marchande."),
        ("8", "La section Operations dans le compte pour le mois en cours offre un sommaire de toutes les "
              "transactions qui ont ete effectuees."),
        ("9", "Le Sommaire des frais de votre compte depuis le debut de l'annee presente une vue d'ensemble "
              "de tous les frais percus a partir des activites de votre compte."),
    ]
    secs_en = [
        ("1", "The Account Summary gives you an overview of your investments. It includes investments made in "
              "Canadian, U.S. or foreign securities, their opening and closing value and your account balance "
              "for the month covered by the statement."),
        ("2", "The Changes to Your Account section presents a summary of all deposits and withdrawals made in "
              "your account as well as the change in the market value of your investments."),
        ("3", "The Your Rate of Return section includes money-weighted and time-weighted returns, calculated "
              "once per year."),
        ("4", "The Registered Accounts and TFSA section displays information specific to these account types, "
              "namely your contributions and the beneficiaries listed on your account."),
        ("5", "The Summary of Your Investments in Canadian Dollars contains information on the asset allocation "
              "for all the investments held in your account."),
        ("6", "The Income You Received section presents the breakdown of each income source for your account, "
              "including interest, dividends and distributions."),
        ("7", "The Details on Your Investments section displays the items contained in each investment "
              "category, namely the quantity of units held, the cost and the market value."),
        ("8", "The Activity in the Account for the Current Month section offers a summary of all transactions "
              "that were carried out."),
        ("9", "The Fees Summary for your account since the beginning of the year presents an overview of all "
              "the fees charged from your account activity."),
    ]
    for num, body in (secs_fr if fr else secs_en):
        d.add(num + "  " + body + "\n")

    # ---- a numbered-narrative line happens to cite a holdings figure / date -> decoys ----
    d.add(("Tous les comptes ouverts avant le " if fr else "All accounts opened before "))
    d.decoy(V.iso_date()); d.add(("ont cette date comme date de debut. " if fr else "have this date as their start date. "))
    d.add(("Valeur marchande de cloture: " if fr else "Closing market value: ")); d.decoy(_money(random.uniform(1000, 90000)))
    d.add(("  Rendement: " if fr else "  Return: ")); d.decoy(_pct()); d.add(" %\n")

    # ---- support phone (THIRD-PARTY dealer line) -> decoy -- real insert: "1-844-274-3762, entre 8 h et 20 h"
    if fr:
        d.add("Pour obtenir de plus amples renseignements, veuillez communiquer avec un specialiste en "
              "placements de ConseilDirect en composant le ")
    else:
        d.add("For more information, please contact a ConseilDirect investment specialist by calling ")
    d.decoy(random.choice(["1-844-274-3762", "1-888-776-6886", "1-800-361-1392"]))
    d.add((", entre 8 h et 20 h (HE), du lundi au vendredi.\n" if fr
           else ", between 8 a.m. and 8 p.m. (ET), Monday to Friday.\n"))

    # ---- legal footer: the issuer firm name in free text -> NEGATIVE (no subject header) ----
    d.add(("MD Marque de commerce deposee de la Banque de Montreal, utilisee sous licence. " if fr
           else "Registered trademark of Bank of Montreal, used under licence. "))
    d.decoy(dealer)
    d.add((" est membre du Fonds canadien de protection des epargnants." if fr
           else " is a member of the Canadian Investor Protection Fund."))
    return d.row()


LAYOUTS = [_layout_bnri, _layout_bmo]    # BMO numbered-section insert (suffix) = held-out structure


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
