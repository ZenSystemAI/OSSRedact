#!/usr/bin/env python3
"""Synthetic PII value generators for the Quebec/Canada corpus (design + research doc 2026-06-14).

Every value is FAKE but STRUCTURALLY FAITHFUL: SINs/cards are Luhn-valid (decoys are Luhn-invalid by
construction), RAMQ NAMs encode the +50-female month rule, postal codes use Quebec G/H/J FSAs with the
excluded-letter set, phones use real Quebec NPAs, bank accounts use the institution-first format the
canonical parser expects. NO real person's data is ever produced. Uses module `random`; callers seed it
(build_dataset and build_heldout seed DIFFERENTLY so the held-out set never overlaps train).

Facts source: docs/research/2026-06-14-qc-pii-data-formats.md. Only SIN/card (Luhn) and IBAN (mod-97) have
verifiable checksums; RAMQ/SAAQ are structural-only (no public check digit).
"""
from __future__ import annotations
import random
import string

# ----- small synthetic name/place pools (common, generic; not real individuals) -----
# Quebec French is ACCENTED (real documents carry accents). The `accents` augmenter (augment.py) strips
# them length-preserving so the model also sees the PDF-extraction-mangled ASCII forms. So pools here use
# the real accented spelling.
_FIRST_FR = ["Marie", "Jean", "Pierre", "Sophie", "Luc", "Nathalie", "Marc", "Isabelle", "François",
             "Julie", "Martin", "Catherine", "André", "Geneviève", "Simon", "Caroline", "Mathieu", "Chantal",
             "Hélène", "Frédéric", "Élise", "Gaétan", "Andrée", "Réjean", "Cécile", "Étienne", "Josée", "Émilie"]
_FIRST_EN = ["John", "Sarah", "Michael", "Emily", "David", "Jessica", "Robert", "Ashley", "James", "Amanda"]
_LAST = ["Tremblay", "Gagnon", "Roy", "Côté", "Bouchard", "Gauthier", "Morin", "Lavoie", "Fortin", "Gagné",
         "Ouellet", "Pelletier", "Bélanger", "Lévesque", "Bergeron", "Girard", "Smith", "Brown", "Wilson",
         "Thériault", "Bédard", "Hébert", "Légaré", "Pépin", "St-Pierre", "Dubé", "Bouchard-Gagné"]
_STREET_TYPES_FR = ["rue", "avenue", "boulevard", "boul.", "chemin", "place", "côte"]
_STREET_NAMES = ["Principale", "Saint-Laurent", "Sainte-Catherine", "des Érables", "René-Lévesque",
                 "du Parc", "Notre-Dame", "Sherbrooke", "Wellington", "Cartier", "des Pins", "Laurier"]
_CITIES = ["Montréal", "Québec", "Laval", "Gatineau", "Sherbrooke", "Trois-Rivières", "Longueuil",
           "Saguenay", "Lévis", "Terrebonne", "Drummondville", "Granby", "Repentigny"]
# generic synthetic company/org name pieces (NOT real companies); shared by employer/issuer/provider doctypes
_ORG_WORDS = ["Boréal", "Cascade", "Cèdre", "Granit", "Horizon", "Lumière", "Méridien", "Nordik", "Polaris",
              "Saphir", "Vertex", "Zéphyr", "Quartz", "Atelier", "Sommet", "Rivière", "Pinacle", "Aurore"]
_ORG_SUFFIX_FR = ["Solutions inc.", "Technologies", "Conseil", "Groupe", "Services", "Industries",
                  "Logistique", "Construction", "Distribution ltée", "Gestion", "Marketing inc."]
_ORG_SUFFIX_EN = ["Solutions Inc.", "Technologies", "Consulting", "Group", "Services", "Industries",
                  "Logistics", "Construction", "Distribution Ltd.", "Holdings", "Marketing Inc."]
# Quebec NPAs (research doc section 4)
_NPA = ["514", "438", "450", "579", "418", "581", "367", "819", "873", "263", "468"]
# Postal: Quebec FSAs start G/H/J; excluded letters anywhere: D F I O Q U (+ W Z never lead)
_FSA_FIRST = "GHJ"
_PC_LETTERS = "ABCEGHJKLMNPRSTVXY"   # excludes D F I O Q U W Z
# Institution codes (authoritative, research doc section 2)
_INSTITUTIONS = {"001": "BMO", "002": "Scotia", "003": "RBC", "004": "TD", "006": "BNC", "010": "CIBC",
                 "614": "Tangerine", "815": "Desjardins"}


# ASCII accent fold for ID codes that are A-Z only (RAMQ NAM letters strip accents in the real format).
_ASCII_FOLD = str.maketrans(
    "àâäáãçčéèêëěíìîïñóòôöõšúùûüýÿžÀÂÄÁÃÇČÉÈÊËĚÍÌÎÏÑÓÒÔÖÕŠÚÙÛÜÝŸŽ",
    "aaaaacceeeeeiiiinooooosuuuuyyzAAAAACCEEEEEIIIINOOOOOSUUUUYYZ",
)


def _fold(s: str) -> str:
    return s.translate(_ASCII_FOLD)


def _luhn_ok(d: str) -> bool:
    s = 0
    for i, c in enumerate(reversed(d)):
        x = int(c)
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        s += x
    return s % 10 == 0


def _luhn_complete(prefix: str) -> str:
    for d in "0123456789":
        if _luhn_ok(prefix + d):
            return prefix + d
    raise RuntimeError("unreachable")


def _break_luhn(valid: str) -> str:
    # flip the last digit so the result FAILS Luhn (for decoys)
    return valid[:-1] + str((int(valid[-1]) + 7) % 10)


def _group(digits: str, sizes, sep) -> str:
    out, i = [], 0
    for n in sizes:
        out.append(digits[i:i + n]); i += n
    if i < len(digits):
        out.append(digits[i:])
    return sep.join(p for p in out if p)


# ---------------- catastrophic-tier values ----------------

def sin(valid: bool = True) -> str:
    """9-digit SIN, Quebec region (first digit 2 or 3), Luhn-valid (or Luhn-invalid if valid=False)."""
    body = random.choice("23") + "".join(random.choice("0123456789") for _ in range(7))
    full = _luhn_complete(body)
    if not valid:
        full = _break_luhn(full)
    style = random.random()
    if style < 0.5:
        return _group(full, (3, 3, 3), " ")
    if style < 0.75:
        return _group(full, (3, 3, 3), "-")
    return full


def payment_card(valid: bool = True) -> str:
    """Visa(16)/MC(16)/Amex(15) PAN, Luhn-valid (or invalid if valid=False)."""
    kind = random.random()
    if kind < 0.45:
        prefix, length, sizes = "4", 16, (4, 4, 4, 4)                       # Visa
    elif kind < 0.85:
        prefix, length, sizes = random.choice(["51", "52", "53", "54", "55"]), 16, (4, 4, 4, 4)  # MC
    else:
        prefix, length, sizes = random.choice(["34", "37"]), 15, (4, 6, 5)  # Amex
    body = prefix + "".join(random.choice("0123456789") for _ in range(length - 1 - len(prefix)))
    full = _luhn_complete(body)
    if not valid:
        full = _break_luhn(full)
    return _group(full, sizes, random.choice([" ", "-", ""]))


def cvv() -> str:
    return "".join(random.choice("0123456789") for _ in range(random.choice([3, 3, 4])))


def card_expiry() -> str:
    mm = f"{random.randint(1, 12):02d}"
    yy = random.randint(26, 32)
    return f"{mm}/{yy}" if random.random() < 0.6 else f"{mm}/20{yy}"


def ramq_nam(sex: str = None, year: int = None, month: int = None, day: int = None) -> str:
    """Quebec health insurance number: 4 letters + YY MM(+50 if F) DD + 2 admin digits. Structural only."""
    sex = sex or random.choice("MF")
    last = "".join(c for c in _fold(random.choice(_LAST)).upper() if c.isalpha())
    given = "".join(c for c in _fold(random.choice(_FIRST_FR)).upper() if c.isalpha())
    letters = (last[:3].ljust(3, "X") + given[0])
    y = year if year is not None else random.randint(45, 99)
    m = month if month is not None else random.randint(1, 12)
    d = day if day is not None else random.randint(1, 28)
    mm = m + 50 if sex == "F" else m
    admin = f"{random.randint(0, 99):02d}"
    digits = f"{y:02d}{mm:02d}{d:02d}{admin}"
    return f"{letters} {digits[:4]} {digits[4:]}" if random.random() < 0.6 else letters + digits


def saaq_permis() -> str:
    """Quebec driver licence: 1 letter + 12 digits (structural only, no checksum)."""
    return random.choice(string.ascii_uppercase) + "".join(random.choice("0123456789") for _ in range(12))


def iban(valid: bool = True) -> str:
    """Foreign IBAN, mod-97 valid (Canada issues none; keep rare). GB-style: GB kk BBBB ssssss cccccccc."""
    bank = "".join(random.choice(string.ascii_uppercase) for _ in range(4))
    bban = bank + "".join(random.choice("0123456789") for _ in range(14))
    # compute check digits so that mod-97 == 1
    rearr = bban + "GB00"
    num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearr)
    check = 98 - (int(num) % 97)
    cc = f"{check:02d}" if valid else f"{(check % 90) + 5:02d}"
    full = "GB" + cc + bban
    return _group(full, (4, 4, 4, 4, 4), " ")


def bank_account(form: str = None) -> str:
    """Canadian account: institution-first III-TTTT(T)-AAAAAAAAA (parser format), or a bare 7/10/11-digit run."""
    inst = random.choice(list(_INSTITUTIONS))
    transit = "".join(random.choice("0123456789") for _ in range(random.choice([4, 5])))
    acct = "".join(random.choice("0123456789") for _ in range(random.randint(6, 9)))
    form = form or random.choice(["hyphen", "hyphen", "bare", "bare10", "bare11"])
    if form == "hyphen":
        return f"{inst}-{transit}-{acct}"
    if form == "bare":
        return "".join(random.choice("0123456789") for _ in range(random.randint(7, 9)))
    if form == "bare10":
        return "".join(random.choice("0123456789") for _ in range(10))
    return "".join(random.choice("0123456789") for _ in range(11))


def uuid4() -> str:
    h = "".join(random.choice("0123456789abcdef") for _ in range(32))
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def interac_ref() -> str:
    return "CA" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(6))


def tax_id() -> str:
    kind = random.random()
    n9 = "".join(random.choice("0123456789") for _ in range(9))
    if kind < 0.4:
        return f"{n9}RT{random.randint(0,9999):04d}"        # GST/HST
    if kind < 0.7:
        return "".join(random.choice("0123456789") for _ in range(10)) + f"TQ{random.randint(0,9999):04d}"  # QST
    return "".join(random.choice("0123456789") for _ in range(10))                                      # NEQ


# ---------------- operational-tier values ----------------

def person(lang: str = "fr", caps: bool = None) -> str:
    first = random.choice(_FIRST_FR if lang == "fr" else _FIRST_EN)
    name = f"{first} {random.choice(_LAST)}"
    caps = random.random() < 0.6 if caps is None else caps
    return name.upper() if caps else name


def email() -> str:
    # email local parts are ASCII: fold accents off the FR name pieces (Légaré -> legare)
    first = _fold(random.choice(_FIRST_FR + _FIRST_EN)).lower()
    last = _fold(random.choice(_LAST)).lower().replace("-", "")
    user = first + random.choice([".", "_", ""]) + last
    dom = random.choice(["videotron.ca", "gmail.com", "hotmail.com", "outlook.com", "sympatico.ca", "yahoo.ca"])
    return f"{user}@{dom}"


def postal_code() -> str:
    a = random.choice(_FSA_FIRST)
    b = random.choice("0123456789")
    c = random.choice(_PC_LETTERS)
    d = random.choice("0123456789")
    e = random.choice(_PC_LETTERS)
    f = random.choice("0123456789")
    sep = " " if random.random() < 0.7 else ""
    return f"{a}{b}{c}{sep}{d}{e}{f}"


def phone() -> str:
    npa = random.choice(_NPA)
    mid = f"{random.randint(0,999):03d}"
    last = f"01{random.randint(0,99):02d}"        # 555-01XX-style fictional block
    nxx = "555"
    style = random.random()
    if style < 0.4:
        return f"{npa}-{nxx}-{last}"
    if style < 0.6:
        return f"({npa}) {nxx}-{last}"
    if style < 0.8:
        return f"+1 {npa} {nxx} {last}"
    return f"{npa}.{nxx}.{last}"


def street_address(lang: str = "fr") -> str:
    num = random.randint(10, 9999)
    st = f"{num}, {random.choice(_STREET_TYPES_FR)} {random.choice(_STREET_NAMES)}"
    if random.random() < 0.3:
        st += f", app. {random.randint(1, 40)}"
    return st


def city() -> str:
    return random.choice(_CITIES)


def company(lang: str = "fr") -> str:
    """A generic synthetic Quebec company name (employer / issuer / dealer / provider). NOT a real company.
    Shared by tax-slip employer fields, GST/QST returns, NEQ register, investment dealers, employment letters."""
    suf = random.choice(_ORG_SUFFIX_FR if lang == "fr" else _ORG_SUFFIX_EN)
    name = f"{random.choice(_ORG_WORDS)} {suf}"
    return name.upper() if random.random() < 0.25 else name


# ---------------- secrets / credentials / system ----------------

def secret() -> str:
    kind = random.random()
    alnum = string.ascii_letters + string.digits
    if kind < 0.18:
        return "sk-" + "".join(random.choice(alnum) for _ in range(48))
    if kind < 0.32:
        return "sk-ant-api03-" + "".join(random.choice(alnum + "_-") for _ in range(40))
    if kind < 0.46:
        return "hf_" + "".join(random.choice(alnum) for _ in range(34))
    if kind < 0.60:
        return "ghp_" + "".join(random.choice(alnum) for _ in range(36))
    if kind < 0.72:
        return "AKIA" + "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
    if kind < 0.84:
        return "xoxb-" + "-".join("".join(random.choice("0123456789") for _ in range(11)) for _ in range(2)) \
               + "-" + "".join(random.choice(alnum) for _ in range(24))
    return "sk_live_" + "".join(random.choice(alnum) for _ in range(24))


_PW_WORDS = ["Hiver", "Montreal", "Soleil", "Hockey", "Caramel", "Pomme", "Voyage", "Liberte", "Erable",
             "Castor", "Riviere", "Boreal", "Tempete", "Cerise", "Lynx", "Cedre", "Orignal", "Banquise"]


def password() -> str:
    """Diverse human + machine password shapes. NEVER contains '@': @ collides with email AND the
    user:pass@host connection-string delimiter, which was the main password->email confusion (v10 round 1:
    xlm-r-base password R=0.848 with 50 password->email errors). Shape diversity (not one template) teaches
    'the value after a password cue, ANY shape, is password' rather than memorizing one pattern."""
    style = random.random()
    if style < 0.30:                                    # word + symbol + digits
        return random.choice(_PW_WORDS) + random.choice("!#$%&*?._-") + str(random.randint(10, 99999))
    if style < 0.55:                                    # random alphanumeric 12-20
        return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(12, 20)))
    if style < 0.75:                                    # passphrase word-word-word(-word)
        return "-".join(random.choice(_PW_WORDS).lower() for _ in range(random.randint(3, 4)))
    if style < 0.92:                                    # mixed letters/digits/symbols 10-16 (no @)
        return "".join(random.choice(string.ascii_letters + string.digits + "!#$%*_-")
                       for _ in range(random.randint(10, 16)))
    return random.choice(_PW_WORDS).lower() + str(random.randint(1000, 9999))   # simple word+digits


def username() -> str:
    # usernames are ASCII: fold accents off the name pieces
    base = _fold(random.choice(_FIRST_FR + _FIRST_EN)).lower()
    suffix = random.choice(["", str(random.randint(1, 99)), _fold(random.choice(_LAST)).lower()[:4]])
    return base + suffix


def file_path() -> str:
    user = username()
    if random.random() < 0.6:
        return f"/home/{user}/" + random.choice([".ssh/id_rsa", ".env", "documents/releve.pdf", ".aws/credentials"])
    return rf"C:\\Users\\{user}\\" + random.choice(["Documents\\\\releve.pdf", "AppData\\\\secrets.txt"])


def public_ip() -> str:
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 172, 192):
            continue
        return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def private_ip() -> str:
    return random.choice([
        f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
        f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "127.0.0.1",
    ])


# ---------------- decoys (hard negatives) + filler ----------------

def amount() -> str:
    val = random.randint(1, 9999) + random.random()
    if random.random() < 0.5:
        return f"{val:,.2f} $"                                   # Flinks style 1,234.56 $
    return f"{int(val):,}".replace(",", " ") + f",{random.randint(0,99):02d} $"   # OQLF 1 234,56 $


def iso_date() -> str:
    return f"20{random.randint(20,26):02d}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"


_MONTHS_FR = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août",
              "septembre", "octobre", "novembre", "décembre"]
_MONTHS_EN = ["January", "February", "March", "April", "May", "June", "July", "August",
              "September", "October", "November", "December"]


def dob(lang: str = "fr") -> str:
    """A CUED birth date (date_of_birth positive). Several real shapes: DD/MM/YYYY, ISO, long month-name form
    ('12 mars 1987' FR / 'March 12, 1987' EN). Birth years 1940-2006. Used wherever a 'date de naissance' /
    'date of birth' cue introduces it; a bare ISO date elsewhere stays a NEGATIVE (transaction date)."""
    d = random.randint(1, 28); m = random.randint(1, 12); y = random.randint(1940, 2006)
    style = random.random()
    if style < 0.35:
        return f"{d:02d}/{m:02d}/{y}"
    if style < 0.6:
        return f"{y}-{m:02d}-{d:02d}"
    if lang == "fr":
        return f"{d} {_MONTHS_FR[m-1]} {y}"
    return f"{_MONTHS_EN[m-1]} {d}, {y}"


def request_datetime(lang: str = "fr") -> str:
    """A long-form date WITH a time (Flinks/statement request datetime, 'Dernière actualisation', issue
    timestamp). This is a DECOY in statement headers (the parser treats date-with-time as request metadata,
    not DOB). Distinct from dob() by the trailing clock time. Use via d.decoy()."""
    d = random.randint(1, 28); m = random.randint(1, 12); y = random.randint(2024, 2026)
    hh = random.randint(0, 23); mm = random.choice(["00", "15", "30", "45", f"{random.randint(0,59):02d}"])
    if lang == "fr":
        return f"{d} {_MONTHS_FR[m-1]} {y} {hh:02d}:{mm}"
    ap = "a.m." if hh < 12 else "p.m."
    h12 = hh % 12 or 12
    return f"{_MONTHS_EN[m-1]} {d}, {y}, {h12}:{mm} {ap}"


def build_hash() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(64))


def order_ref() -> str:
    return random.choice(["CMD-", "REF-", "ORD-"]) + str(random.randint(1000000, 99999999))


def merchant() -> str:
    return random.choice(["IGA", "METRO", "COSTCO WHOLESALE", "AMAZON.CA", "HYDRO-QUEBEC", "BELL CANADA",
                          "VIDEOTRON", "PHARMAPRIX", "TIM HORTONS", "PETRO-CANADA", "SAQ", "RONA"])
