#!/usr/bin/env python3
"""Generate a BIG synthetic Québec PII corpus for validating the OSSRedact gate.

100% SYNTHETIC. Every name/SIN/email/account/secret is fabricated from curated pools + random.
No real client data is ever read. Secrets are format-valid but fake (random bodies), never real keys.

Emits corpus.jsonl: one doc per line -> {id, doctype, lang, text, truth:{cat:[values]}, decoys:[values]}.
`truth` = the exact substrings injected (for recall + leak checking). `decoys` = look-alikes that must
NOT be flagged (invalid-Luhn ids, benign hashes, order numbers) = false-positive probes / "wrenches".
"""
import json, random, sys, string

SEED = 20260614
random.seed(SEED)

N = int(sys.argv[1]) if len(sys.argv) > 1 else 800
OUT = sys.argv[2] if len(sys.argv) > 2 else 'corpus.jsonl'

# ---- curated Québec pools (synthetic) ----
FR_FIRST = ['Jean', 'Marie', 'Pierre', 'Sophie', 'Luc', 'Geneviève', 'François', 'Hélène', 'André',
            'Béatrice', 'Léa', 'Noémie', 'Mathieu', 'Émilie', 'Gabriel', 'Camille', 'Olivier', 'Désirée',
            'Jean-François', 'Marie-Ève', 'Pierre-Luc', 'Anne-Sophie', 'Charles-Antoine', 'Frédéric']
EN_FIRST = ['John', 'Sarah', 'Michael', 'Emily', 'David', 'Jessica', 'Daniel', 'Ashley', 'James', 'Laura',
            'Robert', 'Megan', 'William', 'Rachel', 'Thomas', 'Hannah', 'Christopher', 'Nicole']
LAST = ['Tremblay', 'Gagnon', 'Roy', 'Côté', 'Bouchard', 'Gauthier', 'Morin', 'Lavoie', 'Fortin', 'Gagné',
        'Bélanger', 'Lévesque', 'Bergeron', 'Girard', 'Pelletier', 'Caron', 'Cloutier', 'Boucher', 'Ouellet',
        'Bouchard-Gagné', 'St-Pierre', 'Lévesque-Roy', 'Dubé', 'Desjardins', 'Thériault', 'Beaulieu']
CITIES = ['Montréal', 'Québec', 'Laval', 'Gatineau', 'Sherbrooke', 'Trois-Rivières', 'Saguenay', 'Longueuil',
          'Lévis', 'Drummondville', 'Saint-Jérôme', 'Repentigny', 'Brossard', 'Rimouski']
STREETS = ['rue Sainte-Catherine', 'boul. René-Lévesque', 'avenue du Mont-Royal', 'chemin de la Côte-des-Neiges',
           'rue Saint-Denis', 'boul. Henri-Bourassa', 'rue Sherbrooke', 'avenue du Parc', 'rue Wellington',
           'boul. Taschereau', 'rue Notre-Dame', 'chemin Chambly']
AREA = ['514', '438', '450', '579', '418', '581', '819', '873', '367']
EMAIL_DOM = ['gmail.com', 'hotmail.com', 'outlook.com', 'videotron.ca', 'sympatico.ca', 'example.qc.ca',
             'me.com', 'yahoo.ca']
BANKS_FR = ['Banque Nationale', 'Desjardins', 'Banque Royale', 'Banque TD', 'Banque Scotia', 'BMO']
BANKS_EN = ['National Bank', 'Desjardins', 'Royal Bank', 'TD Bank', 'Scotiabank', 'BMO']
MERCHANTS = ['Metro', 'IGA', 'Provigo', 'Jean Coutu', 'Pharmaprix', 'Canadian Tire', 'SAQ', 'Hydro-Québec',
             'Vidéotron', 'Bell', 'Costco', 'Amazon', 'Uber', 'Tim Hortons', 'STM']
MONTHS_FR = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre',
             'novembre', 'décembre']
MONTHS_EN = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October',
             'November', 'December']
NBSP = ' '


def luhn_complete(prefix_digits):
    """Append a Luhn check digit so the value passes the gate's Luhn validator (SIN, credit card)."""
    digs = [int(c) for c in prefix_digits]
    s = 0
    for i, d in enumerate(reversed(digs)):
        d = d * 2 if i % 2 == 0 else d
        if d > 9:
            d -= 9
        s += d
    return prefix_digits + str((10 - s % 10) % 10)


def rand_digits(n):
    return ''.join(random.choice('0123456789') for _ in range(n))


def b62(n):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def hexs(n):
    return ''.join(random.choice('0123456789abcdef') for _ in range(n))


def name(lang):
    first = random.choice(FR_FIRST if lang == 'fr' else (FR_FIRST + EN_FIRST))
    return f"{first} {random.choice(LAST)}"


def sin():
    # 9-digit, Luhn-valid (real SINs are Luhn-valid). Spaced groups, sometimes NBSP (wrench).
    base = luhn_complete(rand_digits(8))
    sep = NBSP if random.random() < 0.15 else ' '
    return f"{base[0:3]}{sep}{base[3:6]}{sep}{base[6:9]}"


def invalid_sin():
    # 9-digit that FAILS Luhn -> must NOT be flagged as government_id (false-positive wrench)
    while True:
        d = rand_digits(9)
        if luhn_complete(d[:8]) != d:
            return f"{d[0:3]} {d[3:6]} {d[6:9]}"


def phone():
    a = random.choice(AREA)
    mid, last = rand_digits(3), rand_digits(4)
    fmt = random.choice([f"({a}) {mid}-{last}", f"{a}.{mid}.{last}", f"{a}-{mid}-{last}", f"+1 {a} {mid} {last}"])
    return fmt


def email(person):
    base = person.lower().replace(' ', '.').replace('é', 'e').replace('è', 'e').replace('ç', 'c').replace('à', 'a').replace('ê', 'e').replace('-', '')
    n = random.choice(['', str(random.randint(1, 99))])
    return f"{base}{n}@{random.choice(EMAIL_DOM)}"


def address():
    return f"{random.randint(10, 9999)} {random.choice(STREETS)}, {random.choice(CITIES)} (Québec)"


def postal():
    L = string.ascii_uppercase
    return f"{random.choice('GHJ')}{random.choice('0123456789')}{random.choice(L)} {random.choice('0123456789')}{random.choice(L)}{random.choice('0123456789')}"


def account():
    return f"{rand_digits(5)}-{rand_digits(3)}-{rand_digits(7)}"


def uuid():
    return f"{hexs(8)}-{hexs(4)}-{hexs(4)}-{hexs(4)}-{hexs(12)}"


def credit_card():
    return luhn_complete(rand_digits(15))


def date_fr():
    return f"{random.randint(1, 28)} {random.choice(MONTHS_FR)} {random.randint(2023, 2026)}"


def date_en():
    return f"{random.choice(MONTHS_EN)} {random.randint(1, 28)}, {random.randint(2023, 2026)}"


def amount():
    return f"{random.randint(5, 8999)},{random.randint(0,99):02d} $"


# ---- secrets (format-valid, fake bodies) ----
def secret_value():
    kind = random.choice(['openai', 'openai_proj', 'aws', 'github', 'slack', 'jwt', 'bearer', 'conn_pg',
                          'conn_mongo', 'gcp', 'stripe', 'private_key'])
    if kind == 'openai':
        return f"sk-{b62(48)}"
    if kind == 'openai_proj':
        return f"sk-proj-{b62(48)}"
    if kind == 'aws':
        return 'AKIA' + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    if kind == 'github':
        return f"ghp_{b62(36)}"
    if kind == 'slack':
        return f"xoxb-{rand_digits(12)}-{rand_digits(12)}-{b62(24)}"
    if kind == 'jwt':
        return f"eyJ{b62(20)}.eyJ{b62(40)}.{b62(43)}"
    if kind == 'bearer':
        return b62(40)
    if kind == 'conn_pg':
        return f"postgres://svc_{b62(6)}:{b62(20)}@db{random.randint(1,9)}.internal:5432/app"
    if kind == 'conn_mongo':
        return f"mongodb+srv://admin:{b62(18)}@cluster0.{b62(5)}.mongodb.net/prod"
    if kind == 'gcp':
        return f"AIza{b62(35)}"
    if kind == 'stripe':
        return f"sk_live_{b62(40)}"
    if kind == 'private_key':
        body = '\n'.join(b62(64) for _ in range(4))
        return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    return b62(40)


def benign_hash():
    # 40 or 64 hex = git sha / sha256 -> the gate's _BENIGN_HASH filter should NOT redact these
    return hexs(random.choice([40, 64]))


def order_no():
    return f"CMD-{rand_digits(8)}"  # order number, must NOT be flagged


# ===================== document builders =====================
def add(truth, cat, val):
    truth.setdefault(cat, []).append(val)
    return val


def doc_bank_fr(truth, decoys):
    p = name('fr'); a = address(); s = sin(); ph = phone(); em = email(p); acc = account(); uid = uuid()
    add(truth, 'person', p); add(truth, 'address', a); add(truth, 'government_id', s)
    add(truth, 'phone', ph); add(truth, 'email', em); add(truth, 'sensitive_account_id', acc)
    add(truth, 'sensitive_account_id', uid)
    d1, d2 = date_fr(), date_fr(); add(truth, 'date', d1); add(truth, 'date', d2)
    lines = []
    for _ in range(random.randint(8, 22)):
        d = date_fr(); add(truth, 'date', d)
        m = random.choice(MERCHANTS)
        if random.random() < 0.4:
            other = name('fr'); add(truth, 'person', other)
            desc = f"Virement Interac à {other}"
        else:
            desc = f"Achat {m}"
        lines.append(f"{d:<22} {desc:<40} {amount():>12}")
    dec = invalid_sin(); decoys.append(dec)
    txt = (f"RELEVÉ BANCAIRE \u2014 {random.choice(BANKS_FR)}\n"
           f"Titulaire: {p}\nAdresse: {a} {postal()}\nNAS: {s}\n"
           f"Téléphone: {ph}    Courriel: {em}\n"
           f"No de compte: {acc}    Identifiant de connexion: {uid}\n"
           f"No de référence interne (non sensible): {dec}\n"
           f"Période: du {d1} au {d2}\n\n"
           "Date                   Description                              Montant\n"
           + '\n'.join(lines) + f"\nSolde de clôture: {amount()}\n")
    return 'bank_fr', 'fr', txt


def doc_bank_en(truth, decoys):
    p = name('en'); a = address(); s = sin(); ph = phone(); em = email(p); acc = account(); uid = uuid()
    add(truth, 'person', p); add(truth, 'address', a); add(truth, 'government_id', s)
    add(truth, 'phone', ph); add(truth, 'email', em); add(truth, 'sensitive_account_id', acc)
    add(truth, 'sensitive_account_id', uid)
    cc = credit_card(); add(truth, 'credit_card', cc)
    d1, d2 = date_en(), date_en(); add(truth, 'date', d1); add(truth, 'date', d2)
    lines = []
    for _ in range(random.randint(8, 20)):
        d = date_en(); add(truth, 'date', d)
        lines.append(f"{d:<22} {('Purchase ' + random.choice(MERCHANTS)):<40} {amount():>12}")
    txt = (f"ACCOUNT STATEMENT \u2014 {random.choice(BANKS_EN)}\n"
           f"Account holder: {p}\nAddress: {a} {postal()}\nSIN: {s}\n"
           f"Phone: {ph}    Email: {em}\n"
           f"Account No: {acc}    Card on file: {cc}    Session ID: {uid}\n"
           f"Period: {d1} to {d2}\n\n"
           "Date                   Description                              Amount\n"
           + '\n'.join(lines) + f"\nClosing balance: {amount()}\n")
    return 'bank_en', 'en', txt


def doc_email_thread(truth, decoys):
    lang = random.choice(['fr', 'en'])
    p1, p2 = name(lang), name(lang); add(truth, 'person', p1); add(truth, 'person', p2)
    e1, e2 = email(p1), email(p2); add(truth, 'email', e1); add(truth, 'email', e2)
    ph = phone(); add(truth, 'phone', ph)
    s = sin(); add(truth, 'government_id', s)
    if lang == 'fr':
        txt = (f"De: {p1} <{e1}>\nÀ: {p2} <{e2}>\nObjet: Dossier de prêt\n\n"
               f"Bonjour {p2.split()[0]},\n\nMerci de confirmer votre NAS ({s}) et votre numéro: {ph}. "
               f"Je vous rappelle à {address()}. Mon collègue {name('fr')} suivra le dossier.\n\n"
               f"Cordialement,\n{p1}\n{e1}\n")
    else:
        txt = (f"From: {p1} <{e1}>\nTo: {p2} <{e2}>\nSubject: Loan file\n\n"
               f"Hi {p2.split()[0]},\n\nPlease confirm your SIN ({s}) and phone {ph}. "
               f"I will call you back. My colleague {name('en')} will follow up.\n\nBest,\n{p1}\n{e1}\n")
    return 'email_thread', lang, txt


def doc_env(truth, decoys):
    lines = ["# .env \u2014 service configuration"]
    keys = ['OPENAI_API_KEY', 'AWS_ACCESS_KEY_ID', 'GITHUB_TOKEN', 'SLACK_BOT_TOKEN', 'STRIPE_SECRET_KEY',
            'DATABASE_URL', 'MONGO_URI', 'JWT_SECRET', 'GCP_API_KEY', 'SESSION_SECRET']
    for k in random.sample(keys, random.randint(6, 10)):
        v = secret_value(); add(truth, 'secret', v)
        if '\n' in v:  # private key as single env line
            v = v.replace('\n', '\\n')
            add(truth, 'secret', v)  # store the escaped form actually in text
            truth['secret'] = [x for x in truth['secret'] if '-----BEGIN' not in x or '\\n' in x]
        lines.append(f"{k}={v}")
    lines.append(f"ADMIN_EMAIL={email(name('en'))}")
    add(truth, 'email', lines[-1].split('=', 1)[1])
    lines.append(f"# build sha {benign_hash()}"); decoys.append(lines[-1].split()[-1])
    return 'env_file', 'en', '\n'.join(lines) + '\n'


def doc_code(truth, decoys):
    p = name('en'); add(truth, 'person', p); em = email(p); add(truth, 'email', em)
    sk = secret_value(); add(truth, 'secret', sk)
    conn = f"postgres://app:{b62(20)}@10.0.0.{random.randint(2,250)}:5432/db"
    add(truth, 'secret', conn)
    sha = benign_hash(); decoys.append(sha)
    txt = ("# settings.py \u2014 generated config\n"
           "import os\n\n"
           f'OWNER = "{p}"  # contact {em}\n'
           f'API_KEY = "{sk}"\n'
           f'DATABASE_URL = "{conn}"\n'
           f'RELEASE_SHA = "{sha}"  # not a secret\n'
           "DEBUG = False\n")
    return 'code', 'en', txt


def doc_csv(truth, decoys):
    lang = random.choice(['fr', 'en'])
    rows = ['nom,courriel,telephone,nas,code_postal,compte' if lang == 'fr'
            else 'name,email,phone,sin,postal,account']
    for _ in range(random.randint(20, 45)):
        p = name(lang); em = email(p); ph = phone(); s = sin(); pc = postal(); acc = account()
        add(truth, 'person', p); add(truth, 'email', em); add(truth, 'phone', ph)
        add(truth, 'government_id', s); add(truth, 'sensitive_account_id', acc)
        rows.append(f"{p},{em},{ph},{s},{pc},{acc}")
    return 'csv_export', lang, '\n'.join(rows) + '\n'


def doc_form(truth, decoys):
    lang = random.choice(['fr', 'en'])
    p = name(lang); a = address(); s = sin(); ph = phone(); em = email(p); pc = postal()
    add(truth, 'person', p); add(truth, 'address', a); add(truth, 'government_id', s)
    add(truth, 'phone', ph); add(truth, 'email', em)
    emp = name(lang); add(truth, 'person', emp)
    if lang == 'fr':
        txt = (f"DEMANDE DE FINANCEMENT\nNom du demandeur: {p}\nAdresse: {a} {pc}\n"
               f"NAS: {s}\nTéléphone: {ph}\nCourriel: {em}\n"
               f"Employeur: Solutions {emp.split()[-1]} inc.  Contact RH: {emp}\n"
               f"Revenu annuel: {amount()}  Date de naissance: {date_fr()}\n")
        add(truth, 'date', txt.split('Date de naissance: ')[1].strip())
    else:
        txt = (f"FINANCING APPLICATION\nApplicant: {p}\nAddress: {a} {pc}\n"
               f"SIN: {s}\nPhone: {ph}\nEmail: {em}\n"
               f"Employer: {emp.split()[-1]} Solutions Inc.  HR contact: {emp}\n"
               f"Annual income: {amount()}  Date of birth: {date_en()}\n")
        add(truth, 'date', txt.split('Date of birth: ')[1].strip())
    return 'form', lang, txt


def doc_wrench(truth, decoys):
    """Adversarial: ALL-CAPS names, mixed FR/EN, a >600-char unbroken line (chunker hard-window test),
    benign hashes + invalid SIN decoys, accented compound names."""
    p = name('fr').upper(); add(truth, 'person', p)
    s = sin(); add(truth, 'government_id', s)
    em = email(name('fr')); add(truth, 'email', em)
    uid = uuid(); add(truth, 'sensitive_account_id', uid)
    # one very long single line with PII tail past 600 chars (regression guard for the chunker fix)
    filler = "Note de dossier interne sans renseignement personnel particulier mais assez longue pour dépasser la fenêtre du modèle. " * 6
    tail_name = name('fr'); add(truth, 'person', tail_name)
    tail_email = email(tail_name); add(truth, 'email', tail_email)
    longline = filler + f" Client en fin de ligne: {tail_name}, courriel {tail_email}, NAS {sin_for(truth)}."
    decoys.append(benign_hash()); decoys.append(invalid_sin()); decoys.append(order_no())
    txt = (f"DOSSIER MIXTE / MIXED FILE\nClient: {p}  (SIN/NAS: {s})  email: {em}\n"
           f"Session: {uid}   Ref commande (non sensible): {decoys[-1]}\n"
           f"Hash build (non sensible): {decoys[0]}\n"
           f"Numéro interne non valide (décoy): {decoys[1]}\n"
           f"{longline}\n")
    return 'wrench', 'mixed', txt


def sin_for(truth):
    s = sin(); add(truth, 'government_id', s); return s


BUILDERS = [
    (doc_bank_fr, 16), (doc_bank_en, 14), (doc_csv, 18), (doc_email_thread, 14),
    (doc_form, 12), (doc_env, 9), (doc_code, 9), (doc_wrench, 8),
]
_weighted = [b for b, w in BUILDERS for _ in range(w)]

with open(OUT, 'w', encoding='utf-8') as f:
    for i in range(N):
        truth, decoys = {}, []
        builder = random.choice(_weighted)
        doctype, lang, text = builder(truth, decoys)
        f.write(json.dumps({'id': i, 'doctype': doctype, 'lang': lang, 'text': text,
                            'truth': truth, 'decoys': decoys}, ensure_ascii=False) + '\n')

# summary
from collections import Counter
import json as _j
types = Counter(); cats = Counter(); ndecoy = 0; total_chars = 0
for line in open(OUT, encoding='utf-8'):
    d = _j.loads(line)
    types[d['doctype']] += 1
    total_chars += len(d['text'])
    ndecoy += len(d['decoys'])
    for c, vs in d['truth'].items():
        cats[c] += len(vs)
print(f"wrote {N} docs -> {OUT}  ({total_chars/1e6:.2f} MB text)")
print("doctypes:", dict(types))
print("injected truth spans:", dict(cats), " total =", sum(cats.values()))
print("decoys (must NOT be flagged):", ndecoy)
