#!/usr/bin/env python3
"""v11r9c sid<->postal DISAMBIGUATION contrast.

The v11r9/v11r9b regression was specific and reproducible: adding organization/address coverage (which carries
Canadian postal codes) shifted the model's prior so short alphanumeric Quebec-context tokens drift from
sensitive_account_id -> postal_code, dropping sid recall ~1.4-2.4% below the v11r6 floor. Dose-tuning alone did
not fix it (v11r9b "balanced" still failed sid), because the two label families share a SURFACE shape
(short alphanumeric Quebec tokens) and only CONTEXT separates them:

  sensitive_account_id : EFX-BHWBY5ADV2, M932J6KHW3N, a UUID, 2016-R-5838791, CMD-56077531   (dossier/reference cues)
  postal_code          : H3S 1G3, J6R0R5, G4Y 7J1                                            (address cues)

This slice teaches the separation directly: each sid surface form appears under dossier/reference/customer-id
cues (-> sensitive_account_id), each postal under address cues (-> postal_code), and -- the key signal -- a
large block of MIXED documents carries BOTH in one record so the model must use context, not shape, to label
them. Heavily weighted toward sid + mixed so the net pulls sid recall back up without giving back the address WIN.

100% synthetic (random surface forms; public Quebec city/region names are not PII). Offsets are exact (.find on
a cursor). Schema matches the corpus: {"input","output":{"spans":[[s,e,label]],"entities":{}},"meta":{"src":...}}.
"""
import argparse
import json
import os
import random
import string

CITIES = ['Montreal', 'Quebec', 'Laval', 'Gatineau', 'Longueuil', 'Sherbrooke', 'Levis', 'Trois-Rivieres',
          'Saguenay', 'Terrebonne', 'Saint-Jean-sur-Richelieu', 'Repentigny', 'Drummondville', 'Granby']
STREETS = ['rue Saint-Denis', 'boul. Rene-Levesque', 'avenue du Parc', 'rue Sainte-Catherine', 'chemin Chambly',
           'rue Principale', 'boul. Taschereau', 'rue King Ouest', 'avenue Cartier', '3e Avenue', 'rang Saint-Joseph']
NAMES = ['Marc Tremblay', 'Sophie Gagnon', 'Luc Bergeron', 'Nadia Roy', 'Eric Cote', 'Julie Bouchard',
         'Patrick Lavoie', 'Caroline Fortin', 'Martin Pelletier', 'Isabelle Girard']

# ---- sid surface forms (mirror the real corpus shapes) ----
def _alnum(rng, n):
    return ''.join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def _uuid(rng):
    h = '0123456789abcdef'
    g = lambda n: ''.join(rng.choice(h) for _ in range(n))
    return f'{g(8)}-{g(4)}-{g(4)}-{g(4)}-{g(12)}'


def _sid_value(rng):
    f = rng.random()
    if f < 0.22:
        return 'EFX-' + _alnum(rng, rng.choice([9, 10, 11]))
    if f < 0.40:
        return _uuid(rng).upper() if rng.random() < 0.5 else _uuid(rng)
    if f < 0.55:
        return _alnum(rng, rng.choice([10, 11, 12]))
    if f < 0.70:
        return f'{rng.randint(1960, 2024)}-{rng.choice("RBLX")}-{rng.randint(1000000, 9999999)}'
    if f < 0.82:
        return rng.choice(['CMD', 'DOS', 'REF', 'CAS']) + '-' + str(rng.randint(10000000, 99999999))
    if f < 0.92:
        d = str(rng.randint(0, 9))
        return ' '.join(_digits4(rng) for _ in range(rng.choice([2, 3])))  # grouped digit run (Revenu Quebec style)
    return _alnum(rng, 7) + str(rng.randint(100, 999))


def _digits4(rng):
    return ''.join(str(rng.randint(0, 9)) for _ in range(4))


# ---- postal code (Canadian; Quebec prefixes G/H/J dominate, but include others) ----
def _postal(rng):
    a = rng.choice('GHJKLNABCEK')
    b = rng.randint(0, 9)
    c = rng.choice(string.ascii_uppercase.replace('D', '').replace('F', '').replace('I', '').replace('O', '')
                   .replace('Q', '').replace('U', ''))
    d = rng.randint(0, 9)
    e = rng.choice(string.ascii_uppercase)
    f = rng.randint(0, 9)
    sep = ' ' if rng.random() < 0.8 else ''
    return f'{a}{b}{c}{sep}{d}{e}{f}'


# ---- cue templates ----
SID_CUES_FR = ['Numero de dossier: {v}', 'Reference client {v}', 'ID unique du consommateur {v}',
               'Numero de reference: {v}', 'Numero de dossier Equifax {v}', 'No de cas {v}',
               'Identifiant du dossier {v}', 'Votre numero de demande est {v}']
SID_CUES_EN = ['Case number {v}', 'Customer ID: {v}', 'Reference: {v}', 'Account reference {v}',
               'File number {v}', 'Your case ID is {v}']
POSTAL_CUES_FR = ['{city} (Quebec) {v}', 'Code postal: {v}', 'Adresse: {street}, {city}, {v}',
                  'Livraison au {street}, {city} {v}', 'C. P. {box}, {city} (Quebec) {v}']
POSTAL_CUES_EN = ['{city}, QC {v}', 'Postal code: {v}', 'Mailing address: {street}, {city}, QC {v}',
                  'Ship to {street}, {city}, Quebec {v}']


def _emit(text, spans, src='augment_sid_postal_contrast'):
    return {'input': text, 'output': {'spans': spans, 'entities': {}}, 'meta': {'src': src}}


def _span(text, value, label, start=0):
    i = text.find(value, start)
    assert i >= 0, f'value {value!r} not in {text!r}'
    return [i, i + len(value), label], i + len(value)


def _sid_only(rng):
    v = _sid_value(rng)
    t = rng.choice(SID_CUES_FR + SID_CUES_EN).format(v=v)
    sp, _ = _span(t, v, 'sensitive_account_id')
    return _emit(t, [sp])


def _postal_only(rng):
    v = _postal(rng)
    t = rng.choice(POSTAL_CUES_FR + POSTAL_CUES_EN).format(
        v=v, city=rng.choice(CITIES), street=rng.choice(STREETS), box=rng.randint(1000, 9999))
    sp, _ = _span(t, v, 'postal_code')
    return _emit(t, [sp])


MIXED = [
    'Dossier {sid}\nAdresse: {street}, {city} (Quebec) {postal}',
    'Customer ID {sid}. Mailing address: {street}, {city}, QC {postal}.',
    'Formulaire KYC\nNumero de dossier: {sid}\n{name}\n{street}\n{city} (Quebec) {postal}',
    'Reference {sid} -- livrer au {street}, {city} {postal}',
    'No de cas {sid}\nCode postal {postal}\nClient: {name}',
    'Releve de compte\nID unique {sid}\n{name}, {street}, {city} (Quebec) {postal}',
    'File {sid} | ship to {street}, {city}, Quebec {postal}',
]


def _mixed(rng):
    sid = _sid_value(rng)
    postal = _postal(rng)
    name = rng.choice(NAMES)
    t = rng.choice(MIXED).format(sid=sid, postal=postal, name=name,
                                 street=rng.choice(STREETS), city=rng.choice(CITIES))
    spans = []
    cur = 0
    sp, cur = _span(t, sid, 'sensitive_account_id', 0)
    spans.append(sp)
    sp, _ = _span(t, postal, 'postal_code', 0)
    spans.append(sp)
    if name in t:
        sp, _ = _span(t, name, 'person', 0)
        spans.append(sp)
    spans.sort()
    return _emit(t, spans)


def build(n, seed):
    rng = random.Random(seed)
    rows = []
    for _ in range(n):
        r = rng.random()
        if r < 0.42:
            rows.append(_sid_only(rng))      # heavy sid signal
        elif r < 0.62:
            rows.append(_postal_only(rng))   # postal anchor
        else:
            rows.append(_mixed(rng))         # both -> context disambiguation (the key signal)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out-dir', required=True)
    ap.add_argument('--n-train', type=int, default=3000)
    ap.add_argument('--n-val', type=int, default=300)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    for split, n, seed in [('train', args.n_train, 771), ('val', args.n_val, 772)]:
        rows = build(n, seed)
        path = os.path.join(args.out_dir, f'sid_postal_contrast_{split}.jsonl')
        with open(path, 'w', encoding='utf-8') as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + '\n')
        nsid = sum(1 for r in rows for s in r['output']['spans'] if s[2] == 'sensitive_account_id')
        npost = sum(1 for r in rows for s in r['output']['spans'] if s[2] == 'postal_code')
        print(f'{split}: {len(rows)} rows -> {path}  (sid spans {nsid}, postal spans {npost})')


if __name__ == '__main__':
    main()
