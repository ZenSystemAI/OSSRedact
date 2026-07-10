#!/usr/bin/env python3
"""Build the v11r9 WIN heldout from the DOCUMENTED firewall-stress leak forms (RESULT-stress-v11r6-firewall.md).

The original 52 cases were measured live (not committed). This reconstructs the exact FAILURE FORMS the stress
test flagged -- org 8/10 leak, address weak on EN/PO-box/directional/rural -- by a hand-authored path (NOT
augment_v11r7's pools), so it is a non-circular WIN proof: after v11r9, how many of these org/address values
are covered? Offsets are computed by .find() so they are exact. 100% synthetic values (public Quebec
institutions are public entities, not PII; firms/addresses are fabricated).

Output: validation/stress_orgaddr_heldout.jsonl  (schema matches the corpus).
"""
import json
import os

OUT = os.path.join(os.path.dirname(__file__), 'stress_orgaddr_heldout.jsonl')

# (template_with_{v}, value, label). One sensitive value per case (the thing the stress test checked for cover).
INSTITUTIONS = ['Hydro-Québec', 'Revenu Québec', 'Desjardins', 'la SAAQ', 'Loto-Québec', 'la SQDC']
FIRMS = ['Béland & Associés inc.', 'Lavoie & Fils', 'Tremblay Construction Ltée', 'Groupe Patry SENC',
         'Bouchard & Gagnon', 'Fortin Légal inc.', 'Côté Désign', 'Roy & Frères Ltée']
ORG_TEMPLATES = [
    'Je travaille chez {v} depuis 2019.',
    "J'ai un rendez-vous à {v} demain matin.",
    'Le contrat de service est avec {v}.',
    'We signed with {v} last week.',
    'Veuillez facturer {v} pour ce mandat.',
    'Cordialement,\nMarie Tremblay\n{v}',
    '{{"company": "{v}", "status": "active"}}',
    'company,{v},QC',
    'Notre partenaire principal demeure {v} cette année.',
    'La soumission provient de {v}.',
]
# two-org sentence (both spans)
TWO_ORG = [('{a} a fusionné avec {b} en 2021.', 'a', 'b')]

ADDR_VALUES = [
    '200 King St W', '450 Sherbrooke Ave E', '1200 Maisonneuve Blvd W', '88 Wellington St N',
    'Case postale 6204', 'C.P. 1370', '1500 boul. René-Lévesque Ouest', '760 rue Saint-Jean Est',
    '601 rang Sainte-Catherine', '42 route des Pionniers', '15 chemin du Lac Ouest',
]
ADDR_TEMPLATES = [
    'Ship to {v}, please confirm.',
    "L'envoi va au {v}, succ. Centre-ville.",
    'Notre bureau est au {v}, Montréal.',
    'Livrer à {v} avant vendredi.',
    'billing_address,{v},QC',
    '{{"ship_to": "{v}"}}',
]


def _case(text, value, label):
    i = text.find(value)
    assert i >= 0, f'value not in text: {value!r} / {text!r}'
    return {'input': text, 'output': {'spans': [[i, i + len(value), label]], 'entities': {}},
            'meta': {'src': 'stress_heldout'}}


def build():
    rows = []
    vals = INSTITUTIONS + FIRMS
    for ti, t in enumerate(ORG_TEMPLATES):
        for vi, v in enumerate(vals):
            if (ti + vi) % 3:  # ~1/3 of the cross product -> a spread, not every combo
                continue
            rows.append(_case(t.format(v=v), v, 'organization'))
    for t, ka, kb in TWO_ORG:
        for a, b in [('Groupe Patry SENC', 'Lavoie & Fils'), ('Desjardins', 'Béland & Associés inc.')]:
            txt = t.format(a=a, b=b)
            i, j = txt.find(a), txt.find(b)
            rows.append({'input': txt, 'output': {'spans': [[i, i + len(a), 'organization'],
                         [j, j + len(b), 'organization']], 'entities': {}}, 'meta': {'src': 'stress_heldout'}})
    for ti, t in enumerate(ADDR_TEMPLATES):
        for vi, v in enumerate(ADDR_VALUES):
            if (ti + vi) % 2:
                continue
            rows.append(_case(t.format(v=v), v, 'address'))
    return rows


def main():
    rows = build()
    with open(OUT, 'w', encoding='utf-8') as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + '\n')
    n_org = sum(1 for r in rows for s in r['output']['spans'] if s[2] == 'organization')
    n_addr = sum(1 for r in rows for s in r['output']['spans'] if s[2] == 'address')
    print(f'{len(rows)} cases -> {OUT}  (organization spans {n_org}, address spans {n_addr})')


if __name__ == '__main__':
    main()
