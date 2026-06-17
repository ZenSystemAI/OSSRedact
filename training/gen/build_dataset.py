#!/usr/bin/env python3
"""Compose all offset-true generators into the pii-merged-v11 corpus (full re-grounding).

v11 re-grounds the corpus on REAL Quebec/Canada document STRUCTURE (24 generators, each grounded on a real
scaffold or, for the digital-PII doctypes, a synthetic structure). build_dataset draws TRAIN structures
(split='train'); build_heldout draws the DISJOINT held-out structures (split='heldout') so the eval measures
generalization to real layouts the model never trained on (operator data strategy 2026-06-15). A fraction of
rows are augmented (caps / nbsp / unicode-dashes / accent-fold) and ADDED (originals kept) so the model sees
both clean and PDF-extraction-mangled forms. Rows are the offset-true shape {input, output:{spans,entities}, meta}.

Pure Python (stdlib only): runs anywhere, no torch. Writes train.jsonl + val.jsonl + labels.json.
Usage: python build_dataset.py --out <dir> [--total 32000] [--val-total 3200] [--seed 1] [--aug-frac 0.25]
"""
from __future__ import annotations
import sys, os, json, random, argparse, collections, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# scaffold-grounded doctypes (real document structure)
import flinks, bank_statement, credit_card_stmt, investment_stmt, void_cheque                 # banking  # noqa: E402
import tax_slip, tax_return, tax_notice                                                       # tax      # noqa: E402
import ramq_card, saaq_licence, birth_cert, sin_letter                                        # identity # noqa: E402
import insurance, telecom_bill, neq_register, credit_report, restaurant_facture               # other    # noqa: E402
import email_receipt, employment_lease                                                        # comms    # noqa: E402
# synthetic-structure digital-PII doctypes (label coverage + FP control; split-agnostic)
import kyc, credential_dump, system_log, org_contrast, negatives                                          # noqa: E402
from augment import augmenters  # noqa: E402

GEN = {
    'flinks': flinks.gen, 'bank_statement': bank_statement.gen, 'credit_card_stmt': credit_card_stmt.gen,
    'investment_stmt': investment_stmt.gen, 'void_cheque': void_cheque.gen,
    'tax_slip': tax_slip.gen, 'tax_return': tax_return.gen, 'tax_notice': tax_notice.gen,
    'ramq_card': ramq_card.gen, 'saaq_licence': saaq_licence.gen, 'birth_cert': birth_cert.gen,
    'sin_letter': sin_letter.gen, 'insurance': insurance.gen, 'telecom_bill': telecom_bill.gen,
    'neq_register': neq_register.gen, 'credit_report': credit_report.gen,
    'restaurant_facture': restaurant_facture.gen, 'email_receipt': email_receipt.gen,
    'employment_lease': employment_lease.gen,
    'kyc': kyc.gen, 'credential_dump': credential_dump.gen, 'system_log': system_log.gen,
    'org_contrast': org_contrast.gen, 'negatives': negatives.gen,
}

# Volume mix. Moat (flinks transaction decoys) + the catastrophic-ID carriers dominate; negatives carry
# clean-FP coverage; credential_dump/system_log are the SOLE source of secret/password/username/file_path/
# public-ip so they need real volume. Weights are normalized in build() (need not sum to exactly 1).
WEIGHTS = {
    # moat + digital-PII (label coverage + FP control)
    'flinks': 0.100, 'kyc': 0.080, 'negatives': 0.080, 'credential_dump': 0.055, 'system_log': 0.040,
    'org_contrast': 0.040,
    # catastrophic-ID-bearing scaffold doctypes (SIN / NAM / permis / cards / tax_id)
    'tax_slip': 0.045, 'sin_letter': 0.042, 'tax_notice': 0.042, 'credit_report': 0.045,
    'ramq_card': 0.040, 'saaq_licence': 0.040, 'birth_cert': 0.038,
    # other scaffold doctypes
    'bank_statement': 0.030, 'credit_card_stmt': 0.030, 'investment_stmt': 0.026, 'void_cheque': 0.024,
    'tax_return': 0.030, 'insurance': 0.028, 'telecom_bill': 0.028, 'neq_register': 0.026,
    'restaurant_facture': 0.030, 'email_receipt': 0.028, 'employment_lease': 0.026,
}
_LABELS_PATH = os.path.join(os.path.dirname(__file__), '..', 'labels_v20.json')


def build(total: int, seed: int, aug_frac: float, split: str = 'train'):
    random.seed(seed)
    wsum = sum(WEIGHTS.values())
    rows = []
    for name, w in WEIGHTS.items():
        n = max(1, round(total * w / wsum))
        gen = GEN[name]
        for _ in range(n):
            rows.append(gen(split=split))
    # augment a fraction: ADD perturbed copies (keep the originals too)
    augs = list(augmenters().values())
    n_aug = int(len(rows) * aug_frac)
    for r in random.sample(rows, min(n_aug, len(rows))):
        rows.append(random.choice(augs)(r))
    random.shuffle(rows)
    return rows


def label_counts(rows):
    c = collections.Counter()
    neg = 0
    for r in rows:
        spans = r['output']['spans']
        if not spans:
            neg += 1
        for _, _, lab in spans:
            c[lab] += 1
    return c, neg


def write_jsonl(rows, path):
    with open(path, 'w', encoding='utf-8') as w:
        for r in rows:
            w.write(json.dumps(r, ensure_ascii=False) + '\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--total', type=int, default=32000)
    ap.add_argument('--val-total', type=int, default=3200)
    ap.add_argument('--seed', type=int, default=1)
    ap.add_argument('--aug-frac', type=float, default=0.25)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    train = build(args.total, args.seed, args.aug_frac, split='train')
    val = build(args.val_total, args.seed + 9991, args.aug_frac, split='train')   # val = in-distribution
    # de-dup val against train by input string (synthetic collisions are rare but cheap to drop)
    seen = {r['input'] for r in train}
    val = [r for r in val if r['input'] not in seen]

    write_jsonl(train, os.path.join(args.out, 'train.jsonl'))
    write_jsonl(val, os.path.join(args.out, 'val.jsonl'))
    shutil.copy(_LABELS_PATH, os.path.join(args.out, 'labels.json'))

    labels = set(json.load(open(_LABELS_PATH))['labels'])
    tc, neg = label_counts(train)
    print(f"train rows: {len(train)} ({neg} pure-negative)   val rows: {len(val)}")
    print("per-label span counts (train):")
    for lab in sorted(labels):
        flag = '' if tc.get(lab, 0) >= 1000 else '  <-- LOW (<1000)'
        print(f"  {lab:22} {tc.get(lab, 0):>7}{flag}")
    missing = [lab for lab in labels if tc.get(lab, 0) == 0]
    if missing:
        print("WARNING: labels with ZERO coverage:", missing)


if __name__ == '__main__':
    main()
