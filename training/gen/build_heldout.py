#!/usr/bin/env python3
"""Build the held-out test set pii-heldout-v11 (full re-grounding).

Draws split='heldout': for the scaffold-grounded doctypes, layouts.choose returns the held-out partition of
each generator's LAYOUTS -- a REAL document STRUCTURE the train set never produced (e.g. the joint-holder
flinks, the Permis Plus / MRZ licence, the takeout facture). Plus a DISTINCT seed and a higher augmentation
fraction (more ALL-CAPS / NBSP / unicode-dash / accent-fold). Asserts ZERO input-string overlap with the
train set. This measures generalization to UNSEEN real structures (the operator's anti-saturation lever),
which is a much stronger test than the v10 same-structure-different-seed held-out. It is still synthetic
VALUES; a future real-client-document eval remains separate and must never ingest real PII.

Usage: python build_heldout.py --out <heldout_dir> --train <train.jsonl> [--total 5000] [--seed 70001]
"""
from __future__ import annotations
import sys, os, json, argparse, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_dataset import build, label_counts, write_jsonl, _LABELS_PATH  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--train', required=True, help='train.jsonl to check non-overlap against')
    ap.add_argument('--total', type=int, default=5000)
    ap.add_argument('--seed', type=int, default=70001)
    ap.add_argument('--aug-frac', type=float, default=0.5)   # heavier adversarial augmentation for held-out
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    train_inputs = {json.loads(l)['input'] for l in open(args.train, encoding='utf-8') if l.strip()}
    rows = build(args.total, args.seed, args.aug_frac, split='heldout')
    before = len(rows)
    rows = [r for r in rows if r['input'] not in train_inputs]
    dropped = before - len(rows)
    assert dropped == 0, f"held-out overlapped train on {dropped} rows (seed collision); change --seed"

    write_jsonl(rows, os.path.join(args.out, 'test.jsonl'))
    shutil.copy(_LABELS_PATH, os.path.join(args.out, 'labels.json'))
    tc, neg = label_counts(rows)
    print(f"held-out rows: {len(rows)} ({neg} pure-negative), 0 overlap with train")
    labels = set(json.load(open(_LABELS_PATH))['labels'])
    for lab in sorted(labels):
        print(f"  {lab:22} {tc.get(lab, 0):>7}")


if __name__ == '__main__':
    main()
