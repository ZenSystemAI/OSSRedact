#!/usr/bin/env python3
"""Integrity check for a generated v10 corpus (run before training on it).

Asserts, for EVERY row: offset spans are in range and non-empty, every label is one of the 20, the derived
entities value-lists match the spans, and reports per-label coverage + pure-negative count. Exits non-zero
on any violation. Usage: python validate_corpus.py <jsonl> [<jsonl> ...]
"""
from __future__ import annotations
import sys, os, json, collections

_LABELS = set(json.load(open(os.path.join(os.path.dirname(__file__), '..', 'labels_v20.json')))['labels'])


def check_file(path):
    errors = []
    counts = collections.Counter()
    neg = 0
    n = 0
    for ln, line in enumerate(open(path, encoding='utf-8')):
        if not line.strip():
            continue
        n += 1
        r = json.loads(line)
        text = r['input']
        spans = r['output']['spans']
        if not spans:
            neg += 1
        derived = collections.Counter()
        for s, e, lab in spans:
            if not (0 <= s < e <= len(text)):
                errors.append(f"{path}:{ln} span out of range ({s},{e}) len={len(text)}")
                continue
            if text[s:e].strip() == "":
                errors.append(f"{path}:{ln} empty/whitespace span ({s},{e}) label={lab}")
            if lab not in _LABELS:
                errors.append(f"{path}:{ln} label not in scheme: {lab}")
            counts[lab] += 1
            derived[(lab, text[s:e])] += 1
        # entities must match spans exactly
        ent_pairs = collections.Counter()
        for lab, vals in r['output']['entities'].items():
            for v in vals:
                ent_pairs[(lab, v)] += 1
        if ent_pairs != derived:
            errors.append(f"{path}:{ln} entities != spans-derived")
    return n, neg, counts, errors


def main():
    paths = sys.argv[1:]
    if not paths:
        print("usage: validate_corpus.py <jsonl> ...")
        sys.exit(2)
    total_err = []
    for p in paths:
        n, neg, counts, errors = check_file(p)
        print(f"\n{p}: {n} rows, {neg} pure-negative")
        for lab in sorted(_LABELS):
            print(f"  {lab:22} {counts.get(lab, 0):>8}")
        zero = [l for l in _LABELS if counts.get(l, 0) == 0]
        if zero:
            print("  ZERO-COVERAGE:", zero)
        total_err += errors
    if total_err:
        print(f"\nFAIL: {len(total_err)} integrity errors")
        for e in total_err[:30]:
            print("  ", e)
        sys.exit(1)
    print("\nOK: all spans offset-exact, in scheme, entities consistent")


if __name__ == '__main__':
    main()
