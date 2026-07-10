#!/usr/bin/env python3
"""Compose the v12 stage-1 / stage-2 training mixes (plan 048).

Stage 1 (broad): source-balanced public blend + our full corpus.
Stage 2 (adaptation): our corpus + wire-shaped public subsets (privy, nemotron structured).

Sampling is two-pass and memory-light (index first, then re-scan picking sampled lines).
ai4privacy fr/en rows get FR_EN_WEIGHT x sampling weight (our market) but all languages stay in.

Generator-holdout (--holdout-generators telecom_bill,insurance): removes those doctypes from
OUR train rows and writes them to generator_holdout.jsonl in the output dir -- the v12
generalization gate (measures transfer to never-seen generators instead of memorization).

Usage:
  python training/ingest/build_mix_v12.py --stage 1 \
      --public-dir datasets/public-cache/converted \
      --ours datasets/pii-merged-v11r9c \
      --out datasets/pii-merged-v12-stage1 \
      --holdout-generators telecom_bill,insurance
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
LABELS_V20 = REPO / "training" / "labels_v20.json"

# per-source row budgets: {source_file_stem: count} (0 = take all)
STAGE1 = {"ai4privacy-train": 300_000, "nemotron-train": 0, "gretel-train": 0,
          "privy-train": 100_000}
STAGE2 = {"privy-train": 25_000, "nemotron-train-structured": 30_000}
# Stage 4 (2026-07-06): balanced refresher after stage-3 showed ours-heavy adaptation improves BOTH
# in-distribution AND generator-holdout numbers. ~140k public + ours x2 (~108k) = ~44% ours.
STAGE4 = {"ai4privacy-train": 60_000, "nemotron-train": 30_000, "gretel-train": 20_000,
          "privy-train": 30_000}
VAL_BUDGET = {"ai4privacy-validation": 4_000, "nemotron-test": 2_000,
              "gretel-validation": 2_000, "privy-validation": 2_000}
FR_EN_WEIGHT = 2.0


def _index(path: Path, want_lang_weight: bool, structured_only: bool = False):
    """Pass 1: return (line_no, weight) candidates."""
    cands = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            if not line.strip():
                continue
            w = 1.0
            if want_lang_weight or structured_only:
                meta = json.loads(line).get("meta", {})
                if structured_only and meta.get("format") != "structured":
                    continue
                if want_lang_weight and meta.get("lang") in ("fr", "en"):
                    w = FR_EN_WEIGHT
            cands.append((i, w))
    return cands


def _pick_lines(path: Path, picked: set):
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i in picked:
                yield line


def sample_source(path: Path, budget: int, rng: random.Random, structured_only=False):
    lang_weight = path.stem.startswith("ai4privacy")
    cands = _index(path, lang_weight, structured_only)
    if budget and len(cands) > budget:
        weights = [w for _, w in cands]
        idx = rng.choices(range(len(cands)), weights=weights, k=budget)
        picked = {cands[j][0] for j in set(idx)}
        # choices() samples with replacement; top up deterministically to hit the budget
        if len(picked) < budget:
            pool = [i for i, _ in cands if i not in picked]
            rng.shuffle(pool)
            picked.update(pool[: budget - len(picked)])
    else:
        picked = {i for i, _ in cands}
    yield from _pick_lines(path, picked)


def load_ours(ours_dir: Path, holdout: set):
    train, held = [], []
    with open(ours_dir / "train.jsonl", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            doctype = json.loads(line).get("meta", {}).get("doctype", "")
            (held if doctype in holdout else train).append(line)
    return train, held


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", type=int, required=True, choices=[1, 2, 4])
    ap.add_argument("--ours-repeat", type=int, default=1,
                    help="oversample OUR corpus by this integer factor (stage-4 balance lever)")
    ap.add_argument("--public-dir", default=str(REPO / "datasets/public-cache/converted"))
    ap.add_argument("--ours", default=str(REPO / "datasets/pii-merged-v11r9c"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--holdout-generators", default="",
                    help="comma-separated meta.doctype values to hold out of OUR train rows")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    pub = Path(args.public_dir)
    ours_dir = Path(args.ours)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    holdout = {g.strip() for g in args.holdout_generators.split(",") if g.strip()}

    budgets = {1: STAGE1, 2: STAGE2, 4: STAGE4}[args.stage]
    lines = []
    tally = Counter()
    for stem, budget in budgets.items():
        structured_only = stem.endswith("-structured")
        fname = (stem[: -len("-structured")] if structured_only else stem) + ".jsonl"
        path = pub / fname
        if not path.exists():
            sys.exit(f"missing converted source {path} -- run convert_public.py first")
        n0 = len(lines)
        lines.extend(sample_source(path, budget, rng, structured_only))
        tally[stem] = len(lines) - n0

    ours_train, held = load_ours(ours_dir, holdout)
    lines.extend(ours_train * max(1, args.ours_repeat))
    tally["ours"] = len(ours_train) * max(1, args.ours_repeat)

    rng.shuffle(lines)
    with open(out / "train.jsonl", "w", encoding="utf-8") as f:
        f.writelines(lines)

    # val: ours val + small public samples (only the ones already converted; skip missing)
    val_lines = list(open(ours_dir / "val.jsonl", encoding="utf-8"))
    tally["val_ours"] = len(val_lines)
    for stem, budget in VAL_BUDGET.items():
        path = pub / (stem + ".jsonl")
        if path.exists():
            n0 = len(val_lines)
            val_lines.extend(sample_source(path, budget, rng))
            tally["val_" + stem] = len(val_lines) - n0
    rng.shuffle(val_lines)
    with open(out / "val.jsonl", "w", encoding="utf-8") as f:
        f.writelines(val_lines)

    if held:
        with open(out / "generator_holdout.jsonl", "w", encoding="utf-8") as f:
            f.writelines(held)
        tally["generator_holdout"] = len(held)

    shutil.copy(LABELS_V20, out / "labels.json")
    print(json.dumps({"out": str(out), "stage": args.stage, "counts": dict(tally),
                      "holdout_doctypes": sorted(holdout), "seed": args.seed}, indent=2))


if __name__ == "__main__":
    main()
