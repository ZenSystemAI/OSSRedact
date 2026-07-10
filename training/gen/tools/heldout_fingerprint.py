#!/usr/bin/env python3
"""Held-out fingerprint guard (v11 round-2 anti-contamination check).

The recall-first fix adds cue/format diversity to TRAIN layouts only. The held-out scoreboard MUST stay
byte-identical -- if any edit touches a held-out layout fn, gen(), LAYOUTS ordering, or shifts the RNG
stream on the held-out path, this fingerprint changes and the round-1 vs round-2 comparison is invalid.

Usage:
  python tools/heldout_fingerprint.py            # print the combined fingerprint + per-generator hashes
  python tools/heldout_fingerprint.py baseline.json   # write hashes to json
  python tools/heldout_fingerprint.py baseline.json --check   # assert current == saved baseline
"""
from __future__ import annotations
import sys, os, json, random, hashlib, glob, importlib

HERE = os.path.dirname(os.path.abspath(__file__))
GEN_DIR = os.path.dirname(HERE)
sys.path.insert(0, GEN_DIR)

SKIP = {"framework", "values", "layouts", "augment", "build_dataset", "build_heldout",
        "build_windows", "validate_corpus", "labeling", "cue_helpers", "__init__"}
SEEDS = list(range(60))


def gens():
    mods = []
    for f in sorted(glob.glob(os.path.join(GEN_DIR, "*.py"))):
        name = os.path.basename(f)[:-3]
        if name in SKIP or name.startswith("test"):
            continue
        try:
            m = importlib.import_module(name)
        except Exception:
            continue
        if hasattr(m, "gen"):
            mods.append((name, m))
    return mods


def fingerprint():
    out = {}
    for name, m in gens():
        h = hashlib.sha256()
        for s in SEEDS:
            random.seed(s)
            try:
                r = m.gen(split="heldout")
            except TypeError:
                r = m.gen()
            # hash the exact text + the offset-true spans (start,end,label) -> structure + labeling
            h.update(r["input"].encode("utf-8"))
            h.update(repr(r["output"]["spans"]).encode("utf-8"))
        out[name] = h.hexdigest()[:16]
    return out


def main():
    fp = fingerprint()
    combined = hashlib.sha256(json.dumps(fp, sort_keys=True).encode()).hexdigest()[:16]
    args = sys.argv[1:]
    if args and args[0].endswith(".json") and "--check" in args:
        saved = json.load(open(args[0]))
        diffs = {k: (saved.get(k), fp.get(k)) for k in set(saved) | set(fp) if saved.get(k) != fp.get(k)}
        if diffs:
            print("HELD-OUT CONTAMINATED -- these generators' held-out renders changed:")
            for k, (a, b) in sorted(diffs.items()):
                print(f"   {k:22} baseline={a} now={b}")
            sys.exit(1)
        print(f"OK held-out unchanged ({len(fp)} generators, combined={combined})")
        return
    if args and args[0].endswith(".json"):
        json.dump(fp, open(args[0], "w"), indent=2)
        print(f"wrote {args[0]}  ({len(fp)} generators, combined={combined})")
        return
    for k in sorted(fp):
        print(f"   {k:22} {fp[k]}")
    print(f"combined={combined}  ({len(fp)} generators)")


if __name__ == "__main__":
    main()
