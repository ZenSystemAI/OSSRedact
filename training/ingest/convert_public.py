#!/usr/bin/env python3
"""Convert the four public PII datasets (plan 048) into our offset-true jsonl format.

Output rows match datasets/pii-merged-*/train.jsonl exactly:
  {"input": text, "output": {"spans": [[s,e,label],...], "entities": {}}, "meta": {...}}
Gretel (no offsets) emits the legacy value-list form instead:
  {"input": text, "output": {"entities": {label: [values]}}, "meta": {...}}

Strict policy: any source label missing from label_map_v12.py aborts (exit 2) AFTER the pass,
printing the unmapped histogram -- extend the map, re-run. `--audit` only tallies labels (no
output file) so the first run against a new source is cheap.

Usage (network; run in .venv-train which has `datasets` + `huggingface_hub`):
  .venv-train/bin/python training/ingest/convert_public.py \
      --source ai4privacy --split train --limit 500 --audit
  .venv-train/bin/python training/ingest/convert_public.py \
      --source nemotron --split train --out datasets/public-cache/converted/nemotron-train.jsonl
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sys
import zipfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from label_map_v12 import MAPPINGS, map_spans, map_gretel_entities  # noqa: E402

REPO = Path(__file__).resolve().parent.parent.parent
CACHE = REPO / "datasets" / "public-cache"

HF_IDS = {
    "ai4privacy": "ai4privacy/pii-masking-openpii-1m",
    "nemotron": "nvidia/Nemotron-PII",
    "gretel": "gretelai/gretel-pii-masking-en-v1",
    "privy": "beki/privy",
}


def _literal(v):
    """Nemotron/gretel span/entity fields are python-repr STRINGS; privy spans may be too."""
    if isinstance(v, str):
        return ast.literal_eval(v)
    return v


def iter_ai4privacy(split, limit):
    import datasets
    ds = datasets.load_dataset(HF_IDS["ai4privacy"], split=split, streaming=True)
    for i, r in enumerate(ds):
        if limit and i >= limit:
            return
        raw = [(m["start"], m["end"], m["label"]) for m in (r.get("privacy_mask") or [])]
        yield r["source_text"], raw, {"src": "ai4privacy-openpii-1m", "lang": r.get("language"),
                                      "uid": str(r.get("uid"))}


def iter_nemotron(split, limit):
    import datasets
    ds = datasets.load_dataset(HF_IDS["nemotron"], split=split, streaming=True)
    for i, r in enumerate(ds):
        if limit and i >= limit:
            return
        raw = [(m["start"], m["end"], m["label"]) for m in _literal(r.get("spans") or [])]
        yield r["text"], raw, {"src": "nemotron-pii", "lang": "en", "uid": r.get("uid"),
                               "domain": r.get("domain"), "format": r.get("document_format")}


def iter_gretel(split, limit):
    import datasets
    ds = datasets.load_dataset(HF_IDS["gretel"], split=split, streaming=True)
    for i, r in enumerate(ds):
        if limit and i >= limit:
            return
        yield r["text"], _literal(r.get("entities") or []), {
            "src": "gretel-pii-en-v1", "lang": "en", "uid": r.get("uid"), "domain": r.get("domain")}


_PRIVY_SPLIT = {"train": "train", "validation": "dev", "test": "test"}


def _privy_rows(path: Path):
    """privy inner files: JSON array or JSON-lines; auto-detect."""
    with open(path, encoding="utf-8") as f:
        head = f.read(1)
        f.seek(0)
        if head == "[":
            yield from json.load(f)
        else:
            for line in f:
                if line.strip():
                    yield json.loads(line)


def _privy_span(sp):
    """Span dicts (possibly stringified) in either {label,start,end} or Presidio
    {entity_type,start_position,end_position} shape."""
    sp = _literal(sp)
    if "entity_type" in sp:
        return sp["start_position"], sp["end_position"], sp["entity_type"]
    return sp["start"], sp["end"], sp["label"]


def iter_privy(split, limit):
    from huggingface_hub import hf_hub_download
    zp = hf_hub_download(HF_IDS["privy"], "privy-dataset.zip", repo_type="dataset",
                         cache_dir=str(CACHE / "hf"))
    dest = CACHE / "privy"
    if not dest.exists():
        dest.mkdir(parents=True)
        with zipfile.ZipFile(zp) as z:
            z.extractall(dest)
    prefix = _PRIVY_SPLIT[split]
    cands = sorted(dest.rglob(f"{prefix}-*.json"), key=lambda p: p.stat().st_size, reverse=True)
    if not cands:
        raise FileNotFoundError(f"no {prefix}-*.json inside {dest} (zip layout changed?)")
    n = 0
    for r in _privy_rows(cands[0]):
        if limit and n >= limit:
            return
        raw = [_privy_span(sp) for sp in (r.get("spans") or [])]
        yield r["full_text"], raw, {"src": "privy", "lang": "en",
                                    "uid": str(r.get("template_id", ""))}
        n += 1


ITERATORS = {"ai4privacy": iter_ai4privacy, "nemotron": iter_nemotron,
             "gretel": iter_gretel, "privy": iter_privy}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, choices=sorted(ITERATORS))
    ap.add_argument("--split", default="train", choices=["train", "validation", "test"])
    ap.add_argument("--limit", type=int, default=0, help="0 = full split")
    ap.add_argument("--out", default="", help="output jsonl (required unless --audit)")
    ap.add_argument("--audit", action="store_true", help="tally source labels only, write nothing")
    args = ap.parse_args()
    if not args.audit and not args.out:
        ap.error("--out is required unless --audit")

    mapping = MAPPINGS[args.source]
    unknown: dict = {}
    label_hist: Counter = Counter()
    stats = Counter()
    seen = set()
    out_f = None
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        out_f = open(args.out, "w", encoding="utf-8")

    try:
        for text, raw, meta in ITERATORS[args.source](args.split, args.limit):
            stats["rows_in"] += 1
            if args.source == "gretel":
                for ent in raw:
                    for t in (ent.get("types") or []):
                        label_hist[t] += 1
                ents, ambiguous = map_gretel_entities(raw, mapping, unknown)
                if ambiguous:
                    stats["rows_dropped_ambiguous"] += 1
                    continue
                # keep only values actually present in the text (find-based labeling downstream)
                ents = {lab: [v for v in vals if v in text] for lab, vals in ents.items()}
                ents = {lab: vals for lab, vals in ents.items() if vals}
                row = {"input": text, "output": {"entities": ents}, "meta": meta}
                n_spans = sum(len(v) for v in ents.values())
            else:
                for _, _, lab in raw:
                    label_hist[lab] += 1
                spans = map_spans(text, raw, mapping, unknown)
                row = {"input": text, "output": {"spans": spans, "entities": {}}, "meta": meta}
                n_spans = len(spans)

            if not args.audit and out_f is not None:
                h = hashlib.md5(text.encode("utf-8")).hexdigest()
                if h in seen:
                    stats["rows_dropped_dup"] += 1
                    continue
                seen.add(h)
                if n_spans == 0:
                    stats["rows_negative"] += 1  # kept: hard negatives are wanted signal
                out_f.write(json.dumps(row, ensure_ascii=False) + "\n")
                stats["rows_out"] += 1
    finally:
        if out_f is not None:
            out_f.close()

    print(f"[{args.source}/{args.split}] {dict(stats)}", file=sys.stderr)
    print("source-label histogram:", file=sys.stderr)
    for lab, c in label_hist.most_common():
        flag = " UNMAPPED" if lab in unknown else ""
        print(f"  {lab:32s} {c:8d}{flag}", file=sys.stderr)
    if unknown:
        print(f"\nSTRICT: unmapped labels in {args.source}: {unknown}\n"
              f"Extend training/ingest/label_map_v12.py and re-run.", file=sys.stderr)
        if args.out:
            Path(args.out).rename(args.out + ".INCOMPLETE")
            print(f"output moved to {args.out}.INCOMPLETE", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
