#!/usr/bin/env python3
"""Neural-tier real-document validation -- run the FULL GPU gate (deterministic floor + neural NER,
ossredact/pii-gpu-xlmr-large-v11r5) over the real expense corpus and report PII-FREE aggregate metrics.

This is the headline "does it protect real documents" pass: unlike the deterministic-only harness
(realworld_expenses.py), it exercises the model-owned categories (person, address, organization, tax_id,
free-form dates/amounts) that dominate real expense PII.

PRIVACY CONTRACT (hard rules):
  * Inputs are REAL PII; text is read from an OUT-OF-REPO dir (default ~/expenses-eval/text) and sent to the
    on-prem gate over the local network. The redacted text + the entity MAP (original values) returned by /redact
    are held IN MEMORY ONLY and NEVER written to disk.
  * The committed report carries aggregate category counts only. Per-doc detail (out-of-repo, gitignored)
    carries doc id + char count + span count + per-category counts -- NO values, NO offsets-to-values.

Usage:
  OSSREDACT_GATE_URL=http://<gate-host>:8001 python3 validation/realworld_neural.py [--text-dir ~/expenses-eval/text]
  (the gate URL defaults to $OSSREDACT_GATE_URL, else http://localhost:8001 -- no internal host is committed)
"""
from __future__ import annotations
import argparse, glob, json, os, sys, time, urllib.request
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# catastrophic categories whose redacted value MUST NOT survive verbatim in the output (round-trip integrity)
HARD = {'email', 'government_id', 'sensitive_account_id', 'payment_card', 'iban', 'secret', 'tax_id'}


def call(gate: str, route: str, payload: dict, timeout: int = 90) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(gate + route, data=body, headers={'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--gate', default=os.environ.get('OSSREDACT_GATE_URL', 'http://localhost:8001'))
    ap.add_argument('--text-dir', default=os.path.expanduser('~/expenses-eval/text'))
    ap.add_argument('--glob', default='*.layout.txt')
    ap.add_argument('--out-dir', default=os.path.expanduser('~/expenses-eval/results'))
    args = ap.parse_args()

    try:
        hz = json.loads(urllib.request.urlopen(args.gate + '/healthz', timeout=8).read())
    except Exception as e:
        print(f"gate not reachable at {args.gate}: {e}", file=sys.stderr)
        return 2
    print(f"gate: {hz.get('model')} on {hz.get('device')}")

    files = sorted(glob.glob(os.path.join(args.text_dir, args.glob)))
    if not files:
        print(f"no files matched {args.text_dir}/{args.glob}", file=sys.stderr)
        return 2
    os.makedirs(args.out_dir, exist_ok=True)

    by_cat = Counter()
    total_spans = 0
    docs_with_pii = 0
    hard_leaks = Counter()       # original value survived verbatim in the redacted output (round-trip break)
    per_doc = []
    errs = 0
    t0 = time.time()
    for i, f in enumerate(files):
        doc_id = Path(f).name.split('.')[0]
        text = Path(f).read_text(encoding='utf-8', errors='replace')
        try:
            res = call(args.gate, '/redact', {'text': text, 'mode': 'substitute'})
        except Exception as e:
            errs += 1
            if errs <= 5:
                print(f"  ! {doc_id} error: {e}", flush=True)
            continue
        red = res['redacted_text']
        mapping = res.get('mapping', {})              # ORIGINAL VALUES -- in memory only, never persisted
        stats = res.get('stats', {})
        cats = stats.get('by_category', {})
        n = stats.get('total_spans', sum(cats.values()))
        total_spans += n
        if n:
            docs_with_pii += 1
        for c, k in cats.items():
            by_cat[c] += k
        # round-trip self-leak check: no redacted ORIGINAL value may survive verbatim in the output
        leaked_here = 0
        for ph, val in mapping.items():
            if val and val in red:
                lab = ph.strip('<>').rsplit('_', 1)[0].lower()
                if lab in HARD:
                    hard_leaks[lab] += 1
                    leaked_here += 1
        per_doc.append({'doc_id': doc_id, 'chars': len(text), 'n_spans': n,
                        'by_category': cats, 'hard_leaks': leaked_here})  # NO values
        if (i + 1) % 20 == 0:
            print(f"  {i+1}/{len(files)} docs, {total_spans} spans, {time.time()-t0:.0f}s", flush=True)

    dt = time.time() - t0
    n_docs = len(files) - errs
    Path(args.out_dir, 'neural_per_doc.json').write_text(json.dumps(per_doc, indent=2), encoding='utf-8')

    print("\n=========== REAL-DOC VALIDATION (full GPU gate: floor + neural) ===========")
    print(f"gate           : {hz.get('model')}")
    print(f"documents      : {n_docs} ok / {len(files)} ({errs} errors)   runtime {dt:.0f}s")
    print(f"docs w/ >=1 hit: {docs_with_pii}")
    print(f"total spans    : {total_spans}")
    print("by category    :", dict(by_cat.most_common()))
    print(f"\nROUND-TRIP SELF-LEAK (redacted value survives verbatim): "
          f"{sum(hard_leaks.values())} ({'PASS' if not hard_leaks else dict(hard_leaks)})")
    print("===========================================================================")

    out = {'gate_model': hz.get('model'), 'docs_ok': n_docs, 'errors': errs, 'runtime_s': round(dt, 1),
           'docs_with_pii': docs_with_pii, 'total_spans': total_spans,
           'by_category': dict(by_cat), 'hard_leaks': dict(hard_leaks)}
    Path(args.out_dir, 'neural_summary.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
    print(f"wrote {Path(args.out_dir,'neural_summary.json')} + neural_per_doc.json (PII-free, gitignored)")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
