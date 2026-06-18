#!/usr/bin/env python3
"""Run the synthetic corpus through the GPU gate (/redact) for PII, and the deterministic
secret_spans locally for secrets. Aggregate honest numbers + leak-check against ground truth.

PII headline (comparable to the original 'PII spans redacted'): GPU gate tier0+neural.
Secrets: always-on deterministic layer (secret_spans) -- the GPU gate does not run it.
Leak = an injected sensitive VALUE survives verbatim in the redacted output (substring match,
the gate's own recall-as-leak-prevention metric).
"""
import json, os, sys, time, urllib.request
from collections import Counter, defaultdict
from secrets_scan import secret_spans

# Gate URL: CLI arg 2, else $OSSREDACT_GATE_URL, else localhost (no internal host committed for OSS release).
GATE = sys.argv[2] if len(sys.argv) > 2 else os.environ.get('OSSREDACT_GATE_URL', 'http://localhost:8001')
CORPUS = sys.argv[1] if len(sys.argv) > 1 else 'corpus.jsonl'
# high-confidence categories where a leak is a hard failure (mirror the original '0 email/UUID/SIN leaks')
HARD = {'email', 'government_id', 'sensitive_account_id', 'credit_card'}


def redact(text):
    body = json.dumps({'text': text, 'mode': 'substitute'}).encode()
    req = urllib.request.Request(GATE + '/redact', data=body, headers={'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def main():
    docs = [json.loads(l) for l in open(CORPUS, encoding='utf-8') if l.strip()]
    total_pii_spans = 0
    by_cat = Counter()
    leaks = defaultdict(int)          # hard-category leaks via GPU gate
    checked = defaultdict(int)        # injected values checked per category
    secret_total = 0; secret_caught = 0; secret_leaks = 0
    decoy_total = 0; decoy_redacted = 0   # decoys that got (wrongly) redacted = over-redaction
    t0 = time.time(); errs = 0
    for i, d in enumerate(docs):
        text = d['text']
        try:
            res = redact(text)
        except Exception as e:
            errs += 1
            if errs <= 5:
                print(f"  ! doc {d['id']} error: {e}", flush=True)
            continue
        red = res['redacted_text']
        total_pii_spans += res['stats']['total_spans']
        for c, n in res['stats'].get('by_category', {}).items():
            by_cat[c] += n
        # leak check: hard-category injected values must NOT survive verbatim
        for cat in HARD:
            for v in d['truth'].get(cat, []):
                checked[cat] += 1
                if v and v in red:
                    leaks[cat] += 1
        # secrets via the deterministic always-on layer (run locally on the same text)
        for v in d['truth'].get('secret', []):
            secret_total += 1
        ss = secret_spans(text, entropy_backstop=True)
        caught_vals = {text[s['start']:s['end']] for s in ss}
        for v in d['truth'].get('secret', []):
            # caught if the deterministic layer covers it (exact or as a covering span)
            if any(v == cv or v in cv or cv in v for cv in caught_vals):
                secret_caught += 1
            else:
                # would it leak past the FULL stack? only if neither secrets layer nor the gate caught it
                if v in red:
                    secret_leaks += 1
        # decoys: should remain present (not redacted). count over-redactions.
        for v in d['decoys']:
            decoy_total += 1
            if v and v not in red:
                decoy_redacted += 1
        if (i + 1) % 100 == 0:
            dt = time.time() - t0
            print(f"  {i+1}/{len(docs)} docs  {total_pii_spans} PII spans  {dt:.0f}s "
                  f"({(i+1)/dt:.1f} docs/s)", flush=True)
    dt = time.time() - t0
    print("\n================ SYNTHETIC CORPUS VALIDATION ================")
    print(f"docs: {len(docs)}   errors: {errs}   runtime: {dt:.0f}s ({len(docs)/dt:.1f} docs/s)")
    print(f"\nPII spans redacted (GPU gate, tier0+neural): {total_pii_spans}")
    print("  by category:", dict(by_cat.most_common()))
    print(f"\nHARD-category leak check (value survives verbatim in output):")
    for cat in sorted(HARD):
        print(f"  {cat:24} checked={checked[cat]:6}  leaks={leaks[cat]}")
    print(f"\nSecrets (always-on deterministic layer): injected={secret_total} "
          f"caught={secret_caught} ({100*secret_caught/max(secret_total,1):.1f}%)  "
          f"leaked-past-full-stack={secret_leaks}")
    print(f"\nDecoys (look-alikes that must NOT be flagged): {decoy_total} total, "
          f"{decoy_redacted} over-redacted ({100*decoy_redacted/max(decoy_total,1):.1f}%)")
    print("============================================================")
    # machine-readable
    out = {'docs': len(docs), 'errors': errs, 'runtime_s': round(dt, 1),
           'pii_spans_redacted': total_pii_spans, 'by_category': dict(by_cat),
           'hard_leaks': dict(leaks), 'hard_checked': dict(checked),
           'secrets_injected': secret_total, 'secrets_caught': secret_caught,
           'secrets_leaked': secret_leaks, 'decoys_total': decoy_total,
           'decoys_overredacted': decoy_redacted}
    json.dump(out, open('result.json', 'w'), indent=2)
    print("wrote result.json")


if __name__ == '__main__':
    main()
