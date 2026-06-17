#!/usr/bin/env python3
"""Real-document validation harness -- run the ALWAYS-ON deterministic layers (validated_floor + the
secrets scanner) over a corpus of REAL documents (e.g. expense receipts/invoices) and report honest,
PII-FREE aggregate metrics + a self-leak check.

WHY this exists: the synthetic corpus (generate_corpus.py) proves recall on generated PII. This harness
proves the deterministic NEVER-LEAK backstop behaves on real-world text -- different layouts, real OCR/
extraction noise, real separators (NBSP, en-dash), real number shapes. It does NOT run the neural tier
(names/addresses/merchants are model-owned and the model lives on the GPU box); see --tier0-json to fold
in the TS client detector's output for a twin-drift comparison on the same real text.

PRIVACY CONTRACT (hard rules):
  * Inputs are REAL PII. This script reads them from an OUT-OF-REPO dir (default ~/expenses-eval/text).
  * It NEVER writes a PII value into a committed artifact. The Markdown report (--report) carries ONLY
    aggregate counts. Per-doc detail (--out-dir) carries offsets + labels ONLY (no substrings), and lands
    in the same gitignored out-of-repo area.
  * Documents are referenced by opaque ids (exp_NNN), never by their original filename.

Usage:
  .venv-test/bin/python validation/realworld_expenses.py \
      --text-dir ~/expenses-eval/text --glob '*.layout.txt' \
      --out-dir ~/expenses-eval/results --report validation/RESULT-realworld-expenses.md
"""
from __future__ import annotations
import argparse, glob, json, os, sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# Load by explicit path: gate/ and appliance/ BOTH define privacy_gate.py (the appliance copy is the
# older host generation, F14), so a bare `import privacy_gate` is ambiguous. We want the canonical floor
# from gate/privacy_gate.py and the secrets scanner from appliance/secrets_scan.py.
import importlib.util  # noqa: E402


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_gate = _load('ossr_gate', REPO / 'gate' / 'privacy_gate.py')
_secrets = _load('ossr_secrets', REPO / 'appliance' / 'secrets_scan.py')
validated_floor = _gate.validated_floor
merge_spans = _gate.merge_spans
secret_spans = _secrets.secret_spans

# Catastrophic-tier categories: a verbatim survival here is a HARD failure (mirrors run_corpus.py HARD).
HARD = {'email', 'government_id', 'sensitive_account_id', 'payment_card', 'iban', 'secret'}


def redact(text: str, spans: list[dict]) -> str:
    """Mask every span (offsets index the ORIGINAL text) with a typed placeholder, in order."""
    spans = sorted(spans, key=lambda s: s['start'])
    out = []
    last = 0
    for s in spans:
        if s['start'] < last:  # already covered by a prior (merged) span
            continue
        out.append(text[last:s['start']])
        out.append(f"[{s['label'].upper()}]")
        last = s['end']
    out.append(text[last:])
    return ''.join(out)


def scan(text: str) -> list[dict]:
    """The always-on deterministic stack: validated_floor (PII shapes) + secret_spans (credentials)."""
    spans = validated_floor(text)
    for s in secret_spans(text, entropy_backstop=True):
        spans.append({'start': s['start'], 'end': s['end'], 'label': 'secret',
                      'tier': 0, 'conf': 1.0, 'rule': 'secret',
                      'subtype': s.get('subtype') or s.get('rule') or s.get('name')})
    return merge_spans(spans)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--text-dir', default=os.path.expanduser('~/expenses-eval/text'))
    ap.add_argument('--glob', default='*.layout.txt')
    ap.add_argument('--out-dir', default=os.path.expanduser('~/expenses-eval/results'))
    # Auto summary goes to the gitignored work area; the curated, hand-authored analysis lives at
    # validation/RESULT-realworld-expenses.md (committed, PII-free).
    ap.add_argument('--report', default=os.path.expanduser('~/expenses-eval/results/auto_report.md'))
    ap.add_argument('--label', default='expense receipts/invoices (2025-2026)',
                    help='PII-free human description of the corpus for the report')
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.text_dir, args.glob)))
    if not files:
        print(f"no files matched {args.text_dir}/{args.glob}", file=sys.stderr)
        return 2
    os.makedirs(args.out_dir, exist_ok=True)

    n_docs = len(files)
    docs_with_pii = 0
    by_label = Counter()
    by_secret_subtype = Counter()
    leaks = defaultdict(int)            # HARD-category verbatim survivals (must be 0)
    total_chars = 0
    spans_total = 0
    per_doc = []

    for f in files:
        doc_id = Path(f).name.split('.')[0]
        text = Path(f).read_text(encoding='utf-8', errors='replace')
        total_chars += len(text)
        spans = scan(text)
        spans_total += len(spans)
        if spans:
            docs_with_pii += 1
        for s in spans:
            by_label[s['label']] += 1
            if s['label'] == 'secret' and s.get('subtype'):
                by_secret_subtype[s['subtype']] += 1
        red = redact(text, spans)
        # SELF-LEAK CHECK: every value we claim to redact must be gone from the output, verbatim.
        doc_leaks = []
        for s in spans:
            if s['label'] in HARD:
                val = text[s['start']:s['end']]
                if val and val in red:
                    leaks[s['label']] += 1
                    doc_leaks.append({'label': s['label'], 'start': s['start'], 'end': s['end']})
        per_doc.append({
            'doc_id': doc_id, 'chars': len(text), 'n_spans': len(spans),
            # offsets + labels ONLY -- NO values
            'spans': [{'start': s['start'], 'end': s['end'], 'label': s['label'],
                       'rule': s.get('rule'), 'subtype': s.get('subtype')} for s in spans],
            'leaks': doc_leaks,
        })

    # per-doc detail -> gitignored out-of-repo area (offsets only, no values)
    Path(args.out_dir, 'floor_per_doc.json').write_text(
        json.dumps(per_doc, indent=2), encoding='utf-8')

    total_leaks = sum(leaks.values())
    # ---- console summary ----
    print("\n=========== REAL-DOC VALIDATION (always-on deterministic layers) ===========")
    print(f"corpus           : {args.label}")
    print(f"documents        : {n_docs}   ({total_chars:,} chars)")
    print(f"docs w/ >=1 hit  : {docs_with_pii} ({100*docs_with_pii/n_docs:.0f}%)")
    print(f"deterministic spans redacted : {spans_total}")
    print("  by label:", dict(by_label.most_common()))
    if by_secret_subtype:
        print("  secret subtypes:", dict(by_secret_subtype.most_common()))
    print(f"\nSELF-LEAK CHECK (caught value survives verbatim in redacted output):")
    for cat in sorted(HARD):
        c = by_label.get(cat, 0)
        print(f"  {cat:22} redacted={c:5}  leaks={leaks.get(cat,0)}")
    print(f"TOTAL HARD LEAKS : {total_leaks}  ({'PASS' if total_leaks==0 else 'FAIL'})")
    print("============================================================================")

    _write_report(args, n_docs, total_chars, docs_with_pii, spans_total,
                   by_label, by_secret_subtype, leaks, total_leaks)
    print(f"wrote {args.report}")
    print(f"wrote {Path(args.out_dir,'floor_per_doc.json')} (offsets only, gitignored)")
    return 0 if total_leaks == 0 else 1


def _write_report(args, n_docs, total_chars, docs_with_pii, spans_total,
                  by_label, by_secret_subtype, leaks, total_leaks):
    L = []
    L.append("# Real-document validation -- always-on deterministic layers\n")
    L.append("> Generated by `validation/realworld_expenses.py`. **PII-free**: aggregate counts only; "
             "no values, no filenames. Raw text + per-doc offsets stay in a gitignored out-of-repo area.\n")
    L.append(f"- **Corpus**: {args.label}")
    L.append(f"- **Documents**: {n_docs} ({total_chars:,} characters of extracted text)")
    L.append(f"- **Layers exercised**: `validated_floor` (checksum/format-exact PII shapes) + "
             "`secret_spans` (credentials). The neural tier (names, addresses, merchants) is NOT run here "
             "-- it is GPU-resident; see the twin-drift note below.")
    L.append(f"- **Docs with >=1 deterministic hit**: {docs_with_pii} ({100*docs_with_pii/n_docs:.0f}%)\n")
    L.append("## Deterministic spans redacted\n")
    L.append("| Label | Count |")
    L.append("|-------|-------|")
    for lab, n in by_label.most_common():
        L.append(f"| {lab} | {n} |")
    L.append(f"| **total** | **{spans_total}** |\n")
    if by_secret_subtype:
        L.append("### Secret subtypes\n")
        L.append("| Subtype | Count |")
        L.append("|---------|-------|")
        for st, n in by_secret_subtype.most_common():
            L.append(f"| {st} | {n} |")
        L.append("")
    L.append("## Self-leak check\n")
    L.append("Every value the deterministic layer claims to redact must be absent (verbatim) from the "
             "redacted output. This is the never-leak guarantee, measured on real text.\n")
    L.append("| Catastrophic category | Redacted | Leaks |")
    L.append("|-----------------------|----------|-------|")
    for cat in sorted(HARD):
        L.append(f"| {cat} | {by_label.get(cat,0)} | {leaks.get(cat,0)} |")
    L.append(f"\n**Total hard leaks: {total_leaks} -- {'PASS' if total_leaks==0 else 'FAIL'}**\n")
    L.append("## Interpretation\n")
    L.append("The deterministic floor is deliberately THIN (Phase 2, 2026-06-14): it emits only "
             "checksum/format-exact shapes (email, UUID, mod-97 IBAN, Luhn card, Luhn SIN) so it is a "
             "near-zero-false-positive never-leak net. On real expense documents the dominant PII is "
             "**model-owned** (person names, business/merchant names, civic addresses, free-form dates "
             "and amounts), which is why the deterministic count looks sparse relative to the document "
             "count. The headline end-to-end protection number requires the neural tier; that run is "
             "tracked separately (GPU gate).\n")
    Path(args.report).write_text('\n'.join(L) + '\n', encoding='utf-8')


if __name__ == '__main__':
    raise SystemExit(main())
