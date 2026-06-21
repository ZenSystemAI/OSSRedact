#!/usr/bin/env python3
"""LABEL-AWARE eval harness for the OSSRedact gate (plan A baseline).

Measures what the existing label-AGNOSTIC evals cannot:
  - per-category PRECISION / RECALL / F1 (labeled, overlap-based)
  - a label-accuracy CONFUSION MATRIX (gold label -> predicted label)
  - FALSE POSITIVES by predicted label (over-redaction source)
  - FR vs EN split
  - three modes: TIER0-ALONE vs MODEL-ALONE vs FULL-STACK (the "base model strong alone" question)

Runs against the deployed GPU model, replicating prod line-boundary chunking exactly
(gate_service_gpu.py). Eval set = v8 val.jsonl (in the 23-label scheme). NOTE: the v7 checkpoint was
selected on this val (eval_loss), so absolute numbers are mildly optimistic; the relative patterns
(confusion, FP sources, model-alone vs full-stack gaps) are the diagnostic and are robust to that.
100% synthetic data; no value is printed, only counts.
"""
import os, sys, json, collections

GATE_DIR = os.environ.get('GATE_DIR', os.path.expanduser('~/.ossredact/gate'))
MODEL_DIR = os.environ.get('GPU_GATE_MODEL', os.path.expanduser('~/.ossredact/models/ossredact-pii-large'))
# VAL is env-configurable so the same harness scores any scheme: LABELS auto-derives from the sibling
# labels.json, so pointing GPU_GATE_VAL at the v9remap val loads the 20-label scheme automatically.
VAL = os.environ.get('GPU_GATE_VAL', 'datasets/pii-merged/val.jsonl')
MIN_SCORE = 0.5
OUT_JSON = os.environ.get('GPU_GATE_OUT', '/tmp/eval_labelaware_v7.json')

sys.path.insert(0, GATE_DIR)
from privacy_gate import PrivacyGate, GPUTier, validated_floor, merge_spans, post_merge_address  # noqa

# ---- prod chunking (verbatim from gate_service_gpu.py) ----
CHUNK_CHARS, CHUNK_OVERLAP = 600, 80
def _windows(s, base, size=CHUNK_CHARS, overlap=CHUNK_OVERLAP):
    n = len(s); i = 0
    while i < n:
        end = min(i + size, n)
        if end < n:
            j = s.rfind(' ', max(i + size - overlap, i + 1), end)
            if j > i: end = j
        yield s[i:end], base + i
        if end >= n: break
        i = max(end - overlap, i + 1)
def _chunks(text, size=CHUNK_CHARS):
    buf, start, pos = '', 0, 0
    for ln in text.splitlines(keepends=True):
        if len(ln) > size:
            if buf: yield buf, start; buf = ''
            yield from _windows(ln, pos); pos += len(ln); start = pos; continue
        if buf and len(buf) + len(ln) > size: yield buf, start; buf, start = '', pos
        buf += ln; pos += len(ln)
    if buf: yield buf, start

print(f'loading GPU v7 ({MODEL_DIR}) CVD={os.environ.get("CUDA_VISIBLE_DEVICES")} ...', flush=True)
gate = PrivacyGate(None)
gate.npu = GPUTier(MODEL_DIR, device=os.environ.get('GATE_DEVICE', 'cuda'),
                   trust_remote_code=(os.environ.get('GATE_TRUST_REMOTE_CODE') == '1'))
import torch
print('cuda:', torch.cuda.is_available(), torch.cuda.get_device_name(0) if torch.cuda.is_available() else '-', flush=True)

def _adj(spans, off):
    return [{**s, 'start': s['start'] + off, 'end': s['end'] + off} for s in spans]

def detect_mode(text, mode):
    raw = []
    for ch, off in _chunks(text):
        if mode == 'floor':
            raw += _adj(validated_floor(ch), off)
        elif mode == 'model':
            raw += _adj(gate.npu.spans(ch, MIN_SCORE), off)
        elif mode == 'full':
            raw += _adj(gate.detect(ch, MIN_SCORE), off)
    return post_merge_address(merge_spans(raw), text)

# ---- gold: value-list -> char spans (log find-failures) ----
find_total = find_fail = 0
def gold_spans(row):
    global find_total, find_fail
    t = row['input']; out = []
    spans = row.get('output', {}).get('spans')
    if spans:   # Phase 3 (v10) offset-true gold: use the exact spans, no find (no find-failures)
        return [(s, e, lab) for s, e, lab in spans]
    for lab, vals in row['output']['entities'].items():
        for v in vals:
            if not v: continue
            find_total += 1
            i = t.find(v)
            if i < 0:
                find_fail += 1; continue
            while i >= 0:
                out.append((i, i + len(v), lab)); i = t.find(v, i + len(v))
    return out

def overlap(a, b):  # [s,e) intervals
    return a[0] < b[1] and b[0] < a[1]

def lang_of(row):
    m = row.get('meta', {})
    lg = m.get('lang')                       # v10/v11 offset-true rows carry meta.lang directly
    if lg in ('fr', 'en'): return lg
    k = m.get('kind', '') or ''              # legacy v8/v9 rows used meta.kind with _fr/_en suffix
    if '_fr' in k: return 'fr'
    if '_en' in k: return 'en'
    return 'other'

def doc_of(row):
    return row.get('meta', {}).get('doctype', 'unknown')

LABELS = sorted(set(json.loads(open(os.path.join(os.path.dirname(VAL), 'labels.json')).read())['labels']))
rows = [json.loads(l) for l in open(VAL, encoding='utf-8') if l.strip()]
print(f'eval rows: {len(rows)}', flush=True)

MODES = ['floor', 'model', 'full']
# per-mode accumulators
acc = {m: {
    'gold': collections.Counter(), 'hit_label': collections.Counter(), 'hit_detect': collections.Counter(),
    'pred': collections.Counter(), 'pred_tp': collections.Counter(), 'pred_overlap': collections.Counter(),
    'confusion': collections.Counter(), 'clean_fp': 0, 'neg_rows': 0,
    'lang': collections.defaultdict(lambda: {'gold': 0, 'hit_label': 0, 'fp': 0}),
} for m in MODES}

# per-doctype breakdown (MODEL-ALONE mode only = the strict-bar mode). Lets us see which real-document
# STRUCTURES discriminate vs saturate -- the v11 held-out test: scaffold-grounded held-out structures
# (e.g. the joint-holder flinks, the takeout facture) should be HARDER than the in-distribution
# digital-PII doctypes.
bydoc = collections.defaultdict(lambda: {'gold': collections.Counter(), 'hit_label': collections.Counter(),
                                         'pred': collections.Counter(), 'pred_tp': collections.Counter(),
                                         'clean_fp': 0, 'neg_rows': 0, 'rows': 0})

for ri, row in enumerate(rows):
    text = row['input']; G = gold_spans(row); lang = lang_of(row)
    is_neg = (len(G) == 0)
    for m in MODES:
        P = detect_mode(text, m); a = acc[m]
        if is_neg: a['neg_rows'] += 1; a['clean_fp'] += len(P)
        # recall side (per gold span)
        for g in G:
            gl = g[2]; a['gold'][gl] += 1; a['lang'][lang]['gold'] += 1
            ov = [p for p in P if overlap(g, (p['start'], p['end']))]
            if ov: a['hit_detect'][gl] += 1
            if any(p['label'] == gl for p in ov):
                a['hit_label'][gl] += 1; a['lang'][lang]['hit_label'] += 1
            # confusion: best-overlap pred label (or MISS)
            if ov:
                best = max(ov, key=lambda p: min(g[1], p['end']) - max(g[0], p['start']))
                a['confusion'][(gl, best['label'])] += 1
            else:
                a['confusion'][(gl, 'MISS')] += 1
        # precision side (per pred span)
        for p in P:
            pl = p['label']; a['pred'][pl] += 1
            ovg = [g for g in G if overlap(g, (p['start'], p['end'], pl))]
            if ovg:
                a['pred_overlap'][pl] += 1
                if any(g[2] == pl for g in ovg): a['pred_tp'][pl] += 1
            else:
                a['lang'][lang]['fp'] += 1
        # per-doctype accumulation (model-alone mode only)
        if m == 'model':
            bd = bydoc[doc_of(row)]; bd['rows'] += 1
            if is_neg: bd['neg_rows'] += 1; bd['clean_fp'] += len(P)
            for g in G:
                bd['gold'][g[2]] += 1
                if any(p['label'] == g[2] for p in P if overlap(g, (p['start'], p['end']))):
                    bd['hit_label'][g[2]] += 1
            for p in P:
                bd['pred'][p['label']] += 1
                if any(gg[2] == p['label'] for gg in G if overlap(gg, (p['start'], p['end']))):
                    bd['pred_tp'][p['label']] += 1
    if ri % 500 == 0: print(f'  ..{ri}/{len(rows)}', flush=True)

def f1(p, r):
    return round(2 * p * r / (p + r), 4) if (p + r) else 0.0

report = {'model': os.path.basename(MODEL_DIR), 'n_rows': len(rows), 'min_score': MIN_SCORE,
          'find_fail_pct': round(100 * find_fail / find_total, 3) if find_total else 0, 'modes': {}}

print('\n' + '=' * 78)
print(f'LABEL-AWARE BASELINE  model={report["model"]}  rows={len(rows)}  gold-find-fail={report["find_fail_pct"]}%')
print('=' * 78)

for m in MODES:
    a = acc[m]
    tot_gold = sum(a['gold'].values()); tot_hit_label = sum(a['hit_label'].values()); tot_hit_det = sum(a['hit_detect'].values())
    tot_pred = sum(a['pred'].values()); tot_tp = sum(a['pred_tp'].values())
    micro_r = tot_hit_label / tot_gold if tot_gold else 0
    micro_dr = tot_hit_det / tot_gold if tot_gold else 0
    micro_p = tot_tp / tot_pred if tot_pred else 0
    report['modes'][m] = {'labeled_recall': round(micro_r, 4), 'detect_recall': round(micro_dr, 4),
                          'precision': round(micro_p, 4), 'f1': f1(micro_p, micro_r),
                          'clean_fp': a['clean_fp'], 'neg_rows': a['neg_rows'],
                          'per_label': {}}
    print(f"\n### MODE: {m.upper():6}  labeled-recall={micro_r:.4f}  detect-recall={micro_dr:.4f}  "
          f"precision={micro_p:.4f}  F1={f1(micro_p, micro_r):.4f}  clean_fp={a['clean_fp']} (on {a['neg_rows']} neg rows)")
    if m == 'floor':
        print('   (floor only emits checksum-exact email/uuid/iban/luhn shapes; low recall elsewhere is by design)')
    print(f"   {'label':22} {'gold':>6} {'recallL':>8} {'recallD':>8} {'prec':>7} {'F1':>7} {'FP':>6} {'wrongLbl':>8}")
    for L in LABELS:
        g = a['gold'][L]
        if g == 0 and a['pred'][L] == 0: continue
        rL = a['hit_label'][L] / g if g else 0.0
        rD = a['hit_detect'][L] / g if g else 0.0
        pL = a['pred_tp'][L] / a['pred'][L] if a['pred'][L] else 0.0
        fp = a['pred'][L] - a['pred_overlap'][L]
        wrong = a['pred_overlap'][L] - a['pred_tp'][L]
        report['modes'][m]['per_label'][L] = {'gold': g, 'recall_labeled': round(rL, 4), 'recall_detect': round(rD, 4),
                                              'precision': round(pL, 4), 'f1': f1(pL, rL), 'fp': fp, 'wrong_label': wrong,
                                              'pred': a['pred'][L]}
        print(f"   {L:22} {g:>6} {rL:>8.3f} {rD:>8.3f} {pL:>7.3f} {f1(pL, rL):>7.3f} {fp:>6} {wrong:>8}")

# confusion highlights (full mode)
print('\n### CONFUSION (FULL mode) -- top off-diagonal gold->pred (mislabels + misses):')
conf = acc['full']['confusion']
off = [(gp, c) for gp, c in conf.items() if gp[0] != gp[1]]
off.sort(key=lambda x: -x[1])
report['confusion_full_offdiag'] = [{'gold': gp[0], 'pred': gp[1], 'n': c} for gp, c in off[:30]]
for (gl, pl), c in off[:25]:
    print(f"   {gl:22} -> {pl:22} {c}")

# FR/EN split (full)
print('\n### FR vs EN (FULL mode):')
report['lang_full'] = {}
for lng, d in sorted(acc['full']['lang'].items()):
    rec = d['hit_label'] / d['gold'] if d['gold'] else 0
    report['lang_full'][lng] = {'gold': d['gold'], 'labeled_recall': round(rec, 4), 'fp': d['fp']}
    print(f"   {lng:6} gold={d['gold']:>6} labeled-recall={rec:.4f}  fp={d['fp']}")

# per-doctype breakdown (model-alone) -- which real structures discriminate vs saturate
print('\n### PER-DOCTYPE (MODEL-ALONE) -- labeled-recall / precision / clean_fp by document structure:')
report['per_doctype_model'] = {}
print(f"   {'doctype':24} {'rows':>6} {'goldspans':>10} {'recallL':>8} {'prec':>7} {'F1':>7} {'cleanFP':>8}")
for dt in sorted(bydoc):
    bd = bydoc[dt]
    g = sum(bd['gold'].values()); hl = sum(bd['hit_label'].values())
    pr = sum(bd['pred'].values()); tp = sum(bd['pred_tp'].values())
    rL = hl / g if g else 0.0
    pL = tp / pr if pr else 0.0
    report['per_doctype_model'][dt] = {'rows': bd['rows'], 'gold_spans': g, 'labeled_recall': round(rL, 4),
                                       'precision': round(pL, 4), 'f1': f1(pL, rL),
                                       'clean_fp': bd['clean_fp'], 'neg_rows': bd['neg_rows']}
    print(f"   {dt:24} {bd['rows']:>6} {g:>10} {rL:>8.3f} {pL:>7.3f} {f1(pL, rL):>7.3f} {bd['clean_fp']:>8}")

# headline
print('\n### HEADLINE -- base model alone vs full stack:')
mo, fu, t0 = report['modes']['model'], report['modes']['full'], report['modes']['floor']
print(f"   floor-alone : recallL={t0['labeled_recall']:.4f}  prec={t0['precision']:.4f}  clean_fp={t0['clean_fp']}")
print(f"   model-alone : recallL={mo['labeled_recall']:.4f}  prec={mo['precision']:.4f}  clean_fp={mo['clean_fp']}")
print(f"   full-stack  : recallL={fu['labeled_recall']:.4f}  prec={fu['precision']:.4f}  clean_fp={fu['clean_fp']}")

json.dump(report, open(OUT_JSON, 'w'), indent=2)
print(f'\nwrote {OUT_JSON}')
