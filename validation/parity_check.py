#!/usr/bin/env python3
"""Export-parity gate for the qc-pii model (direction D4).

Asserts that a QUANTIZED / exported model still matches the trained fp32 reference at the
logit level, BEFORE it is shipped. We have no automated check today that the ONNX-INT8 (CPU)
or OpenVINO-FP16 (NPU) export still agrees with the fp32 PyTorch model; a silent export
regression would degrade PII recall with nothing to catch it. Adapted from the parity
discipline in localai-org/privacy-filter.cpp (cosine vs reference logits + argmax parity).

Two metrics, per token, over the held-out corpus (run with prod 600/80 chunking so the
inputs match what the model sees in production):
  - LOGIT COSINE: cosine similarity of the per-token logit vectors (fp32 vs exported).
    Reference discipline: fp32-vs-fp32 == 1.000000; f16 >= 0.999; int8 a little lower but
    high. This catches numerical drift (wrong op, bad scale, layout bug).
  - ARGMAX PARITY: fraction of tokens whose predicted label is unchanged. This is the
    privacy-relevant metric -- it is the rate at which the export would flag the SAME tokens
    as PII. Reported overall AND restricted to tokens where either model predicts a non-O
    label (the "PII decision parity"), since that is what actually matters for redaction.

THE EXPORT ITSELF IS A STOP-AND-ASK GATE. This script only COMPARES an already-produced
export against the reference; it does not quantize or deploy. Run it on P620 (card 4 only)
AFTER an export has been produced and BEFORE shipping it:
    CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=4 \\
    python validation/parity_check.py \\
      --ref   /path/to/fp32-model-dir \\
      --exported /path/to/onnx-int8-model-dir \\
      --corpus /path/to/val.jsonl

100% synthetic data only. No text or PII value is ever printed -- only token counts and
aggregate parity statistics.

The pure functions (per_token_cosine, argmax_agreement, parity_verdict) are dependency-light
(numpy only) and unit-tested in validation/test_parity_check.py; the model runners require
torch + onnxruntime + transformers and only run on the box that holds the model.
"""
from __future__ import annotations
import argparse
import json
import os
import sys

import numpy as np

# Per-tier thresholds (cosine, argmax, pii_argmax). The bar depends on the export precision:
# a lossless/f16 conversion should be near-perfect, but INT8 quantization legitimately sits a
# little lower (the privacy-filter.cpp reference: f32 cosine 1.000000, f16 >= 0.999, int8 lower).
# Holding INT8 to the f16 bar produces false FAILs on a genuinely-good export (e.g. the v11r5 base
# dynamic INT8: cosine 0.998 / argmax 0.997 / pii-argmax 0.981 -- faithful, but < 0.999). The
# pii_argmax bar is the privacy-critical one (rate at which the export flags the SAME PII tokens).
TIER_THRESHOLDS = {
    'f32':  {'cos': 0.99999, 'argmax': 1.0,    'pii_argmax': 1.0},
    'f16':  {'cos': 0.999,   'argmax': 0.999,  'pii_argmax': 0.999},
    'int8': {'cos': 0.99,    'argmax': 0.99,   'pii_argmax': 0.97},
}
DEFAULT_TIER = 'f16'
DEFAULT_COS_THRESHOLD = TIER_THRESHOLDS[DEFAULT_TIER]['cos']
DEFAULT_ARGMAX_THRESHOLD = TIER_THRESHOLDS[DEFAULT_TIER]['argmax']

# Prod line-boundary chunking, copied verbatim from validation/eval_labelaware.py so parity
# is measured on production-shaped inputs.
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


# --------------------------------------------------------------------------------------
# Pure metrics (numpy only) -- unit-tested in test_parity_check.py
# --------------------------------------------------------------------------------------
def per_token_cosine(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Per-token cosine similarity between two [T, C] logit matrices -> [T] in [-1, 1].

    A zero vector on either side yields cosine 0.0 for that token (it cannot be similar to
    anything), which is the conservative choice for a parity gate.
    """
    a = np.asarray(a, dtype=np.float64); b = np.asarray(b, dtype=np.float64)
    if a.shape != b.shape:
        raise ValueError(f'shape mismatch: {a.shape} vs {b.shape}')
    na = np.linalg.norm(a, axis=-1); nb = np.linalg.norm(b, axis=-1)
    denom = na * nb
    dot = np.sum(a * b, axis=-1)
    out = np.zeros_like(dot)
    nz = denom > 0
    out[nz] = dot[nz] / denom[nz]
    return out


def argmax_agreement(a: np.ndarray, b: np.ndarray, o_index: int | None = None):
    """Argmax parity between two [T, C] logit matrices.

    Returns (overall_rate, pii_rate, n_tokens, n_pii_tokens):
      overall_rate  -- fraction of all tokens with the same predicted class.
      pii_rate      -- fraction of tokens where EITHER model predicts a non-O label that
                       still agree (the privacy-relevant rate). If o_index is None, pii_rate
                       == overall_rate. If there are no PII tokens, pii_rate is 1.0.
    """
    a = np.asarray(a); b = np.asarray(b)
    if a.shape != b.shape:
        raise ValueError(f'shape mismatch: {a.shape} vs {b.shape}')
    pa = a.argmax(-1); pb = b.argmax(-1)
    agree = (pa == pb)
    n = int(agree.size)
    overall = float(agree.mean()) if n else 1.0
    if o_index is None:
        return overall, overall, n, n
    pii_mask = (pa != o_index) | (pb != o_index)
    n_pii = int(pii_mask.sum())
    pii_rate = float(agree[pii_mask].mean()) if n_pii else 1.0
    return overall, pii_rate, n, n_pii


def parity_verdict(min_cosine, mean_cosine, argmax_rate, pii_argmax_rate,
                   cos_threshold=DEFAULT_COS_THRESHOLD, argmax_threshold=DEFAULT_ARGMAX_THRESHOLD,
                   pii_argmax_threshold=None):
    """Pass/fail verdict. The gate fails closed: any metric below threshold blocks the export.

    pii_argmax_threshold defaults to argmax_threshold when unset (back-compat). For INT8 it is
    usually set a little lower than overall argmax via the tier preset, but it is still the
    privacy-critical bar -- a flip on a PII token is the failure we guard against.
    """
    if pii_argmax_threshold is None:
        pii_argmax_threshold = argmax_threshold
    checks = {
        'mean_cosine': (mean_cosine >= cos_threshold, mean_cosine, cos_threshold),
        'argmax_parity': (argmax_rate >= argmax_threshold, argmax_rate, argmax_threshold),
        'pii_argmax_parity': (pii_argmax_rate >= pii_argmax_threshold, pii_argmax_rate, pii_argmax_threshold),
    }
    ok = all(passed for passed, _, _ in checks.values())
    return {'ok': ok, 'min_cosine': float(min_cosine), 'checks': {
        k: {'pass': bool(p), 'value': float(v), 'threshold': float(t)} for k, (p, v, t) in checks.items()}}


# --------------------------------------------------------------------------------------
# Model runners (P620 only: torch + onnxruntime + transformers + the model weights)
# --------------------------------------------------------------------------------------
def _load_texts(corpus_path, limit=None):
    rows = [json.loads(l) for l in open(corpus_path, encoding='utf-8') if l.strip()]
    if limit: rows = rows[:limit]
    chunks = []
    for row in rows:
        for ch, _off in _chunks(row['input']):
            if ch.strip():
                chunks.append(ch)
    return chunks


def _tokenize(tok, texts, max_len):
    # Tokenize ONCE so the fp32 and exported models receive byte-identical input ids; this
    # isolates numerical export drift from tokenizer drift (tokenizer drift is D5's concern).
    return [tok(t, return_tensors='np', truncation=True, max_length=max_len) for t in texts]


def _run_torch(model_dir, encs, device, trust_remote_code=False):
    import torch
    from transformers import AutoModelForTokenClassification
    model = AutoModelForTokenClassification.from_pretrained(model_dir, trust_remote_code=trust_remote_code)
    model.to(device).eval()
    out = []
    with torch.no_grad():
        for enc in encs:
            ids = torch.tensor(enc['input_ids'], dtype=torch.long, device=device)
            mask = torch.tensor(enc['attention_mask'], dtype=torch.long, device=device)
            logits = model(input_ids=ids, attention_mask=mask).logits[0].float().cpu().numpy()
            out.append(logits)
    return out


def _run_onnx(model_dir, encs, onnx_filename='model.int8.onnx'):
    import onnxruntime as ort
    sess = ort.InferenceSession(os.path.join(model_dir, onnx_filename), providers=['CPUExecutionProvider'])
    out = []
    for enc in encs:
        logits = sess.run(None, {
            'input_ids': enc['input_ids'].astype(np.int64),
            'attention_mask': enc['attention_mask'].astype(np.int64),
        })[0][0]
        out.append(np.asarray(logits, dtype=np.float32))
    return out


def _o_index(model_dir):
    """Index of the 'O' (outside) class from the model config id2label, or None."""
    cfg_path = os.path.join(model_dir, 'config.json')
    if not os.path.exists(cfg_path):
        return None
    cfg = json.load(open(cfg_path))
    id2label = cfg.get('id2label') or {}
    for k, v in id2label.items():
        if str(v).upper() in ('O', 'OUT', 'OUTSIDE'):
            return int(k)
    return None


def run_parity(ref_dir, exported_dir, corpus, max_len, device, onnx_filename, limit, trust_remote_code):
    from transformers import AutoTokenizer
    texts = _load_texts(corpus, limit=limit)
    print(f'corpus chunks: {len(texts)} (max_len={max_len})', flush=True)
    tok = AutoTokenizer.from_pretrained(ref_dir, trust_remote_code=trust_remote_code)
    encs = _tokenize(tok, texts, max_len)
    o_idx = _o_index(ref_dir)
    print(f'O-class index: {o_idx}', flush=True)
    print(f'running fp32 reference ({os.path.basename(ref_dir)}) on {device} ...', flush=True)
    ref_logits = _run_torch(ref_dir, encs, device, trust_remote_code)
    print(f'running exported ({os.path.basename(exported_dir)}/{onnx_filename}) ...', flush=True)
    exp_logits = _run_onnx(exported_dir, encs, onnx_filename)

    cos_all, agree_all, pii_agree_num, pii_tok = [], [], 0, 0
    n_tok = 0
    for ref, exp, enc in zip(ref_logits, exp_logits, encs):
        mask = enc['attention_mask'][0].astype(bool)
        ref = ref[mask]; exp = exp[mask]  # compare only attended positions
        if ref.shape != exp.shape:
            raise SystemExit(f'STOP: per-chunk shape mismatch {ref.shape} vs {exp.shape} '
                             '(token count differs -- likely a tokenizer/export mismatch, not numerical drift)')
        cos_all.append(per_token_cosine(ref, exp))
        ov, pr, n, npii = argmax_agreement(ref, exp, o_idx)
        agree_all.append(ov * n); n_tok += n
        pii_agree_num += pr * npii; pii_tok += npii
    cos = np.concatenate(cos_all) if cos_all else np.array([1.0])
    argmax_rate = (sum(agree_all) / n_tok) if n_tok else 1.0
    pii_rate = (pii_agree_num / pii_tok) if pii_tok else 1.0
    return {
        'n_tokens': int(n_tok), 'n_pii_tokens': int(pii_tok),
        'mean_cosine': float(cos.mean()), 'min_cosine': float(cos.min()),
        'p1_cosine': float(np.percentile(cos, 1)),
        'argmax_parity': float(argmax_rate), 'pii_argmax_parity': float(pii_rate),
    }


def _self_test():
    """Smoke-test the pure metrics without a model (numpy only)."""
    rng = np.random.default_rng(0)
    a = rng.standard_normal((20, 21))
    print('self-test: identical matrices ->', flush=True)
    cos = per_token_cosine(a, a)
    ov, pr, n, npii = argmax_agreement(a, a, o_index=0)
    v = parity_verdict(cos.min(), cos.mean(), ov, pr)
    print(f'  mean_cosine={cos.mean():.6f} min={cos.min():.6f} argmax={ov:.6f} pii_argmax={pr:.6f} ok={v["ok"]}')
    assert v['ok'] and abs(cos.mean() - 1.0) < 1e-9 and ov == 1.0, 'self-test FAILED'
    # a perturbed copy should still be close but not perfect
    b = a + rng.standard_normal((20, 21)) * 0.01
    cos2 = per_token_cosine(a, b)
    print(f'  perturbed: mean_cosine={cos2.mean():.6f} (expected < 1.0)')
    assert cos2.mean() < 1.0
    print('self-test PASSED', flush=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description='Export-parity gate (D4): fp32 reference vs exported model.')
    ap.add_argument('--ref', help='fp32 reference model dir (AutoModelForTokenClassification)')
    ap.add_argument('--exported', help='exported model dir (contains the .onnx file)')
    ap.add_argument('--corpus', help='held-out val.jsonl (rows with an "input" field)')
    ap.add_argument('--onnx-filename', default='model.int8.onnx')
    ap.add_argument('--max-len', type=int, default=512)
    ap.add_argument('--device', default=os.environ.get('GATE_DEVICE', 'cuda'))
    ap.add_argument('--limit', type=int, default=None, help='cap rows (debug)')
    ap.add_argument('--tier', choices=sorted(TIER_THRESHOLDS), default=DEFAULT_TIER,
                    help='precision-tier threshold preset (int8 legitimately sits below the f16 bar)')
    ap.add_argument('--cos-threshold', type=float, default=None, help='override the tier cosine bar')
    ap.add_argument('--argmax-threshold', type=float, default=None, help='override the tier argmax bar')
    ap.add_argument('--pii-argmax-threshold', type=float, default=None, help='override the tier PII-argmax bar')
    ap.add_argument('--trust-remote-code', action='store_true')
    ap.add_argument('--out', default=os.environ.get('PARITY_OUT', '/tmp/parity_check.json'))
    ap.add_argument('--self-test', action='store_true', help='run pure-metric smoke test only (no model)')
    args = ap.parse_args(argv)

    if args.self_test:
        _self_test(); return 0
    if not (args.ref and args.exported and args.corpus):
        ap.error('--ref, --exported and --corpus are required (or use --self-test)')

    tier = TIER_THRESHOLDS[args.tier]
    cos_thr = args.cos_threshold if args.cos_threshold is not None else tier['cos']
    argmax_thr = args.argmax_threshold if args.argmax_threshold is not None else tier['argmax']
    pii_thr = args.pii_argmax_threshold if args.pii_argmax_threshold is not None else tier['pii_argmax']

    stats = run_parity(args.ref, args.exported, args.corpus, args.max_len, args.device,
                       args.onnx_filename, args.limit, args.trust_remote_code)
    verdict = parity_verdict(stats['min_cosine'], stats['mean_cosine'],
                             stats['argmax_parity'], stats['pii_argmax_parity'],
                             cos_thr, argmax_thr, pii_thr)
    report = {**stats, 'tier': args.tier, 'verdict': verdict,
              'ref': os.path.basename(args.ref), 'exported': os.path.basename(args.exported)}
    print('\n' + '=' * 70)
    print(f'EXPORT PARITY  tier={args.tier}  ref={report["ref"]}  exported={report["exported"]}')
    print('=' * 70)
    print(f'  tokens={stats["n_tokens"]}  pii_tokens={stats["n_pii_tokens"]}')
    print(f'  mean_cosine={stats["mean_cosine"]:.6f}  min={stats["min_cosine"]:.6f}  p1={stats["p1_cosine"]:.6f}')
    print(f'  argmax_parity={stats["argmax_parity"]:.6f}  pii_argmax_parity={stats["pii_argmax_parity"]:.6f}')
    for k, c in verdict['checks'].items():
        print(f'  [{"PASS" if c["pass"] else "FAIL"}] {k}: {c["value"]:.6f} (>= {c["threshold"]})')
    json.dump(report, open(args.out, 'w'), indent=2)
    print(f'\nwrote {args.out}')
    print('VERDICT:', 'PASS -- export matches reference' if verdict['ok']
          else 'FAIL -- export diverges from reference; DO NOT SHIP')
    return 0 if verdict['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
