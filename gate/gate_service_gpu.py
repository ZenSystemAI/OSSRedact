#!/usr/bin/env python3
"""Always-on GPU PII redaction gate (own-use redaction: the workbench Deep-detect + the egress proxy).

The GPU sibling of the CPU/NPU sidecar gate. SAME contract, so the egress proxy
(GATEWAY_GATE_URL), the redaction workbench, and the CI parser are all drop-in:
  POST /detect  {text, min_score}  -> {spans:[{start,end,label,tier,conf,rule,...}], elapsed_ms}
  POST /redact  {text, mode='substitute'} -> {redacted_text, mapping(<LABEL_NNN>), stats{request_id,total_spans,by_category,by_rule,elapsed_ms}}
  GET  /healthz                    -> {status, model, device, uptime_s}

Neural tier = xlm-r-LARGE fp16 (pii-gpu-xlmr-large-v6), the strongest tier of the SAME model family as the
always-on CPU/NPU (xlm-r-base) -- so identical labels + BIO decoding + case-norm second pass. Pinned to the GPU host
3090 Ti via CUDA_VISIBLE_DEVICES=4 in the unit. Tier-0 regex/Luhn + context-cue + union merge + provenance
are shared from privacy_gate.py (the provenance-complete superset, mirrored next to this file).

Long text is chunked on line boundaries (the model truncates at 256 tokens) so a multi-page document is fully
scanned even if the caller does not pre-chunk; spans are offset-adjusted back and union-merged.
"""
import os, sys, time, uuid
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privacy_gate import PrivacyGate, GPUTier, merge_spans  # noqa: E402

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

MODEL_DIR = os.environ.get('GPU_GATE_MODEL', os.path.expanduser('~/.ossredact/models/pii-xlmr-large'))
PORT = int(os.environ.get('GPU_GATE_PORT', '8001'))
HOST = os.environ.get('GPU_GATE_HOST', '0.0.0.0')  # host-internal bind; gate behind your firewall (parity with the CPU/NPU gate)
CHUNK_CHARS = 600  # stay under the 256-token window even on dense tabular text (matches the egress proxy)
CHUNK_OVERLAP = 80  # window overlap so a value straddling a boundary is caught in one window + union-merged
MODEL_NAME = f'ossredact/{os.path.basename(MODEL_DIR)} (fp16, CUDA)'
START = time.time()

print(f'loading GPU gate ({MODEL_DIR}) CVD={os.environ.get("CUDA_VISIBLE_DEVICES")} ...', flush=True)
gate = PrivacyGate(None)
gate.npu = GPUTier(MODEL_DIR)  # duck-typed neural tier: xlm-r-large fp16 on cuda:0 (= physical card via CVD)
_warm = gate.detect('warmup Jean Tremblay NAS 046 454 286 compte 006-02761-1234567 courriel a@b.ca')
print(f'GPU gate ready ({len(_warm)} warmup spans)', flush=True)

app = FastAPI(title='OSSRedact GPU gate')
SUPPORTED_REDACT_MODES = {'substitute'}


def _require_supported_redact_mode(mode):
    if mode not in SUPPORTED_REDACT_MODES:
        raise HTTPException(
            status_code=400,
            detail="unsupported redact mode; only 'substitute' is implemented",
        )


def _windows(s, base, size=CHUNK_CHARS, overlap=CHUNK_OVERLAP):
    """Char windows (with overlap, preferring a word boundary near the end) for a single over-long segment --
    so model-only PII past the 256-token cutoff in an unbroken line is NOT truncated away. Yields (text, offset)."""
    n = len(s)
    i = 0
    while i < n:
        end = min(i + size, n)
        if end < n:
            j = s.rfind(' ', max(i + size - overlap, i + 1), end)
            if j > i:
                end = j
        yield s[i:end], base + i
        if end >= n:
            break
        i = max(end - overlap, i + 1)


def _chunks(text, size=CHUNK_CHARS):
    """Prefer line boundaries (keep records intact for tabular/statement data), but HARD-WINDOW any single
    line longer than `size` so a long unbroken paragraph / flattened-OCR line / wide CSV row can't truncate
    its tail PII. Yields (chunk_text, char_offset); spans are union-merged afterward (overlap-safe)."""
    lines = text.splitlines(keepends=True)
    buf, start, pos = '', 0, 0
    for ln in lines:
        if len(ln) > size:
            if buf:
                yield buf, start
                buf = ''
            yield from _windows(ln, pos)
            pos += len(ln)
            start = pos
            continue
        if buf and len(buf) + len(ln) > size:
            yield buf, start
            buf, start = '', pos
        buf += ln
        pos += len(ln)
    if buf:
        yield buf, start


def detect_chunked(text, min_score):
    spans = []
    for chunk, off in _chunks(text):
        for s in gate.detect(chunk, min_score):
            spans.append({**s, 'start': s['start'] + off, 'end': s['end'] + off})
    return merge_spans(spans)


class DetectReq(BaseModel):
    text: str
    min_score: float = 0.5


@app.post('/detect')
def detect(req: DetectReq):
    """Raw spans, no substitution -- the egress proxy owns placeholder naming + cross-turn map consistency."""
    t0 = time.time()
    spans = detect_chunked(req.text, req.min_score)
    return {
        'spans': [{'start': s['start'], 'end': s['end'], 'label': s['label'], 'tier': s['tier'],
                   'conf': round(float(s['conf']), 4), 'rule': s.get('rule'),
                   **({'validator': s['validator']} if s.get('validator') else {}),
                   **({'cue': s['cue']} if s.get('cue') else {}),
                   **({'subtype': s['subtype']} if s.get('subtype') else {}),
                   **({'members': s['members']} if s.get('members', 1) != 1 else {})} for s in spans],
        'elapsed_ms': round((time.time() - t0) * 1000, 1),
    }


class RedactReq(BaseModel):
    text: str
    mode: str = 'substitute'


@app.post('/redact')
def redact(req: RedactReq):
    t0 = time.time()
    _require_supported_redact_mode(req.mode)
    # Chunk long text here (the model truncates at 256 tokens), then delegate the ACTUAL redaction to
    # PrivacyGate.redact -- the single source of truth that does label-aware placeholder dedup AND the Finding-C
    # repeated-value sweep (a value the detector skips at some occurrences is masked with its existing
    # placeholder). The inline positional-only loop this replaces did neither, so direct /redact callers
    # leaked repeated values + minted duplicate placeholders for the same value.
    spans = detect_chunked(req.text, 0.5)
    redacted, mapping, spans = gate.redact(req.text, spans=spans)
    by_cat = defaultdict(int); by_rule = defaultdict(int)
    for s in spans:
        by_cat[s['label']] += 1
        by_rule[s.get('rule', '?')] += 1
    return {
        'redacted_text': redacted,
        'mapping': mapping,
        'stats': {'request_id': uuid.uuid4().hex[:12], 'total_spans': len(spans),
                  'by_category': dict(by_cat), 'by_rule': dict(by_rule),
                  'elapsed_ms': round((time.time() - t0) * 1000, 1)},
    }


@app.get('/healthz')
def healthz():
    return {'status': 'ok', 'model': MODEL_NAME,
            'device': f'cuda:0 (CUDA_VISIBLE_DEVICES={os.environ.get("CUDA_VISIBLE_DEVICES")})',
            'uptime_s': round(time.time() - START, 1)}


if __name__ == '__main__':
    uvicorn.run(app, host=HOST, port=PORT, log_level='warning')
