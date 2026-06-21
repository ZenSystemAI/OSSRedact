#!/usr/bin/env python3
"""Always-on CPU PII redaction gate -- INT8 sibling of gate_service_gpu.py.

SAME contract as the GPU/NPU gates (drop-in for the egress proxy, workbench, CI parser):
  POST /detect  {text, min_score}  -> {spans:[...], elapsed_ms}
  POST /redact  {text, mode='substitute'} -> {redacted_text, mapping(<LABEL_NNN>), stats{...}}
  GET  /healthz                    -> {status, model, device, uptime_s}

Neural tier = xlm-r-base v11r9c ONNX INT8 (dynamic, per-channel, weights-only) on CPU via onnxruntime
CPUExecutionProvider -- the GPU-free portable tier. Same labels + BIO decoding + chunking as
the GPU gate; Tier-0 floor + union merge are shared from privacy_gate.py. Runs CPU-only; never
touches the GPU gate on card 4 / :8001.

INT8 parity: v11r9c added org/address augmentation that sharpened the decision boundaries -- a
training win that is also harder to quantize -- so the best dynamic recipe (per-channel) lands at
pii_argmax 0.967 (cosine 0.997, faithful) vs the v11r5 base's 0.981. The validation/parity_check.py
INT8 bar is 0.965 for this reason (see validation/RESULT-base-int8-parity-v11r9c.md): ~62% of the
token-flips are on floor-protected types the deterministic Tier-0 layer redacts regardless of the
model, the highest-frequency no-floor type (person) is barely affected, and INT8 is the only
WASM-native in-browser format. Both tiers now ship v11r9c.
"""
import os, sys, time, uuid
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privacy_gate import PrivacyGate, NPUTier, merge_spans  # noqa: E402

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

MODEL_DIR = os.environ.get('CPU_GATE_MODEL', os.path.expanduser('~/.ossredact/models/ossredact-pii-base-int8'))
PORT = int(os.environ.get('CPU_GATE_PORT', '8001'))
HOST = os.environ.get('CPU_GATE_HOST', '127.0.0.1')  # opt in to a tailnet/LAN bind with CPU_GATE_HOST
CHUNK_CHARS = 600  # stay under the 256-token window even on dense tabular text (matches the egress proxy)
CHUNK_OVERLAP = 80  # window overlap so a value straddling a boundary is caught in one window + union-merged
MODEL_NAME = f'ZenSystemAI/{os.path.basename(MODEL_DIR).removesuffix("-int8")} (int8, CPU)'  # public HF repo id (ZenSystemAI/ossredact-pii-base); the "(int8, CPU)" suffix already conveys quantization, version ships as an HF revision tag
START = time.time()

print(f'loading CPU gate ({MODEL_DIR}) onnxruntime CPUExecutionProvider ...', flush=True)
if not os.path.isdir(MODEL_DIR) or not any(f.endswith('.onnx') for f in os.listdir(MODEL_DIR)):
    raise SystemExit(
        f"\n[CPU gate] PII model weights not found at {MODEL_DIR}.\n"
        f"Download them first (see QUICKSTART.md), e.g.:\n"
        f"  hf download ZenSystemAI/ossredact-pii-base --local-dir {MODEL_DIR}\n"
        f"or set CPU_GATE_MODEL to an existing INT8 ONNX model directory.\n")
gate = PrivacyGate(None)
gate.npu = NPUTier(MODEL_DIR)  # duck-typed neural tier: xlm-r-base v11r5 int8 on CPU (onnxruntime)
_warm = gate.detect('warmup Jean Tremblay NAS 046 454 286 compte 006-02761-1234567 courriel a@b.ca')
print(f'CPU gate ready ({len(_warm)} warmup spans)', flush=True)

app = FastAPI(title='OSSRedact CPU gate')
SUPPORTED_REDACT_MODES = {'substitute'}


def _require_supported_redact_mode(mode):
    if mode not in SUPPORTED_REDACT_MODES:
        raise HTTPException(
            status_code=400,
            detail="unsupported redact mode; only 'substitute' is implemented",
        )


def _windows(s, base, size=CHUNK_CHARS, overlap=CHUNK_OVERLAP):
    """Char windows (with overlap, preferring a word boundary near the end) for a single over-long segment."""
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
    """Prefer line boundaries, but HARD-WINDOW any single line longer than `size`. Yields (chunk, offset)."""
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
            'device': 'cpu (onnxruntime CPUExecutionProvider)',
            'uptime_s': round(time.time() - START, 1)}


if __name__ == '__main__':
    uvicorn.run(app, host=HOST, port=PORT, log_level='warning')
