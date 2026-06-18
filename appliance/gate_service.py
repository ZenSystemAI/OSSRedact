#!/usr/bin/env python3
"""Always-on PII redaction sidecar for the CI PDF parser, backed by the Intel NPU (OpenVINO FP16 IR).

Drop-in replacement for the retired ~/ai-tools/privacy-filter sidecar: serves the EXACT contract the
parser's redactBertFallback() expects:
  POST /redact  {text, mode='substitute'} -> {redacted_text, mapping, stats{request_id,total_spans,by_category,elapsed_ms}}
  GET  /healthz               -> {status, model, uptime_s}
Placeholders are <LABEL_NNN> so the parser's uniquePlaceholder()/unredact() handle them unchanged.
Tier-0 regex (incl. unicode-dash-normalized accounts, UUIDs, NAS, cards) + NPU neural tier + union merge.
"""
import os, sys, time, json, uuid
from collections import defaultdict
import numpy as np
APPLIANCE_DIR = os.environ.get('GATEWAY_APPLIANCE_DIR') or os.path.dirname(os.path.abspath(__file__))
if APPLIANCE_DIR not in sys.path:
    sys.path.insert(0, APPLIANCE_DIR)
from openvino import Core
from transformers import AutoTokenizer
from privacy_gate import PrivacyGate, _build_known_re, _sweep_known, _case_sensitive_label, _dedup_key
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

MODEL_DIR = os.environ.get('GATEWAY_NPU_MODEL_DIR', os.path.join(APPLIANCE_DIR, 'model'))
XML = os.path.join(MODEL_DIR, 'openvino', 'model_fp16.xml')
DEVICE = 'NPU'
MAXLEN = 512   # match NPUTier/GPUTier + the 600-char chunking: a token-dense 600-char chunk reaches ~300 tokens; 256 truncated the tail and dropped PII (see NPUTier note in privacy_gate.py)
CACHE_DIR = os.environ.get('GATEWAY_NPU_CACHE_DIR', os.path.join(APPLIANCE_DIR, '.ovcache'))
MODEL_NAME = 'ossredact/npu-xlmr-base-v7 (OpenVINO FP16, Intel NPU)'
START = time.time()


class OVTier:
    """OpenVINO neural tier on the NPU. Same .spans() interface PrivacyGate.npu expects."""
    def __init__(self, xml, model_dir, device, max_len=256):
        self.core = Core()
        try:
            self.core.set_property({'CACHE_DIR': CACHE_DIR})  # cache compiled NPU blob -> fast restarts
        except Exception as e:
            print('cache_dir note:', e, flush=True)
        self.max_len = max_len
        m = self.core.read_model(xml)
        m.reshape({i.get_any_name(): [1, max_len] for i in m.inputs})
        self.comp = self.core.compile_model(m, device)
        self.inames = [i.get_any_name() for i in self.comp.inputs]
        self.tok = AutoTokenizer.from_pretrained(model_dir)
        cfg = json.loads(open(model_dir + '/config.json').read())
        self.id2label = {int(k): v for k, v in cfg['id2label'].items()}

    def spans(self, text, min_score=0.5):
        enc = self.tok(text, padding='max_length', truncation=True, max_length=self.max_len,
                       return_offsets_mapping=True, return_tensors='np')
        off = enc['offset_mapping'][0]
        feed = {n: (enc['attention_mask'] if 'mask' in n else enc['input_ids']).astype(np.int64) for n in self.inames}
        logits = list(self.comp(feed).values())[0][0]
        x = logits - logits.max(-1, keepdims=True); p = np.exp(x); p = p / p.sum(-1, keepdims=True)
        ids = p.argmax(-1); out = []; cur = None
        for i, (a, b) in enumerate(off):
            if a == b: continue
            tag = self.id2label[int(ids[i])]; sc = float(p[i, ids[i]])
            if tag == 'O':
                if cur: out.append(cur); cur = None
                continue
            pref, lab = tag.split('-', 1)
            if pref == 'B' or cur is None or cur['label'] != lab:
                if cur: out.append(cur)
                cur = {'start': int(a), 'end': int(b), 'label': lab, 'tier': 1, 'conf': sc, 'rule': 'npu'}
            else:
                cur['end'] = int(b); cur['conf'] = min(cur['conf'], sc)
        if cur: out.append(cur)
        return [s for s in out if s['conf'] >= min_score]


print(f'loading NPU gate (device={DEVICE}) ...', flush=True)
gate = PrivacyGate(None)
gate.npu = OVTier(XML, MODEL_DIR, DEVICE, MAXLEN)
gate.npu.spans('warmup Jean Tremblay NAS 046 454 286 compte 006-02761-1234567')
print('NPU gate ready', flush=True)

app = FastAPI(title='OSSRedact NPU sidecar')
SUPPORTED_REDACT_MODES = {'substitute'}


def _require_supported_redact_mode(mode):
    if mode not in SUPPORTED_REDACT_MODES:
        raise HTTPException(
            status_code=400,
            detail="unsupported redact mode; only 'substitute' is implemented",
        )


class RedactReq(BaseModel):
    text: str
    mode: str = 'substitute'


@app.post('/redact')
def redact(req: RedactReq):
    t0 = time.time()
    _require_supported_redact_mode(req.mode)
    spans = gate.detect(req.text, min_score=0.5)
    counters = defaultdict(int); by_cat = defaultdict(int); by_rule = defaultdict(int); mapping = {}; out = []; last = 0
    seen = {}; label_by_ph = {}
    for s in sorted(spans, key=lambda s: s['start']):
        value = req.text[s['start']:s['end']]
        lab = s['label'].upper()
        ph = seen.get(_dedup_key(s['label'], value))
        if ph is None:
            counters[lab] += 1
            ph = f"<{lab}_{counters[lab]:03d}>"
            seen[_dedup_key(s['label'], value)] = ph
            mapping[ph] = value
            label_by_ph[ph] = s['label']
        by_cat[s['label']] += 1
        by_rule[s.get('rule', '?')] += 1
        out.append(req.text[last:s['start']]); out.append(ph); last = s['end']
    out.append(req.text[last:])
    redacted_text = ''.join(out)
    # Finding C backstop: the positional pass masks only DETECTED span positions, so a value that repeats
    # across a long/multi-page document (footers, repeated headers, line items) leaks at the occurrences the
    # detector skipped. Sweep the redacted text for every already-known value (len>=4, word-boundary-guarded,
    # longest-first) and mask each remaining occurrence with its EXISTING placeholder -- never a new one. Runs
    # only on the literal gaps BETWEEN placeholders, so it cannot rewrite a placeholder already inserted.
    exact_v2p = {v: ph for ph, v in mapping.items() if _case_sensitive_label(label_by_ph.get(ph, ''))}
    ci_v2p = {v: ph for ph, v in mapping.items() if not _case_sensitive_label(label_by_ph.get(ph, ''))}
    protected = set(mapping.keys())
    redacted_text, swept_exact = _sweep_known(redacted_text, _build_known_re(exact_v2p.keys(), ignore_case=False),
                                              exact_v2p, protected_placeholders=protected, case_sensitive=True)
    redacted_text, swept_ci = _sweep_known(redacted_text, _build_known_re(ci_v2p.keys(), ignore_case=True),
                                           ci_v2p, protected_placeholders=protected)
    _swept = swept_exact + swept_ci
    return {
        'redacted_text': redacted_text,
        'mapping': mapping,
        'stats': {
            'request_id': uuid.uuid4().hex[:12],
            'total_spans': len(spans),
            'by_category': dict(by_cat),
            'by_rule': dict(by_rule),       # provenance: which recognizer fired (no values)
            'elapsed_ms': round((time.time() - t0) * 1000, 1),
        },
    }


class DetectReq(BaseModel):
    text: str
    min_score: float = 0.5


@app.post('/detect')
def detect(req: DetectReq):
    """Raw spans, no substitution. The egress proxy owns placeholder naming + cross-turn map consistency,
    so it needs the spans, not a pre-substituted string. Same detector as /redact (Tier-0 + NPU + union merge)."""
    t0 = time.time()
    spans = gate.detect(req.text, min_score=req.min_score)
    return {
        'spans': [{'start': s['start'], 'end': s['end'], 'label': s['label'], 'tier': s['tier'],
                   'conf': round(float(s['conf']), 4), 'rule': s.get('rule'),
                   **({'validator': s['validator']} if s.get('validator') else {}),
                   **({'cue': s['cue']} if s.get('cue') else {}),
                   **({'subtype': s['subtype']} if s.get('subtype') else {}),
                   **({'members': s['members']} if s.get('members', 1) != 1 else {})} for s in spans],
        'elapsed_ms': round((time.time() - t0) * 1000, 1),
    }


@app.get('/healthz')
def healthz():
    return {'status': 'ok', 'model': MODEL_NAME, 'uptime_s': round(time.time() - START, 1)}


if __name__ == '__main__':
    # 0.0.0.0 so the dockerized parser can reach it via host.docker.internal (host-gateway). The host
    # firewall gates LAN exposure (same posture the retired sidecar had on :8001). Parser is loopback-local
    # otherwise; PII text only crosses the host-internal docker bridge.
    uvicorn.run(app, host='0.0.0.0', port=8001, log_level='warning')
