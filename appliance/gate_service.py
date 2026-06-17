#!/usr/bin/env python3
"""Always-on PII redaction sidecar for the CI PDF parser, backed by the Intel NPU (OpenVINO FP16 IR).

Drop-in replacement for the retired ~/ai-tools/privacy-filter sidecar: serves the EXACT contract the
parser's redactBertFallback() expects:
  POST /redact  {text, mode}  -> {redacted_text, mapping, stats{request_id,total_spans,by_category,elapsed_ms}}
  GET  /healthz               -> {status, model, uptime_s}
Placeholders are <LABEL_NNN> so the parser's uniquePlaceholder()/unredact() handle them unchanged.
Tier-0 regex (incl. unicode-dash-normalized accounts, UUIDs, NAS, cards) + NPU neural tier + union merge.
"""
import sys, time, json, uuid
from collections import defaultdict
import numpy as np
sys.path.insert(0, '/opt/ossredact-npu')
from openvino import Core
from transformers import AutoTokenizer
from privacy_gate import PrivacyGate
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

MODEL_DIR = '/opt/ossredact-npu/model'
XML = MODEL_DIR + '/openvino/model_fp16.xml'
DEVICE = 'NPU'
MAXLEN = 256
CACHE_DIR = '/opt/ossredact-npu/.ovcache'
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

app = FastAPI(title='ossredact NPU sidecar')


class RedactReq(BaseModel):
    text: str
    mode: str = 'substitute'


@app.post('/redact')
def redact(req: RedactReq):
    t0 = time.time()
    spans = gate.detect(req.text, min_score=0.5)
    counters = defaultdict(int); by_cat = defaultdict(int); by_rule = defaultdict(int); mapping = {}; out = []; last = 0
    for s in sorted(spans, key=lambda s: s['start']):
        lab = s['label'].upper()
        counters[lab] += 1
        ph = f"<{lab}_{counters[lab]:03d}>"
        mapping[ph] = req.text[s['start']:s['end']]
        by_cat[s['label']] += 1
        by_rule[s.get('rule', '?')] += 1
        out.append(req.text[last:s['start']]); out.append(ph); last = s['end']
    out.append(req.text[last:])
    return {
        'redacted_text': ''.join(out),
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
    # 0.0.0.0 so the dockerized parser can reach it via <docker-host> (host-gateway). The gate-host
    # firewall gates LAN exposure (same posture the retired sidecar had on :8001). Parser is loopback-local
    # otherwise; PII text only crosses the host-internal docker bridge.
    uvicorn.run(app, host='0.0.0.0', port=8001, log_level='warning')
