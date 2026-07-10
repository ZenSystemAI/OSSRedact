#!/usr/bin/env python3
"""Export the base PII model -> fp32 ONNX -> dynamic per-channel INT8 (weights-only) for the CPU +
in-browser tier. Adapted from export_quantize_npu.py. Quantizes directly from the raw fp32 ONNX
(quant_pre_process is skipped -- it corrupts xlm-r shapes). CPU-only; never touches card 4.
Static QDQ activation quantization was the damage source on this architecture (~0.84 cosine), so the
recipe is weights-only dynamic + per_channel (see validation/RESULT-base-int8-parity-v11r9c.md). The
shipped base revision is v11r9c. 100% synthetic calibration data.
"""
import json
import os
from pathlib import Path
import numpy as np
import torch
import onnx
import onnxruntime as ort
from onnxruntime.quantization import (quantize_dynamic, quantize_static, QuantType,
                                      CalibrationDataReader, CalibrationMethod, QuantFormat)
from transformers import AutoTokenizer, AutoModelForTokenClassification

# Model dir is env-overridable so the same recipe can export any revision
# (e.g. OSSREDACT_EXPORT_MODEL_DIR=models/pii-gpu-xlmr-base-v11r9c -- the shipped base).
MDIR = Path(os.environ.get('OSSREDACT_EXPORT_MODEL_DIR', 'models/pii-gpu-xlmr-base-v11r9c'))
FP32 = MDIR / 'model.onnx'
INT8 = MDIR / 'model.int8.onnx'  # dynamic (weights-only) int8 -- the proven v6/v7 recipe
CALIB = 'datasets/pii-merged/train.jsonl'
N_CALIB = 200
MAXLEN = 512

tok = AutoTokenizer.from_pretrained(str(MDIR))


class Wrap(torch.nn.Module):
    def __init__(self, m): super().__init__(); self.m = m
    def forward(self, input_ids, attention_mask):
        return self.m(input_ids=input_ids, attention_mask=attention_mask).logits


class Reader(CalibrationDataReader):
    def __init__(self, path, n):
        rows = [json.loads(l) for l in open(path, encoding='utf-8') if l.strip()][:n]
        self.data = []
        for r in rows:
            enc = tok(r['input'], truncation=True, max_length=MAXLEN, return_tensors='np')
            self.data.append({'input_ids': enc['input_ids'].astype(np.int64),
                              'attention_mask': enc['attention_mask'].astype(np.int64)})
        self.it = iter(self.data)

    def get_next(self):
        return next(self.it, None)

    def rewind(self):
        self.it = iter(self.data)


def main():
    if not FP32.exists():
        print('exporting fp32 onnx (CPU) ...', flush=True)
        model = AutoModelForTokenClassification.from_pretrained(str(MDIR)); model.eval()
        dummy = tok('exporter probe text', return_tensors='pt')
        torch.onnx.export(Wrap(model), (dummy['input_ids'], dummy['attention_mask']), str(FP32),
                          input_names=['input_ids', 'attention_mask'], output_names=['logits'],
                          dynamic_axes={'input_ids': {0: 'b', 1: 's'}, 'attention_mask': {0: 'b', 1: 's'},
                                        'logits': {0: 'b', 1: 's'}}, opset_version=17)
        print('exported fp32 onnx ->', FP32, flush=True)
    else:
        print('fp32 onnx exists ->', FP32, flush=True)

    m = onnx.load(str(FP32), load_external_data=False)
    gather_nodes = [n.name for n in m.graph.node if n.op_type == 'Gather']
    # NOTE: xlm-r's word embedding is a 250K-vocab table (~768MB fp32), so it DOMINATES model
    # size. Unlike distilbert (small vocab, where static_quant_cpu.py kept it fp32), for xlm-r
    # the embedding MUST be quantized or the "int8" stays ~855MB. We quantize ALL ops and rely
    # on STATIC calibration to protect recall; parity_check.py is the gate that judges it.
    print('Gather/embedding nodes (quantized too, not excluded):', gather_nodes, flush=True)

    if not INT8.exists():
        # DYNAMIC int8: weights-only (no activation quant). The static QDQ activation
        # quantization was the damage source (per-tensor/per-channel/no-embed all gave the
        # same ~0.84 cosine / 0.15 PII parity). This is the recipe that produced the deployed
        # v6/v7 int8 models. parity_check.py is the gate.
        #
        # per_channel=True: a 2026-06-20 bake-off (validation/RESULT-base-int8-parity-v11r9c.md)
        # measured five weights-only variants on the v11r9c base against the OOD heldout. Per-channel
        # weight scales are the best dynamic recipe (pii_argmax 0.9638 -> 0.9679, ~free on size);
        # excluding the classifier head does NOTHING (the quant damage is spread across the encoder,
        # not the decision layer). The v11r9c base is genuinely more quant-sensitive than v11r5
        # (the org/address augmentation sharpened decision boundaries), so dynamic int8 lands at
        # pii_argmax 0.967; the int8 parity bar is 0.965 and v11r9c per-channel int8 SHIPS (Option A,
        # validation/RESULT-base-int8-parity-v11r9c.md -- int8 is the WASM-native in-browser format;
        # fp16 needs WebGPU and is NOT a broad-reach substitute).
        print('DYNAMIC INT8 quantization (weights-only, per-channel) ...', flush=True)
        quantize_dynamic(str(FP32), str(INT8), weight_type=QuantType.QInt8, per_channel=True)
        print('dynamic int8 ->', INT8, flush=True)
    else:
        print('int8 exists ->', INT8, flush=True)

    # sanity: load int8 + run one synthetic input (catches a runtime shape failure immediately)
    sess = ort.InferenceSession(str(INT8), providers=['CPUExecutionProvider'])
    enc = tok('Le NAS de Sylvie Bouchard est 046 454 286.', truncation=True,
              max_length=MAXLEN, return_tensors='np')
    out = sess.run(None, {'input_ids': enc['input_ids'].astype(np.int64),
                          'attention_mask': enc['attention_mask'].astype(np.int64)})[0]
    fp32_mb = FP32.stat().st_size / 1e6
    int8_mb = INT8.stat().st_size / 1e6
    print(f'int8 SANITY RUN OK -- logits shape {out.shape}', flush=True)
    print(f'SIZES fp32_onnx={fp32_mb:.1f}MB int8={int8_mb:.1f}MB', flush=True)
    print('DONE', flush=True)


if __name__ == '__main__':
    main()
