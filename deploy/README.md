# deploy/ -- gate appliance artifacts

Version-controlled copies of the deployed gate-appliance code that previously lived only on the
hosts (the un-versioned-appliance gap, finding **F6**). This directory does not yet hold the full
appliance (the GPU service + the shared `privacy_gate.py` still live on the hosts); it captures the
**CPU INT8 tier** added 2026-06-16 plus the export tooling, so that path is reproducible.

## Contents
- `gate_service_cpu.py` -- FastAPI CPU gate (`NPUTier` = onnxruntime INT8 on CPU). Same
  `/detect` `/redact` `/healthz` contract as the GPU gate; CPU-only (never touches a GPU).
- `ossredact-gate-cpu.service` -- systemd unit (port 8011, `CUDA_VISIBLE_DEVICES=` to stay off GPUs).
- `export_quantize_v11_cpu.py` -- exports an xlm-r fp32 checkpoint to ONNX, then **dynamic**
  (weights-only) INT8. Host paths are hard-coded to gpu-host; edit `MDIR`/`CALIB` for another model.

## Why dynamic (weights-only) INT8, not static QDQ
Static QDQ (per-tensor AND per-channel AND embedding-excluded) all collapsed PII recall on xlm-r
(parity PII-argmax ~0.14) -- the damage is **static activation quantization**, not the weights.
`quantize_dynamic` (no activation quant) is faithful and is the recipe behind the deployed v6/v7
INT8 models. Confirmed by the parity gate + an end-task recall check.

## Runbook: export -> parity-gate -> deploy
The export/quantization and the deploy are **STOP-and-ask gates** -- do not run them without
explicit operator approval.

```bash
# 1. EXPORT + QUANTIZE (CPU-only; on the box that holds the fp32 checkpoint, e.g. gpu-host)
CUDA_VISIBLE_DEVICES= .venv/bin/python deploy/export_quantize_v11_cpu.py
#    -> writes model.onnx (fp32) + model.int8.onnx (dynamic INT8) into the model dir

# 2. PARITY GATE (must pass before shipping -- see validation/parity_check.py)
CUDA_VISIBLE_DEVICES= .venv/bin/python validation/parity_check.py \
  --ref <fp32-model-dir> --exported <model-dir-with-model.int8.onnx> \
  --corpus <held-out.jsonl> --max-len 512 --device cpu --tier int8
#    INT8 reference (v11r5 base): cosine 0.998, PII-argmax 0.981; end-task recall -0.56pp vs fp32

# 3. DEPLOY (the CPU tier belongs on the gate-host sidecar box, alongside the NPU tier)
#    copy the model dir (model.int8.onnx + config.json + tokenizer) + gate_service_cpu.py
#    + privacy_gate.py to the host, install the unit, start it:
sudo cp deploy/ossredact-gate-cpu.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ossredact-gate-cpu.service
curl -s http://127.0.0.1:8011/healthz
```

## Deployment record (2026-06-16)
Live on **gate-host** (the sidecar box). The existing `ossredact-gate.service` (:8001) was updated from
**v7 OpenVINO-FP16 on the Intel NPU** to **v11r5-base ONNX-INT8 on CPU** via the systemd drop-in
`ossredact-gate.service.d/v11int8.conf` (repoints `ExecStart` to `gate_service_cpu.py`, sets
`CPU_GATE_PORT=8001` so the egress proxy on :8011 is unchanged). The base unit is preserved, so:

```bash
# rollback to the v7 OpenVINO/NPU tier:
sudo rm /etc/systemd/system/ossredact-gate.service.d/v11int8.conf
sudo systemctl daemon-reload && sudo systemctl restart ossredact-gate.service
```

Result: detect latency ~42ms (was ~112ms on the NPU -- for a model this small, CPU INT8 beats the
NPU's OpenVINO overhead), higher per-entity confidence, egress proxy intact, NRestarts 0. The
gpu-host validation copy of this tier was torn down (one gate, the best model).

## Notes
- `NPUTier(model_dir)` loads `model_dir/model.int8.onnx` + the tokenizer + `config.json` from the
  same dir via the onnxruntime CPUExecutionProvider.
- The full F6 fix (version-control the entire appliance: GPU service, `privacy_gate.py`, the egress
  proxy) is still open; this directory is the start.
