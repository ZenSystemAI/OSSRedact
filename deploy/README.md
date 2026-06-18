# deploy/ -- gate appliance artifacts

Deploy-specific gate artifacts: the CPU INT8 deploy entrypoint and the export tooling, so that
path is reproducible. The full always-on proxy lives under `appliance/`; the GPU and CPU gate
services live under `gate/`.

## Contents
- `gate_service_cpu.py` -- FastAPI CPU gate (onnxruntime INT8 on CPU). Same `/detect` `/redact`
  `/healthz` contract as the GPU gate; CPU-only (never touches a GPU). Byte-identical to
  `gate/gate_service_cpu.py`; CI enforces this via `gate/tests/test_deploy_gate_service_sync.py`.
- `ossredact-gate-cpu.service` -- systemd unit (port 8011, `CUDA_VISIBLE_DEVICES=` to stay off GPUs).
- `export_quantize_v11_cpu.py` -- exports an xlm-r fp32 checkpoint to ONNX, then **dynamic**
  (weights-only) INT8. Set `MDIR` / `CALIB` to your model + calibration set.

## Why dynamic (weights-only) INT8, not static QDQ
Static QDQ (per-tensor AND per-channel AND embedding-excluded) all collapsed PII recall on xlm-r
(parity PII-argmax ~0.14) -- the damage is **static activation quantization**, not the weights.
`quantize_dynamic` (no activation quant) is faithful and is the recipe behind the deployed INT8
models. Confirmed by the parity gate + an end-task recall check.

## Runbook: export -> parity-gate -> deploy
Export/quantization and deploy are **stop-and-ask gates** in any production setting; do not run
them blindly.

```bash
# 1. EXPORT + QUANTIZE (CPU-only; on the box that holds the fp32 checkpoint)
CUDA_VISIBLE_DEVICES= .venv/bin/python deploy/export_quantize_v11_cpu.py
#    -> writes model.onnx (fp32) + model.int8.onnx (dynamic INT8) into the model dir

# 2. PARITY GATE (must pass before shipping -- see validation/parity_check.py)
CUDA_VISIBLE_DEVICES= .venv/bin/python validation/parity_check.py \
  --ref <fp32-model-dir> --exported <model-dir-with-model.int8.onnx> \
  --corpus <held-out.jsonl> --max-len 512 --device cpu --tier int8
#    INT8 reference (v11r5 base): cosine 0.998, PII-argmax 0.981; end-task recall -0.56pp vs fp32

# 3. DEPLOY (the CPU tier runs as a sidecar alongside the proxy)
#    copy the model dir (model.int8.onnx + config.json + tokenizer) + gate_service_cpu.py
#    + privacy_gate.py to the host, install the unit, start it:
sudo cp deploy/ossredact-gate-cpu.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ossredact-gate-cpu.service
curl -s http://127.0.0.1:8011/healthz
```

## Swapping detection tiers
A running gate can be repointed from one tier to another with a systemd drop-in:
`ossredact-gate.service.d/v11int8.conf` repoints `ExecStart` to `gate_service_cpu.py` and sets
`CPU_GATE_PORT` so the egress proxy port is unchanged. The base unit is preserved, so rollback is
removing the drop-in + `daemon-reload` + restart. For a model this small, CPU INT8 detect latency
(~42ms) beats an Intel-NPU OpenVINO tier (~112ms) -- the OpenVINO dispatch overhead dominates.

## Notes
- `NPUTier(model_dir)` loads `model_dir/model.int8.onnx` + the tokenizer + `config.json` from the
  same dir via the onnxruntime CPUExecutionProvider.
- The full appliance proxy lives under `appliance/`; the gate service files are under `gate/`,
  with `deploy/check-gate-drift.sh` for host-vs-repo drift checks.
