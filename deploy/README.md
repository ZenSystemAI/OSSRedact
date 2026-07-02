# deploy/ -- gate appliance artifacts

Deploy-specific gate artifacts: the CPU INT8 deploy entrypoint and the export tooling, so that
path is reproducible. The full always-on proxy lives under `appliance/`; the GPU and CPU gate
services live under `gate/`.

## Contents
- `gate_service_cpu.py` -- FastAPI CPU gate (onnxruntime INT8 on CPU). Same `/detect` `/redact`
  `/healthz` contract as the GPU gate; CPU-only (never touches a GPU). Byte-identical to
  `gate/gate_service_cpu.py`; CI enforces this via `gate/tests/test_deploy_gate_service_sync.py`.
- `ossredact-gate-cpu.service` -- systemd unit (loopback gate port 8001, `CUDA_VISIBLE_DEVICES=` to stay off GPUs).
- `ossredact-egress.service` -- systemd unit for the public client-facing proxy on loopback port 8011.
- `export_quantize_v11_cpu.py` -- exports an xlm-r fp32 checkpoint to ONNX, then **dynamic**
  (weights-only) INT8. Set `MDIR` / `CALIB` to your model + calibration set.
- `pre-push-guard.sh` -- repo-safety pre-push hook logic (see "Repo safety" below).
- `install-git-hooks.sh` -- installs `pre-push-guard.sh` into this clone's `.git/hooks/pre-push`.
- `check-gate-drift.sh` -- md5 the gate detect-service files a REMOTE gate host runs (set `GATE_HOST` to
  its ssh host/alias) vs the repo. A remote host is an rsync copy, not a git checkout, so it can silently
  diverge; run before relying on it. The egress proxy is NOT checked -- it runs the workstation working
  tree directly and cannot drift.
- `requirements-gate-cpu.lock` -- FROZEN `pip freeze` manifest of the production CPU gate + egress venv.
  `requirements.txt` is floor-pins only, so a fresh install could silently pull a transformers/onnxruntime
  bump that changes what PII is caught -- this locks the validated versions. Regen command is in the
  file's header. For an always-on GPU gate on a remote box (recommended: the workstation egress points
  `GATEWAY_GATE_URL` at it, with the loopback CPU gate as `GATEWAY_GATE_FALLBACK_URL`), adapt
  `ossredact-gate-cpu.service`: point `ExecStart` at `gate/gate_service_gpu.py`, pin the card with
  `CUDA_VISIBLE_DEVICES=<gpu-uuid>`, bind a trusted interface, and freeze that venv the same way.

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
#    INT8 (shipped v11r9c base, per-channel): cosine 0.997, PII-argmax 0.967; bar is 0.965 because
#    v11r9c's org/address augmentation sharpened the boundaries (validation/RESULT-base-int8-parity-v11r9c.md)

# 3. DEPLOY (the CPU tier runs as a sidecar alongside the proxy)
#    copy the model dir (model.int8.onnx + config.json + tokenizer) + gate_service_cpu.py
#    + privacy_gate.py + appliance/ to the host, install the units, start them:
sudo cp deploy/ossredact-gate-cpu.service deploy/ossredact-egress.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ossredact-gate-cpu.service
sudo systemctl enable --now ossredact-egress.service
curl -s http://127.0.0.1:8001/healthz
curl -s http://127.0.0.1:8011/healthz
```

## Swapping detection tiers
A running gate can be repointed from one tier to another with a systemd drop-in:
`ossredact-gate.service.d/v11int8.conf` is kept as a legacy example for repointing a base gate unit to
`gate_service_cpu.py`. The public install path uses `ossredact-gate-cpu.service` directly and sets
`CPU_GATE_PORT=8001`, matching the egress proxy's `GATEWAY_GATE_URL` default. For a model this small, CPU INT8 detect latency
(~42ms) beats an Intel-NPU OpenVINO tier (~112ms) -- the OpenVINO dispatch overhead dominates.

## Repo safety: pre-push guard (run once per clone)
`origin` is a PUBLIC repo. Only a clean local `main` (== `origin/main`) is push-safe; `master` and
every advisor/feat/worktree branch embed dev-only paths (`plans/`, `AGENTS.md`, ...) in their history.
`.gitignore` guards `git add`, NOT `git push`, so a pre-push hook is the backstop.

```bash
bash deploy/install-git-hooks.sh   # also repairs a stale core.hooksPath if present
```

This installs a `pre-push` hook (a self-contained copy of `pre-push-guard.sh`, so it works on any
checkout) that ABORTS a push to the public origin when (1) the target is anything other than local
`main` -> `origin/main`, or (2) the pushed ref's tip tree or added commits touch a dev-only path
(`plans/`, `AGENTS.md`, `.agents/`, `extension/`, `*PRELAUNCH-AUDIT*`). Normal `git push origin main`
(incremental) is allowed; `git push --all` / pushing any other branch is blocked. Re-run the installer
after editing the guard. Override only when certain: `git push --no-verify`.

## Notes
- `NPUTier(model_dir)` loads `model_dir/model.int8.onnx` + the tokenizer + `config.json` from the
  same dir via the onnxruntime CPUExecutionProvider.
- Services bind `127.0.0.1` by default. Set `CPU_GATE_HOST` or `GATEWAY_HOST` explicitly only when you intend to
  expose a service on a tailnet or another trusted interface.
- The full appliance proxy lives under `appliance/`; the gate service files are under `gate/`,
  with `deploy/check-gate-drift.sh` for host-vs-repo drift checks.
