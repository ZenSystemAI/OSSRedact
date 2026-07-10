# deploy/ -- gate appliance artifacts

Deployment artifacts for the reproducible CPU INT8 gate and the headless system-service route. The full egress proxy lives under `appliance/`; CPU and optional GPU gate services live under `gate/`.

## Installation routes

- **Desktop, no sudo:** use [QUICKSTART.md](../QUICKSTART.md). It installs user services beneath `$HOME/.local/share/ossredact`.
- **Headless or server, system services:** use [Headless system-service installation](#headless-system-service-installation-opt) below. It intentionally uses `/opt/ossredact` and `/etc/systemd/system`.
- **Off-device management:** follow the [token and remote-transport boundary](../QUICKSTART.md#5-gate-egress-and-control-tokens) before binding a service beyond loopback.

## Contents
- `gate_service_cpu.py` -- FastAPI CPU gate, dynamic weights-only INT8 ONNX through onnxruntime's CPU provider. It shares `/detect`, `/redact`, and `/healthz` contracts with the GPU gate and never uses a GPU.
- `ossredact-gate-cpu.service` and `ossredact-egress.service` -- headless system units for the loopback CPU gate on `:8001` and egress proxy on `:8011`.
- `systemd/user/ossredact-gate-cpu.service` and `systemd/user/ossredact-egress.service` -- the separate desktop user units rooted at `%h/.local/share/ossredact`.
- `export_quantize_v11_cpu.py` -- exports an xlm-r fp32 checkpoint to ONNX, then dynamic weights-only INT8.
- `requirements-gate-cpu.lock` -- frozen, validated CPU gate and egress runtime. `requirements.txt` is only a compatibility floor; a fresh compatibility-floor install can resolve different dependency versions and is not the validated deployment.
- `check-gate-drift.sh` -- compares standalone gate-service files on a configured remote gate host with the repository copy before relying on that host.

## Headless system-service installation (`/opt`)

Use this route for a headless Linux host or an intentional system-service deployment. It is distinct from the no-sudo desktop route: these units run from `/opt/ossredact`, are installed under `/etc/systemd/system`, and are managed with `sudo systemctl`.

### 1. Install the frozen CPU runtime

```bash
sudo install -d -m 0755 /opt
sudo git clone https://github.com/ZenSystemAI/OSSRedact.git /opt/ossredact
sudo chown -R "$USER":"$USER" /opt/ossredact
cd /opt/ossredact
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r deploy/requirements-gate-cpu.lock
```

The lock is the validated public CPU runtime. Do not replace it with `requirements.txt`, which is a compatibility floor rather than a frozen deployment environment.

### 2. Stage the CPU ONNX model

```bash
cd /opt/ossredact
mkdir -p models/ossredact-pii-base-int8
hf download ZenSystemAI/ossredact-pii-base \
  --revision v11r9c \
  --local-dir models/ossredact-pii-base-int8
test -f models/ossredact-pii-base-int8/model.int8.onnx
```

The CPU unit uses `model.int8.onnx` plus tokenizer files and `config.json`. Optional GPU deployments use separate fp16 `.safetensors` or `.bin` weights and a GPU-specific service configuration; they are not a replacement for this CPU artifact.

### 3. Prepare state and install system units

The shipped system units contain the placeholder `User=ossredact`. The egress unit's literal placeholder path `/home/ossredact/.ossredact` follows `User=`, so replace both values with a real service account that has a home directory and create the state directory before start:

```bash
sudo install -d -m 0700 -o "$USER" -g "$USER" "/home/$USER/.ossredact"
sudo install -m 0644 deploy/ossredact-gate-cpu.service /etc/systemd/system/ossredact-gate-cpu.service
sudo install -m 0644 deploy/ossredact-egress.service /etc/systemd/system/ossredact-egress.service
sudo sed -i \
  -e "s|^User=ossredact\$|User=$USER|" \
  -e "s|^ReadWritePaths=-/home/ossredact/\.ossredact\$|ReadWritePaths=-/home/$USER/.ossredact|" \
  /etc/systemd/system/ossredact-gate-cpu.service \
  /etc/systemd/system/ossredact-egress.service
sudo systemctl daemon-reload
sudo systemctl enable --now ossredact-gate-cpu.service
sudo systemctl enable --now ossredact-egress.service
sudo systemctl status ossredact-gate-cpu.service ossredact-egress.service
```

If the service account's home is not under `/home`, retain the hardening and replace only the egress unit's narrow state path with a drop-in:

```ini
# /etc/systemd/system/ossredact-egress.service.d/state-path.conf
[Service]
ReadWritePaths=
ReadWritePaths=-/absolute/path/to/service-home/.ossredact
```

Create that exact state directory with owner-only permissions, then run `sudo systemctl daemon-reload` and restart the egress service. Do not broaden the path to a home tree or disable `ProtectSystem`, `ProtectHome`, `PrivateDevices`, or the other sandbox directives.

### 4. Troubleshoot without dropping hardening

The system-service route is the supported alternative when a desktop user manager or linger setup is unavailable. It still requires systemd sandbox support. For `Failed at step NAMESPACE`, mount-namespace, or sandbox failures, inspect the unit and repair the host policy:

```bash
sudo journalctl -b -u ossredact-gate-cpu.service -u ossredact-egress.service
sudo systemctl status ossredact-gate-cpu.service ossredact-egress.service
```

Do not work around a namespace failure by removing hardening directives or enabling fail-open behavior. For non-loopback gate, egress, or control-plane configuration, follow the separate [token and encrypted-transport boundary](../QUICKSTART.md#5-gate-egress-and-control-tokens) before exposing either service.

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

# 3. DEPLOY
#    Follow "Headless system-service installation" above for the exact /opt checkout,
#    state directory, service-user, hardening, and systemctl steps. Do not enable the
#    placeholder `User=ossredact` units without completing that route.
```

## Swapping detection tiers

The public headless route uses `ossredact-gate-cpu.service` directly with `CPU_GATE_PORT=8001`, matching the egress proxy's default `GATEWAY_GATE_URL`. The CPU gate requires `model.int8.onnx`, `config.json`, and tokenizer files. The optional CUDA GPU gate instead requires fp16 `.safetensors` or `.bin` weights and a GPU-specific service configuration; do not substitute either artifact format for the other.

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

- CPU and egress services bind `127.0.0.1` by default. Set `CPU_GATE_HOST` or `GATEWAY_HOST` only as an intentional remote-use decision, with the separate token and encrypted-transport requirements in [QUICKSTART.md](../QUICKSTART.md#5-gate-egress-and-control-tokens).
- A non-loopback gate uses `GATE_TOKEN`; an egress proxy calling it uses the distinct `GATEWAY_GATE_TOKEN`; `GATEWAY_CONTROL_TOKEN` is only for authenticated remote control and does not authenticate `/v1/*`.
- The full appliance proxy lives under `appliance/`; CPU and optional GPU gate services live under `gate/`.
