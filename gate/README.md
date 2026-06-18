# gate/ -- canonical PII detection gate

`privacy_gate.py` here is the **single source of truth** for the deterministic + neural
detection gate (tier-0 validated floor + NER tiers + merge + redact/rehydrate). Edit it here,
then deploy.

## Files
- `privacy_gate.py` -- the detection + redaction library (NBSP `_normspace` / `_normseps`
  normalization, `context_cued_id_spans`, `explain`).
- `gate_service_gpu.py` / `gate_service_cpu.py` -- FastAPI services exposing `/detect`
  `/redact` `/healthz` on the GPU and CPU tiers (same contract).

## Deploy (stop-and-ask in production)
This gate runs in production; deploying restarts the proxy in front of live traffic, so treat it
as a gated action. Deploy is an rsync of `privacy_gate.py` (plus the service file + model dir) to
the gate host, followed by a service restart. `deploy/check-gate-drift.sh` (set `GATE_HOST` /
`GATE_REMOTE_DIR`) md5-compares the host copy against the repo to catch silent drift.

## Tests
Torch-free (tier0 only), run from the repo root with the project test venv:

```
.venv-test/bin/python -m pytest gate/tests/ -v
```

`test_gate_regression.py` characterizes current tier0 behavior; `test_validated_floor.py`
specifies the thin-floor behavior.
