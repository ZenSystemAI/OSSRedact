# gate/ — canonical PII detection gate

`privacy_gate.py` here is the **single source of truth** for the deterministic + neural
detection gate. Edit it here, then deploy.

## Provenance

Adopted 2026-06-14 from the deployed copy `gpu-host:/opt/ossredact-gpu-gate/privacy_gate.py`
(371 lines, the newest: it carries the NBSP `_normspace`/`_normseps` fix, `context_cued_id_spans`,
and `explain` that the other copy lacked).

Copies that existed before this consolidation:
- `gpu-host:/opt/ossredact/privacy_gate.py` (303 lines) — a stale subset of the deployed copy. RETIRED;
  delete after Phase 2 lands (see plan Task 2.2 Step 6).
- `gpu-host:/opt/ossredact/ossredact/redact.py` (496 lines) — **NOT** a copy of this gate. It is a
  separate module (`RedactionMap` / `Redactor`, the typed-token replacement + rehydration layer). It
  does not define `tier0_spans`/`merge_spans`. Out of scope for this overhaul; leave it in place.

## Deploy (OPERATOR-GATED — do not run without explicit approval)

This gate runs in production. Deploying restarts prod appliances, so it is operator-gated:

```
# GPU reference appliance on gpu-host (ossredact-gate-gpu.service)
rsync -a gate/privacy_gate.py gpu-host:/opt/ossredact-gpu-gate/privacy_gate.py
# NPU appliance on gate-host
rsync -a gate/privacy_gate.py gate-host:/opt/ossredact-npu/privacy_gate.py
```

## Tests

Torch-free (tier0 only), run from the repo root with the project test venv:

```
.venv-test/bin/python -m pytest gate/tests/ -v
```

`test_gate_regression.py` characterizes CURRENT tier0 behavior (the Phase 2 safety net).
`test_validated_floor.py` (added in Phase 2) specifies the thin-floor behavior.
