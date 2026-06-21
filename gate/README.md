# gate/ -- canonical PII detection gate (shared safety core)

`privacy_gate.py` here is the canonical source for the **shared safety core**: the byte-identical
`FLOOR_LABELS`, the checksum-exact deterministic floor (`validated_floor` -- email / UUID / mod-97
IBAN / Luhn card / Luhn SIN), the BN-vs-SIN suppression rule, and the NER tiers + merge +
redact/rehydrate. This core is held identical across `gate/`, `appliance/privacy_gate.py`, and the
in-browser `packages/redaction-core`, and is locked by `validation/parity_vectors.json` (the 3-way
parity suites). Edit the shared core here, then deploy + mirror.

**Intentional divergence (not drift):** `appliance/privacy_gate.py` runs a deliberately THICKER
deterministic floor (`tier0_spans`, plus `context_cued_id_spans` / `glued_checksum_spans` /
`us_zip_spans`) because it has no co-located neural model to recall loose shapes (IP / postal /
phone / date / bare digit-runs); the gate's `validated_floor` leaves those to the NER tier on the
GPU/CPU sidecar. The appliance floor is therefore a strict SUPERSET of the gate floor on every
shared parity vector (over-redaction = the safe direction), asserted by the parity suites. The
long-term plan (direction D1) is to codegen both from one declarative source.

## Files
- `privacy_gate.py` -- the detection + redaction library (NBSP `_normspace` / `_normseps`
  normalization, `validated_floor` thin checksum-exact floor, NER tiers, `explain`).
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
