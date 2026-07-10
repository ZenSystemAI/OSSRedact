# v12 public-data ingest (plan 048)

Converts four public HF PII datasets into our offset-true jsonl and composes the v12
stage-1/stage-2 training mixes. Full recipe + rationale: the v12 training plan (plan 048).

- `label_map_v12.py` -- source schemas → `training/labels_v20.json`. Strict: unmapped labels abort
  conversion with a histogram. Locality (city/state/country) maps to **O** to match our corpus
  convention (street-line-only `address`, separate `postal_code`, verified against
  pii-merged-v11r9c). Wire-policy categories (dates, ages, URLs, demographics) map to O on
  purpose -- they are the hard-negative signal.
- `convert_public.py` -- `--source {ai4privacy,nemotron,gretel,privy} --split ... --out ...`;
  `--audit` tallies labels only; `--limit N` for smoke runs. Gretel emits value-list rows
  (no offsets upstream); the other three emit spans.
- `build_mix_v12.py` -- `--stage 1|2`, source budgets + fr/en 2× weighting,
  `--holdout-generators` writes `generator_holdout.jsonl` (the v12 generalization gate).

Turnkey end-to-end (deps → convert → mix → dry-run → stage-1 → stage-2, idempotent):

```bash
training/train_v12_local.sh
```

Tests (hermetic, no network): `.venv-test/bin/python -m pytest training/tests/test_ingest_v12.py`

Ship-time note: ai4privacy + Nemotron are CC-BY-4.0 -- the v12 model card needs a data-attribution
section (privy MIT, gretel Apache-2.0).
