# Synthetic-corpus validation

Reproducible, 100% synthetic validation of the ossredact gate. No real client data is read or stored:
every name, SIN, account, email, and secret is fabricated from curated Québec pools + a fixed seed
(`SEED=20260614`), so the corpus can be regenerated and re-run on any machine with zero real-data exposure.

## What it measures

- **`generate_corpus.py`** emits `corpus.jsonl`: 5,000 FR + EN documents across eight types (Québec
  bank statements, financing forms, email threads, CSV exports, `.env` files, code, and an adversarial
  "wrench" type), each with **ground truth** (the exact PII substrings injected) and **decoys**
  (look-alikes that must NOT be flagged: invalid-Luhn SINs, git SHAs, order numbers).
  Adversarial cases are sprinkled throughout: ALL-CAPS names, accented/compound names, NBSP-separated
  IDs, mixed FR/EN, and >600-char unbroken lines (chunker-truncation guard).
- **`run_corpus.py`** sends each document to the GPU gate `/redact` (Tier-0 regex + neural xlm-r-large)
  for PII, and runs the deterministic `secret_spans` locally for the always-on secrets layer. A **leak**
  is an injected sensitive value that survives verbatim in the redacted output (substring match = the
  gate's own recall-as-leak-prevention metric).
- **`make_chart.py`** renders `fig3_synthetic_corpus.png` from `result.json`.

## Result (`result.json`)

- **218,931 PII spans redacted** across 5,000 docs (0 errors).
- **Zero email / SIN / account-ID / credit-card leaks**, checked against ground truth
  (32,754 emails, 31,163 SINs, 30,870 account-IDs, 691 cards).
- Always-on secrets layer: **100%** of the 4,365 injected secrets caught deterministically, **0 leaks**,
  with **0 decoy false-positives** (and `cache_key = user_id` style code left untouched). Reaching 100%
  required two fixes to `secrets_scan.py`: the `generic_assign` rule now matches secret keywords inside
  SCREAMING_SNAKE / dotted identifiers (`JWT_SECRET=`, `AWS_ACCESS_KEY_ID=`), and the entropy backstop no
  longer excludes a `=` immediately before a bare token. Both are keyword/shape-gated, so precision holds.
- The gate is deliberately high-recall: ~94% of the adversarial look-alike decoys are over-redacted
  (an invalid-Luhn SIN is indistinguishable from a real one, so it is redacted out of caution).

## Finding fixed during this run

The wrenches surfaced a real gap: **NBSP-separated SINs in cue-less cells** (e.g. a bare CSV field
`653<NBSP>956<NBSP>771`) leaked at 2.5% (770 / 31,163). Root cause: the Tier-0 `DIGIT_RUN_RE` character
class `[\d .\-]` excluded unicode spaces, so the deterministic SIN floor never fired, and the neural tier
misses SINs that have no surrounding "NAS:"/"SIN:" cue. Fixed by adding a length-preserving
unicode-space normalization (`_normspace`, mirroring the existing `_normdash`) to the Tier-0 path.
Re-verified at **0 SIN leaks**.

## Export-parity gate (`parity_check.py`)

Before an exported/quantized model (ONNX-INT8 CPU or OpenVINO-FP16 NPU) is shipped, this gate
confirms it still matches the trained fp32 reference at the logit level -- guarding against a
silent quantization regression that would degrade PII recall. Two per-token metrics over the
held-out corpus (prod 600/80 chunking): **logit cosine** (numerical drift) and **argmax parity**
(reported overall and restricted to PII tokens -- the rate at which the export flags the SAME
tokens as PII). Fails closed below threshold. Adapted from `localai-org/privacy-filter.cpp`.

The pure metrics are numpy-only and unit-tested:
```bash
.venv-test/bin/python validation/parity_check.py --self-test         # smoke test, no model
.venv-test/bin/python -m pytest validation/test_parity_check.py -v   # 11 tests
```
The real comparison needs torch+onnxruntime+the weights and runs on gpu-host (the GPU) AFTER an
export exists (the export/quantization step itself stays a STOP-and-ask gate):
```bash
CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=0 \
python validation/parity_check.py --ref <fp32-dir> --exported <onnx-dir> --corpus <val.jsonl>
```

## Reproduce

```bash
python generate_corpus.py 5000 corpus.jsonl      # synthetic corpus + ground truth
python run_corpus.py corpus.jsonl <gate-url>     # default gate: http://localhost:8001
python make_chart.py                             # -> fig3_synthetic_corpus.png
```

Dependencies: the gate's `privacy_gate.py` (Tier-0 + neural) reachable at `<gate-url>`, and
`secrets_scan.py` on the PYTHONPATH for the local secrets check. `make_chart.py` needs `matplotlib`.
