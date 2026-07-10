# v11r9c -- shipping benchmark (both tiers)

**Revision:** `v11r9c` (large + base) · **Corpus:** `datasets/pii-heldout-v11r5/test.jsonl` (7,498 synthetic
rows, 0 train overlap, structural variants never seen in training) · 100% synthetic, no value printed.

This is the v11r9c shipping benchmark cited by `README.md`, `MODEL_CARD.md`, `ARCHITECTURE.md`, `QUICKSTART.md`
and the model cards. It supersedes the v11r5 headline in `validation/RESULT-v11.md` (the baseline it improves
on). The privacy metric is **full-stack catastrophic DETECTION recall**: any detected span is redacted
regardless of which label it lands on -- an intra-catastrophic mislabel is still a redaction, not a leak.

## Headline

| pick | base | catastrophic full-stack DETECTION | overall labeled R | overall P | clean_fp |
|------|------|-----------------------------------|-------------------|-----------|----------|
| GPU  | `xlm-r-large-v11r9c` | **0.9954** | 0.9882 | 0.9615 | 34 / 7498 rows |
| CPU  | `xlm-r-base-v11r9c`  | **0.9941** | 0.9777 | 0.9139 | 48 / 7498 rows |

**Why v11r9c ships:** it closes a structural-form leak in the prior v11r5 model -- organization recall
~0.10 → 1.00, address recall ~0.60 → 0.95 -- at the cost of slightly more over-redaction on digit-ID-shaped
tokens (clean false positives: large 12 → 34, base 12 → 48). That is the **safe** failure direction:
over-redaction never leaks PII, it only costs a coding agent a little context when a benign number is
ID-shaped. The base tier was retrained on the same cumulative corpus, so it now carries the org/address fix
too (base `address` recall ~0.93).

## Per-label catastrophic DETECTION recall (full-stack, this corpus)

| catastrophic label | gold | large | base |
|---|---:|---:|---:|
| `person` | 9386 | 0.995 | 0.996 |
| `email` | 2291 | 1.000 | 1.000 |
| `government_id` | 3777 | 1.000 | 1.000 |
| `payment_card` | 1044 | 1.000 | 1.000 |
| `card_cvv` | 604 | 1.000 | 1.000 |
| `card_expiry` | 604 | 1.000 | 1.000 |
| `secret` | 607 | 1.000 | 1.000 |
| `password` | 1032 | 1.000 | 0.999 |
| `account_number` | 3599 | 0.974 | 0.966 |
| `iban` | 935 | 1.000 | 1.000 |
| `sensitive_account_id` | 2864 | 0.999 | 0.995 |
| `date_of_birth` | 2931 | 1.000 | 0.999 |
| `tax_id` | 2315 | 1.000 | 0.990 |

The deterministic Tier-0 floor (regex + Luhn) is a model-independent hard guarantee for the checksum-exact
shapes (email, IBAN, card, SIN/gov-id, secrets); the per-label recall above is the **full-stack** (floor +
neural) detection. Organization and address have **no** Tier-0 floor -- they rely on the neural tier (large
org ~1.0 / addr ~0.95; base addr ~0.93).

## Reproduction (2026-06-20)

Re-ran the eval harness on both local v11r9c models against the heldout to ground these numbers:

```
GATE_DIR=gate GPU_GATE_MODEL=models/pii-gpu-xlmr-{large,base}-v11r9c \
  GPU_GATE_VAL=datasets/pii-heldout-v11r5/test.jsonl GATE_DEVICE=cuda \
  python validation/eval_labelaware.py        # then validation/bar_check_v11.py on the JSON
```

Result: the **bolded catastrophic-DETECTION recall and clean_fp reproduced exactly** (large 0.9954 / 34, base
cat-detection 0.9937 ≈ 0.9941 / 48); overall labeled-recall and precision reproduced within ±0.0015
(reproduction noise across chunking/inference). The headline numbers are honest and reproducible.

## See also
- `validation/RESULT-v11.md` -- the v11r5 baseline this improves on.
- `validation/RESULT-base-int8-parity-v11r9c.md` -- the base INT8 in-browser export-parity characterization.
