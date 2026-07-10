# v11r6 -- Structural-Name Recall Fix (retrain-augment)

> Measured 2026-06-18. v11r6 = v11r5 + ~6k structural-form name augmentation (rare/diverse surnames
> x JSON / CSV / key:value / bare forms + ~22% negatives). 100% synthetic; counts only, no values.
> Recipe: xlm-roberta-large, bs8, lr2e-5, max-len 512, 3 epochs, metric_for_best_model=cat_f1.
> Generator: `training/gen/augment_structural_names.py`. Eval: `training/eval_heldout.py`.

## Why
v11r5 detects person names well in PROSE but misses them in STRUCTURAL forms (JSON `"name":"X"`,
CSV cells, `key: value`, bare lines) -- especially rare / non-Anglo surnames. The carrier-wrap
pre-pass (`appliance/name_carrier.py`) recovers most at inference time without a retrain; this
retrain fixes the model itself so the floor is higher even without the pre-pass.

## The gain -- person recall on `structural_names_heldout` (1000 rows, 998 person spans)
The heldout surname pool is **DISJOINT** from training (held-out names, never seen) -> this measures
generalization, not memorization.

| model | person precision | person recall | person F1 |
|-------|------------------|---------------|-----------|
| v11r5 (baseline)   | 0.760 | **0.060** | 0.111 |
| v11r6 (retrained)  | 0.999 | **0.997** | 0.998 |

v11r5 misses ~94% of rare structural-form names; v11r6 catches 99.7%. (`macro_f1` on this set is not
meaningful -- the probe is person-only, so other labels have zero support.)

## No regression -- per-label F1 on `val` (4700 rows)
v11r6 is **equal or better than v11r5 on every label**. `macro_f1` 0.995 -> 0.9999.

| label | v11r5 F1 | v11r6 F1 |
|-------|----------|----------|
| person | 0.935 | 1.000 |
| organization | 0.995 | 0.9995 |
| address | 0.996 | 0.9995 |
| account_number | 0.997 | 1.000 |
| username | 0.988 | 1.000 |
| email / government_id / iban / payment_card / secret / password / tax_id / card_cvv / card_expiry / date_of_birth / file_path / ip_address / phone_number / postal_code / sensitive_account_id | 0.995-1.000 | 1.000 |

Note: `val` is in-distribution (it includes the structural-name augmentation), so v11r6's absolute
val numbers are optimistic; the disjoint heldout above is the generalization signal. The non-person
labels were not part of the augmentation, so their equal-or-better result is a valid no-regression
check.

## Status
Model trained + validated (exit 0; in-dist val cat_f1 0.99999). **ONNX export + gate redeploy are
stop-and-ask gates -- not run.**
