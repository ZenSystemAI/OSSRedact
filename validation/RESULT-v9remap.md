# ossredact v9remap — Phase 1 Validate-Gate Result

> Measured 2026-06-14 on gpu-host (GPU xlm-r-large **v9remap**, the GPU) against
> `pii-merged-v9-remap/val.jsonl` (n=2942, **20-label scheme**). Harness:
> `validation/eval_labelaware.py` (modes tier0 / model / full; prod line-boundary chunking).
> Raw: `/tmp/eval_v9remap.json` on gpu-host. 100% synthetic; counts only, no values printed.
> Compared against the v7 baseline (`BASELINE-v7-labelaware.md`, 23-label scheme).

## Gate decision: PASS

The scheme remap (drop `sensitive_date`; merge numeric-ID cluster -> `account_number`; merge
keys/tokens -> `secret`; UUID-only `sensitive_account_id`) moved precision exactly as predicted.

| mode | v7 labeled-recall | v7 precision | v9remap labeled-recall | v9remap precision | v9remap clean_fp |
|---|---|---|---|---|---|
| tier0-alone | 0.300 | 0.397 | 0.222 | 0.267 | 56 |
| **model-alone** | **0.899** | **0.712** | **0.945** | **0.9992** | **1** |
| full-stack | 0.922 | 0.707 | 0.945 | 0.664 | 57 |

**Model-alone precision 0.712 -> 0.9992; recall 0.899 -> 0.945.** The confusion + FP sinks named in
the v7 baseline (sensitive_date over-fire, numeric-ID cluster, secret-vs-id) are gone.

## Caveats (absolute numbers are optimistic)

- v9remap was checkpoint-selected on this val (`cat_f1`) and the val is in-distribution; the *relative*
  jump is robust, the absolute 0.999 is not the ship number. The fresh held-out (Phase 3) is the real test.
- tier0-alone is low because the still-deployed tier0 emits OLD-scheme labels (e.g. `sensitive_date`,
  generic-digit `sensitive_account_id`) that no longer match the 20-label gold. Phase 2 replaces it.

## The two remaining soft spots are the next two planned fixes, not model failures

- `postal_code`: labeled-recall **0.382** but detect-recall **1.000**. The model finds every postal; the
  `post_merge_address` code stitches 632 of them into `address` and drops the label. -> **Phase 2** fix.
- `username`: labeled-recall **0.629**, detect-recall **1.000**, precision 1.000. The model detects every
  username but mislabels 229 as `file_path` (env/code context overlap). -> **Phase 3** disambiguation pairs.

Everything else is 0.98-1.00 F1 (person 0.992, account_number 0.998, email/iban/tax_id/secret/
sensitive_account_id/date_of_birth/payment_card/card_expiry all ~1.00).

## Full-stack precision 0.664 = the thin-floor case, proven

The un-overhauled tier0 drags model-alone 0.999 down to 0.664: 827 FP on `sensitive_account_id`
(generic digit-runs), 80 on `payment_card`, plus government_id/ip_address/phone over-fire. Phase 2's
`validated_floor` removes exactly these loose rules. This is direct evidence for the weights-first /
thin-deterministic-floor strategy.

## Reads into the plan

- **Phase 1.5 (NEW): base bake-off** before the data overhaul (XLM-R-large vs EuroBERT-610M/210M vs
  mmBERT-base), gated on INT8/OpenVINO export-ability for the NPU tier.
- **Phase 2** (postal fix + thin floor + label-preserving merge): recovers postal recall, lifts
  full-stack precision back toward model-alone.
- **Phase 3** (offset-true data + username/file_path disambiguation pairs): closes the username gap;
  fresh held-out becomes the real scoreboard against the strict bar.
