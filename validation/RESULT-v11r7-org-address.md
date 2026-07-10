# v11r7 -- Organization + Address Recall Fix (retrain-augment)

> Measured 2026-06-19. v11r7 = v11r5 lineage + the v11r6 structural-name aug + new org-heavy / address
> augmentation (`training/gen/augment_v11r7.py`: org 0.42 / addr 0.30 / person 0.28; suffixes, QC
> institutions, signatures, two-org, EN street abbrev, directionals, rural, PO box, mailbox/header
> person). 100% synthetic; counts only, no values. Recipe: xlm-roberta-large, bs8, lr2e-5, max-len 512,
> 3 epochs, `metric_for_best_model=cat_f1` (organization + address added to CATASTROPHIC so the
> checkpoint metric rewards them). Eval: `training/eval_heldout.py` on an NVIDIA GB10 (Grace Blackwell),
> v11r6 as baseline.

## Why
The 52-case egress firewall stress (`validation/RESULT-stress-v11r6-firewall.md`) found the deterministic
floor + secrets + person (model + cue backstop) all SOLID, leaving exactly two no-floor gaps:
**organization (8/10 leak) and address (4/8 leak)** in structural forms (signatures, two-org lines,
street/PO-box/rural addresses). Neither has a Tier-0 checksum floor, so a model miss is a real leak.
v11r7 retrains the model to close both.

## The gain -- `structural_orgaddr_heldout` (1800 rows: org 777 / person 450 / addr 435)
The org / address / person pools in this heldout are **DISJOINT** structural forms not seen in training
-> this measures generalization, not memorization.

| label | v11r6 recall (baseline) | v11r7 recall | v11r6 F1 | v11r7 F1 |
|-------|-------------------------|--------------|----------|----------|
| organization (n=777) | **0.2355** | **0.9949** | 0.3526 | 0.9942 |
| address (n=435)      | **0.3126** | **1.0000** | 0.4338 | 1.0000 |
| person (n=450)       | 0.3756     | **1.0000** | 0.3042 | 1.0000 |

`macro_f1` on this set 0.2727 -> **0.9981**. v11r6 leaked ~77% of structural-form orgs and ~69% of
structural-form addresses; v11r7 catches 99.5% of orgs and 100% of addresses. The person spans in this
org/address-context heldout (a different structural form than the v11r6 names heldout) also jumped
0.38 -> 1.00.

## No regression -- per-label on `val` (6700 rows)
v11r7 is **equal or better than v11r6 on every catastrophic label**. `macro_f1` 0.9765 -> 0.9999;
`micro_f1` 0.9663 -> 0.9999.

| label | v11r6 F1 | v11r7 F1 | note |
|-------|----------|----------|------|
| organization | 0.7558 | **0.9997** | recall 0.6317 -> 0.9995 |
| address | 0.9556 | **0.9998** | recall 0.9283 -> 0.9998 |
| person | 0.9339 | **0.9999** | recall 0.9536 -> 1.0000 |
| email | 0.8846 | **1.0000** | precision 0.7931 -> 1.0 (v11r6 over-fired email) |
| account_number | 1.0000 | 0.9993 | only label that dipped (~1 span / 2088); see below |
| card_cvv / card_expiry / date_of_birth / file_path / government_id / iban / ip_address / password / payment_card / phone_number / postal_code / secret / sensitive_account_id / tax_id / username | 1.0000 | 1.0000 | unchanged |

**The one dip -- account_number F1 1.0000 -> 0.9993** (recall 1.0 -> 0.9995, ~1 span of 2088). This is
within run-to-run noise and is **fully backstopped by the deterministic Tier-0 floor**: valid-shaped
account / reference IDs are caught by digit-run + checksum + context-cue regardless of the NER, so this
sub-0.1% NER dip is not a full-stack leak risk.

Note: `val` is in-distribution (it includes the org/address augmentation), so v11r7's absolute val
numbers are optimistic; the disjoint `structural_orgaddr_heldout` above is the generalization signal.

## Person held -- `structural_names_heldout` (1000 rows, 998 person spans)
The v11r6 structural-name gain was **preserved and slightly improved**: person recall **0.997 (v11r6)
-> 1.000 (v11r7)** on the disjoint rare-surname heldout. The org/address augmentation did not cost the
prior name fix.

## Verdict
v11r7 closes both no-floor gaps decisively (organization and address) while improving person everywhere
and regressing nothing of consequence (one sub-0.1% account_number dip that the deterministic floor
covers). It supersedes v11r6 as the GPU-large tier.

## Status
- Model weights live at `models/pii-gpu-xlmr-large-v11r7` (gitignored; binaries are not in this repo).
- The deterministic cue-name backstop (`cue_name_spans`, across gate / appliance / @ossredact/core /
  workbench) stays as belt-and-suspenders even with v11r7's stronger model.
- v11r7 supersedes v11r6 as the GPU-large tier; the CPU/INT8 ONNX export of v11r7 is future work.
