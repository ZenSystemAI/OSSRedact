# OSSRedact v7 -- Label-Aware Baseline (plan A)

> Measured 2026-06-14 on the GPU host (GPU xlm-r-large **v7**, card 4) against `pii-merged-v8/val.jsonl`
> (n=2942, 23-label scheme). Harness: `validation/eval_labelaware.py`. Raw: `baseline_v7_labelaware.json`.
> Prod line-boundary chunking replicated. **First eval that is label-aware** (existing evals are leak-only).
> Caveat: v7 was selected on v7-val; the **flinks rows in v8-val are unseen** by v7, so flinks-specific
> behavior (transaction dates, account numbers) is genuine generalization, not memorization.
> "FP" = a redaction overlapping no gold span = over-redaction **relative to the data's labeling policy**.

## Headline -- is the base model strong alone?

| mode | labeled-recall | precision | clean-row FP |
|---|---|---|---|
| tier0-alone | 0.300 | 0.397 | 56 |
| **model-alone** | **0.899** | **0.712** | **0** |
| full-stack (tier0+model) | 0.922 | 0.707 | 56 |

**The model carries the recall.** Tier-0 adds only **+2.3% recall** over the model alone, while it
contributes **all 56 clean-row false positives** (model-alone = 0) and slightly **lowers** precision
(0.712 → 0.707). Tier-0's one real recall contribution is on the numeric-ID label
(`sensitive_account_id` labeled-recall 0.45 → 0.93). Everything else, the model already does better.
This is direct evidence for the strategy: **make the base model strong; keep deterministic code as a
narrow leak-floor, not an always-on layer that taxes precision.**

## The weak spot is PRECISION (~0.71), not recall

Detect-recall is ~1.0 (almost nothing leaks). Labeled-recall is 0.92. **Precision 0.71 means ~29% of
redactions are over-redactions or mislabels** -- exactly what breaks the manual category-filter and what
the operator feels as over-redaction. Ranked precision sinks:

| sink | what | evidence |
|---|---|---|
| **`sensitive_date` over-fire** | precision **0.293**, **4616 FP** spans | every transaction date flagged (tier0 DATE_RE @0.8 *and* the model). Single biggest sink. |
| **numeric-ID cluster** | `bank_account` p=0.67 (325 FP), `routing_number` p=0.64 (442 FP), `sensitive_account_id` p=0.58 (544 FP) | model + tier0 both over-emit account-shaped numbers; they also confuse each other |
| **`postal_code → address`** | postal labeled-recall **0.382** (632 relabeled `address`) | `post_merge_address` stitches postal into the address span → label lost (post-processing, not model) |
| **`bank_account → government_id`** | 234 spans | numeric-ID disambiguation |
| **`username → file_path`** | 229 spans | env/code context overlap |
| **`date_of_birth → sensitive_date`** | 226 spans | the predicted linchpin -- DOB collapsed to generic date |
| `access_token`/`api_key` ↔ `sensitive_account_id` | ~65 spans | secret-vs-id confusion in env dumps |

## What's already excellent (don't touch)
`email` 1.00 · `ip_address` 1.00 · `password` 1.00 · `card_expiry` 1.00 · `organization` 1.00 ·
`phone_number` F1 0.99 · `file_path` 0.999 · `address` F1 0.997 · `person` F1 0.97 · `tax_id` 1.00.

## FR vs EN
Near-parity: EN labeled-recall 0.932, FR 0.914. FR carries more FP (4208 vs 1984) -- mostly the
FR flinks/bank statements where the date/numeric over-fire concentrates. FR/EN is **not** a weakness.

## Reads directly into the plan set
- **B (label precedence / merge)** → fixes `postal→address` (632), `DOB→sensitive_date` (226), and the
  numeric-ID label election. Biggest single lever on *correct labeling*.
- **C (tier-0 demote/gate)** → kills the bulk of the 4616 `sensitive_date` FP + numeric-ID FP, and per
  this baseline costs almost no recall (tier-0 only adds +2.3%).
- **E (label scheme)** → the numeric-ID cluster (0.58-0.67 precision, mutual confusion) is the concrete
  case for primary+subtype; decide from the confusion matrix above.
- **D (training)** → push model-alone DOB labeled-recall (0.83) and `sensitive_account_id` (0.45) up so
  the model needs tier-0 even less.
