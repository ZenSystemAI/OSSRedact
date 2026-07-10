# v11r7 base (CPU / in-browser tier) -- Organization + Address + Name Recall Fix

> Measured 2026-06-19. This is the **base** (xlm-roberta-base, 277M -> INT8 ONNX) counterpart to the
> LARGE result in `RESULT-v11r7-org-address.md`. The base tier went straight **v11r5 -> v11r7** on the
> cumulative `pii-merged-v11r7` corpus (v11r5 lineage + the v11r6 structural-name aug + the v11r7
> org/address aug), so a single retrain folds in BOTH augmentation rounds. Baseline = the deployed
> `pii-gpu-xlmr-base-v11r5`. Recipe: xlm-roberta-base, bs8, lr2e-5, max-len 512, 3 epochs,
> `metric_for_best_model=cat_f1` (organization + address in CATASTROPHIC). Trained on an NVIDIA GB10
> (Grace Blackwell): 24,750 steps / 65.7 min, train_loss 0.0297, final in-dist eval macro_f1 0.99997.
> Eval: `training/eval_heldout.py`. 100% synthetic corpus.

## Why this matters for the base tier specifically
The base model is the **always-on CPU tier and the in-browser (INT8 ONNX, zero-upload) tier**. Whatever
the base misses leaks in the on-device demo, so the org/address/name gains have to reach this tier too,
not just the GPU gate. They now do.

## The gain -- `structural_orgaddr_heldout` (1800 rows: org 777 / addr 435 / person 450)
Disjoint structural forms not seen in training -> generalization, not memorization. The base v11r5
baseline never saw the v11r6 name aug OR the v11r7 org/addr aug, so its recall here is near-floor.

| label | base v11r5 recall | base v11r7 recall | v11r5 F1 | v11r7 F1 |
|-------|-------------------|-------------------|----------|----------|
| organization (n=777) | **0.0412** | **0.9743** | 0.0788 | 0.9863 |
| address (n=435)      | **0.1632** | **1.0000** | 0.2247 | 1.0000 |
| person (n=450)       | **0.0733** | **1.0000** | 0.1289 | 0.9815 |

`macro_f1` on this set **0.0618 -> 0.9893**. The deployed base model leaked ~96% of structural-form orgs
and ~84% of structural-form addresses; base v11r7 catches 97.4% of orgs and 100% of addresses.

## Person held -- `structural_names_heldout` (1000 rows, 998 person spans)
This is the v11r6 rare-surname gain, which the base tier had **never received** (no base v11r6 was
trained). One retrain delivers it:

| label | base v11r5 recall | base v11r7 recall | v11r5 F1 | v11r7 F1 |
|-------|-------------------|-------------------|----------|----------|
| person (n=998) | **0.0230** | **0.9960** | 0.0447 | 0.9975 |

(`macro_f1` on this set is 0.50 only because the heldout contains person spans alone -- the absent labels
score 0 and drag the macro; person F1 0.9975 is the real signal.) Base v11r5 leaked ~98% of diverse /
rare-surname names; base v11r7 catches 99.6%.

## No regression -- `val` (6700 rows, in-distribution)
Equal or better on every catastrophic label; no label regressed > 0.005 F1.

| metric | base v11r5 | base v11r7 |
|--------|-----------|-----------|
| macro_f1 | 0.9689 | **1.0000** |
| micro_f1 | 0.9533 | **0.9999** |

Note: `val` includes the org/address/name augmentation, so absolute val numbers are optimistic; the
disjoint heldouts above are the generalization signal.

## Verdict
Base v11r7 brings the CPU / in-browser tier to **parity with the LARGE v11r7 gains** across names,
organization, and address, with no in-distribution regression. Because both the structural-name and
org/address augmentations are cumulative in `pii-merged-v11r7`, the single v11r5 -> v11r7 base retrain
catches up two rounds at once. **Org stays redact-OFF by default** in egress policy (coding-assistant
noise); this retrain means that when a project opts org ON, the in-browser tier actually catches it.

## INT8 ONNX export (done)
Exported with `deploy/export_quantize_v11_cpu.py` (dynamic INT8, weights-only -- the proven v6/v7 recipe;
`OSSREDACT_EXPORT_MODEL_DIR=models/pii-gpu-xlmr-base-v11r7`). Result: `model.int8.onnx` **278 MB**
(identical footprint to the deployed v11r5 base INT8), self-contained, 41-label logits. Functional
spot-check confirmed the quantized model still fires on all v11r7 targets in one pass -- e.g. a rare
surname (`Thandiwe Mkhize`) + organization (`Hydro-Quebec`) + street address + postal code together, and
a structural-form firm name (`Beaulieu & Associes`) -> organization. Quantization did not damage the
gains.

The artifact lives at `models/pii-gpu-xlmr-base-v11r7/model.int8.onnx` (gitignored, like all weights). For
the in-browser tier it is served as `/model/onnx/model_int8.onnx`.

### Export parity gate (`validation/parity_check.py`, tier=int8)
- **Canonical `val` corpus: PASS** -- mean_cosine 0.9990, argmax 0.9989, **pii-argmax 0.9936** (bars
  0.99 / 0.99 / 0.97). This beats the deployed v11r5-base INT8 baseline (pii-argmax 0.981), so the v11r7
  INT8 is *more* faithful than what currently ships.
- The adversarial `structural_orgaddr_heldout` shows a lower exact-label parity (pii-argmax 0.955) -- but
  that is intra-PII label flipping (person<->organization, both still redacted), NOT leaks: a direct
  **non-O detection-recall** check on that same hard corpus gives INT8 **0.9993** vs fp32 1.0000 (2 of
  2895 PII tokens flip to O, and they sit inside multi-token spans that still redact). The privacy-critical
  measure holds; the formal ship gate (parity on `val`) is green.

**Deployed gate + web weights remain v11r5 until the redeploy lands; do not market the v11r7 numbers as
shipping until then.**
