# Base-Model Bake-off Result (Phase 1.5)

> Measured 2026-06-15. Each candidate was full-fine-tuned on pii-merged-v9-remap (same config: 3 epochs,
> max_len 256, entity-F1 selection) and scored MODEL-ALONE on the v9remap val via the label-aware harness;
> GPU(fp16) + CPU(fp32) latency measured on gpu-host the GPU (a dedicated GPU) over a fixed sample. Numbers only.
>
> IMPORTANT: v9remap is near-saturated for the strong encoders, so this pass discriminates on LATENCY +
> trainability + export-class and gives a quality FLOOR. The final quality crown is decided on the v10
> held-out (see RESULT-v10.md) and ultimately the real-Quebec eval. Do not read the v9remap F1 column as
> the scoreboard.

## Decision function (operator, 2026-06-14)

Quality is the objective; latency is a CEILING, not a competing objective. Maximize quality (catastrophic
recall first, then overall labeled-recall + correct labeling) subject to: a normal interactive document must
never feel sluggish (a page/paste well under ~500ms on the real deployment path, ~2s = hard fail). Inside the
comfortable band, never trade quality for marginal speed; latency only disqualifies a model that busts the
ceiling. Net effect on the CPU tier: pick the best-quality ONNX-INT8-clean model under the ceiling, NOT the
fastest.

## Results (model-alone, v9remap val)

| tier | candidate            | params | gpu fp16 ms | cpu fp32 ms | F1     | labeled-R | P      | clean_fp |
|------|----------------------|--------|-------------|-------------|--------|-----------|--------|----------|
| GPU  | xlm-r-large          | 559M   | 8.74        | (n/a)       | 0.9715 | 0.9452    | 0.9992 | 1        |
| GPU  | EuroBERT-610m        | 608M   | 16.68       | (n/a)       | 0.9552 | 0.9354    | 0.9758 | 1        |
| CPU  | xlm-r-base           | 277M   | 4.71        | 36.80       | 0.9698 | 0.9451    | 0.9959 | 0        |
| CPU  | EuroBERT-210m        | 212M   | 7.84        | 53.31       | 0.9660 | 0.9354    | 0.9987 | 0        |
| CPU  | mDeBERTa-v3-base     | 278M   | 12.46       | 64.82       | 0.9660 | 0.9356    | 0.9985 | 0        |
| CPU  | distilbert-multi     | 135M   | 2.54        | 18.49       | 0.9572 | 0.9404    | 0.9746 | 1        |
| CPU  | mmBERT-base          | 308M   | 13.64       | 64.15       | 0.9493 | 0.9305    | 0.9688 | 0        |
| CPU  | MiniLM-L12-H384      | 118M   | 4.63        | 12.54       | 0.9132 | 0.8679    | 0.9633 | 0        |

## Read

- **GPU tier: xlm-r-large wins.** Highest F1 (0.9715) and precision (0.9992) at 8.74ms. The larger
  EuroBERT-610m is BOTH worse (0.9552) and slower (16.68ms): more parameters did not help on this data
  (likely undertrained at 3ep/bs8, or the fixed-label tagging task simply does not need 608M params).
- **CPU tier: xlm-r-base wins on quality.** Best labeled-recall (0.9451, tied with the large) and best F1
  (0.9698) of the CPU field, with zero clean false positives, at 36.8ms fp32 (INT8 will roughly halve that:
  comfortably inside the invisible band). It is NOT the fastest (MiniLM 12.5ms, distilbert 18.5ms) but those
  pay for it in recall (MiniLM 0.868 is a real miss and is disqualified on quality; distilbert 0.940 with 1
  clean FP trails). eurobert-210m and mdeberta match on F1 but trail on recall and are ~1.5-1.8x slower.
- **base vs large are nearly tied on v9remap** (0.9698 vs 0.9715, same 0.945 recall); the large's only edge
  is precision (0.9992 vs 0.9959). This near-tie is exactly why the v10 held-out retrain matters: if the
  large's extra capacity does not separate on harder/richer data, xlm-r-base could serve both tiers.

## CPU INT8-export feasibility (Task 1.5.3)

- Classic encoders (xlm-r base/large, distilbert, mdeberta, MiniLM) export cleanly to ONNX + INT8 via
  Optimum (the established path the existing NPU/CPU artifacts already used). xlm-r-base is therefore
  ONNX-INT8-clean and is the export-safe CPU pick.
- EuroBERT has NO Optimum ONNX config (issue #2300, closed not-planned) and needs trust_remote_code, so it
  is GPU-fp16-tier only. mmBERT (ModernBERT family) export is less proven; it lost on quality+latency anyway.
- INT8 accuracy drop must be measured per label before shipping (do not assume the textbook <1.3% transfers
  to QC-FR recall); that is a deferred, operator-gated export step.

## Provisional picks (confirm on v10 held-out)

- **CPU tier: xlm-r-base** (FacebookAI/xlm-roberta-base) -> ONNX-INT8 deployment.
- **GPU tier: xlm-r-large** (FacebookAI/xlm-roberta-large) -> fp16 deployment.

Both are retrained on the offset-true v10 corpus (pii-merged-v10) and scored on the fresh v10 held-out
(pii-heldout-v10) in RESULT-v10.md; the final pick is made there against the strict ship bar. distilbert and
eurobert-210m are also retrained on v10 as a fast-CPU and a high-precision cross-check.
