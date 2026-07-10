# v11r10 -- org-recall retrain verdict (2026-06-20)

**Status: STAGED, not shipped.** Ship decision is the operator's. v11r9c remains the deployed gate model.

## Why
The adversarial egress stress left ONE systematic model-recall gap: the gate under-detects
**compound / acronym / ALLCAPS organization names** -- canonical Quebec institution forms
(`Caisse Desjardins`, `Mouvement Desjardins`), short acronyms (`IBM`, `MoMA`), ALLCAPS letterhead, and
CamelCase-glued company names. On v11r9c these either fragmented (`Caisse Desjardins` -> `isse Desjardins`,
leaking the head) or were missed entirely (`IBM`, `MoMA` -> zero detection). Zero-detection cannot be rescued
by the egress word-boundary expansion (nothing to expand), so the retrain is the only fix for that tail.

## What changed
- Corpus `datasets/pii-merged-v11r10` = v11r9c corpus + 6k org-recall augmentation (`training/gen/augment_org_v11r10.py`
  + `training/gen/v11r10_lexicon.json`: 393 public-institution orgs, 114 addresses, 135 FR/EN templates, 80
  capitalized-non-org negatives). Offset-exact span placement; 22% negatives as a precision guard; ALLCAPS /
  CamelCase surface-form variants. Public institution names only -- no client data.
- Recipe IDENTICAL to v11r9c: xlm-roberta-large, bs8 lr2e-5 maxlen512 3ep, `metric_for_best_model=cat_f1`.
- Trained on the local 5090 (2277s, train_loss 0.0211, in-dist val cat_f1 0.9997).

## Result 1 -- org-recall gain (the target), org_probe (hard forms, EXACT-span recovery)
`/tmp/org_probe.py`, 10 probes incl. 3 UNSEEN orgs (not in the lexicon -> tests form-generalization, not memorization):

| | v11r9c | v11r10 |
|---|---|---|
| org-recall (exact) | **6/10, fragmented** | **10/10, clean** |

- Previously ZERO-detection (now caught): `IBM`, `MoMA`, `Caisse Desjardins de Lévis`.
- Previously fragmented (now clean full spans): `Caisse Desjardins de Québec` (was `isse Desjardins`),
  `Mutuelle d'assurance des Cantons-de-l'Est` (was `elle d` / `tons` / `'Est`).
- UNSEEN generalization (not in lexicon, all clean on v11r10): `Caisse populaire Saint-Casimir`,
  `Boulangerie Tremblay-Désilets`, `Mutuelle d'assurance des Cantons-de-l'Est`.

## Result 2 -- NO catastrophic-recall regression (the ship gate)
Fair apples-to-apples: both models scored by the identical `validation/eval_labelaware.py` on the identical
current `datasets/pii-merged-v11r9c/val.jsonl` (5550 rows). (The pre-existing `/tmp/v11r9c_eval.json` was on a
stale/larger val and is not comparable; re-run as `/tmp/v11r9c_eval_fair.json`.)

Detect-recall (full stack), all 15 catastrophic labels:

| label | v11r9c | v11r10 |
|---|---|---|
| person | 1.0000 | 1.0000 |
| organization | 1.0000 | 1.0000 |
| address | 0.9998 | 1.0000 |
| account_number | 1.0000 | 1.0000 |
| **sensitive_account_id** | 1.0000 | **1.0000** |
| government_id / tax_id / payment_card / iban | 1.0000 | 1.0000 |
| secret / password / email / phone_number | 1.0000 | 1.0000 |
| date_of_birth / ip_address | 1.0000 | 1.0000 |

**0 catastrophic-recall regressions.** `sensitive_account_id` -- the metric that sank v11r9b and v11r9c during
model selection -- holds at 1.0000. No PII leaks more than before.

## Result 3 -- the cost: org + address PRECISION (over-redaction), contained
Same fair eval, full-stack precision / clean false-positives:

| | v11r9c | v11r10 | delta |
|---|---|---|---|
| precision (all labels) | 0.9773 | 0.9725 | -0.0048 |
| clean_fp (320 negative docs) | 19 | 43 | +24 |

The +24 clean FPs are **entirely org + address**; every other label's precision is unchanged:
- organization precision 0.8871 -> 0.8331
- address precision 1.0000 -> 0.9774

This is the expected, contained side effect of teaching more org/address forms: the model now tags some
capitalized non-org words (framework names, ALLCAPS headers) as organization. It is the operator's accepted
"over-redaction = safe direction" tradeoff, and it lands squarely on the two labels we deliberately strengthened
-- not on any deterministic-secret or identifier surface.

Note: the `structural_orgaddr_heldout` (734 rows, 660 disjoint) shows ~equal org detect-recall for both models
(~1.0) -- its simple single-line `Label : {ORG}` forms are detect-overlapped even by v11r9c, so it under-
discriminates. org_probe (hard forms + exact-span recovery) is the discriminating test, and that is where the
gain is real.

## Product implication (org redaction vs coding UX)
v11r10 sharpens the existing org-vs-coding tradeoff: it over-tags organization MORE than v11r9c. For a
privacy-first egress firewall that is the safe direction (employer/institution names never leak). For a coding
agent it means more framework/tech-term over-redaction (`React`, `PostgreSQL` -> `<ORGANIZATION>`), opt-out via
per-project `exclude:[org]` or the do-not-redact dictionary. The org precision drop (0.887 -> 0.833) is the
quantified cost of that direction.

## Recommendation
STAGE v11r10. It closes the last systematic recall gap (org compound/acronym/ALLCAPS) with zero catastrophic-
recall regression and a contained, accepted precision cost on org+address only. Ship is the operator's decision;
if shipped, it pairs with the org-vs-coding product choice (keep org-on, document the opt-out). If the coding-UX
noise is judged too high, v11r9c stays deployed and the egress word-boundary expansion still recovers the
fragmented (non-zero-detection) org forms at inference time.

## Artifacts
- Staged model: `models/pii-gpu-xlmr-large-v11r10` (2.2G, full tokenizer incl sentencepiece) + `out/pii-gpu-xlmr-large-v11r10`.
- Eval JSONs: `/tmp/v11r9c_eval_fair.json`, `/tmp/v11r10_eval.json`, `/tmp/heldout_v11r9c.json`, `/tmp/heldout_v11r10.json`.
- Not deployed. Not ONNX-exported (base/CPU tier unchanged). The deployed gate still serves v11r9c.
