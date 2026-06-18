# OSSRedact: Measured Results (real, for Track D benchmarks)

> All numbers MEASURED 2026-06-14 on-box, not estimated. Recall = leak-prevention (label-agnostic substring
> match); clean_fp = over-redactions on negative rows. Source of truth for the launch benchmark tables/graphs.

## v11 (CURRENT model): real-structure held-out, 5-round error-mine

> MEASURED 2026-06-16 on pii-heldout-v11r5 (7498 synthetic rows, 0 train overlap, UNSEEN document structures).
> 20-label scheme (training/labels_v20.json). The privacy metric is full-stack catastrophic DETECTION recall
> (any detected span is redacted regardless of which label it gets -- an intra-catastrophic mislabel is still a
> redaction, not a leak). Full per-label tables, the r1->r5 trajectory, and the labeled-vs-detection framing:
> **validation/RESULT-v11.md**.

| pick | base | catastrophic FULL-stack DETECTION | overall labeled R | overall P | clean_fp |
|------|------|-----------------------------------|-------------------|-----------|----------|
| GPU  | xlm-r-large-v11r5 | **0.9964** | 0.9785 | 0.9598 | 12 / 7498 rows |
| CPU  | xlm-r-base-v11r5  | **0.9932** | 0.9664 | 0.9456 | 12 / 7498 rows |

- Every catastrophic label is caught at >=0.974 full-stack detection (large); 11 of 13 at 1.000. The one
  residual is account_number on the Equifax ACROFILE comma-positional tradeline (0.974 detection, ~94 of 3599 --
  the hardest unseen-structure case). clean_fp 12/7498 = negligible over-redaction.
- FR is not weaker than EN (FR R=0.980, EN R=0.978): the Quebec-French moat holds on unseen structure.
- This held-out is ANTI-SATURATION: built ONLY from structural variants never trained (unlike the v6/v7
  generation below, where train and held-out shared layouts). It measures generalization to UNSEEN document
  structure. Trajectory: catastrophic detection 0.955 (r1) -> 0.9964 (r5, large).
- The strict model-alone LABELED bar (spec 3.8) is not the ship gate; it penalizes redaction-safe
  intra-catastrophic mislabels. Ship criterion = full-stack catastrophic DETECTION + clean_fp, both met.

## Tier eval (v6/v7 generation, HISTORICAL -- synthetic held-out sets; eval_suite.py)
Latency p95 below is on the EVAL hardware (3090Ti for npu/gpu tiers, CPU for distilbert), NOT deployment NPU.

| set | metric | CPU distilbert-v6 | NPU xlm-r-base-v6 | GPU xlm-r-large-v6 |
|---|---|---|---|---|
| tabular_caps_GATE (ALL-CAPS, never trained) | recall | 0.9227 | **0.9549** | 0.9549 |
| tabular_test | recall | 0.9375 | 0.9677 | 0.9677 |
| v6_val (n=2422) | recall | 0.9778 | 0.9895 | 0.9897 |
| canonical_clean (n=500) | recall | 0.9870 | 0.9858 | 0.9858 |
| all sets | clean_fp | 0 to 2 | 0 | 0 |
| p95 latency (eval HW) | ms | ~33 (CPU) | ~5 (GPU) | ~20 (GPU) |

Key finding: **NPU base ≈ GPU large on recall** (0.955 caps-gate, identical) at ~4× lower latency, so NPU is the
right always-on deployment tier. CPU distilbert trails by ~3pts recall (the cheapest/most-portable tier).

Deployment latency (measured on the actual Intel NPU via OpenVINO, earlier): ~34 ms / 256-tok window.
Appliance end-to-end added latency (T8): clean fast-path 1.7 ms median; PII request 23.5 ms median.

## C1: Synthetic Québec corpus validation (100% synthetic, re-runnable, no real-data exposure)
- 5,000 FR + EN docs (bank statements, financing forms, email threads, CSV exports, `.env`, code), 0 errors.
  **218,931 PII spans redacted.**
- by label: phone_number 50001, person 39274, email 34330, government_id 26058, postal_code 25953,
  sensitive_date 24691, payment_card 3074, api_key 2896, address 2519, access_token 2205,
  sensitive_account_id 1994, bank_account 1714, file_path 1352, routing_number 1279, organization 650,
  date_of_birth 650, password 233, iban 30, username 25, ip_address 1, card_cvv 1, tax_id 1.
- **Hard-category leak check (value survives verbatim in output): ZERO email / account-ID / SIN / credit-card.**
  Checked 32,754 emails, 30,870 account-IDs, 31,163 SINs, 691 cards against ground truth.
- Adversarial NBSP-separated SINs in cue-less cells initially leaked (770/31,163); root-caused to the Tier-0
  digit-run regex excluding unicode spaces, fixed by normalizing NBSP/unicode spaces in the deterministic floor,
  re-verified at **0** SIN leaks.
- **Model fine-tune (v6 -> v7):** person recall on FR bank-statement transaction lines ("Virement Interac a
  {NAME}") was 25% (the v6 training data had no transaction-description examples). Added diverse FR/EN
  transaction-line examples (payee names = person, merchants left unlabelled), retrained xlm-r-large -> **v7**:
  FR-transaction person recall **25% -> 100%**, no regression elsewhere, merchants still not over-redacted,
  hard-category leaks still 0. Deployed to both the GPU gate (xlm-r-large v7) and the NPU gate
  (xlm-r-base v7, OpenVINO FP16 IR), verified end-to-end through the egress proxy.
- Verdict: zero identity-critical leaks across a large adversarial synthetic corpus; FR transaction-line
  payee names now caught.

## C2: code-context PII recall (synthetic, seed=42, N=300 rows)
- **OVERALL recall = 1.0000 (1197/1197)**: perfect across json/yaml/sql/csv/log/env/comments, FR + EN, all
  categories (person/email/phone/account/nas/card/ip/postal/address).
- C2-HARD (adversarial: names glued into identifiers, delimiter-free, mixed FR/EN): 0.882 (15/17). The only 2
  misses = full names glued into camelCase/snake_case identifiers (`customerJeanTremblay`, `jean_tremblay_x`).

## Known limitations (honest, for the model card)
1. Names glued into code identifiers (camel/snake_case): subword tokenization limits recovery; not retrained
   (FP risk on legit identifiers in the coding use case).
2. Bare 11 to 19 digit transaction-reference numbers adjacent to letters: Tier-0 word-boundary edge; low severity.
3. Synthetic-trained and synthetic-validated; broader real-domain coverage is future work.
4. FR + EN only by design (the moat); multilingual is an explicit future axis, not v1.
