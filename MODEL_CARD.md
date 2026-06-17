---
language:
  - fr
  - en
license: mit
tags:
  - token-classification
  - pii
  - ner
  - privacy
  - quebec
pipeline_tag: token-classification
---

# qc-pii NER Suite (3 tiers)

> License: MIT, (c) 2026 ZenSystemAI. Matches the published `@ossredact/core` package and its `LICENSE`.

## Model description

qc-pii is the detection model behind a **local privacy gateway**: an HTTP proxy that sits in front of cloud LLM APIs (Anthropic `/v1/messages`, OpenAI-compatible `/v1/chat/completions` routing Codex/omp, and OpenAI `/v1/responses` for Codex CLI today). On egress the gateway redacts PII and secrets in the request's free-text fields to stable placeholders; on the response it rehydrates those placeholders back to the real values. The local client (Claude Code, Codex, Hermes) sees real data; the cloud model only ever sees placeholders. The NER model runs **locally on-device** (deployed always-on tier: dynamic-INT8 ONNX on CPU via onnxruntime; Intel NPU / OpenVINO FP16 preserved as a drop-in alternate), so detection never leaves the machine.

The motivation: going fully local for data sovereignty is too expensive (256GB+ of VRAM). Instead, filter private data out, use cloud SOTA, redact on egress and rehydrate transparently. Two users are served: (1) the hobbyist who wants data sovereignty but cannot afford GPUs; (2) the employee who unknowingly leaks client PII into ChatGPT or Claude (always-on DLP).

This card describes a **3-tier NER suite** with a French-Quebec + English focus. **This bilingual Quebec PII focus is the moat**: competitors lean on generic Presidio or regex, while qc-pii is trained for French-Quebec and English PII.

| Tier | Base model | Footprint / format | Role |
|---|---|---|---|
| CPU | xlm-roberta-base | dynamic-INT8 ONNX on CPU (onnxruntime) | Deployed always-on workhorse |
| CPU | distilbert-multilingual | 135MB static-INT8 | Most portable tier |
| NPU | xlm-roberta-base | OpenVINO FP16 IR on the Intel NPU (alternate tier) | Preserved drop-in alternate |
| GPU | xlm-roberta-large | (full precision) | Highest-capacity tier |

The suite covers **20 labels** (shipped model, `training/labels_v20.json`): `account_number`, `address`, `card_cvv`, `card_expiry`, `date_of_birth`, `email`, `file_path`, `government_id`, `iban`, `ip_address`, `organization`, `password`, `payment_card`, `person`, `phone_number`, `postal_code`, `secret`, `sensitive_account_id`, `tax_id`, `username`.

The prior 23-label scheme was consolidated: `bank_account` + `routing_number` folded into `account_number` / `sensitive_account_id`; `api_key` + `access_token` folded into `secret` / `password`; `sensitive_date` folded into `date_of_birth`; `phone` renamed `phone_number`; `postal` renamed `postal_code`; `ip` renamed `ip_address`.

**Repo scope vs deployed appliance.** This repository contains the detection library and CLI (`gate/privacy_gate.py`: Tier-0 regex+Luhn floor, NER tier wrappers, merge, redact/rehydrate), the training code, the validation code, and the egress proxy (`appliance/`: SSE stream rehydration, the AES-GCM session/project entity map, the known-entity backstop, and the deterministic secrets/entropy layer described in the pipeline below). The deployed GPU NER gate service (`gate_service_gpu.py`) remains host-only (tracked as finding F6).

Alongside the NER model run two deterministic layers (in the deployed appliance):
- **Tier-0** (regex + Luhn) owns the catastrophic structured categories.
- A **deterministic secrets layer** (ported gitleaks-style patterns + Shannon-entropy backstop with UUID / git-SHA / sequential false-positive filters).

### Request pipeline

1. Extract redactable text fields (system, messages, tool_result text); never touch tool_use input, tool schemas, images, or model name.
2. Cheap deterministic gate, **always** runs (microseconds): Tier-0 regex + Luhn PII + secrets/entropy scan.
3. Fast path: if clean, forward unchanged (zero model cost).
4. Targeted on-device NER pass only on flagged or natural-language fields (pure code with no Tier-0 hit is skipped).
5. Union merge (connected-component, no fragment leaks) + session + project entity map (AES-GCM at rest, same value maps to same placeholder across turns, plus a known-entity backstop that re-redacts any value once identified even if the model later misses it).
6. Forward upstream with the auth header verbatim.
7. Stream-rehydrate the SSE response, reassembling placeholders that split across deltas, and rehydrating tool_use argument JSON at the value level.

### Policy

Per-project and per-session PII config (session overrides project overrides default). Secrets and credentials (api_key, password, access_token) **always** redact regardless of policy. Operational labels (file_path, username, organization) are excluded by default to avoid breaking the coding use case. Git commit/content hashes (40/64 hex) are allowlisted so they are never redacted.

## Intended use

- Always-on DLP / privacy gateway in front of cloud LLM APIs, so private data never reaches the cloud model.
- French-Quebec + English PII and secret detection for coding agents (Claude Code, Codex, Hermes) and chat traffic.
- Data-sovereignty use where local GPU inference is not affordable, but cloud SOTA is still wanted.

## Out-of-scope use

- Languages other than French and English. Multilingual support is an explicit future axis, not v1.
- Sole reliance for catastrophic categories (secrets, payment cards, SIN). Recall is below 100%, so the deterministic Tier-0 and secrets layers are the reliable floor for those categories, not the NER model on its own.
- Domains far from the validated distribution (broad real-world domains beyond the synthetic Québec validation set are future work).
- Redacting structured fields the pipeline deliberately leaves untouched (tool_use input, tool schemas, images, model name).

## Training data

The NER models are **trained on a SYNTHETIC corpus** of French-Quebec + English PII. This is stated explicitly: the suite is **synthetic-trained**.

Validation was conducted on a **synthetic Québec corpus** of 5,000 French-Québec + English documents (bank statements, financing forms, email threads, CSV exports, `.env` files, and code), **redacted entirely locally**. It is fully synthetic, not training data, and can be re-generated and re-run anywhere with no real-data exposure. Broader real-world domains remain future work.

## Evaluation

**Metric definition.** `recall` is **leak-prevention recall**: the fraction of true PII spans the system catches (and therefore prevents from leaking). `clean_fp` is over-redaction: the count of redactions on negative (clean) rows.

### Current model: v11 (real-structure held-out, 5-round error-mine loop)

Measured on `pii-heldout-v11r5` (7,498 synthetic rows, 0 train overlap, unseen document structures -- an anti-saturation held-out built ONLY from structural variants never seen in training). Source: `validation/RESULT-v11.md`.

The privacy metric is **full-stack catastrophic DETECTION recall**: any detected span is redacted regardless of which label it gets -- an intra-catastrophic mislabel is still a redaction, not a leak.

| pick | base | catastrophic full-stack DETECTION | overall labeled R | overall P | clean_fp |
|------|------|-----------------------------------|-------------------|-----------|----------|
| GPU  | xlm-r-large-v11r5 | **0.9964** | 0.9785 | 0.9598 | 12 / 7498 rows |
| CPU  | xlm-r-base-v11r5  | **0.9932** | 0.9664 | 0.9456 | 12 / 7498 rows |

Every catastrophic label is caught at >=0.974 full-stack detection (large); 11 of 13 at 1.000. FR is not weaker than EN (FR R=0.980, EN R=0.978): the Quebec-French moat holds on unseen structure.

### v6/v7 historical (superseded by v11 -- see validation/RESULT-v11.md)

Earlier results on the v6 generation sets (in-distribution held-out, train and val shared document layouts). Kept for reference; **do not use these as current figures**.

#### Recall per tier per set (v6/v7)

| Tier (model) | ALL-CAPS gate | tabular test | v6 val | canonical | clean_fp |
|---|---|---|---|---|---|
| NPU (xlm-r-base) | 0.955 | 0.968 | 0.990 | 0.986 | 0 |
| GPU (xlm-r-large) | 0.955 | (matches NPU) | 0.990 | (matches NPU) | 0 |
| CPU (distilbert) | 0.923 | 0.938 | 0.978 | 0.987 | 0 to 2 |

GPU xlm-r-large recall is identical to NPU on the reported sets (0.955 ALL-CAPS gate, 0.990 v6 val). **Key finding: the base model equals GPU large on recall at about 4x lower latency, so the base model is the always-on tier (deployed as CPU INT8 ONNX on onnxruntime; NPU/OpenVINO is the preserved alternate).**

#### vs Microsoft Presidio (v6/v7)

Presidio configured with English + French large spaCy, union, evaluated on the same sets with the same metric.

| Set | qc-pii recall | Presidio recall | qc-pii clean_fp | Presidio clean_fp |
|---|---|---|---|---|
| ALL-CAPS gate | 0.955 | 0.779 | 0 | (n/a) |
| v6 val | 0.990 | 0.759 | 0 | 343 |
| canonical | 0.986 | 0.798 | 0 | 508 |

qc-pii wins recall by **17 to 23 points** and has far fewer false positives.

### Synthetic Québec corpus

A generated corpus of 5,000 FR + EN documents (bank statements, financing forms, email threads, CSV exports, `.env`, code), redacted entirely locally:
- **218,931** PII spans redacted.
- **Zero** email, SIN, account-ID, or credit-card leaks in the redacted output (verified against ground truth).
- Adversarial cases included (ALL-CAPS, NBSP-separated IDs, mixed FR/EN, long unbroken lines, look-alike decoys). A NBSP-separated-SIN gap in cue-less cells was surfaced, fixed (the deterministic floor now normalizes unicode spaces), and re-verified at zero SIN leaks.

### C2 code-context PII (synthetic)

- **100% recall** across JSON, YAML, SQL, CSV, logs, .env, code comments, FR + EN.
- Adversarial variant (full names glued into camelCase / snake_case identifiers): **0.882**.

### Latency

| Path | Median |
|---|---|
| Appliance clean fast-path | 1.7ms |
| PII-bearing request | 23.5ms |
| on-device per 256-token window | about 34ms |

Charts are available at `./charts/fig1..fig5` (png).

## Limitations and ethical considerations

- **Synthetic-trained and synthetic-validated.** Models are trained and validated entirely on synthetic Québec data. Broader real-world domains are future work.
- **Recall is below 100%.** The deterministic layer (Tier-0 regex + Luhn, plus the secrets layer) is the reliable floor for catastrophic categories (secrets, cards, SIN). Do not rely solely on the NER model for those categories.
- **Glued-identifier gap.** Full names glued into code identifiers (camelCase / snake_case) are under-detected (adversarial C2 recall 0.882).
- **Letter-glued digit-run gap.** Bare long digit runs glued to adjacent letters can be missed unless a financial / identity cue is nearby.
- **French and English only by design.** Multilingual support is an explicit future axis, not v1.

### Honest positioning

The redaction-proxy concept already exists. og-local/OutGate (BSL license) and rehydra-sdk (MIT) both proxy these wire formats with round-trip streaming rehydration. qc-pii's distinct contribution is: a trained French-Quebec + English PII NER model (competitors use generic Presidio / regex), running the model locally on-device (CPU INT8 always-on; NPU/OpenVINO alternate tier): no cloud detection call, true data sovereignty, an always-on deterministic secrets + structured-PII floor, and Quebec Law 25 framing. **No "first" or "only" claim is made.**

## How to use

The model is deployed **behind the gateway**, not called directly. The deployed always-on tier runs **dynamic-INT8 ONNX** on CPU via onnxruntime (the Intel NPU / OpenVINO FP16 tier is preserved as a drop-in alternate). Point any tool at the gateway:

```bash
export ANTHROPIC_BASE_URL=http://<host>:8011
```

Then run Claude Code, Codex, or Hermes as usual. The gateway redacts PII and secrets on egress and rehydrates the placeholders on the response, transparently. It works under a Claude Max subscription: billing stays on Max, no API key needed, and the auth header is forwarded verbatim.

## Status

The Track A appliance is built, running as a systemd service, and verified end-to-end (a real Claude Code session through the proxy redacts and rehydrates transparently). It is **not yet published**. The workbench UI is built. The OpenAI/Codex `/v1/chat/completions` and `/v1/responses` (Codex) adapters are live; the Hermes adapter is still planned.
