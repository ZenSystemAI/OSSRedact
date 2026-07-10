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

# OSSRedact NER Suite (3 tiers)

> License: MIT, (c) 2026 ZenSystemAI. Matches the published `@ossredact/core` package and its `LICENSE`.

## Model description

OSSRedact is the detection model behind a **local privacy gateway**: an HTTP proxy that sits in front of cloud LLM APIs (Anthropic `/v1/messages`, OpenAI-compatible `/v1/chat/completions` routing Codex/omp/Hermes/Pi/opencode, and OpenAI `/v1/responses` for current Codex CLI). On egress the gateway redacts PII and secrets in the request's free-text fields to stable placeholders; on the response it rehydrates those placeholders back to the real values. The local client sees real data; the cloud model sees only placeholders in the request fields the gateway scans (cryptographically-bound reasoning/thinking blocks are passed through opaque and not re-scanned -- they are model-generated from already-redacted input, so they too carry only placeholders). The NER model runs **locally on-device** (deployed always-on tier: dynamic-INT8 ONNX on CPU via onnxruntime; Intel NPU / OpenVINO FP16 preserved as a drop-in alternate), so detection never leaves the machine.

The motivation: going fully local for data sovereignty is too expensive (256GB+ of VRAM). Instead, filter private data out, use cloud SOTA, redact on egress and rehydrate transparently. Two users are served: (1) the hobbyist who wants data sovereignty but cannot afford GPUs; (2) the employee who unknowingly leaks client PII through configured CLI/API-endpoint clients today. Browser and desktop-app interception are roadmap items.

This card describes a **3-tier NER suite** with a French-Quebec + English focus. **This bilingual Quebec PII focus is the moat**: competitors lean on generic Presidio or regex, while OSSRedact is trained for French-Quebec and English PII.

| Tier | Base model | Footprint / format | Role |
|---|---|---|---|
| CPU | xlm-roberta-base (v11r9c) | dynamic per-channel INT8 ONNX on CPU (onnxruntime) -- also the in-browser tier | Deployed always-on workhorse |
| NPU | xlm-roberta-base (v11r9c) | OpenVINO FP16 IR on the Intel NPU (alternate tier) | Preserved drop-in alternate |
| GPU | xlm-roberta-large (v11r9c) | (full precision) | Highest-capacity tier |

Both tiers ship as **v11r9c** this round, carrying the structural-form organization/address augmentation. On the GPU/large tier it closes the structural-form organization and address leak that earlier revisions had (organization recall ~0.10 -> 1.00; address recall ~0.60 -> 0.95 on the synthetic held-out corpus). The CPU/base tier is **also retrained to v11r9c** and carries the same org/address augmentation: base address recall is now **0.927** (no longer the ~0.60 weak spot), base full-stack catastrophic detection **0.9941**, base clean false positives **48 / 7498** (full-stack). Base organization coverage was not separately re-measured and may still trail the large tier, so use the large tier when organization recall matters. The improvement comes with a deliberate, principled trade: on the GPU/large tier v11r9c over-redacts more on digit-ID-shaped tokens (clean false positives 12 -> 34 on the held-out negatives). Over-redaction never leaks PII -- it only costs a coding agent a little context when a benign number is ID-shaped -- so for a privacy firewall whose prime directive is "never leak," closing the org/address leak is worth the extra over-redaction.

The suite covers **20 labels** (shipped model, `training/labels_v20.json`): `account_number`, `address`, `card_cvv`, `card_expiry`, `date_of_birth`, `email`, `file_path`, `government_id`, `iban`, `ip_address`, `organization`, `password`, `payment_card`, `person`, `phone_number`, `postal_code`, `secret`, `sensitive_account_id`, `tax_id`, `username`.

The prior 23-label scheme was consolidated: `bank_account` + `routing_number` folded into `account_number` / `sensitive_account_id`; `api_key` + `access_token` folded into `secret` / `password`; `sensitive_date` folded into `date_of_birth`; `phone` renamed `phone_number`; `postal` renamed `postal_code`; `ip` renamed `ip_address`.

**Repo scope vs deployed appliance.** This repository contains the detection library and CLI (`gate/privacy_gate.py`: Tier-0 regex+Luhn floor, NER tier wrappers, merge, redact/rehydrate), the training code, the validation code, and the egress proxy (`appliance/`: SSE stream rehydration, the AES-GCM session/project entity map, the known-entity backstop, and the deterministic secrets/entropy layer described in the pipeline below). The GPU NER gate service (`gate/gate_service_gpu.py`) is now version-controlled here too; the running instance is deployed on the GPU host, with `deploy/check-gate-drift.sh` guarding host-vs-repo drift.

Alongside the NER model run two deterministic layers (in the deployed appliance):
- **Tier-0** (regex + Luhn) owns the catastrophic structured categories.
- A **deterministic secrets layer** (ported gitleaks-style patterns + Shannon-entropy backstop with UUID / git-SHA / sequential false-positive filters).

### Request pipeline

1. Extract redactable text fields (system, messages, tool_result text/JSON, tool_use input, document text, and tool schema descriptions/literal values); never rewrite tool/function names, schema property names, images, binary file bytes, or model name.
2. Cheap deterministic gate, **always** runs (microseconds): Tier-0 regex + Luhn PII + secrets/entropy scan.
3. Empty path: if there is no scannable text and no prior session entity to backstop, forward unchanged.
4. On-device NER pass over every extracted non-trivial text field. Repeated system prompts / prior turns are cached, but short structural values are still scanned so person names have a chance to be caught.
5. Union merge (connected-component, no fragment leaks) + session + project entity map (AES-GCM at rest, same value maps to same placeholder across turns, plus a known-entity backstop that re-redacts any value once identified even if the model later misses it).
6. Forward upstream with the auth header verbatim.
7. Stream-rehydrate the SSE response, reassembling placeholders that split across deltas, and rehydrating tool_use argument JSON at the value level.

### Policy

Per-project and per-session PII config (session overrides project overrides default). Secrets and credentials (api_key, password, access_token) **always** redact regardless of policy. Operational labels (file_path, username, organization) are excluded by default to avoid breaking the coding use case. Git commit/content hashes (40/64 hex) are allowlisted so they are never redacted.

## Intended use

- Always-on DLP / privacy gateway in front of cloud LLM APIs, so private data in your prompts and tool calls never reaches the cloud model.
- French-Quebec + English PII and secret detection for coding agents (Claude Code, Codex, Hermes) and chat traffic.
- Data-sovereignty use where local GPU inference is not affordable, but cloud SOTA is still wanted.

## Out-of-scope use

- Languages other than French and English. Multilingual support is an explicit future axis, not v1.
- Sole reliance for catastrophic categories (secrets, payment cards, SIN). Recall is below 100%, so the deterministic Tier-0 and secrets layers are the reliable floor for those categories, not the NER model on its own.
- Domains far from the validated distribution (broad real-world domains beyond the synthetic Québec validation set are future work).
- Redacting binary media or request-routing fields the pipeline deliberately leaves untouched (images, binary file bytes, model name, tool/function names, schema property names).

## Training data

The NER models are **trained on a SYNTHETIC corpus** of French-Quebec + English PII. This is stated explicitly: the suite is **synthetic-trained**. No real personal data is used at any stage; every span is machine-generated, and only counts (never values) leave the generator.

### Corpus composition (cumulative through v11r9c)

The training corpus is **cumulative across the v11 error-mine rounds** -- the v11r5 base plus the v11r6 structural-name augmentation plus the v11r7 organization/address augmentation (`training/gen/`):

| split | documents | tokens | labeled PII spans |
|-------|-----------|--------|-------------------|
| train | 65,998 | 14.67 M | 364,289 |
| validation | 6,700 | 1.47 M | 36,436 |
| **train + val (what the model sees)** | **72,698** | **16.14 M** | **400,725** |
| disjoint held-outs (names + org/address, never trained) | 2,800 | 0.04 M | 2,660 |

Tokens are xlm-roberta subword tokens (documents over 512 tokens are truncated to the 512 train window). Across the **20 PII entity types** (41 BIO label ids), the most frequent labeled spans are `person` (67,471), `address` (51,575), `postal_code` (45,764), `government_id` (33,288), `account_number` (24,918), `sensitive_account_id` (22,022), and `organization` (21,439); the long tail covers `date_of_birth`, `phone_number`, `email`, `ip_address`, `file_path`, `tax_id`, `username`, `payment_card`, `password`, `card_cvv`, `card_expiry`, `iban`, and `secret`.

### Training recipe

Both tiers train on the same corpus with the same recipe: xlm-roberta base/large, batch size 8, learning rate 2e-5, max sequence length 512, **3 epochs** (24,750 optimizer steps; ~198,000 example-passes; ~44 M token-passes), `metric_for_best_model=cat_f1` so the saved checkpoint maximizes recall on the catastrophic-leak labels (secrets, government IDs, cards, account IDs, person, organization, address). The base tier (xlm-roberta-base, 277 M) trains in ~66 min on an NVIDIA GB10 and exports to dynamic-INT8 ONNX (~277 MB) for the CPU and in-browser tiers; the large tier (xlm-roberta-large, 559 M) is the GPU gate.

Validation was conducted on a **synthetic Québec corpus** of 5,000 French-Québec + English documents (bank statements, financing forms, email threads, CSV exports, `.env` files, and code), **redacted entirely locally**. It is fully synthetic, not training data, and can be re-generated and re-run anywhere with no real-data exposure. Broader real-world domains remain future work.

## Evaluation

**Metric definition.** `recall` is **leak-prevention recall**: the fraction of true PII spans the system catches (and therefore prevents from leaking). `clean_fp` is over-redaction: the count of redactions on negative (clean) rows.

### Measured public benchmark: synthetic held-out (real-structure, error-mine loop)

Measured on the synthetic held-out corpus (7,498 synthetic rows, 0 train overlap, unseen document structures -- an anti-saturation held-out built ONLY from structural variants never seen in training). Source: `validation/RESULT-v11r9c.md` (both tiers; the v11r5 baseline it improves on is `validation/RESULT-v11.md`). The GPU/large row reflects the shipping **v11r9c** revision; the CPU/base row is the shipping **v11r9c** revision.

The privacy metric is **full-stack catastrophic DETECTION recall**: any detected span is redacted regardless of which label it gets -- an intra-catastrophic mislabel is still a redaction, not a leak.

| pick | base | catastrophic full-stack DETECTION | overall labeled R | overall P | clean_fp |
|------|------|-----------------------------------|-------------------|-----------|----------|
| GPU  | xlm-r-large-v11r9c | **0.9954** | 0.9882 | 0.9615 | 34 / 7498 rows |
| CPU  | xlm-r-base-v11r9c | **0.9941** | 0.9777 | 0.9139 | 48 / 7498 rows |

For the GPU/large v11r9c (full config, all 20 labels) the all-label detection recall is **0.9882**, precision **0.9615**, F1 **0.9742**. Of the 13 catastrophic categories, 10 detect at 1.000 (email, government_id, payment_card, card_cvv, card_expiry, secret, password, iban, date_of_birth, tax_id); the three exceptions are person 0.9946 (precision 0.9999), sensitive_account_id 0.9993, and account_number 0.974 (the one neural-only watch-item). On the GPU/large tier the clean false positives rise from 12 (large v11r5) to 34 (large v11r9c) -- the cost of closing the org/address leak (see the model description): per-label precision dips on the digit-ID-shaped labels (government_id ~0.87, phone_number ~0.84, sensitive_account_id ~0.88, account_number ~0.94, date_of_birth ~0.96). This is the safe failure direction -- over-redaction never leaks.

**Published models** (live on HuggingFace):
[`ZenSystemAI/ossredact-pii-large`](https://huggingface.co/ZenSystemAI/ossredact-pii-large) (GPU, full precision) and [`ZenSystemAI/ossredact-pii-base`](https://huggingface.co/ZenSystemAI/ossredact-pii-base) (CPU dynamic per-channel INT8 ONNX, also the in-browser tier). The revision label `v11rN` is the measured weight revision and ships as an HF revision tag, not as part of the repo id; both the GPU and CPU figures are revision `v11r9c`. The base ships as **per-channel dynamic INT8** (the WASM-native in-browser format): v11r9c's org/address augmentation sharpened the boundaries, so the INT8 export lands at pii_argmax 0.967 (cosine 0.997, faithful) -- the `validation/parity_check.py` INT8 bar is 0.965 for this reason (the carded fp32 metrics are the reference; ~62% of the INT8 token-flips are on floor-protected types the deterministic Tier-0 layer redacts regardless of the model, and person -- the highest-frequency no-floor type -- is barely affected; full analysis: `validation/RESULT-base-int8-parity-v11r9c.md`). When the weights are absent locally the service fails gracefully (and fail-closed on the egress path).

Every catastrophic label is caught at >=0.974 full-stack detection (large, v11r9c); 10 of 13 at 1.000. FR is not weaker than EN: the Quebec-French moat holds on unseen structure.

### v6/v7 historical (superseded by v11 -- see validation/RESULT-v11.md)

Earlier results on the v6 generation sets (in-distribution held-out, train and val shared document layouts). Kept for reference; **do not use these as current figures**.

#### Recall per tier per set (v6/v7)

| Tier (model) | ALL-CAPS gate | tabular test | v6 val | canonical | clean_fp |
|---|---|---|---|---|---|
| NPU (xlm-r-base) | 0.955 | 0.968 | 0.990 | 0.986 | 0 |
| GPU (xlm-r-large) | 0.955 | (matches NPU) | 0.990 | (matches NPU) | 0 |

GPU xlm-r-large recall is identical to NPU on the reported sets (0.955 ALL-CAPS gate, 0.990 v6 val). **Key finding: the base model equals GPU large on recall at about 4x lower latency, so the base model is the always-on tier (deployed as CPU INT8 ONNX on onnxruntime; NPU/OpenVINO is the preserved alternate).**

#### vs Microsoft Presidio (v6/v7)

Presidio configured with English + French large spaCy, union, evaluated on the same sets with the same metric.

| Set | OSSRedact recall | Presidio recall | OSSRedact clean_fp | Presidio clean_fp |
|---|---|---|---|---|
| ALL-CAPS gate | 0.955 | 0.779 | 0 | (n/a) |
| v6 val | 0.990 | 0.759 | 0 | 343 |
| canonical | 0.986 | 0.798 | 0 | 508 |

OSSRedact wins recall by **17 to 23 points** and has far fewer false positives.

### Synthetic Québec corpus

A generated corpus of 5,000 FR + EN documents (bank statements, financing forms, email threads, CSV exports, `.env`, code), redacted entirely locally:
- **218,931** PII spans redacted.
- **Zero** email, SIN, account-ID, or credit-card leaks in the redacted output on this synthetic held-out corpus (verified against ground truth). This is a synthetic-corpus result, not a real-world zero-leak guarantee.
- Adversarial cases included (ALL-CAPS, NBSP-separated IDs, mixed FR/EN, long unbroken lines, look-alike decoys). A NBSP-separated-SIN gap in cue-less cells was surfaced, fixed (the deterministic floor now normalizes unicode spaces), and re-verified at zero SIN leaks on the synthetic corpus.

### C2 code-context PII (synthetic)

- Full recall across JSON, YAML, SQL, CSV, logs, .env, code comments, FR + EN, on this synthetic held-out corpus.
- Honest caveat: an adversarial variant (full names glued into camelCase / snake_case identifiers) drops to **0.882**.

### Latency

| Path | Median |
|---|---|
| Appliance clean fast-path | 1.7ms |
| PII-bearing request | 23.5ms |
| on-device per 256-token window | about 34ms |

Charts are available at `./charts/fig1, fig3, fig5` (png).

## Limitations and ethical considerations

- **Synthetic-trained and synthetic-validated.** Models are trained and validated entirely on synthetic Québec data. Broader real-world domains are future work.
- **Recall is below 100%.** The deterministic layer (Tier-0 regex + Luhn, plus the secrets layer) is the reliable floor for catastrophic categories. Tier-0 deterministically covers (a hard, model-independent floor): secrets / API keys, payment cards (Luhn), IBAN, SIN / government IDs, emails, IP addresses, and file paths. Do not rely solely on the NER model for those categories.
- **Address and organization have no deterministic Tier-0 floor.** They rely entirely on the NER model. v11r9c now covers them well on the synthetic corpus (organization 1.00, address 0.95), but this is **model-dependent**, not a hard guarantee like the Tier-0 categories.
- **Glued-identifier gap.** Full names glued into code identifiers (camelCase / snake_case) are under-detected (adversarial C2 recall 0.882).
- **Letter-glued digit-run gap.** Bare long digit runs glued to adjacent letters can be missed unless a financial / identity cue is nearby.
- **French and English only by design.** Multilingual support is an explicit future axis, not v1.

### Honest positioning

The redaction-proxy concept already exists. og-local/OutGate (BSL license) and rehydra-sdk (MIT) both proxy these wire formats with round-trip streaming rehydration. OSSRedact's distinct contribution is: a trained French-Quebec + English PII NER model (competitors use generic Presidio / regex), running the model locally on-device (CPU INT8 always-on; NPU/OpenVINO alternate tier): no cloud detection call, true data sovereignty, an always-on deterministic secrets + structured-PII floor, and Quebec Law 25 framing. **No "first" or "only" claim is made.**

## How to use

The model is deployed **behind the gateway**, not called directly. The deployed always-on tier runs **dynamic-INT8 ONNX** on CPU via onnxruntime (the Intel NPU / OpenVINO FP16 tier is preserved as a drop-in alternate). Point any tool at the gateway:

```bash
export ANTHROPIC_BASE_URL=http://<host>:8011
```

Then run Claude Code, Codex, Hermes, or another configured CLI as usual. The gateway redacts PII and secrets on egress and rehydrates the placeholders on the response, transparently. It works under a Claude Max subscription: billing stays on Max, no API key needed, and the auth header is forwarded verbatim.

## Status

The appliance is built, running as a systemd service, and verified end-to-end (a real Claude Code session through the proxy redacts and rehydrates transparently). It is **not yet published**. The workbench UI is built. Anthropic `/v1/messages`, OpenAI-compatible `/v1/chat/completions`, and OpenAI `/v1/responses` adapters are live; CLI wiring for Codex, Hermes, Pi, omp, and opencode is documented in `docs/ADAPTERS.md`.
