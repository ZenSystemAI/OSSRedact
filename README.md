# OSSRedact

[![CI](https://github.com/ZenSystemAI/OSSRedact/actions/workflows/ci.yml/badge.svg)](https://github.com/ZenSystemAI/OSSRedact/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40ossredact%2Fcore?label=%40ossredact%2Fcore)](https://www.npmjs.com/package/@ossredact/core)
[![models](https://img.shields.io/badge/%F0%9F%A4%97%20models-ZenSystemAI-ffd21e)](https://huggingface.co/ZenSystemAI)
[![license](https://img.shields.io/badge/license-MIT-2ea44f)](LICENSE)

**A local privacy gateway that strips PII and secrets before they reach a cloud LLM, and puts them back in the reply.**

- **Use cloud SOTA, keep your data home.** No 256GB GPU rig required -- filter the private data out, let the cloud model work on placeholders, get the real values back transparently.
- **Hand the AI placeholders for scanned fields.** Your tool works with real data while the cloud sees replacements for fields the gateway scans; opaque reasoning/thinking content is a documented exception.
- **A deterministic safety floor.** Recognized secret patterns, checksums, shapes, and contextual cues can trigger model-independent redaction for structured values in every mode, including `Off`. This is a rule-triggered floor, not a claim that every opaque secret, identifier, or account number is recognized.
- **Local by default.** The desktop and headless CPU routes run detection on-device. An intentional remote gate creates a separate authenticated transport boundary.
- **Watch it locally.** By default the local console shows, per request, each real value -> the placeholder the cloud sees, and each placeholder -> the real value on reply. Authenticated off-device control is an explicit opt-in, not a consequence of binding a port.

OSSRedact is an HTTP proxy that sits in front of cloud LLM APIs. On the way out it redacts PII and secrets in the request's free-text fields to stable placeholders. On the way back it rehydrates those placeholders into the real values. Your local tool sees real data; the cloud model receives replacements in the fields the gateway scans. Opaque reasoning/thinking blocks are byte-preserved and not re-scanned, so client-injected real data in such a block can pass through. Claude Code and Codex use documented Anthropic and OpenAI adapter paths; Hermes, Pi, omp, and opencode use the same adapters.

![The OSSRedact Workbench redacting a French banking document fully on-device](docs/media/workbench-redaction.png)

*The Workbench after a deep detect on a French banking document: name, SIN, cards, accounts, address, and dates become stable placeholders, entirely in-browser. Try it live (works offline once loaded) at [ossredact.dev/app](https://ossredact.dev/app/).*

![OSSRedact vs Microsoft Presidio -- held-out Quebec FR/EN PII](charts/fig5_vs_presidio.png)

*Historical v6/v7 comparison against Microsoft Presidio on held-out Quebec FR/EN PII. Current measured v11 numbers are below.*

## Why

Going fully local for data sovereignty is too expensive: SOTA-quality local inference needs 256GB+ of VRAM. OSSRedact takes the other path. Filter the private data out, use cloud SOTA, redact on egress and rehydrate transparently. Two users:

1. **The hobbyist** who wants data sovereignty but cannot justify a GPU rig. Keep using cloud Claude, keep your data home.
2. **The employee** who unknowingly leaks client PII through configured CLI/API-endpoint clients today. Browser and desktop-app interception are roadmap items, not current coverage.

## How it works

The request pipeline, in order:

```
client (real data)
   |
   v
1. Extract redactable text fields (system, messages, tool_result text/JSON,
   tool_use input, document text, and tool schema descriptions/literal values).
   Never rewrites tool/function names, schema property names, images, binary file bytes, or model name.
   |
   v
2. Tier-0 deterministic rules, ALWAYS, in microseconds:
   recognized shape/checksum/cue-backed PII rules plus secret patterns and a filtered entropy backstop.
   |
   v
3. Empty path: if there is no scannable text and no prior session entity to backstop,
   forward unchanged.
   |
   v
4. On-device NER pass over every extracted non-trivial text field.
   Repeated system prompts / prior turns are cached, but short structural
   values are still scanned so person names have a chance to be caught.
   |
   v
5. Union merge (connected-component, no fragment leaks) +
   session/project entity map (AES-GCM at rest). Same value maps to the
   same placeholder across turns. A known-entity backstop re-redacts any
   value once identified, even if the model later misses it.
   |
   v
6. Forward upstream, auth header verbatim.
   |
   v
7. Stream-rehydrate the SSE response: reassemble placeholders split across
   deltas, rehydrate tool_use argument JSON at the value level.
   |
   v
client receives the real values back
```

**Policy.** PII config is per-project and per-session (session overrides project overrides default). A single **redaction mode** sets the overall stance, toggleable live from the console:

- **Privacy** (default) -- redact all detected PII, organizations included.
- **Coding** -- additionally let organization/framework names (`React`, `PostgreSQL`, an employer name), bind/localhost IP literals, and UUID-shaped session/request ids through, so an AI coding agent keeps its context and its file/session plumbing keeps working; names, addresses, emails, phones and the floor still redact.
- **Off** -- pass soft PII (names, addresses, emails) through, for when redaction gets in the way.

Bare dates and version strings never redact at the egress in **any** mode (they are the highest-volume false-positive class on real traffic and identify nobody on their own; set `GATEWAY_REDACT_DATES=1` to restore date redaction in Privacy mode). The Workbench keeps its own per-label date filter for document review.

The **deterministic floor is never disableable by any mode for spans that earned deterministic provenance**. It relies on recognized secret rules, checksums, shapes, and contextual cues, not a model label alone. The `account_number` floor requires a recognized account cue plus a shaped value; generic structured digit runs are handled as `sensitive_account_id`, not proof that every account number is known. Model-only account/government identity spans are soft `sensitive_ref` values, model credential candidates are shape-vetted, and model card or DOB candidates remain redaction candidates. The `username` label is excluded by default and file paths are narrowed to the home-dir username (`GATEWAY_PATH_POLICY`) so the coding use case keeps working; git commit and content hashes (40/64 hex) are allowlisted and never redacted.

## Install and run

Choose the route that matches the host:

- **Desktop Linux account, no sudo:** [QUICKSTART.md](QUICKSTART.md) installs user units beneath `$HOME/.local/share/ossredact`, including the user-manager and linger prerequisites.
- **Headless or server host:** [deploy/README.md](deploy/README.md#headless-system-service-installation-opt) installs the separate `/opt/ossredact` system-service route.
- **Off-device control or a non-loopback bind:** read [the token and encrypted-transport boundary](QUICKSTART.md#5-gate-egress-and-control-tokens) first. `GATEWAY_CONTROL_TOKEN` protects remote control-plane requests, not `/v1/*` relay traffic.
- **Security boundaries and limitations:** read [SECURITY.md](SECURITY.md) before exposing any service beyond loopback.

After a local installation is running, point a local client at the egress proxy:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8011
claude
```

The local gate-served settings page (`/`) and full browser console (`/console`) stay loopback-only. The live activity feed contains real values in memory; remote access to that control-plane data is opt-in and header-authenticated as documented above.

Anthropic `/v1/messages`, OpenAI-compatible `/v1/chat/completions` (Codex, omp, Hermes, Pi, opencode), and OpenAI `/v1/responses` use the same redact/rehydrate contract. Tool-specific wiring is documented in `docs/ADAPTERS.md`. The TypeScript redaction core shared by the Workbench is published as [`@ossredact/core`](https://www.npmjs.com/package/@ossredact/core).

## Desktop app

One app, two surfaces, one codebase (`workbench/`) -- shipped both as a static web build (runs in any browser, no install) and as a Tauri tray app.

- **Redact** -- a document-redaction workbench. Drop a `.pdf` / `.docx` / `.xlsx` / `.txt` / `.md` / `.csv` / `.json`, or paste text; PII is detected and masked **entirely in the browser**, so the document never leaves the machine. The deterministic **Tier-0 floor** (secrets, payment cards, IBANs, IDs -- regex + Luhn/mod-97) runs in-browser with no model at all; the in-browser **neural** tier loads when its INT8 weights are staged at `/model/` (the hosted demo and packaged builds bundle them -- a bare `npm run dev` of this repo serves the Tier-0 floor only). Format-preserving export, click-to-inspect provenance, batch processing with a shared map, and round-trip restore of a redacted copy.
- **Firewall** -- the console for the always-on proxy: a **Connect** tab with copy-paste setup for Claude Code / Codex, the **live activity** proof (each real value to the placeholder the cloud sees, and back), the **do-not-redact and always-redact dictionaries**, and the **Privacy / Coding / Off** mode switch. It talks to the local daemon and degrades gracefully to a "start the firewall" prompt when none is running.

**Light and dark theme**, following your OS preference. As a native app it is **tray-resident** (minimize to tray, optional launch-on-login), with the egress daemon running as a separate background service the app connects to. Build installers with `npm run app:build` (a Linux `.deb` is provided; macOS/Windows build from the same scaffold). The Firewall console is also served by the daemon itself at `http://127.0.0.1:8011/` with no app install at all.

## What it catches

**Repo scope vs deployed appliance.** This repository contains the detection library and CLI, the training and validation code, and the egress proxy (`appliance/`: the `:8011` gateway, SSE rehydration, AES-GCM session/project entity maps, the known-entity backstop, and the deterministic secrets layer).

**Tier-0 deterministic floor (always on, in the deployed appliance).** The appliance uses recognized format checks, checksums, and context cues for deterministic spans, plus recognized secret patterns and a filtered entropy backstop. The floor is strongest when its concrete rule matches; it is not a generic PII or secret coverage promise.

**NER suite, 3 tiers, French-Quebec + English focus.** The bilingual Quebec PII focus is the moat: competitors use generic English-first detectors.

| Tier | Model | Notes |
|------|-------|-------|
| CPU | xlm-roberta-base | the deployed always-on workhorse, dynamic-INT8 ONNX on CPU (onnxruntime) |
| NPU | xlm-roberta-base | preserved drop-in alternate, OpenVINO FP16 IR on the Intel NPU (alternate tier) |
| GPU | xlm-roberta-large | optional CUDA tier using fp16 `.safetensors` or `.bin` artifacts |

**20 labels** (shipped model, `training/labels_v20.json`): `account_number`, `address`, `card_cvv`, `card_expiry`, `date_of_birth`, `email`, `file_path`, `government_id`, `iban`, `ip_address`, `organization`, `password`, `payment_card`, `person`, `phone_number`, `postal_code`, `secret`, `sensitive_account_id`, `tax_id`, `username`.

The prior 23-label scheme was consolidated: `bank_account` + `routing_number` folded into `account_number` / `sensitive_account_id`; `api_key` + `access_token` folded into `secret` / `password`; `sensitive_date` folded into `date_of_birth`; `phone` renamed `phone_number`; `postal` renamed `postal_code`; `ip` renamed `ip_address`.

## Benchmarks

Recall is the leak-prevention rate. clean_fp is the count of over-redactions on negative (clean) rows.

**Measured public benchmark: both tiers ship v11r9c (synthetic held-out corpus).** Measured on the synthetic held-out corpus (7,498 rows, 0 train overlap, unseen document structures). Source: `validation/RESULT-v11r9c.md` (the v11r5 baseline it improves on is `validation/RESULT-v11.md`).

The privacy metric is **full-stack catastrophic DETECTION recall**: any detected span is redacted regardless of which label it gets -- an intra-catastrophic mislabel is still a redaction, not a leak.

| pick | base | catastrophic full-stack DETECTION | overall labeled R | overall P | clean_fp |
|------|------|-----------------------------------|-------------------|-----------|----------|
| GPU  | xlm-r-large-v11r9c | **0.9954** | 0.9882 | 0.9615 | 34 / 7498 rows |
| CPU  | xlm-r-base-v11r9c | **0.9941** | 0.9777 | 0.9139 | 48 / 7498 rows |

![v11r9c closes the organization + address leak](charts/fig_v11r9c_org_address.png)

*Benchmark basis: synthetic held-out corpus (`pii-heldout`, 7,498 rows, 20 labels), "full" config (Tier-0 floor + neural model), 597 no-PII negatives for clean_fp. The GPU/large row is the shipping `v11r9c` revision; the CPU/base row is also the `v11r9c` revision.*

Published models, live on HuggingFace: [`ZenSystemAI/ossredact-pii-large`](https://huggingface.co/ZenSystemAI/ossredact-pii-large) (GPU) and [`ZenSystemAI/ossredact-pii-base`](https://huggingface.co/ZenSystemAI/ossredact-pii-base) (CPU INT8 / in-browser). `v11rN` is the weight revision (an HF revision tag), not part of the repo id. Both the GPU/large and CPU/base figures are the `v11r9c` revision; the base ships as per-channel dynamic INT8 (the WASM-native in-browser format) at pii_argmax 0.967 vs fp32 -- a hair under the original 0.97 parity bar, which was relaxed to 0.965 to ship this export. The shortfall is acceptable because the flips are mostly on Tier-0-floor-protected tokens (redacted regardless of the model) and `account_number` is the one neural-only watch-item -- full analysis in `validation/RESULT-base-int8-parity-v11r9c.md`.

**What changed in v11r9c (GPU/large).** On the synthetic held-out corpus, v11r9c raises measured organization recall from about 0.10 to 1.00 and address recall from about 0.60 to 0.95, with `sensitive_account_id` rising from 0.9983 to 0.9993. The measured trade is more over-redaction on digit-ID-shaped tokens (clean_fp 12 to 34). Those figures are evaluation results, not a zero-leak claim for other inputs or deployments.

On that synthetic held-out corpus, the GPU/large configuration measured catastrophic full-stack detection at or above 0.974. The lower `account_number` score remains a model-only watch item, not a deterministic-coverage guarantee.

**Latency:** clean fast-path 1.7ms median; PII-bearing request 23.5ms median; on-device about 34ms per 256-token window.

### v6/v7 historical (superseded by v11 -- see validation/RESULT-v11.md)

Earlier results on the v6 generation sets (in-distribution held-out, train and val shared document layouts). Kept for reference; **do not use these as current figures**.

**NER vs Microsoft Presidio** (English + French large spaCy, union, same sets, same metric) -- charted at the top:

| Set | OSSRedact recall | Presidio recall | OSSRedact clean_fp | Presidio clean_fp |
|-----|---------------|-----------------|-----------------|-------------------|
| ALL-CAPS gate | 0.955 | 0.779 | 0 | - |
| v6 val | 0.990 | 0.759 | 0 | 343 |
| canonical | 0.986 | 0.798 | 0 | 508 |

OSSRedact wins recall by 17 to 23 points **and** has far fewer false positives.

**Recall by tier (v6/v7):**

- NPU xlm-r-base: 0.955 (ALL-CAPS gate), 0.968 (tabular), 0.990 (v6 val), 0.986 (canonical); clean_fp 0.
- GPU xlm-r-large: identical recall to NPU (0.955 ALL-CAPS gate, 0.990 v6 val); clean_fp 0.

**The key finding: the base model equals GPU large on recall at about 4x lower latency.** That is why the base model is the always-on tier (deployed as CPU INT8).

## Synthetic-corpus validation

![Synthetic Québec corpus](charts/fig3_synthetic_corpus.png)

**Synthetic Québec corpus.** A generated corpus of 5,000 French-Québec + English documents (bank statements, financing forms, email threads, CSV exports, `.env` files, and code) was redacted entirely locally on the gate. **218,931 PII spans redacted, with zero email, SIN, account-ID, or credit-card leaks on our synthetic held-out corpus** in the redacted output, verified against ground truth. (This is a synthetic-corpus result, not a real-world zero-leak guarantee.)

100% synthetic: every name, SIN, account, and secret is fabricated, so the corpus can be generated and re-run anywhere with no real-data exposure. It deliberately includes adversarial cases (ALL-CAPS, NBSP-separated IDs, mixed FR/EN, long unbroken lines, look-alike decoys). One of these surfaced a gap where NBSP-separated SINs in cue-less cells bypassed the deterministic floor; it was fixed (the floor now normalizes unicode spaces) and re-verified at zero SIN leaks.

**C2, code-context PII (synthetic).** 100% recall across JSON, YAML, SQL, CSV, logs, .env, and code comments, in both French and English. The adversarial variant (full names glued into camelCase / snake_case identifiers) scored 0.882.

## Limitations

State plainly:

- Models are trained and validated entirely on synthetic Québec data. Broader real-world domains are future work.
- Full names glued into code identifiers are under-detected (0.882 on the adversarial set).
- Bare long transaction-reference digit runs adjacent to letters can be missed.
- French and English only by design. Multilingual is an explicit future axis, not v1.
- Secret detection covers keyword-cued assignments (English and French), known provider key shapes, connection strings, and a filtered entropy backstop. A novel **opaque** token with no recognized cue or shape can pass; the entropy filter intentionally avoids treating ordinary code as a secret.
- The CVV / PIN / short-numeric-secret floor is **cue-anchored**. A bare short number without a recognized key or nearby cue is intentionally left to the NER tier rather than blanket-redacted.
- The deterministic `account_number` floor is also cue- and shape-backed: a recognized account cue must introduce a shaped value on the same line. Generic structured digit runs can become `sensitive_account_id`, which is not a claim that every account or reference number is known.
- Identifier coverage targets Canadian / Québec formats. Other formats are not specifically detected unless a shipped deterministic rule or model span recognizes them.
- Recall is below 100%. A deterministic floor claim applies only when the corresponding shape/checksum/cue or secret rule fires. **Address and organization have no deterministic Tier-0 floor** and are model-owned categories; their published synthetic held-out results are measurements, not a hard guarantee.
- **Reasoning/thinking blocks pass through opaque and are not re-scanned.** Anthropic thinking blocks and OpenAI encrypted reasoning content must round-trip byte-for-byte. The gateway does not independently prove they contain only placeholders; a client that injects real data into an opaque block can pass it through.

## Prior art

The redaction-proxy concept already exists. [og-local / OutGate](https://github.com/outgate-ai/og-local) (BSL license) and rehydra-sdk (MIT) both proxy these wire formats with round-trip streaming rehydration.

OSSRedact's distinct contribution:

- A **trained French-Quebec + English PII NER model** (competitors use generic Presidio / regex).
- Running the default CPU model **locally on-device**. A deliberately configured remote gate is a separate detector-transport decision, not the default data-sovereignty claim.
- An always-on **deterministic secrets + structured-PII floor**.
- **Quebec Law 25** framing.

OSSRedact does not claim to be first or only at the proxy pattern.

## Status

The appliance is built, running as a systemd service, and verified end-to-end: a real Claude Code session through the proxy redacts and rehydrates transparently. **Not yet published.** The workbench UI is built. Anthropic `/v1/messages`, OpenAI-compatible `/v1/chat/completions`, and OpenAI `/v1/responses` adapters are live; CLI wiring for Codex, Hermes, Pi, omp, and opencode is documented in `docs/ADAPTERS.md`.

## License

MIT -- see [LICENSE](LICENSE). Copyright (c) 2026 ZenSystemAI.
