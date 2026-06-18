# OSSRedact Quickstart

OSSRedact is a **local privacy gateway**: an HTTP proxy that sits in front of cloud LLM APIs. On egress it redacts PII and secrets in the request's free-text fields to stable placeholders; on the response it rehydrates those placeholders back to the real values. Your local client sees real data; the cloud model only ever sees placeholders. Claude Code and Codex are verified today, and OpenAI/Anthropic-compatible tools such as Hermes, Pi, omp, and opencode route through the same documented adapters. The detection model runs **locally on-device** (CPU INT8 always-on; NPU/OpenVINO alternate), so detection never leaves your machine.

You point your tool at it by setting `ANTHROPIC_BASE_URL=http://<host>:8011`. It works under a Claude Max subscription: billing stays on Max, no API key is needed, and the auth header is forwarded verbatim.

Two services make up the appliance:

| Service | Port | Role |
|---|---|---|
| `ossredact-ner.service` | `:8001` | Local NER detection engine (the model) |
| `ossredact-gate.service` | `:8011` | Egress proxy you point your client at |

> Note: the egress proxy on `:8011` is the endpoint clients talk to. The NER gate on `:8001` is an internal dependency the proxy calls; you do not point clients at it directly.

---

## 1. Prerequisites

**Hardware**
- An on-device box for the NER engine. The deployed always-on tier runs `xlm-roberta-base` as a dynamic-INT8 ONNX model on CPU via onnxruntime, the always-on workhorse. The Intel NPU / OpenVINO FP16 IR tier (Meteor Lake AI Boost) is preserved as a drop-in alternate.
- CPU portable tier: `distilbert-multilingual`, 135 MB static-INT8, the most portable tier.
- GPU tier: `xlm-roberta-large`.

The `xlm-roberta-base` tier matches the GPU `xlm-roberta-large` tier on recall at about 4x lower latency, which is why the base model is the always-on tier (deployed as CPU INT8).

**Python environment**

```bash
python3 -m venv ~/ossredact/.venv
source ~/ossredact/.venv/bin/activate
pip install openvino transformers fastapi httpx cryptography pyyaml
```

---

## 2. The two systemd services

The detection engine and the egress proxy run as separate systemd services. Start the NER engine first (the proxy depends on it).

```bash
# Start
sudo systemctl start ossredact-ner.service     # NER detection engine on :8001
sudo systemctl start ossredact-gate.service     # egress proxy on :8011

# Enable on boot
sudo systemctl enable ossredact-ner.service
sudo systemctl enable ossredact-gate.service

# Check status
systemctl status ossredact-ner.service ossredact-gate.service

# Follow logs
journalctl -u ossredact-gate.service -f
```

---

## 3. Point Claude Code at it

Set the base URL to the egress proxy on `:8011`. Use the appliance's tailnet hostname so other machines on your tailnet can reach it.

```bash
export ANTHROPIC_BASE_URL=http://<tailnet-host>:8011
claude
```

- Works under a **Claude Max** subscription: billing stays on Max, no API key needed.
- The auth header is forwarded **verbatim** to Anthropic, so your existing Max login is honored.
- Your local Claude Code session sees real data the whole time. Only the cloud model sees placeholders.

To make it permanent, add the export to your shell profile (`~/.bashrc` or `~/.zshrc`).

> **Adapters:** Anthropic `/v1/messages`, OpenAI `/v1/chat/completions` (routing Codex/omp/Hermes/Pi/opencode), and OpenAI `/v1/responses` (the API the current Codex CLI speaks) are supported today, same redact/rehydrate contract. Tool-specific wiring is documented in `docs/ADAPTERS.md`. (The egress-proxy code lives under `appliance/` and the GPU NER gate service it calls under `gate/`; both are version-controlled, with `deploy/check-gate-drift.sh` guarding host-vs-repo drift -- F6 closed.)

---

## 4. Policy: `gateway-config.yaml`

Policy is layered **per project and per session**: session overrides project, which overrides the default. PII categories are configurable; secrets are not.

**Always-on, regardless of policy (in the deployed appliance):**
- Secrets and credentials (`api_key`, `password`, `access_token`) **always redact**. You cannot turn these off.
- A deterministic Tier-0 layer (regex + Luhn) owns the catastrophic structured categories, and a deterministic secrets layer (gitleaks-style patterns + Shannon-entropy backstop) runs underneath the model as a reliable floor in the deployed appliance.

**Excluded by default (so the coding use case keeps working):**
- Operational labels `file_path`, `username`, `organization` are excluded by default.
- Git commit / content hashes (40-hex and 64-hex) are allowlisted and never redacted.

### Example `gateway-config.yaml`

```yaml
# default policy: applies unless a project or session overrides it
default:
  pii:
    person: redact
    address: redact
    email: redact
    phone: redact
    postal: redact
    ip: redact
    date_of_birth: redact
    government_id: redact          # Canadian SIN / NAS
    tax_id: redact
    # excluded by default to avoid breaking the coding use case:
    file_path: off
    username: off
    organization: off
  # secrets are always on and cannot be disabled here:
  #   api_key, password, access_token

# per-project override
projects:
  acme-loans:
    pii:
      organization: redact         # this client wants org names redacted too

# per-session override (highest precedence)
sessions:
  exploratory-debug:
    pii: off                       # turn all PII off for this session...
    # ...secrets STILL redact regardless
```

### Toggle a single category

Set the category to `redact` or `off` in the relevant layer (default, project, or session):

```yaml
default:
  pii:
    organization: redact     # was off by default; now redacted everywhere
```

### Turn PII off for one session while keeping secrets on

Set `pii: off` under a session. Secrets (`api_key`, `password`, `access_token`) keep redacting because they are policy-independent:

```yaml
sessions:
  my-session:
    pii: off
```

---

## 5. How a request flows (what the proxy actually does)

1. Extract redactable text fields (`system`, `messages`, `tool_result` text). It never touches `tool_use` input, tool schemas, images, or the model name.
2. Run the cheap deterministic Tier-0 gate **always** (microseconds): regex + Luhn PII plus a secrets / entropy scan.
3. **Empty path:** if there is no scannable text and no prior session entity to backstop, forward it unchanged.
4. On-device NER pass over every extracted non-trivial text field. Repeated system prompts / prior turns are cached, but short structural values are still scanned so person names have a chance to be caught.
5. Union merge (connected-component, no fragment leaks) against a session + project entity map (AES-GCM at rest). The same value maps to the same placeholder across turns, with a known-entity backstop that re-redacts any value once identified, even if the model later misses it.
6. Forward upstream with the auth header verbatim.
7. Stream-rehydrate the SSE response, reassembling placeholders that split across deltas and rehydrating `tool_use` argument JSON at the value level.

---

## 6. Verify it works

**Health check (proxy)**

```bash
curl -s http://<tailnet-host>:8011/healthz
```

**Health check (NER engine)**

```bash
curl -s http://<tailnet-host>:8001/healthz
```

**Dry-run a redaction**

Send some free text containing obvious PII and confirm the egress payload carries placeholders rather than real values (watch the proxy log, or use the dry-run endpoint if your build exposes one):

```bash
journalctl -u ossredact-gate.service -f
# in another shell, run a short Claude Code prompt that includes a fake
# email + a fake Canadian SIN, then confirm the upstream-bound text shows
# placeholders, and the response you receive locally has the real values
# rehydrated back in.
```

A successful end-to-end check: a real Claude Code session through the proxy redacts on egress and rehydrates on the response transparently, so the conversation reads normally on your side while the cloud only saw placeholders.

---

## 7. What it detects

**Repo scope vs deployed appliance.** This repository contains the detection library and CLI (`gate/privacy_gate.py`: Tier-0 regex+Luhn floor, NER tier wrappers, merge, redact/rehydrate), the training code, the validation code, and the egress proxy (`appliance/`: the `:8011` always-on gateway, SSE stream rehydration, the AES-GCM session/project entity map, the known-entity backstop, and the deterministic secrets/entropy layer). The GPU NER gate service (`gate/gate_service_gpu.py`) is now version-controlled here too; the running instance is deployed on the GPU host, with `deploy/check-gate-drift.sh` guarding host-vs-repo drift (F6 closed).

A 3-tier NER suite focused on **French-Quebec + English** (the bilingual Quebec PII focus is the differentiator), across **20 labels** (`training/labels_v20.json`): `account_number`, `address`, `card_cvv`, `card_expiry`, `date_of_birth`, `email`, `file_path`, `government_id`, `iban`, `ip_address`, `organization`, `password`, `payment_card`, `person`, `phone_number`, `postal_code`, `secret`, `sensitive_account_id`, `tax_id`, `username`.

The prior 23-label scheme was consolidated: `bank_account` + `routing_number` folded into `account_number` / `sensitive_account_id`; `api_key` + `access_token` folded into `secret` / `password`; `sensitive_date` folded into `date_of_birth`; `phone` renamed `phone_number`; `postal` renamed `postal_code`; `ip` renamed `ip_address`.

Underneath the model in the deployed appliance: a deterministic Tier-0 (regex + Luhn) owning the catastrophic structured categories, plus a deterministic secrets layer (gitleaks-style patterns + Shannon-entropy backstop with UUID / git-SHA / sequential false-positive filters).

### Measured results (v11, current)

Recall is leak-prevention; `clean_fp` is over-redaction on negative rows.

**Current model: v11** (real-structure held-out, 7,498 rows, unseen document structures). Source: `validation/RESULT-v11.md`.

The privacy metric is **full-stack catastrophic DETECTION recall**: any detected span is redacted regardless of which label it gets -- an intra-catastrophic mislabel is still a redaction, not a leak.

| pick | base | catastrophic full-stack DETECTION | overall labeled R | overall P | clean_fp |
|------|------|-----------------------------------|-------------------|-----------|----------|
| GPU  | xlm-r-large-v11r5 | **0.9964** | 0.9785 | 0.9598 | 12 / 7498 rows |
| CPU  | xlm-r-base-v11r5  | **0.9932** | 0.9664 | 0.9456 | 12 / 7498 rows |

Every catastrophic label is caught at >=0.974 full-stack detection (large); 11 of 13 at 1.000. FR is not weaker than EN (FR R=0.980, EN R=0.978).

- **Synthetic Québec corpus** (5,000 FR + EN docs, redacted entirely locally): 218,931 PII spans redacted; zero email, SIN, account-ID, or credit-card leaks in the output, verified against ground truth. 100% synthetic and re-runnable anywhere.
- **C2, code-context PII** (synthetic): 100% recall across JSON, YAML, SQL, CSV, logs, `.env`, and code comments, FR + EN. Adversarial variant (full names glued into camelCase / snake_case identifiers): 0.882.
- **Latency:** clean fast-path 1.7 ms median; PII-bearing request 23.5 ms median; on-device about 34 ms per 256-token window.

### v6/v7 historical (superseded by v11 -- see validation/RESULT-v11.md)

Earlier results on the v6 generation sets (in-distribution held-out). Kept for reference; **do not use as current figures**.

- **NPU `xlm-roberta-base`** recall: ALL-CAPS gate 0.955, tabular 0.968, v6 val 0.990, canonical 0.986; `clean_fp` 0.
- **GPU `xlm-roberta-large`** recall: identical to NPU (0.955 ALL-CAPS gate, 0.990 v6 val); `clean_fp` 0.
- **CPU `distilbert`** recall: 0.923 / 0.938 / 0.978 / 0.987; `clean_fp` 0 to 2.
- **vs Microsoft Presidio** (English + French large spaCy, union, same sets and metric): ALL-CAPS gate OSSRedact 0.955 vs 0.779; v6 val 0.990 vs 0.759 (Presidio `clean_fp` 343 vs 0); canonical 0.986 vs 0.798 (Presidio `clean_fp` 508 vs 0). OSSRedact wins recall by 17 to 23 points with far fewer false positives.

Charts are available at `./charts/fig1..fig5` (png).

---

## 8. Honest positioning and limitations

The redaction-proxy concept already exists. og-local/OutGate (BSL license) and rehydra-sdk (MIT) both proxy these wire formats with round-trip streaming rehydration. OSSRedact's distinct contribution is: a trained French-Quebec + English PII NER model (competitors use generic Presidio / regex), running the model **locally on-device** (no cloud detection call, true data sovereignty), an always-on deterministic secrets + structured-PII floor, and Quebec Law 25 framing. We do not claim "first" or "only".

**Why this design:** going fully local for data sovereignty is too expensive (256 GB+ VRAM). Instead, filter private data out, use cloud SOTA, and redact on egress while rehydrating transparently. It serves (1) the hobbyist who wants data sovereignty but cannot afford GPUs, and (2) the employee who unknowingly leaks client PII into ChatGPT / Claude (always-on DLP).

**Limitations, stated plainly:**
- Models are trained and validated entirely on synthetic Québec data. Broader real-world domains are future work.
- Full names glued into code identifiers are under-detected.
- Bare long transaction-reference digit runs adjacent to letters can be missed.
- French + English only by design. Multilingual is an explicit future axis, not v1.
- Recall is below 100%, so the deterministic layer is the reliable floor for catastrophic categories (secrets, cards, SIN).

---

## 9. Status

The Track A appliance is built, running as a systemd service, and verified end-to-end (a real Claude Code session through the proxy redacts and rehydrates transparently). It is **not yet published**. The workbench UI is built. Anthropic `/v1/messages`, OpenAI-compatible `/v1/chat/completions`, and OpenAI `/v1/responses` adapters are live; CLI wiring for Codex, Hermes, Pi, omp, and opencode is documented in `docs/ADAPTERS.md`.
