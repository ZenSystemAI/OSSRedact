# OSSRedact Quickstart

OSSRedact is a **local privacy gateway**: an HTTP proxy that sits in front of cloud LLM APIs. On egress it redacts PII and secrets in the request's free-text fields to stable placeholders; on the response it rehydrates those placeholders back to the real values. Your local client sees real data; the cloud model only ever sees placeholders in the fields the gateway scans (reasoning/thinking blocks pass through opaque -- they are model-generated from already-redacted input, so they too carry only placeholders). Claude Code and Codex are both verified end-to-end -- Codex on the OpenAI API-key path and on the ChatGPT/Codex-plan path (the gate routes plan requests, identified by the `chatgpt-account-id` header, to the ChatGPT backend; `GATEWAY_CHATGPT_UPSTREAM` overrides it). OpenAI/Anthropic-compatible tools such as Hermes, Pi, omp, and opencode route through the same documented adapters. The detection model runs **locally on-device** (CPU INT8 always-on; NPU/OpenVINO alternate), so detection never leaves your machine.

You point your tool at it by setting `ANTHROPIC_BASE_URL=http://127.0.0.1:8011` on the same machine. Binding to a tailnet or LAN address is an explicit opt-in via `GATEWAY_HOST` after you have decided that exposure is intended.

Two services make up the appliance:

| Service | Port | Role |
|---|---|---|
| `ossredact-gate-cpu.service` | `127.0.0.1:8001` | Local CPU INT8 NER detection engine |
| `ossredact-egress.service` | `127.0.0.1:8011` | Egress proxy you point your client at |

> Note: the egress proxy on `:8011` is the endpoint clients talk to. The NER gate on `:8001` is an internal dependency the proxy calls; you do not point clients at it directly.

---

## 1. Prerequisites

**Checkout path**

The shipped systemd units expect the repo at `/opt/ossredact`:

```bash
sudo mkdir -p /opt
sudo git clone https://github.com/ZenSystemAI/OSSRedact.git /opt/ossredact
sudo chown -R "$USER":"$USER" /opt/ossredact
cd /opt/ossredact
```

**Hardware**
- An on-device box for the NER engine. The deployed always-on tier runs `xlm-roberta-base` as a dynamic-INT8 ONNX model on CPU via onnxruntime, the always-on workhorse. The Intel NPU / OpenVINO FP16 IR tier (Meteor Lake AI Boost) is preserved as a drop-in alternate.
- GPU tier: `xlm-roberta-large`.

The `xlm-roberta-base` tier matches the GPU `xlm-roberta-large` tier on recall at about 4x lower latency, which is why the base model is the always-on tier (deployed as CPU INT8).

**Python environment**

```bash
python3 -m venv /opt/ossredact/.venv
source /opt/ossredact/.venv/bin/activate
pip install -r requirements.txt   # pinned runtime deps (onnxruntime, transformers, fastapi, the hf CLI, ...)
```

---

## 2. Get the model

The public model repos are publication targets. Both tiers ship at revision **v11r9c**; the CPU base tier ships as a per-channel dynamic INT8 export (pii_argmax 0.967 vs fp32; the parity bar is 0.965 because v11r9c's org/address augmentation sharpened the boundaries -- see `validation/RESULT-base-int8-parity-v11r9c.md`). Once the repos are public, download the base into the path expected by `deploy/ossredact-gate-cpu.service`:

```bash
sudo mkdir -p /opt/ossredact/models/ossredact-pii-base-int8
sudo chown -R "$USER":"$USER" /opt/ossredact/models
hf download ZenSystemAI/ossredact-pii-base \
  --revision v11r9c \
  --local-dir /opt/ossredact/models/ossredact-pii-base-int8
```

The optional large GPU tier ships as **v11r9c** (the revision that closes the org/address structural-form leak):

```bash
hf download ZenSystemAI/ossredact-pii-large \
  --revision v11r9c \
  --local-dir /opt/ossredact/models/ossredact-pii-large
```

Both `ossredact-pii-base` and `ossredact-pii-large` are published and public under the `v11r9c` revision, so the commands above resolve and download the INT8 ONNX weights. If a gate is ever pointed at a model dir that is missing or incomplete, it fails gracefully (graceful load-failure is implemented) rather than serving stale or partial weights.

---

## 3. The two systemd services

The detection engine and the egress proxy run as separate systemd services. Start the NER engine first (the proxy depends on it).

```bash
sudo cp deploy/ossredact-gate-cpu.service deploy/ossredact-egress.service /etc/systemd/system/

# Run the services as YOUR user (they ship with a placeholder `User=ossredact`; the egress writes its
# entity map under $HOME/.ossredact, so it must run as a real account with a home directory):
sudo sed -i "s/^User=ossredact\$/User=$USER/" \
  /etc/systemd/system/ossredact-gate-cpu.service /etc/systemd/system/ossredact-egress.service

sudo systemctl daemon-reload

# Start
sudo systemctl start ossredact-gate-cpu.service  # NER detection engine on 127.0.0.1:8001
sudo systemctl start ossredact-egress.service    # egress proxy on 127.0.0.1:8011

# Enable on boot
sudo systemctl enable ossredact-gate-cpu.service
sudo systemctl enable ossredact-egress.service

# Check status
systemctl status ossredact-gate-cpu.service ossredact-egress.service

# Follow logs
journalctl -u ossredact-egress.service -f
```

---

## 4. Point Claude Code at it

Set the base URL to the egress proxy on `:8011`.

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8011
claude
```

- Works under a **Claude Max** subscription: billing stays on Max, no API key needed.
- The auth header is forwarded **verbatim** to Anthropic, so your existing Max login is honored.
- Your local Claude Code session sees real data the whole time. Only the cloud model sees placeholders.

To make it permanent, add the export to your shell profile (`~/.bashrc` or `~/.zshrc`).

To expose the proxy on a tailnet interface instead of loopback, set `GATEWAY_HOST=<tailnet-ip-or-host>` in a systemd drop-in for `ossredact-egress.service`, then restart it. Keep the NER gate on loopback unless you have a specific reason to expose `/detect`.

> **Adapters:** Anthropic `/v1/messages`, OpenAI `/v1/chat/completions` (routing Codex/omp/Hermes/Pi/opencode), and OpenAI `/v1/responses` (the API the current Codex CLI speaks) are supported today, same redact/rehydrate contract. Tool-specific wiring is documented in `docs/ADAPTERS.md`. (The egress-proxy code lives under `appliance/` and the GPU NER gate service it calls under `gate/`; both are version-controlled, with `deploy/check-gate-drift.sh` guarding host-vs-repo drift.)

---

## 5. Policy: `gateway-config.yaml`

The proxy reads `~/.ossredact/gateway-config.yaml` (override the path with the `GATEWAY_CONFIG` env var). An annotated example ships in the repo -- copy it to get started:

```bash
mkdir -p ~/.ossredact
cp appliance/gateway-config.example.yaml ~/.ossredact/gateway-config.yaml
```

The config is **live-reloaded** on change, so you can edit policy without restarting the proxy.

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

### Allowlist: your own known-safe values (do-not-redact dictionary)

Sometimes detection gets in *your* way -- your own name inside a file path, your own email, an internal project codename. The **allowlist** is an opt-in, default-empty list of values that pass through **un-redacted** even when a detector flags them. It is the inverse of redaction.

```yaml
# top level of gateway-config.yaml (sibling of `default:` / `projects:` / `sessions:`)
allowlist:
  - alex
  - alex@example.com
  - /home/alex/dev/myrepo
```

You can also point `GATEWAY_ALLOWLIST_FILE` at a newline-delimited file of values (`#`-prefixed lines are comments). The list is live-reloaded on change.

Semantics -- read these before adding anything:
- **Value-exact + case-insensitive.** A span is dropped only when its **whole** text equals an entry (after Unicode-NFC + trim + case-fold). Allowlisting `alex` passes `Alex` / `ALEX` / the `alex` token in `/home/alex`, but never un-redacts a larger string that merely *contains* it (`alex@acme-bank.example` stays redacted).
- **Allowlisted values DO reach the cloud verbatim.** Only add things you are comfortable the model seeing.
- **Secrets and the hard floor are NEVER exemptable.** Credentials (`api_key`, `password`, `access_token`) and the deterministic money/identity floor (`payment_card`, `iban`, `bank_account`, `government_id`, `tax_id`, `date_of_birth`, …) always redact, even if you list their value. The allowlist is for *soft* identifiers -- name, email, file paths, organization, address -- only.

### Local console: edit the dictionary + watch redaction live

The egress proxy serves a small **local console** at its own address -- open `http://127.0.0.1:8011/` in a browser on the same machine. It has two tabs:

- **Do-not-redact dictionary** -- add/remove your own known-safe values in a UI instead of editing YAML. Changes are written to `GATEWAY_ALLOWLIST_FILE` and go live in the gate immediately (the hard floor stays non-exemptable, as above).
- **Live activity** -- a real-time feed of every request your tools send through the gate, and exactly what it masked: **outbound**, each real value → the placeholder the cloud model actually receives; **inbound**, each placeholder in the reply → swapped back to your real value. This is the visual proof the firewall is working on *your own* sessions. It shows real values, so it is held in memory only (never written to disk) and -- like the dictionary editor -- **every console endpoint is loopback-only**, unreachable over the network even when the gate binds a LAN/tailnet address. A "Blur values" toggle masks the real column for safe screen-sharing; `GATEWAY_LIVE_VIEW=0` disables the feed entirely.

---

## 6. How a request flows (what the proxy actually does)

1. Extract redactable text fields (`system`, `messages`, `tool_result` text/JSON, `tool_use` input, document text, and tool schema descriptions/literal values). It never rewrites tool/function names, schema property names, images, binary file bytes, or the model name.
2. Run the cheap deterministic Tier-0 gate **always** (microseconds): regex + Luhn PII plus a secrets / entropy scan.
3. **Empty path:** if there is no scannable text and no prior session entity to backstop, forward it unchanged.
4. On-device NER pass over every extracted non-trivial text field. Repeated system prompts / prior turns are cached, but short structural values are still scanned so person names have a chance to be caught.
5. Union merge (connected-component, no fragment leaks) against a session + project entity map (AES-GCM at rest). The same value maps to the same placeholder across turns, with a known-entity backstop that re-redacts any value once identified, even if the model later misses it.
6. Forward upstream with the auth header verbatim.
7. Stream-rehydrate the SSE response, reassembling placeholders that split across deltas and rehydrating `tool_use` argument JSON at the value level.

---

## 7. Verify it works

**Health check (proxy)**

```bash
curl -s http://127.0.0.1:8011/healthz
```

**Health check (NER engine)**

```bash
curl -s http://127.0.0.1:8001/healthz
```

**Localhost smoke check**

```bash
curl -s http://127.0.0.1:8001/healthz
curl -s http://127.0.0.1:8011/healthz
curl -s http://127.0.0.1:8001/redact \
  -H 'content-type: application/json' \
  -d '{"text":"Email user@example.com and note SIN 046 454 286.","mode":"substitute"}'
```

The `/redact` response should contain placeholders such as `<EMAIL_001>` and `<GOVERNMENT_ID_001>` plus a local mapping.

**Dry-run a redaction through the egress proxy**

Send some free text containing obvious PII and confirm the egress payload carries placeholders rather than real values (watch the proxy log, or use the dry-run endpoint if your build exposes one):

```bash
journalctl -u ossredact-egress.service -f
# in another shell, run a short Claude Code prompt that includes a fake
# email + a fake Canadian SIN, then confirm the upstream-bound text shows
# placeholders, and the response you receive locally has the real values
# rehydrated back in.
```

A successful end-to-end check: a real Claude Code session through the proxy redacts on egress and rehydrates on the response transparently, so the conversation reads normally on your side while the cloud only saw placeholders.

---

## 8. What it detects

**Repo scope vs deployed appliance.** This repository contains the detection library and CLI (`gate/privacy_gate.py`: Tier-0 regex+Luhn floor, NER tier wrappers, merge, redact/rehydrate), the training code, the validation code, and the egress proxy (`appliance/`: the `:8011` always-on gateway, SSE stream rehydration, the AES-GCM session/project entity map, the known-entity backstop, and the deterministic secrets/entropy layer). The GPU NER gate service (`gate/gate_service_gpu.py`) is now version-controlled here too; the running instance is deployed on the GPU host, with `deploy/check-gate-drift.sh` guarding host-vs-repo drift.

A 3-tier NER suite focused on **French-Quebec + English** (the bilingual Quebec PII focus is the differentiator), across **20 labels** (`training/labels_v20.json`): `account_number`, `address`, `card_cvv`, `card_expiry`, `date_of_birth`, `email`, `file_path`, `government_id`, `iban`, `ip_address`, `organization`, `password`, `payment_card`, `person`, `phone_number`, `postal_code`, `secret`, `sensitive_account_id`, `tax_id`, `username`.

The prior 23-label scheme was consolidated: `bank_account` + `routing_number` folded into `account_number` / `sensitive_account_id`; `api_key` + `access_token` folded into `secret` / `password`; `sensitive_date` folded into `date_of_birth`; `phone` renamed `phone_number`; `postal` renamed `postal_code`; `ip` renamed `ip_address`.

Underneath the model in the deployed appliance: a deterministic Tier-0 (regex + Luhn) owning the catastrophic structured categories, plus a deterministic secrets layer (gitleaks-style patterns + Shannon-entropy backstop with UUID / git-SHA / sequential false-positive filters).

### Measured results (v11, current)

Recall is leak-prevention; `clean_fp` is over-redaction on negative rows.

**Measured benchmark** on our synthetic held-out corpus (7,498 rows, 20 labels, "full" config = Tier-0 floor + neural model). Source: `validation/RESULT-v11r9c.md` (the v11r5 baseline it improves on is `validation/RESULT-v11.md`). Both tiers ship the **v11r9c** revision -- the CPU/base was retrained on the same cumulative corpus, so it now carries the organization/address fix too.

The privacy metric is **full-stack catastrophic DETECTION recall**: any detected span is redacted regardless of which label it gets -- an intra-catastrophic mislabel is still a redaction, not a leak.

| pick | base | catastrophic full-stack DETECTION | overall labeled R | overall P | clean_fp |
|------|------|-----------------------------------|-------------------|-----------|----------|
| GPU  | xlm-r-large-v11r9c | **0.9954** | 0.9882 | 0.9615 | 34 / 7498 rows |
| CPU  | xlm-r-base-v11r9c  | **0.9941** | 0.9777 | 0.9139 | 48 / 7498 rows |

For the GPU/large tier (v11r9c), all-label F1 is 0.9742. Every catastrophic label is caught at >=0.974 full-stack detection under v11r9c (10 of 13 at 1.000; person 0.9946, sensitive_account_id 0.9993, account_number 0.974). FR is not weaker than EN.

**Why v11r9c ships:** it closes a real structural-form leak in the prior model -- organization recall ~0.10 → 1.00, address recall ~0.60 → 0.95 -- at the cost of slightly more over-redaction on digit-ID-shaped tokens (clean false positives 12 → 34). That is the safe failure direction: over-redaction never leaks PII; it only costs a coding agent a little context when a benign number is ID-shaped. For a privacy firewall whose prime directive is "never leak," closing the org/address leak is worth the extra over-redaction -- a deliberate, principled trade. The CPU/base tier ships the same **v11r9c** revision, so it carries the org/address fix too (base `address` recall ~0.93; its own clean-FP trade is 12 → 48).

- **Synthetic Québec corpus** (5,000 FR + EN docs, redacted entirely locally): 218,931 PII spans redacted; on our synthetic held-out corpus, zero email, SIN, account-ID, or credit-card leaks in the output, verified against ground truth. 100% synthetic and re-runnable anywhere.
- **C2, code-context PII** (synthetic): on our synthetic held-out corpus, full recall across JSON, YAML, SQL, CSV, logs, `.env`, and code comments, FR + EN. The adversarial variant (full names glued into camelCase / snake_case identifiers) is a separate, harder case: 0.882.
- **Latency:** clean fast-path 1.7 ms median; PII-bearing request 23.5 ms median; on-device about 34 ms per 256-token window.

### v6/v7 historical (superseded by v11 -- see validation/RESULT-v11.md)

Earlier results on the v6 generation sets (in-distribution held-out). Kept for reference; **do not use as current figures**.

- **NPU `xlm-roberta-base`** recall: ALL-CAPS gate 0.955, tabular 0.968, v6 val 0.990, canonical 0.986; `clean_fp` 0.
- **GPU `xlm-roberta-large`** recall: identical to NPU (0.955 ALL-CAPS gate, 0.990 v6 val); `clean_fp` 0.
- **vs Microsoft Presidio** (English + French large spaCy, union, same sets and metric): ALL-CAPS gate OSSRedact 0.955 vs 0.779; v6 val 0.990 vs 0.759 (Presidio `clean_fp` 343 vs 0); canonical 0.986 vs 0.798 (Presidio `clean_fp` 508 vs 0). OSSRedact wins recall by 17 to 23 points with far fewer false positives.

Charts are available at `./charts/fig1, fig3, fig5` (png).

---

## 9. Honest positioning and limitations

The redaction-proxy concept already exists. og-local/OutGate (BSL license) and rehydra-sdk (MIT) both proxy these wire formats with round-trip streaming rehydration. OSSRedact's distinct contribution is: a trained French-Quebec + English PII NER model (competitors use generic Presidio / regex), running the model **locally on-device** (no cloud detection call, true data sovereignty), an always-on deterministic secrets + structured-PII floor, and Quebec Law 25 framing. We do not claim "first" or "only".

**Why this design:** going fully local for data sovereignty is too expensive (256 GB+ VRAM). Instead, filter private data out, use cloud SOTA, and redact on egress while rehydrating transparently. It serves (1) the hobbyist who wants data sovereignty but cannot afford GPUs, and (2) the employee who unknowingly leaks client PII through configured CLI/API-endpoint clients today. Browser and desktop-app interception are roadmap items.

**Limitations, stated plainly:**
- Models are trained and validated entirely on synthetic Québec data. Broader real-world domains are future work.
- Full names glued into code identifiers are under-detected.
- Bare long transaction-reference digit runs adjacent to letters can be missed.
- French + English only by design. Multilingual is an explicit future axis, not v1.
- Recall is below 100%, so the deterministic layer is the reliable floor for catastrophic categories (secrets, cards, SIN).
- The deterministic Tier-0 floor (regex + Luhn) covers secrets/API keys, payment cards (Luhn), IBAN, SIN / government IDs, emails, IP addresses, and file paths -- these are a hard, model-independent guarantee. **Address and organization have no Tier-0 floor**: they rely entirely on the NER model. v11r9c (GPU/large) now covers them well on our synthetic held-out corpus (organization 1.0, address 0.95), but that is model-dependent, not a hard guarantee like the Tier-0 categories.

---

## 10. Status

The appliance is built, running as a systemd service, and verified end-to-end (a real Claude Code session through the proxy redacts and rehydrates transparently). It is **not yet published**. The workbench UI is built. Anthropic `/v1/messages`, OpenAI-compatible `/v1/chat/completions`, and OpenAI `/v1/responses` adapters are live; CLI wiring for Codex, Hermes, Pi, omp, and opencode is documented in `docs/ADAPTERS.md`.
