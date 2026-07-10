# OSSRedact Quickstart

OSSRedact is a **local privacy gateway**: an HTTP proxy that sits in front of cloud LLM APIs. On egress it redacts PII and secrets in the request's free-text fields to stable placeholders; on the response it rehydrates those placeholders back to the real values. Your local client sees real data; the cloud model receives placeholders in the fields the gateway scans. Opaque reasoning/thinking blocks pass through unchanged and are not re-scanned, so a client must not inject real data into them. Claude Code and Codex are both verified end-to-end on their documented paths. OpenAI/Anthropic-compatible tools such as Hermes, Pi, omp, and opencode use the same documented adapters. The default CPU gate detects on-device; intentionally configuring a remote gate creates a separate detector-transport boundary described below.

You point a local tool at `ANTHROPIC_BASE_URL=http://127.0.0.1:8011`. Loopback is the default. Binding a service to another interface through `GATEWAY_HOST` or `CPU_GATE_HOST` is an explicit remote-use opt-in with the authentication and transport requirements in [Gate, egress, and control tokens](#5-gate-egress-and-control-tokens).

Two services make up the appliance:

| Service | Port | Role |
|---|---|---|
| `ossredact-gate-cpu.service` | `127.0.0.1:8001` | Local CPU INT8 NER detection engine |
| `ossredact-egress.service` | `127.0.0.1:8011` | Egress proxy you point your client at |

> Note: the egress proxy on `:8011` is the endpoint clients talk to. The NER gate on `:8001` is an internal dependency the proxy calls; you do not point clients at it directly.

---

## 1. Desktop installation (primary, no sudo)

This is the primary route for a Linux desktop account. It installs the checkout, virtual environment, models, and two **user** services under `$HOME/.local/share/ossredact`; it never writes `/opt` or `/etc`. For a headless server or a system-service deployment, use the explicit [`deploy/README.md`](deploy/README.md#headless-system-service-installation-opt) route instead.

**User-manager prerequisite**

The desktop route requires a running `systemd --user` manager. Install and control it from a normal desktop login. If the services must survive logout, or the application runs through an SSH, kiosk, or other session without a user bus, arrange `loginctl enable-linger "$USER"` once with the host authority required by your distribution. A missing user manager is not a reason to switch these user units to `sudo systemctl`.

```bash
systemctl --user show-environment >/dev/null
```

**Checkout and validated CPU runtime**

```bash
mkdir -p "$HOME/.local/share"
git clone https://github.com/ZenSystemAI/OSSRedact.git "$HOME/.local/share/ossredact"
cd "$HOME/.local/share/ossredact"
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r deploy/requirements-gate-cpu.lock
```

`deploy/requirements-gate-cpu.lock` is the frozen, validated public CPU gate and egress runtime. `requirements.txt` is a compatibility floor for development and compatibility checks, not a substitute for the validated lock.

**Runtime artifacts**

- The default CPU gate uses `xlm-roberta-base` with per-channel dynamic, weights-only INT8 ONNX (`model.int8.onnx`) through onnxruntime's `CPUExecutionProvider`.
- The optional CUDA GPU gate uses `xlm-roberta-large` fp16 weights (`.safetensors` or `.bin`) through PyTorch. Those GPU artifacts are not CPU ONNX artifacts and do not satisfy the desktop CPU unit.
- An Intel NPU/OpenVINO FP16 IR remains a separate alternate tier.

---

## 2. Download the CPU model

From the desktop checkout, download the artifact required by the CPU user unit:

```bash
cd "$HOME/.local/share/ossredact"
mkdir -p models/ossredact-pii-base-int8
hf download ZenSystemAI/ossredact-pii-base \
  --revision v11r9c \
  --local-dir models/ossredact-pii-base-int8
test -f models/ossredact-pii-base-int8/model.int8.onnx
```

The CPU directory also needs its tokenizer and `config.json`. Do not point the CPU unit at the optional GPU model directory. If you deliberately deploy the GPU tier, download `ZenSystemAI/ossredact-pii-large` into a separate directory and use its fp16 `.safetensors` or `.bin` artifacts with the GPU service procedure, not the CPU user unit.

---

## 3. Install and control user units

The egress service writes its maps, policy files, and local runtime state only under `~/.ossredact`. Create that directory before starting so the unit's narrow `ReadWritePaths=-%h/.ossredact` permission has an existing target:

```bash
cd "$HOME/.local/share/ossredact"
mkdir -p "$HOME/.ossredact" "$HOME/.config/systemd/user"
chmod 700 "$HOME/.ossredact"
cp deploy/systemd/user/ossredact-gate-cpu.service \
  deploy/systemd/user/ossredact-egress.service \
  "$HOME/.config/systemd/user/"

systemctl --user daemon-reload
systemctl --user enable --now ossredact-gate-cpu.service
systemctl --user enable --now ossredact-egress.service
systemctl --user status ossredact-gate-cpu.service ossredact-egress.service
journalctl --user -u ossredact-egress.service -f
```

The user units retain the default sandboxing: `PrivateDevices=yes` for the CPU gate, `ProtectSystem=strict`, `ProtectHome=read-only`, no new privileges, and an egress write exception only for `~/.ossredact`.

**Namespace and hardening troubleshooting**

If the journal reports `Failed at step NAMESPACE`, a mount-namespace setup failure, or a missing user bus, first inspect the exact unit error:

```bash
journalctl --user -b -u ossredact-gate-cpu.service -u ossredact-egress.service
systemctl --user status ossredact-gate-cpu.service ossredact-egress.service
```

Do **not** create a drop-in that disables `PrivateDevices`, `ProtectSystem`, `ProtectHome`, or `ReadWritePaths`. A namespace failure means the host's user-manager sandbox support needs repair or the machine should use the headless `/opt` system-service route. That route preserves the hardening profile rather than weakening it.

---

## 4. Point a local client at it

Set the local egress URL:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8011
claude
```

- Works under a **Claude Max** subscription: billing stays on Max, with the existing auth header forwarded upstream.
- Your local client sees rehydrated values; the upstream receives replacements for fields the proxy scans.
- To make the route permanent, add the export to your shell profile.

Anthropic `/v1/messages`, OpenAI-compatible `/v1/chat/completions`, and OpenAI `/v1/responses` use the same redact/rehydrate contract. Tool-specific wiring is in `docs/ADAPTERS.md`. `GATEWAY_CONTROL_TOKEN` is not an authentication mechanism for these `/v1/*` relay routes; see the next section before exposing the proxy remotely.
## 5. Gate, egress, and control tokens

The loopback desktop installation needs none of these tokens. They have separate boundaries and must not be reused as if they protected the same surface.

| Variable | Boundary and behavior |
|---|---|
| `GATE_TOKEN` | Configures a **non-loopback gate service**. The gate refuses to start without it and requires `X-OSSRedact-Gate-Token` on `/detect` and `/redact`; `/healthz` remains public. It does not authenticate the egress relay or the console. |
| `GATEWAY_GATE_TOKEN` | The egress proxy's outbound gate credential. It sends this value as `X-OSSRedact-Gate-Token` only when it calls the protected gate's `/detect` endpoint. It must match that remote gate's `GATE_TOKEN`. |
| `GATEWAY_CONTROL_TOKEN` | Opts the egress **control plane** into authenticated off-device management. It is checked as `X-OSSRedact-Control-Token`; it does not protect `/v1/*` relay traffic. |

Keep optional values in the owner-only environment file consumed by both desktop units, never in the checkout:

```bash
install -d -m 700 "$HOME/.config/ossredact"
touch "$HOME/.config/ossredact/environment"
chmod 600 "$HOME/.config/ossredact/environment"
```

For remote control, bind `GATEWAY_HOST` only to a trusted interface, set `GATEWAY_CONTROL_TOKEN` in that file, and use authenticated encrypted transport such as a private overlay network with HTTPS. The proxy itself does not add TLS. Never expose a raw non-loopback listener to the public internet.

Remote control is limited to control-plane routes such as `/api/*` and `/gate/*`. `GET /api/claude_cli/bootstrap` is an explicit client-configuration passthrough, not a redaction or remote-control route. `/` and `/console` remain loopback-only. A remote control request, including fetch-based SSE at `/api/stream`, sends `X-OSSRedact-Control-Token` in a header only; URL query credentials are never accepted. State-changing control routes also require `X-OSSRedact-Control: 1`.

The desktop console keeps the control token only in session memory, never in a URL or persistent browser storage. A live-stream reconnect reuses the header while that console session is alive; restart or reload requires the operator to enter the token again. A browser-served remote console also needs its exact origin in `GATEWAY_CORS_ORIGINS`; that origin setting does not bypass token authentication.

If `GATEWAY_GATE_TOKEN` is missing or wrong for a reachable protected gate, the gate returns an authentication error. The egress treats that as a degraded gate and fails closed by default instead of forwarding unredacted content. `GATEWAY_GATE_FALLBACK_URL` is attempted only after a connection-level transport failure, never after a gate authentication or other reachable HTTP error.

---

## 6. Policy: `gateway-config.yaml`

The proxy reads `~/.ossredact/gateway-config.yaml` (override the path with the `GATEWAY_CONFIG` env var). An annotated example ships in the repo -- copy it to get started:

```bash
mkdir -p ~/.ossredact
cp appliance/gateway-config.example.yaml ~/.ossredact/gateway-config.yaml
```

The config is **live-reloaded** on change, so you can edit policy without restarting the proxy.

Policy is layered **per project and per session**: session overrides project, which overrides the default. PII categories are configurable; deterministic secret rules remain policy-independent once they match.

**Always-on, regardless of policy (in the deployed appliance):**
- Deterministically detected secrets and credentials are policy-independent: a span that matches a shipped secret rule continues to redact in every mode. This does not imply that an unrecognized opaque secret is detected.
- The deterministic Tier-0 floor is provenance-gated: recognized shapes, checksums, and contextual cues drive its floor spans, while deterministic secret rules add recognized provider shapes, assignments, and a filtered entropy backstop. It is a rule-triggered safety floor, not a claim that every identifier or opaque secret is recognized.

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
  # deterministic secret rules are policy-independent once they match
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
    # ...deterministic secret spans STILL redact regardless
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
- **Secrets and deterministic floor spans are NEVER allowlist-exempt.** This includes spans that earned deterministic provenance through a recognized secret rule, checksum, shape, or cue. It does not turn every model label into a hard floor: the allowlist remains for soft detected values such as names, emails, file paths, organizations, and addresses.

### Local console: edit the dictionary + watch redaction live

The egress proxy serves a small **local console** at its own address -- open `http://127.0.0.1:8011/` in a browser on the same machine. It has two tabs:

- **Do-not-redact dictionary** -- add/remove your own known-safe values in a UI instead of editing YAML. Changes are written to `GATEWAY_ALLOWLIST_FILE` and go live in the gate immediately (the hard floor stays non-exemptable, as above).
- **Live activity** -- a real-time feed of every request your tools send through the gate, and exactly what it masked: **outbound**, each real value → the placeholder the cloud model actually receives; **inbound**, each placeholder in the reply → swapped back to your real value. It holds real values in memory only. It is loopback-only by default; an explicitly configured remote control client can read the control-plane feed only with its header token over the encrypted authenticated transport described above. A "Blur values" toggle masks the real column for safe screen-sharing; `GATEWAY_LIVE_VIEW=0` disables the feed entirely.

Prefer the **full console** (the same UI the desktop app wraps: connect snippets, live activity, dictionary +
denylist, settings, and the document-redaction workbench)? The gate serves it at
`http://127.0.0.1:8011/console` -- build it once with `cd workbench && npm ci && npm run build` (or point
`GATEWAY_CONSOLE_DIR` at an existing build). Loopback-only, same-origin, zero extra configuration. The hosted
demo on the website intentionally does **not** connect to gates -- a public web page should never hold your
gate's controls -- so use this, or the desktop app, to manage a running gate.

---

## 7. How a request flows (what the proxy actually does)

1. Extract redactable text fields (`system`, `messages`, `tool_result` text/JSON, `tool_use` input, document text, and tool schema descriptions/literal values). It never rewrites tool/function names, schema property names, images, binary file bytes, or the model name.
2. Run the deterministic Tier-0 rules **always** (microseconds): shape/checksum/cue-backed PII rules plus the secrets scanner and filtered entropy backstop.
3. **Empty path:** if there is no scannable text and no prior session entity to backstop, forward it unchanged.
4. On-device NER pass over every extracted non-trivial text field. Repeated system prompts / prior turns are cached, but short structural values are still scanned so person names have a chance to be caught.
5. Union merge (connected-component, no fragment leaks) against a session + project entity map (AES-GCM at rest). The same value maps to the same placeholder across turns, with a known-entity backstop that re-redacts any value once identified, even if the model later misses it.
6. Forward upstream with the auth header verbatim.
7. Stream-rehydrate the SSE response, reassembling placeholders that split across deltas and rehydrating `tool_use` argument JSON at the value level.

---

## 8. Verify it works

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
  -d '{"text":"Email demo.user@example.test and note SIN 046 454 286.","mode":"substitute"}'
```

The `/redact` response should contain placeholders such as `<EMAIL_001>` and `<GOVERNMENT_ID_001>` plus a local mapping.

**Dry-run a redaction through the egress proxy**

Send some free text containing obvious PII and confirm the egress payload carries placeholders rather than real values (watch the proxy log, or use the dry-run endpoint if your build exposes one):

```bash
journalctl --user -u ossredact-egress.service -f
# in another shell, run a short Claude Code prompt that includes a fake
# email + a fake Canadian SIN, then confirm the upstream-bound text shows
# placeholders, and the response you receive locally has the real values
# rehydrated back in.
```

A successful end-to-end check: a real Claude Code session through the proxy redacts on egress and rehydrates on the response transparently, so the conversation reads normally on your side while the cloud only saw placeholders.

---

## 9. What it detects

**Repo scope vs deployed appliance.** This repository contains the detection library and CLI, training and validation code, and the egress proxy (`appliance/`: the `:8011` gateway, SSE rehydration, AES-GCM session/project entity maps, known-entity backstop, and deterministic secrets layer). CPU and optional GPU gate services are version-controlled with their corresponding deployment artifacts.

A 3-tier NER suite focused on **French-Quebec + English** (the bilingual Quebec PII focus is the differentiator), across **20 labels** (`training/labels_v20.json`): `account_number`, `address`, `card_cvv`, `card_expiry`, `date_of_birth`, `email`, `file_path`, `government_id`, `iban`, `ip_address`, `organization`, `password`, `payment_card`, `person`, `phone_number`, `postal_code`, `secret`, `sensitive_account_id`, `tax_id`, `username`.

The prior 23-label scheme was consolidated: `bank_account` + `routing_number` folded into `account_number` / `sensitive_account_id`; `api_key` + `access_token` folded into `secret` / `password`; `sensitive_date` folded into `date_of_birth`; `phone` renamed `phone_number`; `postal` renamed `postal_code`; `ip` renamed `ip_address`.

Underneath the model in the deployed appliance is a deterministic Tier-0 composed of format checks, checksum validation, and context-cue rules, plus a deterministic secrets layer with recognized patterns and a filtered entropy backstop. Its guarantee is tied to those rules firing, not to a model label alone.

### Measured results (v11, current)

Recall is leak-prevention; `clean_fp` is over-redaction on negative rows.

**Measured benchmark** on our synthetic held-out corpus (7,498 rows, 20 labels, "full" config = Tier-0 floor + neural model). Source: `validation/RESULT-v11r9c.md` (the v11r5 baseline it improves on is `validation/RESULT-v11.md`). Both tiers ship the **v11r9c** revision -- the CPU/base was retrained on the same cumulative corpus, so it now carries the organization/address fix too.

The privacy metric is **full-stack catastrophic DETECTION recall**: any detected span is redacted regardless of which label it gets -- an intra-catastrophic mislabel is still a redaction, not a leak.

| pick | base | catastrophic full-stack DETECTION | overall labeled R | overall P | clean_fp |
|------|------|-----------------------------------|-------------------|-----------|----------|
| GPU  | xlm-r-large-v11r9c | **0.9954** | 0.9882 | 0.9615 | 34 / 7498 rows |
| CPU  | xlm-r-base-v11r9c  | **0.9941** | 0.9777 | 0.9139 | 48 / 7498 rows |

For the GPU/large tier on that **synthetic held-out corpus**, all-label F1 is 0.9742 and catastrophic full-stack detection measured at or above 0.974. Those results are corpus measurements, not a zero-leak guarantee for arbitrary traffic.

**Why v11r9c ships:** on the synthetic held-out corpus it raises measured organization recall from about 0.10 to 1.00 and address recall from about 0.60 to 0.95, with a clean-false-positive trade from 12 to 34. The CPU/base revision carries the same augmentation, but model results remain model-dependent and do not replace the deterministic floor.

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

## 10. Honest positioning and limitations

The redaction-proxy concept already exists. OSSRedact's distinct contribution is a trained French-Quebec + English PII NER model, a default on-device CPU gate, an always-on deterministic secrets and structured-PII floor, and Quebec Law 25 framing. A deliberately configured remote gate changes the detector-transport boundary and must be treated as remote infrastructure. OSSRedact does not claim to be first or only at the proxy pattern.

**Why this design:** going fully local for data sovereignty is too expensive (256 GB+ VRAM). Instead, filter private data out, use cloud SOTA, and redact on egress while rehydrating transparently. It serves (1) the hobbyist who wants data sovereignty but cannot afford GPUs, and (2) the employee who unknowingly leaks client PII through configured CLI/API-endpoint clients today. Browser and desktop-app interception are roadmap items.

**Limitations, stated plainly:**
- Models are trained and validated entirely on synthetic Québec data. Broader real-world domains are future work.
- Full names glued into code identifiers are under-detected.
- Bare long transaction-reference digit runs adjacent to letters can be missed.
- French + English only by design. Multilingual is an explicit future axis, not v1.
- Recall is below 100%. The deterministic layer is the strongest protection only when one of its concrete rules matches; it is shape-, checksum-, and cue-backed rather than an omniscient PII guarantee.
- A bare opaque secret with no recognized key, assignment cue, provider shape, or accepted entropy pattern can pass. The entropy backstop deliberately filters common code-like values to limit false positives.
- The deterministic `account_number` floor uses a recognized same-line account cue plus a shaped value. Generic structured digit runs can be labeled `sensitive_account_id`, but this is not a claim that every account or reference number is known.
- **Address and organization have no deterministic Tier-0 floor.** They are model-owned categories. Published synthetic held-out results are model-dependent measurements, not a security guarantee.
- **Reasoning/thinking blocks are opaque and not re-scanned.** Anthropic thinking blocks and OpenAI encrypted reasoning content must round-trip byte-for-byte. Model output from already-redacted input may contain placeholders, but the gateway does not independently prove that condition; real data injected by a client into an opaque block can pass through.

---

## 11. Status

The appliance is built, running as a systemd service, and verified end-to-end (a real Claude Code session through the proxy redacts and rehydrates transparently). It is **not yet published**. The workbench UI is built. Anthropic `/v1/messages`, OpenAI-compatible `/v1/chat/completions`, and OpenAI `/v1/responses` adapters are live; CLI wiring for Codex, Hermes, Pi, omp, and opencode is documented in `docs/ADAPTERS.md`.
