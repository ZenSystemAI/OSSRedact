# appliance/ -- the always-on egress privacy proxy

This directory is the always-on **egress privacy proxy**: the layer that redacts PII and
secrets in front of every cloud LLM call made by Claude Code, Codex, omp, opencode, and any
OpenAI/Anthropic-compatible client. It is version-controlled here so the enforcement layer can
be rebuilt from the repo alone.

## File map

| File | Role | Port / service |
|---|---|---|
| `egress_proxy.py` | The egress proxy: redacts PII + secrets on the outbound request, rehydrates placeholders on the response. Serves `/v1/messages` (Anthropic), `/v1/chat/completions` (OpenAI, via `openai_adapter.py`), and `/v1/responses` (OpenAI Responses, via `responses_adapter.py`). | binds `:8011`; systemd service `ossredact-egress` |
| `openai_adapter.py` | OpenAI chat-completions schema translation (request fields, response, SSE stream) for Codex / omp / any OpenAI-compatible client. Pure stdlib (`json`, `re` only). | imported by `egress_proxy.py` |
| `responses_adapter.py` | OpenAI Responses-API schema translation (request fields, response, SSE stream) for current Codex CLI. Pure stdlib (`base64`, `binascii`, `json`, `re` only). | imported by `egress_proxy.py` |
| `entity_map.py` | AES-GCM 256-bit session entity map at rest (value <-> placeholder), TTL'd + size-capped. | imported by `egress_proxy.py` |
| `secrets_scan.py` | Always-on deterministic (regex) secrets detector; a hard import of the proxy. No model. | imported by `egress_proxy.py` |
| `privacy_gate.py` | The appliance detector the proxy imports (`tier0_spans`, `context_cued_id_spans`, `merge_spans`, `post_merge_address`, `explain`). See "Two privacy_gate.py copies" below. | imported by `egress_proxy.py` and `gate_service.py` |
| `gate_service.py` | An OpenVINO / Intel-NPU neural gate (`DEVICE='NPU'`, OpenVINO FP16 IR) -- an alternate detection tier. | binds `:8001`; exposes `/detect` + `/redact` |
| `gateway-config.example.yaml` | Policy schema (upstream URLs, TTLs, category toggles). Example only; the live `gateway-config.yaml` is gitignored. | mtime-watched live (no restart on policy edits) |

## Detection tiers

`gate_service.py` here is an OpenVINO/NPU gate (one alternate tier). The CPU ONNX-INT8 tier
(`gate/gate_service_cpu.py`, see `deploy/README.md`) and the GPU tier
(`gate/gate_service_gpu.py`) share the same `/detect` `/redact` `/healthz` contract, so the
egress proxy is agnostic to which one `GATEWAY_GATE_URL` points at.

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

## Environment knobs (`GATEWAY_*`, with defaults)

All config is env-vars-with-defaults read at process start; no secrets in any of them.

| Var | Default | Purpose |
|---|---|---|
| `GATEWAY_ANTHROPIC_UPSTREAM` | `https://api.anthropic.com` | Anthropic upstream |
| `GATEWAY_OPENAI_UPSTREAM` | `https://api.openai.com` | OpenAI upstream |
| `GATEWAY_APPLIANCE_DIR` | directory containing the running file | module import root for sibling appliance files |
| `GATEWAY_GATE_URL` | `http://127.0.0.1:8001` | the neural gate (`/detect`) |
| `GATEWAY_NPU_MODEL_DIR` | `<GATEWAY_APPLIANCE_DIR>/model` | NPU model directory |
| `GATEWAY_NPU_CACHE_DIR` | `<GATEWAY_APPLIANCE_DIR>/.ovcache` | OpenVINO compiled-model cache |
| `GATEWAY_PORT` | `8011` | proxy listen port |
| `GATEWAY_CONFIG` | `~/.ossredact/gateway-config.yaml` | live policy file (mtime-watched) |
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

## Mirrored rehydration helpers (keep in lockstep)

`openai_adapter.py` and `responses_adapter.py` mirror the small pure rehydration helpers
(`rehydrate_text` / `_rehydrate_json` / `rehydrate_json_string` / `split_safe` / `Field`) from
`egress_proxy.py`. They are duplicated on purpose so the adapters import nothing heavy and stay
unit-testable. If you change the placeholder grammar or the JSON-safe rehydration in
`egress_proxy.py`, you MUST mirror it in both adapters.
