# Appliance: the always-on Beelink egress privacy proxy

This directory is the version-controlled snapshot of the **always-on egress privacy
proxy** that runs on the Beelink host (`~/sparx-npu/`). It is the layer that redacts
PII and secrets in front of every cloud LLM call made by Claude Code, Codex, omp, and
opencode. Before this commit (F6) the appliance lived ONLY on one disk; this snapshot
makes it reconstructable from git.

The files here are **rsynced verbatim from the live host** (byte-identical, md5-verified)
so the running enforcement layer can be rebuilt from the repo alone. The live service on
Beelink is untouched by this snapshot -- it is read/copy only.

## File map: host + port + service

| File | Role | Host | Port / service |
|---|---|---|---|
| `egress_proxy.py` | The egress proxy: redacts PII + secrets on the outbound request, rehydrates placeholders on the response. Serves `/v1/messages` (Anthropic) + `/v1/chat/completions` (OpenAI, via `openai_adapter.py`). | Beelink `~/sparx-npu/` | binds `:8011`; systemd service `qc-pii-egress` (the always-on layer) |
| `openai_adapter.py` | OpenAI chat-completions schema translation (request fields, response, SSE stream) for Codex / omp / any OpenAI-compatible client. Pure stdlib (`json`, `re` only). | Beelink `~/sparx-npu/` | imported by `egress_proxy.py` (no own port) |
| `entity_map.py` | AES-GCM 256-bit session entity map at rest (value <-> placeholder), TTL'd + size-capped. | Beelink `~/sparx-npu/` | imported by `egress_proxy.py` (no own port) |
| `secrets_scan.py` | Always-on deterministic (regex) secrets detector; a HARD import of the proxy (`egress_proxy.py:27`). No model. | Beelink `~/sparx-npu/` | imported by `egress_proxy.py` (no own port) |
| `privacy_gate.py` | The DEPLOYED detector snapshot the proxy imports (`tier0_spans`, `context_cued_id_spans`, `merge_spans`, `post_merge_address`, `explain`). See "Two privacy_gate.py copies" below. | Beelink `~/sparx-npu/` | imported by `egress_proxy.py:25` and `gate_service.py:17` (no own port) |
| `gate_service.py` | The OpenVINO / Intel-NPU neural gate (`DEVICE='NPU'`, OpenVINO FP16 IR). This is the **rollback path**, NOT the current live tier. | Beelink `~/sparx-npu/` | binds `:8001`; exposes `/detect` + `/redact` |
| `gateway-config.example.yaml` | Policy schema (public upstream URLs, TTLs, category toggles). Example only; the live `gateway-config.yaml` is gitignored. | -- | mtime-watched live on the host (no restart needed on policy edits) |

### Current live tier vs rollback

`gate_service.py` here is the OpenVINO/NPU gate and is the **rollback** path. The
current LIVE detection tier is `deploy/gate_service_cpu.py` (ONNX-INT8) -- see
`deploy/README.md:44-58`. That CPU tier is already version-controlled under `deploy/`
and is intentionally NOT duplicated here.

## Two privacy_gate.py copies (BY DESIGN -- follow-up F14)

The repo deliberately holds TWO `privacy_gate.py` copies:

- `gate/privacy_gate.py` (repo library, NEWER): the thinned `validated_floor` +
  `_iban_ok` (IBAN mod-97) detector from plans 004 and 014, v11 / 20-label era. It does
  NOT define `tier0_spans` or `context_cued_id_spans`.
- `appliance/privacy_gate.py` (this dir, OLDER): the DEPLOYED snapshot the live proxy
  actually imports. It defines `tier0_spans` (`:109`) + `context_cued_id_spans` (`:91`)
  but does NOT have `validated_floor` / `_iban_ok`.

`egress_proxy.py:25` imports `tier0_spans`, so the live proxy depends on the OLDER
snapshot. The proxy reaches it via `sys.path.insert(0, '/home/steven/sparx-npu')`
(`egress_proxy.py:24`) -- in a repo checkout, put `appliance/` on `PYTHONPATH`.

**Do NOT** overwrite `gate/privacy_gate.py` with this older copy -- that would revert
plans 004 (un-thin the floor) and 014 (drop IBAN mod-97). **Do NOT** delete this
snapshot or sync one onto the other. Reconciling the live proxy onto the newer detector
is a separate, behavior-changing, separately-gated follow-up (finding F14, the same
single-source goal as D1 / plan 016).

## Auth model: forwarded verbatim, never stored

The proxy never stores client credentials. It forwards the client's `authorization` and
`x-api-key` headers verbatim to the upstream (`egress_proxy.py:562-565`, comment
"Never store auth"). There is therefore NO credential file in this repo and none on the
host (`~/sparx-npu/.env` does not exist). Upstreams are env-overridable with public
defaults (`api.anthropic.com` / `api.openai.com`).

## Environment knobs (`GATEWAY_*`, with defaults)

All config is env-vars-with-defaults read at process start; no secrets in any of them.

| Var | Default | Purpose |
|---|---|---|
| `GATEWAY_ANTHROPIC_UPSTREAM` | `https://api.anthropic.com` | Anthropic upstream |
| `GATEWAY_OPENAI_UPSTREAM` | `https://api.openai.com` | OpenAI upstream |
| `GATEWAY_GATE_URL` | `http://127.0.0.1:8001` | the neural gate (`/detect`) |
| `GATEWAY_PORT` | `8011` | proxy listen port |
| `GATEWAY_CONFIG` | `~/sparx-npu/gateway-config.yaml` | live policy file (mtime-watched) |
| `GATEWAY_MAPS_DIR` | `~/sparx-npu/maps` | session entity maps dir (gitignored) |
| `GATEWAY_MAP_KEY` | `<MAPS_DIR>/.mapkey` | AES key file (`0600`, gitignored; auto-generated if absent) |
| `GATEWAY_MAP_TTL_H` | `24` | entity-map TTL (hours) |
| `GATEWAY_MAP_MAX` | `5000` | max entities per map |
| `GATEWAY_DRYRUN` | `0` | don't forward upstream; echo would-be-upstream body |
| `GATEWAY_EXPLAIN` | `0` | opt-in per-span provenance (no values) in `meta['explain']` |

## Mirrored rehydration helpers (keep in lockstep)

`openai_adapter.py` (docstring lines 13-16) warns that its small pure rehydration helpers
(`rehydrate_text` / `_rehydrate_json` / `rehydrate_json_string` / `split_safe` / `Field`)
MIRROR the identical ones in `egress_proxy.py`. They are duplicated on purpose so the
adapter imports nothing heavy and stays unit-testable. If you change the placeholder
grammar or the JSON-safe rehydration in `egress_proxy.py`, you MUST mirror it here.

## Keeping the snapshot in lockstep with the host

The proxy is currently edited live on Beelink -- that is how the deployed
`privacy_gate.py` diverged into a different generation from `gate/privacy_gate.py`. Add a
periodic md5 drift-check (`ssh beelink md5sum ~/sparx-npu/*.py` vs `appliance/`) to catch
silent host edits. The committed `gateway-config.example.yaml` must track schema changes
to the live (gitignored) `gateway-config.yaml`.

## What this unblocks

- **D3** -- the OpenAI adapter is now maintainable in-repo.
- The **Step-C repo split** (model <-> workbench <-> appliance separation).
- Disaster recovery: the running enforcement layer is reconstructable from git.
