# Routing LLM CLIs through the OSSRedact proxy

The OSSRedact egress proxy is an always-on privacy layer that sits in front of the
cloud LLM APIs. On the way OUT it redacts PII and secrets in every user-supplied text
field of the request, swapping each detected value for a stable placeholder
(`<EMAIL_001>`, `<PERSON_002>`, ...). On the way BACK it rehydrates those placeholders to
the real values locally, so your CLI sees real data while the upstream model only ever
reasons over placeholders. Point any compatible tool at the proxy instead of the vendor
endpoint and the redaction happens transparently.

Live on the tailnet: `http://100.65.111.24:8011`.

## Routes the proxy exposes today

| Route | Wire format | Used by |
|---|---|---|
| `/v1/messages` | Anthropic Messages | Claude / Anthropic clients, opencode (anthropic adapter), Hermes (Claude), Pi / omp (`anthropic-messages`) |
| `/v1/chat/completions` | OpenAI Chat Completions | opencode (openai-compatible adapter), Hermes, Pi / omp (`openai-completions`), older Codex (`wire_api = "chat"`) |

Both routes run the SAME redact-on-egress / rehydrate-on-response contract.

> **Not yet routed: `/v1/responses` (OpenAI Responses API).** As of this writing the live
> proxy returns `404` for `POST /v1/responses` (verified against its OpenAPI route table:
> only `/v1/messages`, `/v1/chat/completions`, and `/healthz` are served). The Responses
> adapter is planned, not live. This matters for current Codex CLI -- see the Codex section
> for the exact consequence and the working fallback.

## The privacy guarantee

EVERY user-supplied text field in a request is redacted before egress. The extractor walks
the request schema and isolates each free-text / data field (system prompt, message
content, tool-result content for the Anthropic route; message content strings and text
content-parts for the OpenAI route), then redacts in place. Tool schemas, tool-call
arguments, image / audio blocks, and the `model` field are not free text and are not sent
with raw user values. A once-identified entity is also re-masked anywhere it reappears
later in the session via the known-entity backstop, so a value the model misses in a new
context still cannot leak. If the proxy is unreachable, your CLI simply cannot reach the
upstream -- it fails closed, it does not fall back to a raw direct call.

## How to verify redaction is happening

Watch the proxy's egress log. Every redacted request prints one line:

```
[egress] redaction=redacted spans=3 labels={'email': 1, 'person': 2} rules={...} wire_placeholders=['<EMAIL_001>', '<PERSON_002>', '<PERSON_003>'] stream=false degraded=false
```

The OpenAI route prints the same line tagged `[egress:openai]`. Read it like this:

- `redaction=redacted spans=N` -- N values were replaced with placeholders before egress.
  N spans redacted means N real values never left the box.
- `redaction=scanned-clean` -- fields were scanned, nothing matched, nothing to redact.
- `redaction=skip` -- no PII signal and no prior session entities; forwarded unchanged.
- `wire_placeholders=[...]` -- the exact placeholder tokens present in the OUTBOUND body
  (this is what the upstream model actually receives in place of your data).
- `degraded=true` -- the neural detection tier was unreachable and only the deterministic
  Tier-0 + secrets pass ran. Investigate before trusting the request.

If you send a request containing an email / name / card number and the log shows
`redaction=redacted spans=N` with `N >= 1` and your real value appears in
`wire_placeholders` only as a `<LABEL_NNN>` token (never the raw value), redaction is
working. The log never prints raw PII or secret values.

---

## Codex CLI

Hits: **`/v1/responses`** (current Codex), or **`/v1/chat/completions`** (older Codex via
`wire_api = "chat"`).

In `~/.codex/config.toml` add a custom provider block and select it:

```toml
[model_providers.ossredact]
name = "OSSRedact proxy"
base_url = "http://100.65.111.24:8011"
wire_api = "responses"
env_key = "OPENAI_API_KEY"

# then select it
model_provider = "ossredact"
```

**Why a custom `[model_providers.*]` block (and not an env var):** Codex's built-in `openai`
provider ignores `base_url` overrides from `config.toml`, so pointing it at the proxy
requires a custom provider block. `env_key = "OPENAI_API_KEY"` tells Codex which env var
holds the key it forwards as the upstream `Authorization` header.

> **Heads-up -- current Codex needs a route the proxy does not yet serve.** Recent Codex
> CLI accepts ONLY `wire_api = "responses"` (the `chat` wire protocol was removed and now
> errors at config-load). `responses` targets `/v1/responses`, which the live proxy returns
> `404` for today. So with current Codex + this proxy, requests fail at the route. Until the
> Responses adapter ships, your options are:
>
> 1. Use a Codex version that still supports `wire_api = "chat"`, and set
>    `wire_api = "chat"` in the block above -- that routes to the live `/v1/chat/completions`
>    and redacts correctly. (Newer Codex rejects `"chat"`, so this only works on older builds.)
> 2. Wait for the proxy's `/v1/responses` route, then keep `wire_api = "responses"` exactly
>    as shown above -- no other config change needed.

---

## opencode (opencode.ai)

Hits: **`/v1/chat/completions`** (openai-compatible adapter) or **`/v1/messages`**
(anthropic adapter), depending on which npm adapter you choose.

In `opencode.json`, add a custom provider. Pick the adapter for the wire format you want:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "ossredact": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "OSSRedact proxy",
      "options": {
        "baseURL": "http://100.65.111.24:8011/v1"
      },
      "models": {
        "your-model-id": { "name": "Your Model" }
      }
    }
  }
}
```

To route the Anthropic wire format instead, swap the adapter:

```json
"npm": "@ai-sdk/anthropic"
```

**Note on `baseURL`:** the `@ai-sdk/openai-compatible` adapter appends `/chat/completions`
to `baseURL`, so set `baseURL` to `http://100.65.111.24:8011/v1` and it resolves to the
proxy's `/v1/chat/completions` route. The `@ai-sdk/anthropic` adapter appends `/v1/messages`,
so for that adapter set `baseURL` to the proxy root `http://100.65.111.24:8011`. Either way
the final URL must land on a route the proxy serves -- confirm with the egress log.

---

## Hermes (NousResearch Agent)

Hits: **`/v1/chat/completions`** (default OpenAI wire), and **`/v1/messages`** for Claude
models.

In `~/.hermes/config.yaml` set the model's `base_url` to the proxy:

```yaml
model:
  provider: custom
  base_url: http://100.65.111.24:8011
```

Or set it via environment instead of editing the file:

```bash
export OPENAI_BASE_URL=http://100.65.111.24:8011
```

When `base_url` is set, Hermes calls it directly (no vendor-default fallback). Hermes speaks
Chat Completions for OpenAI-style models -- those land on `/v1/chat/completions` -- and
Anthropic Messages for Claude models, which land on `/v1/messages`. Pick the model
accordingly and confirm the route in the egress log (`[egress]` vs `[egress:openai]`).

---

## Pi (@mariozechner/pi)

Hits: **`/v1/chat/completions`** (`api = "openai-completions"`) or **`/v1/messages`**
(`api = "anthropic-messages"`).

In `~/.pi/agent/models.json` add a provider block pointing `baseUrl` at the proxy and pick
the wire format with `api`:

```json
{
  "providers": {
    "ossredact": {
      "baseUrl": "http://100.65.111.24:8011",
      "api": "openai-completions",
      "models": {
        "your-model-id": {}
      }
    }
  }
}
```

For the Anthropic wire format, set `api` to `anthropic-messages` instead -- requests then
land on `/v1/messages` rather than `/v1/chat/completions`.

---

## oh-my-pi (omp)

Hits: **`/v1/chat/completions`** (`api = "openai-completions"`) or **`/v1/messages`**
(`api = "anthropic-messages"`).

Same shape as Pi, in YAML. In `~/.omp/agent/models.yml` add a provider block:

```yaml
providers:
  ossredact:
    baseUrl: http://100.65.111.24:8011
    api: openai-completions
    models:
      your-model-id: {}
```

Set `api: anthropic-messages` to route the Anthropic wire format (`/v1/messages`) instead
of Chat Completions.

---

## After wiring any tool

Send one request with a known PII value (an email, a name, a card number) and check the
egress log shows `redaction=redacted spans=N` with `N >= 1` and your real value appearing
only as a `<LABEL_NNN>` placeholder in `wire_placeholders`. If the log line never appears,
the tool is not actually routing through the proxy -- re-check the base URL and that no
vendor-default endpoint is overriding it.
