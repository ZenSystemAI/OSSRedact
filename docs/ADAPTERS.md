# Routing LLM CLIs through the OSSRedact proxy

The OSSRedact egress proxy is an always-on privacy layer that sits in front of the
cloud LLM APIs. On the way OUT it redacts PII and secrets in every user-supplied text
field of the request, swapping each detected value for a stable placeholder
(`<EMAIL_001>`, `<PERSON_002>`, ...). On the way BACK it rehydrates those placeholders to
the real values locally, so your CLI sees real data while the upstream model reasons over
placeholders, not your real values. (Extended-thinking / reasoning blocks -- Anthropic `thinking`
and OpenAI reasoning `encrypted_content` -- are cryptographically bound and must round-trip
byte-for-byte, so they are passed through opaque and not re-scanned; the model generated them
from already-redacted input, so they too carry only placeholders.) Point any compatible tool at
the proxy instead of the vendor endpoint and the redaction happens transparently.

Default local endpoint: `http://127.0.0.1:8011`. If you intentionally bind the egress proxy to a
tailnet or another trusted interface with `GATEWAY_HOST`, replace `127.0.0.1` with that host.

## Routes the proxy exposes today

| Route | Wire format | Used by |
|---|---|---|
| `/v1/messages` | Anthropic Messages | Claude / Anthropic clients, opencode (anthropic adapter), Hermes (Claude), Pi / omp (`anthropic-messages`) |
| `/v1/chat/completions` | OpenAI Chat Completions | opencode (openai-compatible adapter), Hermes, Pi / omp (`openai-completions`), older Codex (`wire_api = "chat"`) |
| `/v1/responses` | OpenAI Responses API | current Codex CLI (`wire_api = "responses"`) |

All three routes run the SAME redact-on-egress / rehydrate-on-response contract.

## What gets redacted

EVERY user-supplied text field in a request is *scanned* before egress, and detected PII and
secrets are masked in place. The extractor walks the request schema and isolates free-text /
user-data fields (system prompt, message content, tool-result text/JSON, Anthropic
`tool_use.input`, Anthropic document text sources, OpenAI Responses `input`, `instructions`,
`prompt.variables`, agentic item text, JSON argument values including native numeric leaves
under sensitive keys, and tool schema descriptions/literal values). Routing IDs, tool/function
names, schema property names, images / audio, binary file bytes, and the `model` field are not
free text and are left structural.

Two tiers do the detecting, and they are not equally strong -- be honest about which is which:

- **The deterministic hard floor** (secrets/API keys, payment cards + CVV/expiry via Luhn+cues,
  IBANs via mod-97, bank/account IDs via context cues, government/tax IDs, date of birth) is the
  model-independent guarantee: detected by tier-0 rules, redacted on every request **in every mode
  including `Off`**, never allowlist-exempt, and its placeholders are withheld from executed
  tool-call arguments. This is the layer you can rely on.
- **Deterministic but SOFT detections** (emails, IPs, UUIDs) are caught by the same tier-0 rules
  but carry soft labels: `privacy` mode redacts them, `coding` mode passes IPs and UUIDs (they are
  load-bearing in code traffic), and `Off` passes all of them. Bare dates/versions
  (`sensitive_date`) are never redacted at the egress in any mode (2026-07-02 wire-level policy;
  the Workbench keeps its own toggleable date filter). Do not mistake these for the floor.
- **The neural tier** raises coverage for free-text PII (names, addresses, organizations) that
  has no deterministic signature. It is high-recall but model-dependent -- detection is not
  perfect, so treat free-text PII as best-effort *on top of* the floor, not a hard guarantee.
  Since 2026-07-02 a model-only detection can no longer mint a floor-privileged label:
  model-detected account-shaped values surface as soft `<SENSITIVEREF_n>` placeholders
  (allowlistable, mode-exemptible, rehydrated into tool arguments).

A once-identified entity is also re-masked anywhere it reappears later in the session via the
known-entity backstop, so a value the model misses in a new context still cannot leak. If the
proxy is unreachable, your CLI simply cannot reach the upstream -- it fails closed, it does not
fall back to a raw direct call.

## How to verify redaction is happening

Watch the proxy's egress log. Every redacted request prints one line:

```
[egress] redaction=redacted spans=3 labels={'email': 1, 'person': 2} rules={...} wire_placeholders=['<EMAIL_001>', '<PERSON_002>', '<PERSON_003>'] stream=false degraded=false
```

The OpenAI routes print the same line tagged `[egress:openai]` or `[egress:responses]`.
Read it like this:

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

### ChatGPT / Codex plan path

This is the intended no-per-use path, but it still needs a logged-in synthetic end-to-end verification run.
Keep Codex signed in with ChatGPT, or with a Codex access token, and put this in
**user-level** `~/.codex/config.toml`:

```toml
model_provider = "ossredact_chatgpt_plan"

[model_providers.ossredact_chatgpt_plan]
name = "OSSRedact ChatGPT-plan bridge"
base_url = "http://127.0.0.1:8011/v1"
wire_api = "responses"
requires_openai_auth = true
```

Do not put this in project `.codex/config.toml`; Codex ignores provider and credential
redirect settings there. Do not set `env_key`, `OPENAI_API_KEY`, or `CODEX_API_KEY` for
this profile. Codex supplies its normal OpenAI auth, OSSRedact forwards `Authorization`
unchanged, and the request lands on `/v1/responses`.

If a logged-in synthetic Codex run does not route through this provider, the next path is a
fixture-backed Codex app-server bridge. Do not guess private ChatGPT backend envelopes.

### Platform API-key path

This path is already supported, but it uses standard OpenAI API billing instead of included
ChatGPT/Codex plan usage:

```toml
# User-level ~/.codex/config.toml only.
openai_base_url = "http://127.0.0.1:8011/v1"
```

Current Codex should keep `wire_api = "responses"` so it lands on `/v1/responses`. Older
Codex builds that still support `wire_api = "chat"` can use `/v1/chat/completions`, but
newer Codex rejects `"chat"` at config load.

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
        "baseURL": "http://127.0.0.1:8011/v1"
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
to `baseURL`, so set `baseURL` to `http://127.0.0.1:8011/v1` and it resolves to the
proxy's `/v1/chat/completions` route. The `@ai-sdk/anthropic` adapter appends `/v1/messages`,
so for that adapter set `baseURL` to the proxy root `http://127.0.0.1:8011`. Either way
the final URL must land on a route the proxy serves -- confirm with the egress log.

---

## Hermes (NousResearch Agent)

Hits: **`/v1/chat/completions`** for OpenAI-compatible custom providers,
**`/v1/responses`** when `api_mode: codex_responses` is selected, and **`/v1/messages`**
when `api_mode: anthropic_messages` is selected.

For a direct custom endpoint in `~/.hermes/config.yaml`:

```yaml
# ~/.hermes/config.yaml
model:
  provider: custom
  model: your-model-id
  base_url: http://127.0.0.1:8011/v1
  api_mode: chat_completions
  api_key: OSSREDACT_UPSTREAM_API_KEY
```

Hermes v0.16.0 also has a local OAuth-backed OpenAI-compatible proxy:

```bash
hermes proxy start --provider nous --host 127.0.0.1 --port 8645
```

To keep that OAuth provider as the paid/subscription upstream while still redacting first,
run OSSRedact in front of it:

```bash
export GATEWAY_OPENAI_UPSTREAM=http://127.0.0.1:8645
export GATEWAY_PORT=8011
```

Then point OpenAI-compatible clients at OSSRedact (`http://127.0.0.1:8011/v1`), not
directly at Hermes. The chain is: client -> OSSRedact -> Hermes proxy -> provider.

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
      "baseUrl": "http://127.0.0.1:8011/v1",
      "api": "openai-completions",
      "apiKey": "OSSREDACT_UPSTREAM_API_KEY",
      "models": [
        {
          "id": "your-model-id",
          "name": "Your Model"
        }
      ]
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
    baseUrl: http://127.0.0.1:8011/v1
    api: openai-completions
    apiKey: OSSREDACT_UPSTREAM_API_KEY
    models:
      - id: your-model-id
        name: Your Model
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
