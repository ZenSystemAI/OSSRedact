# OSSRedact Architecture

A technical deep-dive of the OSSRedact local privacy gateway, written for a reader who wants to
understand or audit the design.

## What OSSRedact is

OSSRedact is a **local privacy gateway**: an HTTP proxy that sits in front of cloud LLM APIs. On
egress it redacts PII and secrets in the request's free-text fields to stable placeholders; on
the response it rehydrates those placeholders back to the real values. The local client sees
real data; the cloud model only ever sees placeholders.

The wire formats supported today are Anthropic `/v1/messages`, OpenAI-compatible
`/v1/chat/completions` (routing Codex, Hermes, Pi, omp, opencode, and other OpenAI-compatible clients via openai_adapter.py),
and OpenAI `/v1/responses` (the API the current Codex CLI speaks, via responses_adapter.py) -- all through the same
redact/rehydrate contract. The egress-proxy code now lives in this repo under `appliance/`; the GPU NER
gate service it calls is version-controlled under `gate/` and deployed on the GPU host (drift-guarded by `deploy/check-gate-drift.sh`). Tool-specific wiring is documented in `docs/ADAPTERS.md`. Point any tool at the gateway with:

```
ANTHROPIC_BASE_URL=http://127.0.0.1:8011
```

It works under a Claude Max subscription: billing stays on Max, no API key is needed, and the
auth header is forwarded verbatim.

The detection model runs **locally on-device** (deployed always-on tier: xlm-roberta-base as
dynamic-INT8 ONNX on CPU via onnxruntime; the Intel NPU / OpenVINO FP16 tier is preserved as a
drop-in alternate). There is no cloud detection call, which is what makes this true data sovereignty
rather than another cloud DLP hop.

### Why the proxy approach

Going fully local for data sovereignty is too expensive (256GB+ VRAM to run a SOTA model at
home). OSSRedact takes the other route: filter private data out, use cloud SOTA, redact on egress
and rehydrate transparently. Two users motivate the design:

1. The hobbyist who wants data sovereignty but cannot afford GPUs.
2. The employee who unknowingly leaks client PII through configured CLI/API-endpoint clients today. Browser and desktop-app interception are roadmap items.

### Honest positioning

The redaction-proxy concept already exists. og-local/OutGate (BSL license) and rehydra-sdk (MIT)
both proxy these wire formats with round-trip streaming rehydration. OSSRedact does **not** claim to
be first or only. Its distinct contribution is:

- A trained French-Quebec + English PII NER model (competitors use generic Presidio/regex).
- Running that model locally on-device (CPU INT8 always-on; NPU/OpenVINO available as an alternate tier): no cloud detection call, true data sovereignty.
- An always-on deterministic secrets + structured-PII floor.
- Quebec Law 25 framing.

---

## Process and topology

```
                          host (loopback by default, on-device)
   local tool                +-------------------------------------------------+
   (Claude Code, Codex,      |                                                 |
    Hermes, Pi, opencode)    |   :8011  egress proxy                           |
       |                     |          - extract / gate / merge / rehydrate   |
       |  ANTHROPIC_BASE_URL |          - holds session+project entity map     |
       |  = http://127.0.0.1:8011             |                                |
       +---------------------+----------------+                                |
                             |                v                                |
                             |   :8001  gate + NER engine                      |
                             |          - Tier-0 regex+Luhn / secrets+entropy  |
                             |          - on-device NER (CPU INT8 ONNX;        |
                             |            NPU/OpenVINO alt)                    |
                             |                |                                |
                             +----------------|--------------------------------+
                                              v
                              on-device CPU INT8 (NPU/OpenVINO alt)
                                              |
   cloud LLM API  <----- auth header verbatim, placeholders only -----+
   (api.anthropic.com /v1/messages)
```

- **`:8011` egress proxy** is the front door the local tool points at. It owns the request
  pipeline, the entity map, and stream rehydration.
- **`:8001` gate + NER engine** owns detection: the deterministic Tier-0 / secrets layer and the
  on-device NER pass.
- Both bind `127.0.0.1` by default. Tailnet or LAN exposure is an explicit operator opt-in via
  `GATEWAY_HOST` / `CPU_GATE_HOST`; the gateway should not be exposed to the open LAN or internet.
  Only the egress to the cloud LLM API leaves the host, carrying placeholders and the verbatim auth header.

---

## The request pipeline (7 steps)

```
 request in
    |
 [1] extract redactable text fields
    |
 [2] cheap deterministic gate  (ALWAYS, microseconds)
    |
 [3] empty path: no scannable text and no known entity?  --yes--> forward unchanged
    |  no
 [4] on-device NER pass over extracted non-trivial fields
    |
 [5] union merge (connected-component) + session+project entity map
    |
 [6] forward upstream, auth header verbatim
    |
 [7] stream-rehydrate the SSE response
    |
 response out (real values restored to the local client)
```

### 1. Extract redactable text fields

The proxy pulls the fields that can carry model-visible user data: `system`, `messages`,
`tool_result` text/JSON, `tool_use` input, Anthropic document text, and tool schema
descriptions/literal values. It never rewrites tool/function names, schema property names, images,
binary file bytes, or the model name. This boundary matters: rewriting routing or schema structure
would break the request, while structured argument values are user data and must be scanned.

### 2. Cheap deterministic gate (always, microseconds)

Every extracted field passes through the Tier-0 deterministic gate, every time, with no
exceptions. Two scans run here:

- **Tier-0 PII**: regex + Luhn check. This owns the catastrophic structured categories (payment
  cards via Luhn, SIN/NAS, etc.).
- **Secrets / entropy scan**: ported gitleaks-style patterns plus a Shannon-entropy backstop, with
  UUID / git-SHA / sequential false-positive filters.

This runs in microseconds, so it is cheap enough to be unconditional. It is also the reliable
floor: because NER recall is below 100%, the deterministic layer is what anchors coverage of the
catastrophic categories (secrets, cards, SIN), independent of the model.

### 3. Empty path

If a request has no scannable extracted text and no prior session entity to backstop, it is
forwarded unchanged. Normal non-empty text fields proceed to the local NER pass even when Tier-0
finds nothing, because the NER-only labels (person, organization, address) have no deterministic
floor and short structural values can carry them.

### 4. On-device NER pass

The on-device NER model runs on every extracted non-trivial text field. Repeated system prompts and
prior turns are cached, but code-like fields and short structural values are not skipped solely
because Tier-0 is clean. That trade keeps the privacy posture fail-safer for NER-only labels such
as person names.

The model processes text in **256-token windows** at about 34ms per window.

### 5. Union merge + entity map

Detections from the deterministic layers and the NER pass are combined with a **union merge** so
that overlapping or adjacent spans from different detectors become one clean span. The merge is
**connected-component**: spans that touch or overlap are grouped into a single component and
redacted as a whole. This is what prevents **fragment leaks**. (See the dedicated section below.)

The merged entities then flow through the **session + project entity map** (AES-GCM at rest),
which assigns the same placeholder to the same value across turns and applies the **known-entity
backstop**. (See the dedicated section below.)

### 6. Forward upstream

The rewritten request (placeholders in place of real values) is forwarded to the cloud LLM API.
The client's **auth header is forwarded verbatim**, which is what lets a Claude Max subscription
work without an API key.

### 7. Stream-rehydrate the SSE response

The upstream response is a Server-Sent Events stream. As deltas arrive, the proxy reverses the
placeholder map so the local client receives real values. This requires reassembling placeholders
that split across deltas and rehydrating `tool_use` argument JSON at the value level. (See the
Streaming SSE rehydration section below.)

---

## The cheap-gate fast path

The fast path is the performance backbone. The principle is: **never pay for a model when a
microsecond-scale deterministic check can clear the request.**

```
field --> Tier-0 regex+Luhn + secrets/entropy
              |
        any hit? ----no, and not natural-language----> forward unchanged (0 model cost)
              |
             yes / natural-language
              |
              v
        targeted on-device NER pass
```

Two consequences:

- A clean request is forwarded with zero model inference. The measured clean fast-path latency is
  **1.7ms median**.
- The NER model is invoked only where it can add detections the deterministic layer cannot, which
  keeps on-device inference proportional to actual PII risk rather than total traffic volume.

---

## The targeted on-device NER pass with chunking

The on-device NER pass is the always-on detection workhorse. It runs `xlm-roberta-base` as a
dynamic-INT8 ONNX model on CPU via onnxruntime (the Intel NPU / OpenVINO FP16 tier is preserved as
a drop-in alternate).

```
extracted non-trivial text field
        |
   chunk into 256-token windows
        |
   +----+----+----+ ...
   | w0 | w1 | w2 |        ~34ms per window
   +----+----+----+
        |
   per-window NER spans --> union merge (step 5)
```

- **Targeting**: every extracted non-trivial text field enters this pass. Repeated system prompts
  and prior turns are cached; empty/non-text requests can still forward unchanged.
- **Chunking**: text is processed in 256-token windows, at about 34ms per window.
- **Why the base tier is the right always-on tier**: the base model matches the GPU large model on
  recall at far lower latency, so the always-on tier runs the base model on-device (CPU INT8, ~42ms;
  the NPU/OpenVINO tier is the preserved alternate).

---

## The union merge: connected-component, no fragment leaks

Multiple detectors (Tier-0 regex+Luhn, the secrets/entropy scan, and the NER pass) can each fire
on the same region of text, often with **partially overlapping** spans. A person's name might be
caught as two adjacent tokens by NER, while a structured detector catches an embedded digit run.
If you redact each span independently, the gaps between them can leak fragments of the real value:
the placeholders end up interleaved with unredacted characters.

The union merge treats spans as nodes in a graph and draws an edge between any two spans that
overlap or are adjacent. Each **connected component** is then redacted as a single span.

```
detector spans on the same region:

   [---- A ----]
            [----- B -----]
                       [-- C --]

connected-component union:

   [============ merged ============]   <-- one placeholder, no gaps
```

Because the whole connected component is replaced atomically, there are **no fragment leaks**: no
sliver of the real value survives between two adjacent redactions.

---

## Session + project AES-GCM entity map and the known-entity backstop

### The entity map

Once a value is identified, it must map to a **stable placeholder** so that the same real value
gets the same placeholder across every turn of a conversation. Without this, the cloud model would
see a different token for the same entity each turn and lose coreference; rehydration would also be
ambiguous.

The entity map is scoped to **session and project**, with **AES-GCM at rest**. The same value
yields the same placeholder across turns within that scope.

### The known-entity backstop

NER recall is below 100%. A value the model catches on turn 1 might be missed on turn 5 (different
phrasing, a chunk boundary, an adversarial gluing). The **known-entity backstop** closes this gap:
once a value has been identified, it is recorded, and any later occurrence of that value is
**re-redacted deterministically even if the NER model misses it that turn.**

#### Cross-turn leak example the backstop fixes

```
Turn 1 (user):   "Marie Tremblay called about her file."
   NER detects "Marie Tremblay" --> placeholder PERSON_1, recorded in the entity map.
   Cloud model sees: "PERSON_1 called about her file."

Turn 5 (user):   "...and tremblay, marie still hasn't sent the form"
   NER misses this lowercased, reordered occurrence.
   WITHOUT the backstop: "Marie Tremblay" leaks to the cloud verbatim.
   WITH the backstop:    the known value is matched and re-redacted to PERSON_1
                          before the request leaves the host.
```

The backstop turns a one-time successful detection into a durable guarantee for the rest of the
session/project scope.

---

## Concurrency and multi-agent isolation

The gateway is a **single process** (`:8011`, one async event loop; no per-client workers). It does
not fork a process or thread per client -- many simultaneous agents are handled as **interleaved
coroutines on one loop**. While one request is awaiting the on-device NER pass or the upstream API,
the loop serves another. So "many agents at once" means request multiplexing, not CPU parallelism,
and each in-flight request keeps its own body, context, and placeholder map as coroutine-local state
-- there is no shared per-request mutable global, so two requests never see each other's text in
memory.

### Isolation is by session, not by process

PII isolation between agents is enforced by the **session -> entity-map-file** mapping, not by memory
or process separation. Each request derives a `(session, project)` key, and that pair selects exactly
one encrypted map file; an agent can only read, write, or rehydrate against its own file.

- `session` comes from the client's session header (`x-claude-code-session-id`, or `x-session-id` on
  the OpenAI routes); absent that, a hash of the system prompt; absent both, a unique per-request
  ephemeral id (so two truly handle-less first-turn flows never share one map).
- The map path is `sha256(project \0 session)`, so two different sessions hash to different files,
  different placeholder counters, and different replay maps. Agent A's `<PERSON_001>` and agent B's
  `<PERSON_001>` are minted from independent counters in independent files and can never collide or
  cross-rehydrate.

A tool that sends a stable session header (Claude Code does on every request) therefore gets a
per-conversation map fully isolated from every other client on the same gateway.

### Same-session concurrency

When one agent fires parallel requests on the same session (parallel tool calls, sub-agents), they
share one map file and must be serialized at the mint stage. Detection (the awaited NER calls) runs
**outside** the lock so the model stays busy; then the `load -> mint -> save` cycle runs under a
per-`(session, project)` lock: an in-process re-entrant lock **plus** a cross-process `fcntl.flock`
on a sidecar `.lock` file, with an atomic file replace. The second request to take the lock loads the
file the first just saved, sees its placeholders, and reuses them -- so the same value gets **one
stable placeholder even under concurrency**. This is also what keeps the upstream prompt cache warm:
an unstable placeholder would change the redacted prefix bytes every turn and bust the cache, which
re-bills the whole conversation as uncached input.

### Replay is scoped to the outbound body

The placeholder->value map handed to the response rehydrator is scoped to the placeholders that
actually appear in **this request's outbound body**, not the full session map. The upstream model can
only emit a placeholder it received, so this is sufficient for rehydration (including cross-turn,
since re-sent history carries its placeholders) while guaranteeing a request can never rehydrate a
value it did not send. This is the isolation boundary when two header-less clients share a system
prompt (and therefore one map file): each request still only reconstitutes its own values, and an
unknown placeholder is left raw rather than mapped to another flow's value.

### Throughput and limits

- **One event loop**: CPU-bound work between awaits (regex scans, the merge, JSON (de)serialization)
  briefly stalls all in-flight requests; there is no CPU parallelism in the proxy itself.
- **One on-device NER engine** is the throughput ceiling -- every non-trivial field from every agent
  funnels through it, scanned in 256-token windows.
- **Per-`(session, project)` mint serialization**: heavy same-session concurrency serializes at the
  lock; different sessions take different locks and do not contend.
- **Cross-process** safety (multiple gateway instances sharing one map directory) rests on
  `fcntl.flock` -- host-local advisory locking; it does not extend across hosts or a network
  filesystem without working flock semantics.
- For strict **multi-tenant** separation (different parties' data through one gateway), key the
  session on a per-client/auth fingerprint as well, so distinct clients never share a map file even
  when they share a system prompt.

---

## Streaming SSE rehydration

The response is an SSE stream of incremental deltas. The proxy rehydrates placeholders back to
real values as the stream flows to the local client. Three concerns drive the design.

### Tail-buffer for split placeholders

A placeholder token can be split across two deltas. If you rehydrate each delta independently, you
would fail to match the placeholder and pass a broken token to the client.

```
delta n     : "... please contact PER"
delta n+1   : "SON_1 about the file"

naive per-delta rehydration: "PER" and "SON_1" both pass through unmatched.

with tail-buffer:
   hold back the suffix that could be the start of a placeholder ("PER"),
   prepend it to the next delta, then match "PERSON_1" and rehydrate.
```

The proxy keeps a **tail buffer**: it holds back the trailing portion of a delta that could be the
beginning of a placeholder, prepends it to the next delta, and only emits text once it is sure no
placeholder straddles the boundary.

### tool_use input_json_delta accumulation

For `tool_use` blocks, arguments stream as `input_json_delta` fragments that are not individually
valid JSON. The proxy **accumulates** these fragments, then rehydrates the tool arguments at the
**value level** so that a placeholder appearing inside a JSON string value is restored to its real
value without corrupting the JSON structure.

```
input_json_delta : {"to": "EM
input_json_delta : AIL_1", "subject": "..."}

accumulate --> {"to": "EMAIL_1", "subject": "..."}
value-level rehydrate --> {"to": "marie@example.com", "subject": "..."}
```

### Hallucinated-placeholder safety policy

The cloud model could emit a placeholder-looking string that was never in the egress map (a
hallucination). Rehydrating it against nothing, or guessing, would be unsafe. The policy is: a
placeholder is only rehydrated if it is in **this request's replay** -- the placeholders that
appeared in the request's own outbound body (see *Concurrency and multi-agent isolation*). A
placeholder-shaped token with **no entry is left as-is**, not invented and not mapped to a real
value -- which also guarantees a request can never rehydrate a value it did not itself send.

---

## The deterministic secrets layer (deployed appliance)

Secrets are handled by a deterministic layer that runs in the deployed appliance as part of the always-on cheap gate (step 2), independent of the NER model. It has two parts:

- **Pattern matching**: ported gitleaks-style patterns for known credential shapes.
- **Shannon-entropy backstop**: high-entropy strings that match no known pattern are flagged as
  likely secrets, with **UUID / git-SHA / sequential** false-positive filters so that legitimate
  high-entropy-but-not-secret strings are not over-redacted.

Because this layer is deterministic and always-on, it is the reliable floor for the catastrophic
secret categories regardless of model recall or policy configuration.

---

## Policy resolution

Policy is layered. The resolution order for PII categories is:

```
session  >  project  >  default
```

- **session overrides project overrides default.** A per-session PII config wins over a
  per-project config, which wins over the built-in default.

On top of that ordering, three rules are fixed and not subject to policy:

- **Secrets and credentials always redact.** `api_key`, `password`, `access_token` and the like are
  redacted regardless of any policy setting. Policy can never turn the secrets floor off.
- **Operational labels excluded by default.** `file_path`, `username`, `organization` are excluded
  by default to avoid breaking the coding use case (redacting every file path or username would make
  the gateway unusable for coding agents).
- **Hash allowlist.** Git commit / content hashes (40-hex and 64-hex) are allowlisted so they are
  never redacted. These look high-entropy but are not PII, and redacting them would break diffs and
  references.

```
for each candidate category:
   if category in {api_key, password, access_token, ...secrets}:  REDACT  (always, non-negotiable)
   elif value matches 40/64-hex git/content hash:                 KEEP    (allowlist)
   elif category in {file_path, username, organization}:          KEEP    (default exclusion)
   else:                                                          resolve(session > project > default)
```

---

## Models

A 3-tier NER suite with a **French-Quebec + English focus**. This bilingual Quebec PII focus is the
moat: competitors lean on generic Presidio/regex.

| Tier | Model                       | Runtime                                   | Role                                  |
|------|-----------------------------|-------------------------------------------|---------------------------------------|
| CPU  | xlm-roberta-base            | dynamic-INT8 ONNX on CPU (onnxruntime)    | the deployed always-on workhorse      |
| NPU  | xlm-roberta-base            | OpenVINO FP16 IR, Intel NPU (alternate tier) | preserved drop-in alternate        |
| GPU  | xlm-roberta-large           | GPU                                       | highest-capacity tier                 |

Underneath the NER suite sit two deterministic layers (in the deployed appliance):

- **Tier-0 (regex + Luhn)** owns the catastrophic structured categories.
- **Deterministic secrets layer** (gitleaks-style patterns + Shannon-entropy backstop with
  UUID/git-SHA/sequential FP filters).

**Repo scope vs deployed appliance.** This repository contains the detection library and CLI (`gate/privacy_gate.py`: Tier-0 regex+Luhn floor, NER tier wrappers, merge, redact/rehydrate), the training code, the validation code, and the egress proxy (`appliance/`: the `:8011` always-on gateway, SSE stream rehydration, the AES-GCM session/project entity map, the known-entity backstop, and the deterministic secrets/entropy layer). The GPU NER gate service (`gate/gate_service_gpu.py`) is now version-controlled here too; the running instance is deployed on the GPU host, with `deploy/check-gate-drift.sh` guarding host-vs-repo drift. The pipeline described in this document is that of the deployed appliance.

### 20 labels

The shipped model uses **20 labels** (`training/labels_v20.json`):

`account_number`, `address`, `card_cvv`, `card_expiry`, `date_of_birth`, `email`, `file_path`,
`government_id`, `iban`, `ip_address`, `organization`, `password`, `payment_card`, `person`,
`phone_number`, `postal_code`, `secret`, `sensitive_account_id`, `tax_id`, `username`.

The prior 23-label scheme was consolidated: `bank_account` + `routing_number` folded into `account_number` / `sensitive_account_id`; `api_key` + `access_token` folded into `secret` / `password`; `sensitive_date` folded into `date_of_birth`; `phone` renamed `phone_number`; `postal` renamed `postal_code`; `ip` renamed `ip_address`.

---

## Measured numbers

Recall here means **leak-prevention**. `clean_fp` means **over-redaction on negative rows**.

### Measured public benchmark: both tiers v11r9c (synthetic held-out, 5-round error-mine loop)

Measured on the synthetic held-out corpus (7,498 synthetic rows, 20 labels, "full" config = Tier-0 floor + neural model, 0 train overlap, unseen document structures -- an anti-saturation held-out built ONLY from structural variants never seen in training). Source: `validation/RESULT-v11r9c.md` (the v11r5 baseline it improves on is `validation/RESULT-v11.md`). Both tiers now ship the `v11r9c` revision -- the GPU/large as `pii-gpu-xlmr-large-v11r9c` and the CPU/base as `pii-gpu-xlmr-base-v11r9c`, retrained on the same cumulative corpus so the base now carries the organization/address fix too (base `address` recall ~0.93).

The privacy metric is **full-stack catastrophic DETECTION recall**: any detected span is redacted regardless of which label it gets -- an intra-catastrophic mislabel is still a redaction, not a leak.

| pick | base | catastrophic full-stack DETECTION | overall labeled R | overall P | clean_fp |
|------|------|-----------------------------------|-------------------|-----------|----------|
| GPU  | xlm-r-large-v11r9c | **0.9954** | 0.9882 | 0.9615 | 34 / 7498 rows |
| CPU  | xlm-r-base-v11r9c  | **0.9941** | 0.9777 | 0.9139 | 48 / 7498 rows |

The v11r9c catastrophic recall essentially holds vs the prior v11r5 large model (0.9964 -> 0.9954, -0.001). The reason v11r9c ships is the structural-form leak it closes: **organization recall ~0.10 -> 1.00** and **address recall ~0.60 -> 0.95** on the synthetic corpus. The honest tradeoff is more over-redaction on digit-ID-shaped tokens: clean false positives on no-PII rows rise from 12 to 34 (per-label precision dips on `government_id` ~0.87, `phone_number` ~0.84, `sensitive_account_id` ~0.88, `account_number` ~0.94, `date_of_birth` ~0.96). This is the **safe** failure direction -- over-redaction never leaks PII, it only costs a coding agent a little context when a benign number is ID-shaped -- so for a privacy firewall whose prime directive is "never leak," closing the org/address leak is worth the extra over-redaction. FR is not weaker than EN: the Quebec-French moat holds on unseen structure.

### v6/v7 historical (superseded by v11 -- see validation/RESULT-v11.md)

Earlier results on the v6 generation sets (in-distribution held-out, train and val shared document layouts). Kept for reference; **do not use these as current figures**.

#### NER recall and false positives (v6/v7)

| Model            | ALL-CAPS gate | tabular test | v6 val | canonical | clean_fp |
|------------------|---------------|--------------|--------|-----------|----------|
| NPU xlm-r-base   | 0.955         | 0.968        | 0.990  | 0.986     | 0        |
| GPU xlm-r-large  | 0.955         | (identical to NPU) | 0.990 | (identical) | 0     |

**Key result:** the base model **equals** GPU large on recall at about **4x lower latency**, which is
why the base model is the always-on tier (deployed as CPU INT8).

#### vs Microsoft Presidio (v6/v7)

Presidio configured with English + French large spaCy, union, same sets, same metric:

| Test          | OSSRedact recall | Presidio recall | OSSRedact clean_fp | Presidio clean_fp |
|---------------|---------------|-----------------|-----------------|-------------------|
| ALL-CAPS gate | 0.955         | 0.779           | 0               | (n/a)             |
| v6 val        | 0.990         | 0.759           | 0               | 343               |
| canonical     | 0.986         | 0.798           | 0               | 508               |

OSSRedact wins recall by **17 to 23 points** and has **far fewer false positives**.

### Synthetic Québec corpus

A generated corpus of 5,000 FR + EN documents (bank statements, financing forms, email threads,
CSV exports, `.env`, code), redacted entirely locally:

- **218,931** PII spans redacted.
- **Zero** email, SIN, account-ID, or credit-card leaks in the redacted output **on this synthetic
  corpus** (verified against ground truth); this is a synthetic-corpus result, not a real-world
  zero-leak guarantee.
- Adversarial cases included (ALL-CAPS, NBSP-separated IDs, mixed FR/EN, long unbroken lines,
  look-alike decoys). A NBSP-separated-SIN gap in cue-less cells was surfaced, fixed, and re-verified
  at zero SIN leaks.

### C2: code-context PII (synthetic)

- On our synthetic code-context corpus, recall is **1.000** across JSON, YAML, SQL, CSV, logs, `.env`,
  and code comments, in FR + EN. This is the realistic, structured-PII case.
- **Honest adversarial caveat** (see Limitations #11): full names *glued* into camelCase / snake_case
  identifiers are a harder, adversarial case and are under-detected -- **0.882** on that variant. The
  glued/adversarial number, not the structured 1.000, is the one to lead with when reasoning about
  worst-case identifier leaks.

### Latency

| Path                       | Latency        |
|----------------------------|----------------|
| appliance clean fast-path  | 1.7ms median   |
| PII-bearing request        | 23.5ms median  |
| on-device per 256-token window | about 34ms |

---

## Limitations

Stated plainly:

- Models are trained and validated entirely on **synthetic Québec data**, and every "zero leak" /
  "verified" claim in this document is scoped to **our synthetic held-out corpus** -- it is not a
  real-world zero-leak guarantee. Broader real-world domains are future work.
- **The deterministic Tier-0 floor does not cover every category.** It deterministically covers
  (model-independent hard floor): secrets / API keys, payment cards (Luhn), IBAN, SIN / government
  IDs, emails, IP addresses, and file paths. **Address and organization have NO deterministic
  floor** -- they rely entirely on the NER model. v11r9c now covers them well on the synthetic
  corpus (org 1.0, address 0.95), but that coverage is **model-dependent**, not a hard guarantee
  like the Tier-0 categories.
- **#11 -- Glued / adversarial identifiers.** Full names **glued into code identifiers**
  (camelCase / snake_case) are an adversarial case and are under-detected: **0.882** on the
  synthetic adversarial variant, versus 1.000 on structured code-context PII. Lead with the
  realistic structured number for typical traffic, but treat glued identifiers as a known worst-case
  gap, not a solved one.
- Bare long **digit runs glued to adjacent letters** can be missed unless a financial / identity cue
  is nearby.
- **French and English only** by design. Multilingual is an explicit future axis, not v1.
- **Recall is below 100%.** The deterministic layer is the reliable floor only for the catastrophic
  *structured* categories (secrets, cards, SIN, IBAN, emails, IP, file paths); the model-dependent
  categories (person, organization, address) have no such floor.

Charts: `./charts/fig1, fig3, fig5` (png).

---

## Status

- **appliance is built**, running as a **systemd service**, and **verified end-to-end**: a
  real Claude Code session through the proxy redacts and rehydrates transparently.
- **Not yet published.**
- The workbench UI is **built**. Anthropic `/v1/messages`, OpenAI-compatible `/v1/chat/completions`, and OpenAI `/v1/responses` adapters are live; CLI wiring for Codex, Hermes, Pi, omp, and opencode is documented in `docs/ADAPTERS.md`. (Both the egress-proxy code under `appliance/` and the GPU NER gate service under `gate/` are now version-controlled; `deploy/check-gate-drift.sh` guards host vs repo drift.)
