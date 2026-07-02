#!/usr/bin/env python3
"""OSSRedact egress privacy proxy -- the appliance.

Sits in front of cloud LLM APIs. On egress it redacts PII + secrets in the request's free-text/data
fields to stable placeholders; on the response it rehydrates the placeholders back to the real values, so
the LOCAL client (Claude Code) sees real data while the upstream model only ever reasons over placeholders.

Co-located with the NER gate (:8001) on the same host; binds :8011. Built up across RUNBOOK steps:
  S2 : /v1/messages field extraction + passthrough + DRYRUN echo.
  S3 : cheap deterministic gate (Tier-0) inline + forward-unchanged-if-clean fast path.
  S4 : targeted NPU pass (gate /detect, chunked, cached) + union merge + span substitution + non-stream rehydrate.
  S5 : session+project entity map (AES-GCM) for cross-turn placeholder stability.
  S6 : streaming (SSE) rehydration with placeholder reassembly across deltas.
  S7 : secrets layer wired into the cheap gate (always-on, ignores PII policy).
  S8 : gateway-config.yaml policy resolution (session > project > default).
"""
import os, sys, json, time, re, hashlib, hmac, asyncio, threading
from collections import deque, OrderedDict
from urllib.parse import urlsplit, urlunsplit, urlencode
import yaml
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import (JSONResponse, StreamingResponse, HTMLResponse, PlainTextResponse,
                               FileResponse, RedirectResponse)
import uvicorn

APPLIANCE_DIR = os.environ.get('GATEWAY_APPLIANCE_DIR') or os.path.dirname(os.path.abspath(__file__))
if APPLIANCE_DIR not in sys.path:
    sys.path.insert(0, APPLIANCE_DIR)
from privacy_gate import tier0_spans, merge_spans, post_merge_address, explain, FLOOR_LABELS, UUID_RE  # cheap Tier-0 (no model load)
from entity_map import EntityMap, derive_session, map_file_lock, gc_maps
import redact_core
import allowlist as allowlist_mod   # the do-not-redact dictionary (value-exact, opt-in)
import denylist as denylist_mod     # the always-redact dictionary (term scanner, opt-in)
from math import log2 as _log2
from secrets_scan import secret_spans, shannon, is_benign_token, looks_like_code_expr, code_call_shape  # deterministic secrets (always-on) + FP helpers
import openai_adapter   # OpenAI /v1/chat/completions schema translation (Codex / omp / OpenAI-compatible)
import responses_adapter   # OpenAI /v1/responses schema translation (Codex CLI speaks /v1/responses ONLY)
import tool_arg_policy   # B5: withhold FLOOR/secret-class placeholders from EXECUTED tool-call arguments
from name_carrier import name_shaped, carrier_person_spans   # plan 026: rare-name carrier-wrap booster (NER recall)

ANTHROPIC_UPSTREAM = os.environ.get('GATEWAY_ANTHROPIC_UPSTREAM', 'https://api.anthropic.com')
OPENAI_UPSTREAM = os.environ.get('GATEWAY_OPENAI_UPSTREAM', 'https://api.openai.com')
# Codex with a ChatGPT/Codex PLAN (no platform API key) authenticates against the ChatGPT backend, not the
# platform API -- its OAuth token has no `api.responses.write` scope, so api.openai.com 401s it. Plan
# requests are routed here instead (see /v1/responses), keyed on the chatgpt-account-id header Codex sends
# only on the plan path. Override for a self-hosted/enterprise ChatGPT backend.
CHATGPT_UPSTREAM = os.environ.get('GATEWAY_CHATGPT_UPSTREAM', 'https://chatgpt.com/backend-api/codex')
GATE_URL = os.environ.get('GATEWAY_GATE_URL', 'http://127.0.0.1:8001')
# AVAILABILITY: an optional SECOND gate tried only when the primary is unreachable. The primary can be a remote
# high-quality tier (e.g. a GPU large model on the tailnet); if that box or the network path is down, a fail-closed
# egress otherwise 503s EVERY request -- a total LLM outage -- even when a healthy local gate exists. Point this at
# the loopback CPU gate (http://127.0.0.1:8001) so a primary outage DEGRADES to the local base tier instead of a
# hard stop. Only connection-level failures fail over (a reachable gate returning 4xx/5xx is a real error, not an
# outage, and is NOT masked by retrying elsewhere). The fallback still runs the full floor + neural base model, so
# fail-CLOSED semantics are preserved end to end -- this trades a quality tier for availability, never redaction.
# UNSET (default) => single-gate behaviour, unchanged. Must differ from GATE_URL to take effect.
GATE_FALLBACK_URL = os.environ.get('GATEWAY_GATE_FALLBACK_URL', '').strip()
# Reject a request body larger than this BEFORE it is parsed and fanned out to the detector (one /detect call per
# 600-char chunk per field). Without a cap a single multi-MB field becomes thousands of sequential detector calls
# that pin the shared gate and stall other sessions. 32 MiB comfortably covers a full 1M-token context turn; raise
# via GATEWAY_MAX_BODY_BYTES if a legitimate payload is ever larger. 0 disables the cap.
MAX_BODY_BYTES = int(os.environ.get('GATEWAY_MAX_BODY_BYTES', str(32 * 1024 * 1024)))
# Per-request cap on CONCURRENT neural /detect calls. Detection is read-only and per-field independent, so fields
# CAN be scanned in parallel -- BUT a live sweep against the deployed detector (2026-06-21, validation/
# RESULT-gate-latency-2026-06-21.md) showed the detector is ~6-8ms/call (loopback + warm GPU) and is a SINGLE CUDA
# stream behind a SYNC handler with GIL-bound post-processing, so client concurrency does NOT parallelize the GPU --
# it just adds contention. Measured optimum was ~2 (a marginal +7%); >=6 REGRESSED sharply (8 was ~0.7x = slower).
# So the default is capped LOW (the win here is the cache-bust fix + the LRU cache, not detector fan-out). Tune with
# GATEWAY_DETECT_CONCURRENCY; raise it only if the detector ever becomes remote (RTT to hide) or batched (P2).
DETECT_CONCURRENCY = max(1, int(os.environ.get('GATEWAY_DETECT_CONCURRENCY', '2')))
DRYRUN = os.environ.get('GATEWAY_DRYRUN', '0') == '1'        # don't forward upstream; echo would-be-upstream body
EXPOSE_MAP = os.environ.get('GATEWAY_TEST_EXPOSE_MAP', '0') == '1'   # test-only: include replay map in dryrun
PORT = int(os.environ.get('GATEWAY_PORT', '8011'))
HOST = os.environ.get('GATEWAY_HOST', '127.0.0.1')
# OFF-DEVICE control plane (opt-in). By default the control API (/api/*, settings UI) is loopback-ONLY: a
# remote GUI can read /healthz but cannot manage a gate it does not share a machine with. Set a shared secret
# here and an authenticated remote peer (the OSSRedact desktop console pointing at this gate over a trusted
# network -- e.g. a tailnet) may reach the control routes by presenting it. Loopback peers still need no token
# (the local settings UI is unchanged). UNSET => exactly the prior loopback-only behaviour (zero new exposure).
# SECURITY: enabling this exposes the live-activity proof feed (REAL PII values) to any peer holding the token,
# so set it only on a trusted/encrypted network and treat the token like a credential. Compared constant-time.
CONTROL_TOKEN = os.environ.get('GATEWAY_CONTROL_TOKEN', '').strip()
# Extra browser ORIGINS allowed to read control responses cross-origin (comma-separated, exact match), on top of
# the always-allowed loopback + Tauri origins. Needed only for a BROWSER-served console pointed at a remote gate
# (the desktop app's tauri origin is already allowed). Pair with CONTROL_TOKEN; an origin here still cannot reach
# a control route without the token. Example: GATEWAY_CORS_ORIGINS=http://my-pc:5180,https://console.example.ts.net
CONTROL_CORS_ORIGINS = frozenset(
    o.strip().rstrip('/') for o in os.environ.get('GATEWAY_CORS_ORIGINS', '').split(',') if o.strip())
LOG_REQUESTS = os.environ.get('GATEWAY_LOG_REQUESTS', '1') == '1'   # logs COUNTS/LABELS/placeholder TOKENS only
EXPLAIN = os.environ.get('GATEWAY_EXPLAIN', '0') == '1'   # opt-in: per-span provenance (no values) in meta['explain']
# FAIL CLOSED when the neural gate is unreachable (FIX-ROUND-3 HIGH). Post-FIX-2 EVERY non-trivial field is
# neural-scanned, so a gate outage means an NER-only name (no Tier-0 fallback) in ANY scanned field would pass
# upstream RAW. When degraded (a field needed the gate and got None back), the route refuses to forward and returns
# 503 instead of leaking. Default ON; set GATEWAY_FAIL_OPEN=1 ONLY to deliberately trade privacy for availability.
FAIL_CLOSED = os.environ.get('GATEWAY_FAIL_OPEN', '0') != '1'
START = time.time()
# Surfaced on /healthz so a connecting GUI can show which gate build it reached (override per deploy).
SERVICE_VERSION = os.environ.get('GATEWAY_VERSION', '0.2.0')
# Placeholder TOKEN matcher for the wire_placeholders LOG line (observability only; never model-visible). A label
# may carry INTERNAL underscores (gate-form <PHONE_NUMBER_001> / <SENSITIVE_ACCOUNT_ID_001>), so [A-Z0-9_]+ before
# the final '_\d{3,}' separator (FIX-ROUND-2 LOW: the old [A-Z0-9]+ missed multi-underscore labels, so the log
# under-reported which tokens actually went upstream -- a verification gap, not a leak).
_PH_TOKEN_RE = re.compile(r'<[A-Z0-9_]+_\d{3,}>')

# credential labels (from secrets_scan AND the NER model) -- always redacted, ignore the PII toggle
ALWAYS_REDACT = {'secret', 'password', 'api_key', 'access_token'}
# Labels the user do-not-redact allowlist can NEVER exempt: credentials PLUS the hard deterministic
# money/government floor. A user may declare their own name / email / file paths safe (person, email,
# file_path, organization, address, phone, ...), but must never be able to wave a real payment card,
# bank account / IBAN, government or tax ID, or date of birth past the firewall -- those carry a Tier-0
# floor and have no legitimate "allowlist my own value" use case. Fail-closed by construction.
# Single source of truth: the hard floor lives in privacy_gate.FLOOR_LABELS, which merge_spans also uses to
# keep a floor label from being downgraded to a soft one (floor stickiness). Importing the SAME set here
# guarantees the merge-stickiness set and the two egress guards (policy_allows_pii + the allowlist drop) can
# never drift apart. (ALWAYS_REDACT, the credential subset, is retained above for the PII-toggle bypass.)
FLOOR_NEVER_EXEMPT = FLOOR_LABELS
PROSE_MIN_WORDS = 8               # a field with >= this many word tokens of natural language → neural-scan it

app = FastAPI(title='OSSRedact egress proxy')

# ---------------------------------------------------------------------------
# Loopback-scoped CORS for the CONTROL API only (/api/* + /healthz). The OSSRedact
# desktop app (Tauri webview, origin tauri://localhost or http://tauri.localhost) and
# a locally-served web console (http://localhost:PORT) reach this daemon CROSS-ORIGIN,
# so the browser/webview needs CORS headers to read the control responses + open the
# SSE feed. CORS alone does NOT grant access: every control route is ALSO peer-guarded
# (_control_allowed = loopback OR a valid GATEWAY_CONTROL_TOKEN), so an unauthenticated
# remote origin can never reach them regardless of CORS. The redaction routes (/v1/*) are
# deliberately untouched -- they get no CORS headers and pass straight through. Origins are
# allow-listed to localhost / 127.0.0.1 / [::1] / tauri.localhost, plus any explicit
# GATEWAY_CORS_ORIGINS (for a browser console on a remote gate) -- never reflected blindly.
# ---------------------------------------------------------------------------
_CORS_ORIGIN_RE = re.compile(
    r'^(https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?|https?://tauri\.localhost|tauri://localhost)$', re.I)


def _is_control_path(path):
    return path == '/healthz' or path.startswith('/api')


def _cors_allows(origin):
    # Always allow loopback + Tauri (the regex). Additionally allow any operator-configured exact origin so a
    # browser-served console on another host can read a remote gate's control responses (still token-gated).
    if not origin:
        return False
    return bool(_CORS_ORIGIN_RE.match(origin)) or origin.rstrip('/') in CONTROL_CORS_ORIGINS


@app.middleware('http')
async def _control_cors(request: Request, call_next):
    # Classify the path defensively: a classifier bug must never break the relay, but it must ALSO never cause the
    # downstream route to run twice. call_next() (which executes the route, including state-changing control writes)
    # is invoked on EXACTLY ONE code path below; the only work wrapped in a try/except after it is header mutation,
    # which cannot re-run the route. (Prior code re-called call_next in an outer except -> a post-route error could
    # double-execute a mutating write.)
    try:
        is_control = _is_control_path(request.url.path)
    except Exception as e:
        print(f"[cors middleware path-classify error] {type(e).__name__}", flush=True)
        is_control = False
    if not is_control:
        # Fast path: not a control route -> forwarded with ZERO header changes.
        return await call_next(request)

    origin = request.headers.get('origin')
    try:
        allow = _cors_allows(origin)
    except Exception as e:
        print(f"[cors middleware origin-check error] {type(e).__name__}", flush=True)
        allow = False

    if request.method == 'OPTIONS':
        # CORS preflight (e.g. POST /api/allowlist with content-type: application/json). Answer here without
        # touching the route; only emit allow-headers when the origin is permitted.
        hdrs = {}
        if allow:
            hdrs = {'access-control-allow-origin': origin, 'vary': 'Origin',
                    'access-control-allow-methods': 'GET, POST, OPTIONS',
                    # x-ossredact-control-token lets an authenticated remote console reach the control API.
                    'access-control-allow-headers': 'content-type, x-ossredact-control, x-ossredact-control-token',
                    'access-control-max-age': '600'}
        return PlainTextResponse('', status_code=204, headers=hdrs)

    resp = await call_next(request)   # the route runs exactly once
    if allow:
        try:
            resp.headers['access-control-allow-origin'] = origin
            resp.headers['vary'] = 'Origin'
        except Exception as e:
            # Header mutation failed -- return the already-produced response as-is; never re-run the route.
            print(f"[cors middleware header error] {type(e).__name__}", flush=True)
    return resp


# ---------------------------------------------------------------------------
# Live activity view (LOOPBACK-ONLY proof console). An in-memory, never-persisted
# ring of recent redaction events so the operator can SEE, live, exactly what the
# gate masked in each of their own sessions: the real value -> the placeholder the
# upstream model actually received, and (on the reply) the placeholders rehydrated
# back to real values. This surface intentionally exposes real PII VALUES -- that
# IS the proof -- so it is held in memory only (never written to disk, dropped on
# restart) and every live endpoint is loopback-guarded exactly like the settings
# UI. GATEWAY_LIVE_VIEW=0 disables it entirely.
# ---------------------------------------------------------------------------
LIVE_VIEW = os.environ.get('GATEWAY_LIVE_VIEW', '1') != '0'
_LIVE_MAX = max(10, int(os.environ.get('GATEWAY_LIVE_MAX', '300')))
_live_ring = deque(maxlen=_LIVE_MAX)        # recent events, in-memory only
_live_subscribers = set()                   # set[asyncio.Queue] -- connected /api/stream listeners
_live_seq = 0
_PH_LABEL_RE = re.compile(r'<([A-Z0-9_]+)_\d{3,}>')


# Canonical label set (redaction-core + gate scheme). Placeholder MINTING strips non-alphanumerics from the
# label (payment_card -> <PAYMENTCARD_001>), so we map the stripped token form back to the canonical
# underscore name for clean, correctly-coloured chips in the live view.
_CANON_LABELS = ['account_number', 'address', 'card_cvv', 'card_expiry', 'date_of_birth', 'email', 'file_path',
                 'government_id', 'iban', 'ip_address', 'organization', 'password', 'payment_card', 'person',
                 'phone_number', 'postal_code', 'secret', 'sensitive_account_id', 'sensitive_date', 'tax_id',
                 'username', 'name', 'api_key', 'access_token', 'bank_account', 'routing_number', 'url',
                 'path', 'filepath', 'phone', 'uuid', 'sensitive_ref']
_STRIPPED_LABEL = {re.sub(r'[^a-z0-9]', '', lbl): lbl for lbl in _CANON_LABELS}


def _ph_label(ph):
    m = _PH_LABEL_RE.match(ph)
    if not m:
        return 'value'
    raw = re.sub(r'[^a-z0-9]', '', m.group(1).lower())
    return _STRIPPED_LABEL.get(raw, m.group(1).lower())


def _client_label(req, route):
    """Best-effort friendly client name for the live view, from a strong header signal then the User-Agent,
    falling back to the API surface. Never includes the API key or any identifying value."""
    if req.headers.get('x-claude-code-session-id'):
        return 'Claude Code'
    ua = (req.headers.get('user-agent') or '').lower()
    for key, name in (('claude-code', 'Claude Code'), ('codex', 'Codex'), ('opencode', 'OpenCode'),
                      ('oh-my-pi', 'Oh My Pi'), ('ohmypi', 'Oh My Pi'), ('hermes', 'Hermes'),
                      ('cursor', 'Cursor'), ('continue', 'Continue'), ('aider', 'Aider'),
                      ('anthropic', 'Anthropic SDK'), ('openai', 'OpenAI SDK')):
        if key in ua:
            return name
    return {'/v1/messages': 'Anthropic API', '/v1/chat/completions': 'OpenAI-compatible',
            '/v1/responses': 'Codex / Responses'}.get(route, route)


def _live_emit(kind, route, client, ctx, payload):
    """Append one event to the ring and fan it out to live subscribers. Never raises into the hot path."""
    if not LIVE_VIEW:
        return
    global _live_seq
    try:
        _live_seq += 1
        sess = (ctx.get('session_resolved') or ctx.get('session') or '')
        ev = {'seq': _live_seq, 'ts': round(time.time(), 3), 'kind': kind, 'route': route,
              'client': client, 'session': sess[:12], **payload}
        _live_ring.append(ev)
        for q in list(_live_subscribers):
            try:
                q.put_nowait(ev)
            except Exception:
                pass   # slow/dead consumer: drop, never block redaction
    except Exception:
        pass


def _live_request(route, client, ctx, meta, replay, stream):
    """Emit the OUTBOUND event: what the gate redacted before forwarding upstream (real value -> placeholder).
    Fully guarded: a live-view bug must never break the user's actual request."""
    if not LIVE_VIEW:
        return
    try:
        entities = [{'placeholder': ph, 'value': val, 'label': _ph_label(ph)}
                    for ph, val in (replay or {}).items()]
        entities.sort(key=lambda e: e['placeholder'])
        _live_emit('request', route, client, ctx, {
            'redaction': meta.get('redaction') or 'skip',
            'n_spans': meta.get('n_spans', 0), 'n_new': meta.get('n_new', 0),
            'n_swept': meta.get('n_swept', 0), 'by_label': meta.get('by_label', {}),
            'degraded': bool(meta.get('degraded')), 'stream': bool(stream), 'entities': entities})
    except Exception:
        pass


def _live_response(route, client, ctx, replay, present_phs):
    """Emit the INBOUND event: placeholders that came back in the model's reply and were rehydrated to real values.
    Fully guarded: a live-view bug must never break the user's actual response."""
    if not LIVE_VIEW or not replay:
        return
    try:
        phs = sorted(set(present_phs) & set(replay))
        if not phs:
            return
        entities = [{'placeholder': ph, 'value': replay[ph], 'label': _ph_label(ph)} for ph in phs]
        _live_emit('response', route, client, ctx, {'n_rehydrated': len(entities), 'entities': entities})
    except Exception:
        pass


def _withheld_tokens(out_text, replay, tool_replay):
    """Placeholder tokens left LITERAL in rehydrated TOOL-ARG output because tool_arg_policy suppressed them
    (B5 anti-exfiltration): tokens present in the output that the full replay knows but the tool-arg replay
    withheld. `tool_replay is replay` is the fast path when nothing was suppressed (see tool_arg_replay)."""
    if not replay or tool_replay is replay:
        return []
    return [tok for tok in _PH_TOKEN_RE.findall(out_text) if tok in replay and tok not in tool_replay]


def _live_tool_arg_withheld(live_ctx, withheld):
    """Emit the WITHHELD event: floor/secret-class placeholders that stayed inert <LABEL_NNN> literals inside
    EXECUTED tool-call arguments (tool_arg_policy suppression). Before this event the agent received the
    literal token SILENTLY -- observed live 2026-07-02: an agent ran Write(<SENSITIVEACCOUNTID_004>/bench2.py)
    and created a junk directory, and nothing on any console said why. Placeholder tokens + labels only,
    never values (the withheld value staying secret is the whole point). Fully guarded like the other
    live-view emitters: a live-view bug must never break the user's actual response."""
    if not LIVE_VIEW or not withheld or not live_ctx:
        return
    try:
        toks = sorted(withheld)
        _live_emit('tool_arg_withheld', live_ctx['route'], live_ctx['client'], live_ctx['ctx'],
                   {'n_withheld': len(toks), 'labels': sorted({_ph_label(t) for t in toks}),
                    'placeholders': toks})
    except Exception:
        pass


async def _tally_rehydrations(aiter, replay, live_ctx):
    """Passthrough wrapper over the RAW upstream stream that tallies which placeholders appeared (so the live
    view can show streamed rehydration). A placeholder token can split across SSE chunks, so we keep a short
    tail carry. Pure observation -- it never alters the bytes handed to the rehydrating stream transform."""
    seen = set()
    carry = ''
    try:
        async for chunk in aiter:
            if replay:
                text = carry + (chunk.decode('utf-8', 'ignore') if isinstance(chunk, (bytes, bytearray)) else str(chunk))
                for m in _PH_TOKEN_RE.finditer(text):
                    if m.group(0) in replay:
                        seen.add(m.group(0))
                carry = text[-40:]
            yield chunk
    finally:
        if live_ctx:
            _live_response(live_ctx['route'], live_ctx['client'], live_ctx['ctx'], replay, seen)


# ----------------------------------------------------------------------------
# Field extraction (SPECS §2.1 step 1): isolate the redactable free-text/data
# fields. We descend to the leaf dict holding each text string and keep a
# (container, key) handle so substitution writes the redacted value back IN
# PLACE. Tool_use inputs in assistant history are model-visible too, so they
# are recursively surfaced as user data. We still never touch tool schemas,
# image blocks, routing identifiers, or model.
# ----------------------------------------------------------------------------
class Field:
    __slots__ = ('container', 'key', 'kind')

    def __init__(self, container, key, kind):
        self.container = container
        self.key = key
        self.kind = kind

    @property
    def text(self):
        return self.container[self.key]

    def write(self, value):
        self.container[self.key] = value


def _append_anthropic_document_fields(block, fields, claimed):
    """Surface text-bearing Anthropic document sources without touching binary/base64 media."""
    source = block.get('source')
    if not isinstance(source, dict):
        return
    stype = source.get('type')
    if stype not in ('text', 'content'):
        return
    for key in ('text', 'content', 'data'):
        value = source.get(key)
        if isinstance(value, str) and (id(source), key) not in claimed:
            claimed.add((id(source), key))
            fields.append(Field(source, key, 'message'))
        elif isinstance(value, (dict, list)):
            responses_adapter._recurse_collect(
                value, 'message', fields, [], claimed, struct_scope=False)


# Free-text block-type aliases: Anthropic uses `text`; the Responses-style/OpenAI shapes use `input_text` /
# `output_text` for the SAME free text. Recognizing only `text` let an `input_text` block extract ZERO fields ->
# the whole body was forwarded UNSCANNED (fail-open). Binary/opaque blocks carry no scannable free text (their
# bytes are handled elsewhere) and must NOT be recursed into as user text.
_TEXT_BLOCK_TYPES = ('text', 'input_text', 'output_text')
# Keep in sync with openai_adapter._BINARY_BLOCK_TYPES. `image_url` is the OpenAI Chat image part; it never
# appears on the Anthropic path, but listing it here keeps the two binary-skip sets identical (no drift).
# `thinking` / `redacted_thinking` are OPAQUE REASONING blocks, not media, but they belong in the skip set for the
# same reason: their bytes must NOT be surfaced for redaction. Extended-thinking blocks are cryptographically bound
# -- Anthropic's `signature` is a MAC over the `thinking` content, and the client must re-send the block VERBATIM
# (content + signature) on every follow-up turn. Redacting the thinking (or rehydrating it on the response) changes
# bytes the signature covers, which (a) desyncs content<->signature and (b) mutates a block that lives inside the
# cached prefix -> Anthropic re-processes the whole prompt every turn (the operator's "context maxed / 5h usage
# climbs fast" symptom). The blocks are generated by the upstream model from ALREADY-REDACTED input, so they carry
# only placeholders -- there is no real PII in them to protect. So: OPAQUE PASSTHROUGH, never redacted here and
# never rehydrated on the response (see _OPAQUE_REASONING_BLOCK_TYPES + _rehydrate_json).
_OPAQUE_REASONING_BLOCK_TYPES = ('thinking', 'redacted_thinking')
_BINARY_BLOCK_TYPES = ('image', 'input_image', 'image_url', 'document', 'redacted_thinking', 'thinking')


def _collect_content_list(seq, kind, fields, claimed):
    """Walk a content/system array: typed text blocks (incl. input_text/output_text aliases), BARE STRING
    elements (array-of-strings), and -- as a fail-CLOSED backstop -- any UNKNOWN non-binary block type recursed
    for its free text, so no novel/aliased shape can bypass redaction."""
    for idx, blk in enumerate(seq):
        if isinstance(blk, str):
            if blk.strip():
                fields.append(Field(seq, idx, kind))
            continue
        if not isinstance(blk, dict):
            continue
        t = blk.get('type')
        if t in _TEXT_BLOCK_TYPES and isinstance(blk.get('text'), str):
            fields.append(Field(blk, 'text', kind))
        elif t not in _BINARY_BLOCK_TYPES:
            responses_adapter._recurse_collect(blk, kind, fields, [], claimed, struct_scope=False)


def extract_text_fields(body):
    fields = []
    claimed = set()
    sysv = body.get('system')
    if isinstance(sysv, str):
        fields.append(Field(body, 'system', 'system'))
    elif isinstance(sysv, list):
        _collect_content_list(sysv, 'system', fields, claimed)
    for msg in (body.get('messages') or []):
        if not isinstance(msg, dict):
            continue
        c = msg.get('content')
        if isinstance(c, str):
            fields.append(Field(msg, 'content', 'message'))
        elif isinstance(c, list):
            for idx, blk in enumerate(c):
                if isinstance(blk, str):
                    if blk.strip():       # array-of-strings content (C2): a bare string element IS user text
                        fields.append(Field(c, idx, 'message'))
                    continue
                if not isinstance(blk, dict):
                    continue
                t = blk.get('type')
                if t in _TEXT_BLOCK_TYPES and isinstance(blk.get('text'), str):   # text / input_text / output_text (C1)
                    fields.append(Field(blk, 'text', 'message'))
                elif t == 'tool_result':
                    cc = blk.get('content')
                    if isinstance(cc, str):
                        fields.append(Field(blk, 'content', 'tool_result'))
                    elif isinstance(cc, list):
                        for cbi, cb in enumerate(cc):
                            if isinstance(cb, str):
                                if cb.strip():
                                    fields.append(Field(cc, cbi, 'tool_result'))
                            elif isinstance(cb, dict) and cb.get('type') in _TEXT_BLOCK_TYPES and isinstance(cb.get('text'), str):
                                fields.append(Field(cb, 'text', 'tool_result'))
                            elif isinstance(cb, (dict, list)) and not (
                                    isinstance(cb, dict) and cb.get('type') in _BINARY_BLOCK_TYPES):
                                responses_adapter._recurse_collect(
                                    cb, 'tool_result', fields, [], claimed, struct_scope=False)
                    elif isinstance(cc, dict):
                        responses_adapter._recurse_collect(
                            cc, 'tool_result', fields, [], claimed, struct_scope=False)
                elif t in ('tool_use', 'server_tool_use'):
                    inp = blk.get('input')
                    if isinstance(inp, str):
                        fields.append(Field(blk, 'input', 'tool_result'))
                    elif isinstance(inp, (dict, list)):
                        responses_adapter._recurse_collect(
                            inp, 'tool_result', fields, [], claimed, struct_scope=False)
                elif t == 'document':
                    _append_anthropic_document_fields(blk, fields, claimed)
                elif t not in _BINARY_BLOCK_TYPES:
                    # unknown / future / aliased block type carrying free text -- recurse so it can never bypass
                    # redaction (fail-CLOSED backstop for C1-class shape gaps).
                    responses_adapter._recurse_collect(blk, 'message', fields, [], claimed, struct_scope=False)
    tools = body.get('tools')
    if isinstance(tools, list):
        responses_adapter._recurse_collect(tools, 'tool_result', fields, [], claimed)
    # top-level metadata (Anthropic: metadata.user_id) -- free-form, can carry PII; forwarded RAW before this.
    # Parity with the OpenAI adapters, which already redact their metadata map (struct_scope=False = user data).
    md = body.get('metadata')
    if isinstance(md, dict):
        responses_adapter._recurse_collect(md, 'tool_result', fields, [], claimed, struct_scope=False)
    return fields


# ----------------------------------------------------------------------------
# Detection: cheap deterministic gate (always) + targeted neural pass (only on
# flagged or natural-language fields; pure code with no Tier-0 hit is skipped).
# ----------------------------------------------------------------------------
SECRETS_ENTROPY = os.environ.get('GATEWAY_SECRETS_ENTROPY', '1') == '1'
# git commit / content hash: lowercase hex of exactly 40 or 64 chars. Benign in dev text -- never redact
# (would break the coding assistant). Narrower than the secrets FP filter so real UUIDs/accounts stay redacted.
_BENIGN_HASH = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')

# file_path over-redaction precision (operator policy GATEWAY_PATH_POLICY). The NER tags the WHOLE absolute path as
# `file_path`, but the only identity-bearing part is the home-dir username (/home/<user>/, /Users/<user>/). Tagging
# the whole path breaks the coding agent's file ops (it gets a placeholder, not a usable path) AND busts the
# Anthropic prompt cache (paths are everywhere -> mint+sweep churn). So narrow each file_path span to JUST the
# home-dir username (kept under the file_path label, which is CASE-SENSITIVE in entity_map -> /home/alex round-
# trips exactly, no /home/Alex mangle), and DROP the span when the path has no home-dir username (/etc, /var,
# /assets, relative/project paths -- structurally not PII, and the model needs them to work). PII a detector tags
# INDEPENDENTLY (an email, a card, a key with a cue, a denylisted term) keeps its OWN span and is still redacted; a
# value that ONLY the whole-path span covered (e.g. a bare high-entropy blob the secret floor skips next to a '/',
# or a client name the NER did not tag) passes through as non-username path text -- the operator's accepted
# tradeoff, narrowable further via the denylist. (This pre-existing entropy-blob-in-path gap is NOT widened here: it
# also passed under the legacy filepath-excluded default.) Policy: `username` (default)
# narrows; `passthrough` drops every file_path span (paths reach the model verbatim, username included); `full`
# keeps the model's whole-path span (the legacy over-redaction).
PATH_POLICY = os.environ.get('GATEWAY_PATH_POLICY', 'username')
# Wire-level date redaction opt-back-in (see resolve_pii_policy): default 0 = sensitive_date never redacts
# at the egress in any mode. Set 1 to restore the pre-2026-07-02 behavior (privacy mode redacts dates).
REDACT_DATES = os.environ.get('GATEWAY_REDACT_DATES', '0') == '1'
# Home-dir username matcher. Case-INSENSITIVE (macOS resolves /users/ == /Users/; /HOME/ occurs), tolerant of
# repeated separators (/home// path-join artifact) and BOTH separators, and accepts the Windows drive form
# (C:\Users\<user>\) and the tilde home (~<user>/). .search() takes the FIRST home root so a mid-path "/Users/"
# directory is not mistaken for a second home (the NER emits one span per path anyway).
_HOME_USER_RE = re.compile(
    r'(?:[\\/]+home[\\/]+|(?:[A-Za-z]:)?[\\/]+users[\\/]+|~)([^\\/\s]+)', re.IGNORECASE)


def _is_filepath_label(label):
    return re.sub(r'[^a-z0-9]', '', str(label or '').casefold()) in ('filepath', 'path')


# ---------------------------------------------------------------------------
# MODEL-FLOOR DIET -- floor = deterministic provenance (RC2 fat-floor fix, no retrain, 2026-07-02).
#
# The FLOOR privileges (merge-sticky, un-allowlistable, redacted even in 'off' mode, WITHHELD from executed
# tool-call arguments) exist because the deterministic tier-0 rules that mint those labels are near-certain:
# a Luhn card, a mod-97 IBAN, a keyword-cued credential. The GPU NER is out-of-distribution on coding traffic
# and mints the SAME labels on junk -- observed live 2026-07-02: whole file paths tagged sensitive_account_id,
# the Python identifier DIGIT_RUN_RE tagged password, the code fragment `re.compile(r` tagged secret. Because
# the label alone carried the privilege, that junk became un-allowlistable, survived every mode, and was
# withheld from tool args -- an agent received a literal <SENSITIVEACCOUNTID_004> as a file path and ran
# Write(<SENSITIVEACCOUNTID_004>/bench2.py), creating a junk directory.
#
# Fix: floor privileges now REQUIRE deterministic provenance. Tier-0 rules own the hard guarantee (untouched
# and still un-bypassable); a MODEL span (tier != 0) claiming a floor label is treated as RECALL for soft PII:
#   - bank/account/government identity labels -> relabeled to the SOFT 'sensitive_ref' (still redacts in
#     privacy AND coding -- the model's recall is kept -- but passes in 'off', is allowlist-exemptible, and
#     not merge-sticky). It stays WITHHELD from executed tool args (adversarial review 2026-07-02:
#     rehydrating a model-claimed identity into an executed command re-opens the B5 curl-exfil class); the
#     Write(<placeholder>/...) incident class is fixed by the path-shape narrowing below plus the
#     tool_arg_policy value-shape migration exceptions, not by tool-arg rehydration of identity refs.
#     A REAL account/IBAN/SIN in the same text still gets its floor from the tier-0 twin span (digit-run /
#     mod-97 / Luhn), which union-merges floor-sticky as before.
#   - credential labels (secret/password/api_key/access_token) -> three-way verdict
#     (_model_credential_verdict): 'floor' for real key/password shapes, 'drop' ONLY for provable code
#     shapes (identifiers, call expressions -- keeps agent edits working), 'ref' for everything else so a
#     model-detected human password STILL REDACTS (the original binary gate's shannon>=4.0 bar was
#     unreachable under 16 chars and silently un-redacted prose passwords -- adversarial review, same
#     night). Deterministic secrets rules are untouched.
#   - payment_card / card_cvv / card_expiry / date_of_birth model spans are unchanged (no observed junk, and
#     the model is the only recall for uncued DOBs -- dropping privilege there would be a real loss).
#   - back-compat guard, ANY tier: a span labeled sensitive_account_id/account_number whose exact text is a
#     UUID relabels to the soft 'uuid' -- the DEPLOYED GPU gate still emits the old floor label for UUIDs
#     (its /detect spans arrive with tier 0) until it is redeployed with the 2026-07-02 demotion.
# ---------------------------------------------------------------------------
_MODEL_IDENTITY_FLOOR = frozenset({'sensitive_account_id', 'account_number', 'bank_account', 'iban',
                                   'routing_number', 'government_id', 'tax_id'})
_MODEL_CRED_FLOOR = frozenset({'secret', 'password', 'api_key', 'access_token'})
_UUID_RELABEL = frozenset({'sensitive_account_id', 'account_number'})
# Version-pin back-compat veto for model/old-gate email spans (re-review 2026-07-02): drop ONLY the observed
# junk shape -- a numeric last segment (`core@0.2.0`, `unpkg@1.1.0`) or an IPv4 tail (`user@192.168.1.1`).
# The earlier "no ASCII-alpha TLD" test also dropped legitimate accented/IDN-TLD addresses
# (`usuario@empresa.quebec` with a Unicode TLD) that tier-0's ASCII EMAIL_RE cannot catch -- leaving the
# model span as their only protection. A numeric-tail test keeps those redacted.
_VERSION_PIN_TAIL_RE = re.compile(r'\.\d+$')
# A bare code-identifier shape: what a Python/JS variable, constant, or function name looks like. The model
# tags these as password/secret on coding traffic (DIGIT_RUN_RE -> password, live 2026-07-02).
_CODE_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
# Known credential prefixes (the secrets_scan provider set, casefolded): a token starting with one of these is
# a real key shape even when its tail is short/low-entropy, so the model's floor claim is honored.
_CRED_PREFIXES = ('sk-', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_', 'xox', 'akia', 'asia',
                  'aiza', 'ya29.', 'npm_', 'pypi-', 'eyj', 'glpat-', 'rk_live_', 'rk_test_')


def _model_credential_verdict(raw):
    """Three-way verdict on a MODEL-claimed credential span (deterministic shape test only; the tier-0
    secrets floor is unaffected either way):
      'floor' -> the claim stands: real key/token shapes keep full floor privilege (withheld from tool args).
      'drop'  -> unambiguous CODE, not a secret: bare code identifiers/expressions (DIGIT_RUN_RE,
                 re.compile(r, os.environ.get(). Dropping keeps agent edits of source files working.
      'ref'   -> everything else: demote to soft 'sensitive_ref' -- STILL REDACTED in privacy+coding.
    RECALIBRATED after adversarial review (2026-07-02, same night as the diet landed): the original binary
    keep-or-drop gate used shannon>=4.0, which is mathematically unreachable for tokens under 16 chars
    (shannon <= log2(len)) -- it silently DROPPED nearly every model-detected human password
    ('Hunter2Pass', 'sunshine1sunshine') in every mode, an under-redaction regression. Now a failed floor
    test demotes instead of dropping: over-redaction is the safe error; only provable code shapes drop."""
    tok = raw.strip().strip('\'"`')
    if len(tok) < 8:
        return 'drop'                  # sub-8 uncued model-only "credentials" are noise; cue rules own PINs
    low = tok.casefold()
    if any(low.startswith(p) for p in _CRED_PREFIXES):
        return 'floor'
    if is_benign_token(tok):           # UUID / git-SHA / all-digit / sequential (detect-secrets FP filters):
        return 'drop'                  # owned elsewhere (uuid label, hash allowlist, numeric-cue rules)
    # A CALL / SUBSCRIPT expression is unambiguously code at ANY entropy (`re.compile(r`,
    # `base64.b64encode(x)`) -- drop it BEFORE the entropy escape, or a high-char-diversity code fragment the
    # model mis-tags floors and re-breaks agent edits (the original incident; completeness fuzz 2026-07-02).
    if code_call_shape(tok):
        return 'drop'
    n_classes = (any(c.islower() for c in tok) + any(c.isupper() for c in tok)
                 + any(c.isdigit() for c in tok))
    # Length-relative entropy: shannon is bounded by log2(len), so compare against the token's own ceiling
    # rather than an absolute bar a short token can never reach. The distinct-character RATIO is a second,
    # more stable randomness signal for single-alphabet blobs where a couple of collision-repeats drag
    # shannon just under the bar (completeness fuzz 2026-07-02: ~3-7% of uniformly-random single-class
    # alphabetic tokens leaked to 'ref' on shannon alone) -- a near-all-distinct token of real length is a
    # generated key whatever its shannon.
    rand_looking = (shannon(tok) >= 0.75 * _log2(max(2, len(tok)))
                    or (len(tok) >= 12 and len(set(tok)) / len(tok) >= 0.7))
    # ENTROPY ESCAPE: a random-looking multi-class token is credential-like WHATEVER (non-call) punctuation
    # it carries -- a custom bearer token that happens to be underscore- or dot-shaped
    # (`db_9fZ2Qw8rLm4xKp7Ty3Vn6Bs`, `v1a2b3.c4d5e6.f7g8h9`) keeps its floor instead of being dropped as a
    # bare dotted/const reference below.
    if rand_looking and n_classes >= 2:
        return 'floor'
    # DROP the remaining PROVABLE code shapes only: SCREAMING_CONST and bare dotted references
    # (looks_like_code_expr, minus the call-shape already handled). A bare snake_case identifier is the
    # documented AMBIGUOUS case (variable name vs `correct_horse_battery_staple` passphrase), NOT provable
    # code -- routing it to 'drop' shipped uncued snake-case passwords the model tagged in every mode incl.
    # privacy (completeness fuzz). It now falls through to 'ref' (redacted in privacy + coding; over-
    # redaction is the safe error for the rare mis-tagged lowercase code identifier).
    if looks_like_code_expr(tok):
        return 'drop'
    # A random-looking token keeps its floor even when SINGLE-class and not code-shaped -- an all-letter
    # high-entropy blob (`xkqvhzwjlmnpr`) is a generated key, not prose (leak-check 2026-07-02: dropping the
    # standalone rand_looking clause here let such a token demote to sensitive_ref and ship in OFF mode).
    if n_classes >= 2 or rand_looking:
        return 'floor'                 # mixed-class human password / random single-class blob -> floor
    return 'ref'                       # single-class LOW-entropy prose-ish token: redact softly (no floor)


def demote_model_floor(spans, text):
    """Provenance-aware floor diet (see block comment above). Tier-0 spans pass through untouched -- the
    deterministic floor is never weakened here (fail-closed direction preserved); only MODEL claims lose
    unearned floor privilege. Runs BEFORE merge_spans so a demoted label can never become merge-sticky."""
    out = []
    for s in spans:
        label = s.get('label')
        val = text[s['start']:s['end']]
        if label in _UUID_RELABEL and UUID_RE.fullmatch(val):
            # any tier: the deployed gate's floor:uuid spans arrive as tier-0 sensitive_account_id until the
            # gate-side 2026-07-02 demotion is redeployed; local tier-0 already mints 'uuid' directly.
            out.append({**s, 'label': 'uuid'})
            continue
        if s.get('tier') == 0:
            out.append(s)
            continue
        if label in _MODEL_IDENTITY_FLOOR:
            out.append({**s, 'label': 'sensitive_ref'})
            continue
        if label == 'email' and _VERSION_PIN_TAIL_RE.search(val):
            # deployed-gate back-compat: the old GPU gate still mints email spans for npm version pins
            # (core@0.2.0) / IP tails until it is redeployed. Only those numeric-tail shapes are dropped;
            # a real accented/IDN-TLD email keeps its span (see _VERSION_PIN_TAIL_RE).
            continue
        if label in _MODEL_CRED_FLOOR:
            verdict = _model_credential_verdict(val)
            if verdict == 'floor':
                out.append(s)                              # real key/password shape: floor claim stands
            elif verdict == 'ref':
                out.append({**s, 'label': 'sensitive_ref'})  # still redacted (privacy+coding), no floor perks
            continue                                       # 'drop': provable code shape (DIGIT_RUN_RE class)
        out.append(s)
    return out


# Path-shaped text: an absolute/home/drive-rooted path with >= 2 separators and no whitespace. Used to extend
# the file_path narrowing to demoted 'sensitive_ref'/'uuid' spans whose TEXT is really a path the model
# mis-labeled (the observed whole-path-as-account_id junk).
_DRIVE_ROOT_RE = re.compile(r'^[A-Za-z]:[\\/]')


def _path_shaped(txt):
    if not txt or any(ch.isspace() for ch in txt):
        return False
    if not (txt.startswith('/') or txt.startswith('~') or _DRIVE_ROOT_RE.match(txt)):
        return False
    return (txt.count('/') + txt.count('\\')) >= 2


def _narrow_path_spans(spans, text):
    """Apply GATEWAY_PATH_POLICY to file_path spans. Non-file_path spans pass through unchanged. A narrowed
    username keeps the original span's label/tier/conf, so it stays a case-sensitive file_path placeholder.

    EXTENDED 2026-07-02 (fat-floor diet follow-through): a 'sensitive_ref' or 'uuid' span whose TEXT is
    path-shaped is the model mis-labeling a whole path (the junk demote_model_floor just softened) -- it gets
    the SAME narrowing, RELABELED to file_path so the username (a) mints under the case-SENSITIVE file_path
    contract (no /home/alex -> /home/Alex sweep-mangle) and (b) converges on the same placeholder an NER
    file_path span of the same path would mint (prompt-cache byte-stability). Tier-0 FLOOR spans are NEVER
    narrowed: they cannot reach either branch (floor labels are neither file_path nor sensitive_ref/uuid,
    and demote_model_floor never touches tier-0 floor labels)."""
    if PATH_POLICY == 'full':
        return spans
    out = []
    for s in spans:
        pathish_soft = (s.get('label') in ('sensitive_ref', 'uuid')
                        and _path_shaped(text[s['start']:s['end']]))
        if not (_is_filepath_label(s.get('label')) or pathish_soft):
            out.append(s)
            continue
        if PATH_POLICY == 'passthrough':
            continue   # drop -> the whole path reaches the model verbatim
        m = _HOME_USER_RE.search(text[s['start']:s['end']])
        if m is None:
            continue   # no home-dir username in this path -> not PII -> drop (path passes through verbatim)
        username = text[s['start'] + m.start(1):s['start'] + m.end(1)]
        if _PH_TOKEN_RE.fullmatch(username):
            continue   # the "username" is itself a leaked placeholder (/home/<FILEPATH_001>/...) echoed back --
                       # narrowing onto it would remint <FILEPATH_005> over <FILEPATH_001> and leak a raw token
                       # to the local chat on rehydrate (RC4). Already redacted -> leave it, do not re-mint.
        narrowed = {**s, 'start': s['start'] + m.start(1), 'end': s['start'] + m.end(1)}
        if pathish_soft:
            narrowed['label'] = 'file_path'   # case-sensitive mint + placeholder convergence (see docstring)
        out.append(narrowed)
    return out


def cheap_gate(text):
    """Deterministic, always-on, microseconds. Tier-0 regex+Luhn PII + secrets (always redacted)."""
    return tier0_spans(text) + secret_spans(text, entropy_backstop=SECRETS_ENTROPY)


_CODE_CHARS = set('{}[]()<>=;+*/\\|&%$#@~`')


def _looks_like_prose(text):
    """Natural-language heuristic = neural-scan trigger. Pure code is symbol-dense and excluded (the cost
    control), but structured PII in code is still caught by Tier-0 (which triggers neural on that field anyway)."""
    toks = text.split()
    if len(toks) < PROSE_MIN_WORDS:
        return False
    alpha = sum(1 for t in toks if any(c.isalpha() for c in t))
    if alpha < len(toks) * 0.6:
        return False
    code = sum(1 for c in text if c in _CODE_CHARS)
    return code <= len(text) * 0.03


def _chunks(text, size=600, overlap=80):
    """Window long fields so the NPU's 256-token cap never truncates away PII. Small overlap + the union
    merge handle an entity that straddles a boundary. Yields (offset, chunk_text)."""
    n = len(text)
    if n <= size:
        yield 0, text
        return
    i = 0
    while i < n:
        end = min(i + size, n)
        if end < n:
            j = text.rfind(' ', max(i + size - overlap, i + 1), end)
            if j > i:
                end = j
        yield i, text[i:end]
        if end >= n:
            break
        i = max(end - overlap, i + 1)


_DETECT_CACHE = OrderedDict()   # LRU: most-recently-used at the end
_CACHE_MAX = 4096


def _detect_cache_key(text, min_score):
    digest = hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()
    return digest, len(text), float(min_score)


async def _detect_against(aclient, gate_url, text, min_score):
    """Run the full chunked /detect against ONE gate. Returns offset-corrected spans, or raises on any failure
    (connection or HTTP). The whole text is scanned against a single gate so a mid-text failover cannot splice
    spans from two gates with divergent label sets."""
    allspans = []
    for off, chunk in _chunks(text):
        r = await aclient.post(gate_url + '/detect', json={'text': chunk, 'min_score': min_score})
        r.raise_for_status()
        for s in r.json().get('spans', []):
            sp = {'start': s['start'] + off, 'end': s['end'] + off, 'label': s['label'],
                  'tier': s.get('tier', 1), 'conf': s.get('conf', 0.5), 'rule': s.get('rule', 'npu')}
            for k in ('validator', 'cue', 'subtype', 'members'):
                if s.get(k) is not None:
                    sp[k] = s[k]
            allspans.append(sp)
    return allspans


def _is_connection_error(exc):
    """Distinguish 'gate unreachable' (fail over / degrade) from 'gate answered with an error' (a real fault we
    must NOT paper over by retrying a different gate). httpx raises ConnectError/ConnectTimeout/ReadTimeout/
    PoolTimeout etc. (all httpx.TransportError) when it never got a valid HTTP response; HTTPStatusError means a
    reachable gate returned 4xx/5xx."""
    return isinstance(exc, httpx.TransportError)


async def _detect_neural(aclient, text, min_score=0.5):
    """Call the neural gate /detect (chunked); offset spans back to field coords. Cache by a digest of text+score so
    repeating prompts / prior turns aren't re-scanned while raw text is not retained as a cache key. Returns spans,
    or None if the gate is unreachable (caller then keeps Tier-0 only and flags degraded).

    When GATEWAY_GATE_FALLBACK_URL is set and the PRIMARY gate is unreachable (connection-level, not an HTTP error),
    the whole detection is retried once against the fallback gate before giving up -- so a remote-primary outage
    degrades to the local base tier instead of failing the request closed."""
    key = _detect_cache_key(text, min_score)
    cached = _DETECT_CACHE.get(key)
    if cached is not None:
        _DETECT_CACHE.move_to_end(key)   # mark most-recently-used (LRU)
        return cached
    try:
        allspans = await _detect_against(aclient, GATE_URL, text, min_score)
    except Exception as e:
        use_fallback = GATE_FALLBACK_URL and GATE_FALLBACK_URL != GATE_URL and _is_connection_error(e)
        if not use_fallback:
            print(f"[gate /detect error] {type(e).__name__}", flush=True)   # never log text
            return None
        print(f"[gate /detect primary unreachable: {type(e).__name__}; failing over to fallback gate]", flush=True)
        try:
            allspans = await _detect_against(aclient, GATE_FALLBACK_URL, text, min_score)
        except Exception as e2:
            print(f"[gate /detect fallback error] {type(e2).__name__}", flush=True)   # never log text
            return None
    # LRU insert: keep the HOT working set resident instead of FREEZING at capacity. The old `if len < MAX` insert
    # guard stopped caching ENTIRELY once 4096 keys filled and never evicted, so a long-lived gateway went cold on
    # every field forever (a latency cliff -- repeated large system prompts / prior-turn text stopped hitting). Now
    # the least-recently-used entry is evicted instead. The dict ops are synchronous (no await between them) so they
    # are atomic on the single-threaded event loop even with concurrent detection; the key is a content hash so a
    # racing duplicate insert is idempotent.
    _DETECT_CACHE[key] = allspans
    _DETECT_CACHE.move_to_end(key)
    while len(_DETECT_CACHE) > _CACHE_MAX:
        _DETECT_CACHE.popitem(last=False)
    return allspans


# ----------------------------------------------------------------------------
# Prompt-cache freeze: keep Anthropic's cached prefix byte-stable across turns.
# ----------------------------------------------------------------------------
# Claude Code re-sends the WHOLE conversation (system prompt + memory + prior turns) with REAL PII every turn, so
# the proxy must re-redact it every turn. For Anthropic's prompt cache to HIT, the redacted prefix bytes must be
# IDENTICAL turn-over-turn. Per-value placeholders are already stable (entity_map), but the pass-3 known-value
# SWEEP applies the WHOLE entity map -- which GROWS across the session -- so a value first learned on a LATER turn
# gets retroactively swept into the otherwise-identical system/memory text, shifting the prefix bytes and busting
# the cache (the operator's "context balloons one shot / 5h usage climbs fast" symptom: the full ~100k prefix is
# re-processed every turn instead of cache-read).
#
# Fix ("redact once, freeze"): memoize each field's FINAL redacted text per (session, map-generation). The first
# time a field's exact source text is redacted in a session it runs the full pipeline and is stored; every later
# turn the SAME source text replays the stored bytes VERBATIM (skipping the growing sweep), so the prefix is
# byte-identical and the cache hits. Privacy is unchanged: already-sent content gains nothing from a re-sweep (it
# already went upstream when it was the live tail), and BRAND-NEW content (the latest user message + tool results)
# still gets the full current-map sweep. The map-created-ts in the key auto-invalidates the memo on map rotation /
# idle-expiry. In-memory, LRU-bounded; the key is a one-way hash and the value carries only placeholders -- raw
# PII is never stored. Disable with GATEWAY_FREEZE_PREFIX=0 (reverts to re-sweeping every field every turn).
FREEZE_PREFIX = os.environ.get('GATEWAY_FREEZE_PREFIX', '1') == '1'
_FREEZE_CACHE = OrderedDict()   # (session, project, gen, cfg, src_hash) -> final redacted text ; LRU, recent at end
_FREEZE_MAX = int(os.environ.get('GATEWAY_FREEZE_MAX', '4096'))


# `cfg` is the live-config fingerprint (RC3): folding it into the key means a config change -- mode toggle,
# allowlist/denylist edit, policy YAML edit -- INVALIDATES the memoized redaction for a re-sent field, so it is
# re-swept under the NEW policy instead of replaying stale bytes minted under the old one. The fingerprint is
# STABLE while config is unchanged (the mtimes/sig don't move), so a config-stable session keeps hitting the
# freeze and the Anthropic prompt-cache prefix stays byte-identical; only a real config change busts it.
def _freeze_key(session, project, gen, cfg, src):
    h = hashlib.sha256(src.encode('utf-8', 'surrogatepass')).hexdigest()
    return (session, project, gen, cfg, h)


def _freeze_get(session, project, gen, cfg, src):
    key = _freeze_key(session, project, gen, cfg, src)
    val = _FREEZE_CACHE.get(key)
    if val is not None:
        _FREEZE_CACHE.move_to_end(key)
    return val


def _freeze_put(session, project, gen, cfg, src, final):
    key = _freeze_key(session, project, gen, cfg, src)
    _FREEZE_CACHE[key] = final
    _FREEZE_CACHE.move_to_end(key)
    while len(_FREEZE_CACHE) > _FREEZE_MAX:
        _FREEZE_CACHE.popitem(last=False)


# ----------------------------------------------------------------------------
# Policy (SPECS §4): per-project + per-session PII config, secrets always on.
# Resolution: session override > project override > default. Config is mtime-watched (live edits).
# ----------------------------------------------------------------------------
CONFIG_PATH = os.environ.get('GATEWAY_CONFIG', os.path.expanduser('~/.ossredact/gateway-config.yaml'))
# operational labels excluded by DEFAULT (high-volume, low-sensitivity; redacting the WHOLE value adds noise + can
# degrade the coding assistant). 'filepath' is deliberately NOT blanket-excluded anymore: the model tags the whole
# absolute path, but _narrow_path_spans (GATEWAY_PATH_POLICY=username, the default) reduces a file_path span to JUST
# the home-dir username and passes the rest of the path through verbatim -- so agent file ops keep working WHILE the
# identity-bearing username is still protected. (Re-adding 'filepath' here forces full passthrough, equivalent to
# GATEWAY_PATH_POLICY=passthrough; GATEWAY_PATH_POLICY=full restores the legacy whole-path redaction.) 'username' (a
# bare model 'username' label, not the in-path case) stays excluded as low-sensitivity. organization is deliberately
# NOT excluded: the v11r9c+ model detects it reliably and leaking an employer/client defeats the firewall's purpose.
DEFAULT_EXCLUDE = ['username']
DEFAULT_CONFIG = {'secrets': {'enabled': True, 'entropy_backstop': True},
                  'pii': {'default': {'enabled': True, 'exclude': DEFAULT_EXCLUDE}, 'projects': {}, 'sessions': {}}}
# friendly category -> model/Tier-0 labels (for the optional restrictive allowlist + the exclude list)
CATEGORY_LABELS = {
    'person': ['person'], 'address': ['address'], 'phone': ['phone_number'], 'email': ['email'],
    'account': ['sensitive_account_id', 'account_number', 'bank_account', 'iban', 'routing_number'],
    'nas': ['government_id'], 'tax': ['tax_id'], 'card': ['payment_card', 'card_cvv', 'card_expiry'],
    'dob': ['date_of_birth'], 'date': ['sensitive_date'], 'postal': ['postal_code'], 'ip': ['ip_address'],
    'org': ['organization'], 'filepath': ['file_path'], 'username': ['username'],
    # 'uuid' (demoted from the account floor 2026-07-02): deterministic tier-0 catch, SOFT policy -- privacy
    # mode redacts it, coding/off pass it (session/request ids are load-bearing in agent traffic).
    'uuid': ['uuid'],
    # 'sensitive_ref' = a MODEL-claimed bank/account/government id with NO deterministic backstop (the
    # provenance-demoted floor labels, see demote_model_floor). Redacts in privacy AND coding, passes in off,
    # allowlist-exemptible, not merge-sticky, rehydrates into tool args.
    'ref': ['sensitive_ref'],
}
LABEL_CATEGORY = {lab: cat for cat, labs in CATEGORY_LABELS.items() for lab in labs}
_CONFIG = {}
_CONFIG_MTIME = -1
# The do-not-redact dictionary: user-declared known-safe VALUES (their name, own email, file paths) that
# are never redacted even when detected. Opt-in, default empty. Built from the config `allowlist:` key and/
# or a newline-delimited GATEWAY_ALLOWLIST_FILE. Live-refreshed on config mtime change (like the policy).
_ALLOWLIST = set()


# The UI-managed allowlist lives in a newline-delimited file (default ~/.ossredact/allowlist.txt, override with
# GATEWAY_ALLOWLIST_FILE). Editing it -- by hand or via the local settings UI at GET / -- is live-reloaded on the
# file's OWN mtime, so the gate picks up changes without a restart and without touching gateway-config.yaml.
_ALLOWLIST_FILE = os.environ.get('GATEWAY_ALLOWLIST_FILE') or os.path.expanduser('~/.ossredact/allowlist.txt')
_ALLOWLIST_MTIME = -1


def _read_allowlist_file():
    """The user-file values only (one per line, '#' = comment) -- exactly what the settings UI manages. [] if absent."""
    try:
        with open(_ALLOWLIST_FILE) as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith('#')]
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[allowlist file err] {type(e).__name__}", flush=True)
        return []


def _load_allowlist_values(cfg):
    # effective allowlist = the hand-written config `allowlist:` key UNION the UI-managed file.
    return list(cfg.get('allowlist') or []) + _read_allowlist_file()


def _refresh_allowlist_if_file_changed():
    """Rebuild _ALLOWLIST when the UI-managed file changes (its mtime is tracked separately from the config)."""
    global _ALLOWLIST, _ALLOWLIST_MTIME
    try:
        mt = os.path.getmtime(_ALLOWLIST_FILE)
    except OSError:
        mt = -1
    if mt != _ALLOWLIST_MTIME:
        _ALLOWLIST_MTIME = mt
        _ALLOWLIST = allowlist_mod.build_allow_set(_load_allowlist_values(_CONFIG or {}))


# The ALWAYS-redact dictionary (the INVERSE of the allowlist): user-declared terms/phrases that must ALWAYS
# be redacted even when no detector flags them -- internal project codenames, client names, hostnames the
# NER model does not recognize as PII. Opt-in, default empty. It ONLY ADDS redaction, so it can never weaken
# the floor. Built from the config `denylist:` key UNION a UI-managed GATEWAY_DENYLIST_FILE; compiled to one
# boundary-aware regex and live-refreshed when EITHER the file or the config changes (no restart).
_DENYLIST = None                # compiled re.Pattern | None (None == no terms declared)
_DENYLIST_FILE = os.environ.get('GATEWAY_DENYLIST_FILE') or os.path.expanduser('~/.ossredact/denylist.txt')
_DENYLIST_SIG = None            # (file_mtime, config_mtime) the compiled pattern was last built for


def _read_denylist_file():
    """The user-file terms only (one per line, '#' = comment) -- exactly what the settings UI manages. [] if absent."""
    try:
        with open(_DENYLIST_FILE) as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith('#')]
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[denylist file err] {type(e).__name__}", flush=True)
        return []


def _load_denylist_values(cfg):
    # effective denylist = the hand-written config `denylist:` key UNION the UI-managed file.
    return list(cfg.get('denylist') or []) + _read_denylist_file()


def _refresh_denylist_if_changed():
    """Recompile _DENYLIST when EITHER the UI-managed file OR the config changes (a single signature tuple
    tracks both, so editing gateway-config.yaml's `denylist:` key takes effect too)."""
    global _DENYLIST, _DENYLIST_SIG
    try:
        fmt = os.path.getmtime(_DENYLIST_FILE)
    except OSError:
        fmt = -1
    sig = (fmt, _CONFIG_MTIME)
    if sig != _DENYLIST_SIG:
        _DENYLIST_SIG = sig
        _DENYLIST = denylist_mod.compile_denylist(_load_denylist_values(_CONFIG or {}))


# ---------------------------------------------------------------------------
# Redaction MODE (privacy | coding | off) -- the one-switch UI toggle, read live from a tiny file the
# settings API manages. Applied as a global overlay in resolve_pii_policy:
#   privacy : redact ALL detected PII (default, strongest). Exception: bare dates/versions never redact at
#             the egress in any mode (wire-level date policy 2026-07-02; GATEWAY_REDACT_DATES=1 restores).
#   coding  : additionally let org / ip / uuid categories through (org->organization, ip->ip_address,
#             uuid->uuid) so a coding agent keeps framework names, bind/localhost IPs, and session/request
#             ids -- everything else (names, addresses, emails, phones, the floor) still redacts.
#   off     : pass SOFT PII (names/org/address/email/phone/...) through, for when redaction is in the way.
# CRITICAL: 'off' is NOT a credential bypass. The deterministic floor -- secrets, payment cards, bank/IBAN,
# government/tax IDs, DOB (FLOOR_NEVER_EXEMPT) -- is FORCE-redacted in every mode (policy_allows_pii returns
# True for those labels unconditionally), so no mode can ever leak a credential or money/government id.
_MODE_FILE = os.environ.get('GATEWAY_MODE_FILE') or os.path.expanduser('~/.ossredact/mode')
_MODES = ('privacy', 'coding', 'off')
_DEFAULT_MODE = 'privacy'


def current_mode():
    """The active redaction mode, read live from the mode file each call (one tiny word). Unknown/absent ->
    'privacy' (fail safe)."""
    try:
        with open(_MODE_FILE) as fh:
            m = fh.read().strip().lower()
        return m if m in _MODES else _DEFAULT_MODE
    except FileNotFoundError:
        return _DEFAULT_MODE
    except Exception as e:
        print(f"[mode file err] {type(e).__name__}", flush=True)
        return _DEFAULT_MODE


def _write_mode(mode):
    """Persist the mode atomically. Self-guards its invariant (defense in depth) even though the only caller
    already validates, so a stray writer can never persist an out-of-range mode."""
    if mode not in _MODES:
        raise ValueError(f'mode must be one of {_MODES}')
    os.makedirs(os.path.dirname(_MODE_FILE) or '.', exist_ok=True)
    tmp = _MODE_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(mode + '\n')
    os.replace(tmp, _MODE_FILE)


def load_config():
    global _CONFIG, _CONFIG_MTIME, _ALLOWLIST
    try:
        mt = os.path.getmtime(CONFIG_PATH)
        if mt != _CONFIG_MTIME:
            with open(CONFIG_PATH) as fh:
                _CONFIG = yaml.safe_load(fh) or {}
            _CONFIG_MTIME = mt
            _ALLOWLIST = allowlist_mod.build_allow_set(_load_allowlist_values(_CONFIG))
    except FileNotFoundError:
        if not _CONFIG:
            _CONFIG = DEFAULT_CONFIG
            _ALLOWLIST = allowlist_mod.build_allow_set(_load_allowlist_values({}))
    except Exception as e:
        print(f"[config load err] {type(e).__name__}", flush=True)
        if not _CONFIG:
            _CONFIG = DEFAULT_CONFIG
    return _CONFIG


_AUTH_FP_SALT = 'ossredact-session-tenant-v1'  # stable salt: namespaces map files per credential (not for secrecy)


def _auth_fingerprint(headers):
    """A short, stable per-CREDENTIAL discriminator from the upstream API key / Authorization header, used to
    namespace the system-prompt session fallback so two DIFFERENT credentials sharing an identical system prompt
    get SEPARATE entity maps (multi-tenant isolation -- a header-less client cannot guess + rehydrate another
    tenant's predictable placeholder). Returns '' when no credential is present (one shared key = one trust
    domain = prior behavior). The raw key is never stored -- only this hash, and only as a map-file namespace."""
    cred = headers.get('x-api-key') or headers.get('authorization') or ''
    if not cred:
        return ''
    return hashlib.sha256((_AUTH_FP_SALT + '\x00' + cred).encode('utf-8', 'ignore')).hexdigest()[:16]


def current_allowlist():
    """The active do-not-redact set (refreshes on config mtime change). The hard floor is NEVER allowlist-
    exempt (the caller guards FLOOR_NEVER_EXEMPT: credentials + card/account/government/tax/DOB) -- this
    list is for the user's own soft identifiers (name, email, file paths, organization, address)."""
    load_config()
    _refresh_allowlist_if_file_changed()
    return _ALLOWLIST


def current_denylist():
    """The active always-redact pattern (refreshes on config/file mtime change), or None when empty. These
    user terms are force-redacted even when the model misses them; they ONLY add redaction, never exempt."""
    load_config()
    _refresh_denylist_if_changed()
    return _DENYLIST


def _config_fingerprint():
    """A small hashable snapshot of the live redaction config (RC3): the mode word plus the mtimes/signature the
    policy YAML, allowlist, and denylist were last refreshed at. Folded into the FREEZE key so a config change
    invalidates memoized per-field redactions. Call AFTER current_allowlist()/current_denylist()/load_config()
    (which refresh these globals) so it reflects the request's config. Stable while config is unchanged -> the
    freeze keeps hitting and the upstream prompt-cache prefix stays byte-identical; only an edit moves it."""
    return (current_mode(), _CONFIG_MTIME, _ALLOWLIST_MTIME, _DENYLIST_SIG)


def _denylist_spans(text, pattern):
    """Always-redact dictionary hits in egress span shape: conf 1.0, tier 0, rule 'denylist' (so the
    already-token-exact match is NOT word-expanded). DENY_LABEL 'custom' -> a <CUSTOM_n> placeholder."""
    return [{'start': d['start'], 'end': d['end'], 'label': d['label'], 'conf': 1.0,
             'tier': 0, 'rule': 'denylist'} for d in denylist_mod.find_spans(text, pattern)]


def resolve_pii_policy(ctx):
    cfg = load_config().get('pii') or {}
    pol = dict(cfg.get('default') or {'enabled': True, 'exclude': DEFAULT_EXCLUDE})
    proj = (cfg.get('projects') or {}).get(ctx.get('project'))
    if proj:
        pol = {**pol, **proj}
    sess = (cfg.get('sessions') or {}).get(ctx.get('session_resolved') or ctx.get('session'))
    if sess:
        pol = {**pol, **sess}
    # Global MODE overlay (applied last so the UI toggle always wins over config defaults). 'off' disables
    # soft-PII redaction wholesale (the floor stays -- see policy_allows_pii); 'coding' lets organizations,
    # dates/versions AND IP addresses through; 'privacy' is the default (no change). The floor is never affected.
    mode = current_mode()
    if mode == 'off':
        pol = {**pol, 'enabled': False}
    elif mode == 'coding':
        # Coding-agent traffic is dense with NON-PII tokens the prose model / tier-0 mistake for soft PII:
        # organizations (frameworks / vendors), dates that are timestamps / copyright years / log dates / semver
        # like 2.4.11 (DATE_RE cannot tell those from a D.M.YY date by value, RC5), and IP literals that are bind
        # / localhost / config addresses (0.0.0.0, 127.0.0.1, ::1). Redacting them mangles diffs, version checks,
        # config, and networking code. Let those CATEGORIES through (org->organization, date->sensitive_date,
        # ip->ip_address), plus 'uuid' (2026-07-02): session/request ids are load-bearing in agent traffic --
        # redacting them broke file ops and churned the prompt cache while identifying nobody by themselves.
        # The hard floor is untouched -- date_of_birth and every credential / card / account /
        # gov-id stay FLOOR_NEVER_EXEMPT and redact in coding mode -- and privacy mode still redacts all of these.
        extra = [c for c in ('org', 'date', 'ip', 'uuid') if c not in (pol.get('exclude') or [])]
        if extra:
            pol = {**pol, 'exclude': list(pol.get('exclude') or []) + extra}
    # WIRE-LEVEL DATE POLICY (operator decision 2026-07-02): bare dates/versions (label sensitive_date) are
    # never redacted at the egress, in ANY mode. On real agent traffic they are the highest-volume false-
    # positive class (ISO/log/changelog dates, YYYYMMDD build stamps, and semver like 2.4.11 that DATE_RE
    # cannot tell from a D.M.YY date by value -- RC5), and every mint burns map entries + placeholder buffer
    # for no defensible privacy gain: a bare date identifies nobody without the surrounding facts, which are
    # what actually get redacted. The Workbench keeps its own date filter (user-toggleable + revertible there;
    # this policy is appliance-only). date_of_birth is a FLOOR label and untouched by this exclude. Values
    # already minted as sensitive_date stop being swept on the next request (_sweep_keeps honors this policy).
    # Escape hatch: GATEWAY_REDACT_DATES=1 restores the old mode-scoped behavior (privacy mode redacts dates).
    if not REDACT_DATES:
        excl = pol.get('exclude') or []
        if 'date' not in excl:
            pol = {**pol, 'exclude': list(excl) + ['date']}
    return pol


def policy_allows_pii(label, ctx):
    """Default: redact every detected PII label EXCEPT the exclude list (so no sensitive label is silently
    dropped). The deterministic floor always redacts. An optional `categories` allowlist makes it restrictive."""
    # The hard floor (secrets + payment cards + bank/IBAN + government/tax IDs + DOB) is force-redacted in
    # EVERY mode/policy: no exclude, no `enabled:false`, and no 'off' mode can ever leak a credential or a
    # money/government identifier. This enforces the FLOOR_NEVER_EXEMPT invariant at the policy layer too
    # (it was already non-exempt to the user allowlist).
    if label in FLOOR_NEVER_EXEMPT:
        return True
    # The user ALWAYS-redact dictionary (label 'custom') is force-redacted in every mode too: a term the user
    # declared must-redact must not be releasable by 'off' mode or an exclude list (it only ever adds redaction).
    if label == denylist_mod.DENY_LABEL:
        return True
    pol = resolve_pii_policy(ctx)
    if not pol.get('enabled', True):
        return False
    cat = LABEL_CATEGORY.get(label, label)
    excl = pol.get('exclude')
    if excl is not None and (label in excl or cat in excl):
        return False
    cats = pol.get('categories')          # optional restrictive allowlist (redact ONLY these)
    if cats is not None:
        return label in cats or cat in cats
    return True


def _sweep_keeps(value, ph, ctx, allow, pol=None):
    """Pass-3 cross-turn sweep veto (RC3), mirroring the pass-2 span policy so a mode toggle / allowlist edit
    takes effect on values ALREADY in the session map -- instead of the sweep eternally replaying a placeholder
    minted under an older policy. Keep replaying value->ph only if the placeholder's own label is still
    redactable under the current policy/mode AND the value is not user-allowlisted. The hard floor is never
    exempt: policy_allows_pii returns True for FLOOR_NEVER_EXEMPT, and the allowlist check skips floor labels, so
    a credential / card / gov-id / DOB minted earlier keeps being swept in every mode.

    MIGRATION GUARD (adversarial review 2026-07-02): live session maps minted BEFORE the fat-floor diet hold
    floor placeholders for values the diet no longer floors -- <SENSITIVEACCOUNTID_n> over a UUID or a whole
    file path. By label alone those are FLOOR_NEVER_EXEMPT and would sweep forever, silently defeating the
    uuid demotion and re-creating the Write(<placeholder>/bench2.py) incident for every session that spans
    the upgrade. Mirror demote_model_floor at the map boundary, scoped to the IDENTITY labels only (a
    credential/card/gov placeholder is never value-shape exempted): UUID-valued -> evaluate under the 'uuid'
    policy (passes in coding/off, still sweeps in privacy); path-shaped -> stop sweeping (fresh pass-2
    narrowing re-owns the path's username per request)."""
    label = _ph_label(ph)
    if label in _UUID_RELABEL:
        if UUID_RE.fullmatch(value):
            label = 'uuid'
        elif _path_shaped(value):
            return False
    allows = pol if pol is not None else (lambda lbl: policy_allows_pii(lbl, ctx))
    if not allows(label):
        return False
    if label not in FLOOR_NEVER_EXEMPT and allow and allowlist_mod.is_allowlisted(value, allow):
        return False
    return True


# Person/org names carry internal hyphens + apostrophes (Marie-Eve, O'Neil, Hydro-Quebec); treat those as
# word-internal so an expanded span covers the whole name. Other labels expand across alphanumerics only.
_NAME_CONNECTORS = {'person': "-'’", 'organization': "-'’"}


def expand_word_spans(text, spans):
    """Grow a NEURAL span to its full surrounding word. The model can tag only SOME subword tokens of an
    ALLCAPS / accented word (e.g. only 'G' of 'GENEVIEVE', only the accented vowel of 'BELANGER'), which would
    leave the rest of a real name/value LITERAL after substitution -- a silent partial leak on exactly the
    French/Quebec text this firewall targets (reproduced: 'GENEVIEVE' -> '<PERSON>ENEVIEVE'). If any subword of
    a word is PII, the whole word is PII, so expand to the word boundary (alnum + name-internal hyphen/apostrophe
    for person/org). Tier-0 floor spans are already exact and are left untouched. Safe direction: expansion only
    ever covers MORE, never less; overlaps it creates are unioned by merge_spans immediately after."""
    n = len(text)
    out = []
    for s in spans:
        if s.get('tier') == 2 or str(s.get('rule', '')).startswith('gpu'):
            extra = _NAME_CONNECTORS.get(s['label'], '')
            a, b = s['start'], s['end']
            while a > 0 and (text[a - 1].isalnum() or text[a - 1] in extra):
                a -= 1
            while b < n and (text[b].isalnum() or text[b] in extra):
                b += 1
            if (a, b) != (s['start'], s['end']):
                s = {**s, 'start': a, 'end': b}
        out.append(s)
    return out


def substitute(text, spans, emap, ctx):
    """Replace span VALUES with stable placeholders via the session entity map. Secret spans always redact;
    PII spans honor policy. Returns (redacted_text, n_redacted)."""
    return redact_core.redact_text(text, spans, emap, lambda label: policy_allows_pii(label, ctx))


# A value under a secret-NAMED key is a credential even with no text cue / no '='/':' the text secret-floor needs.
# Specific key names only (no bare `token`, which matches token_count/token_type usage fields).
_SECRET_KEY_RE = re.compile(
    r'(?i)(?:^|[_\-.])(?:passw(?:or)?d|pwd|secret|secret[_-]?key|api[_-]?key|apikey|access[_-]?key|'
    r'access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|authorization|client[_-]?secret|'
    r'private[_-]?key|motdepasse|mot[_\-.]?de[_\-.]?passe|mdp|jeton|'
    r'pin|account[_-]?pin|card[_-]?pin|nip|passcode|pass[_-]?code|otp)(?:$|[_\-.])')


def _is_secret_key(k):
    return isinstance(k, str) and _SECRET_KEY_RE.search(k) is not None


# Card-COMPONENT key names (PAN / CVV / expiry). A value under such a key IS card data even with no text cue --
# e.g. tool_use.input {"card_expiry": "11/29"} or {"cvv": "123"}: the cue is the KEY NAME, which the text floor
# never sees, so a bare MM/YY or 3-digit value slipped the floor. Force-redact to the matching card_* floor label.
_CARD_KEY_RE = re.compile(
    r'(?i)(?:^|[_\-.])(?:card[_-]?(?:number|num|no|pan)|cardnumber|pan|'
    r'cvv2?|cvc2?|card[_-]?cvv|card[_-]?cvc|security[_-]?code|sec[_-]?code|cvv[_-]?code|'
    r'card[_-]?expir(?:y|ation)?|exp[_-]?date|expir(?:y|ation)|card[_-]?exp)(?:$|[_\-.])')


# Identity key NAMES: a value (numeric OR string) under these is a government ID / birth date even with no text
# cue -- e.g. tool args {"ssn": 123456789} or {"dob": "1980-04-12"}. The key is the only signal the text floor
# never sees. Boundary-anchored on key separators so 'using'/'business'/'canvas' never match the segments.
_GOVID_KEY_RE = re.compile(r'(?i)(?:^|[_\-.])(?:ssn|sin|nas|social[_-]?security(?:[_-]?(?:number|no))?|'
                           r'national[_-]?id|numero[_-]?assurance[_-]?sociale)(?:$|[_\-.])')
_DOB_KEY_RE = re.compile(r'(?i)(?:^|[_\-.])(?:dob|date[_-]?of[_-]?birth|birth[_-]?date|birthdate|'
                         r'date[_-]?de[_-]?naissance)(?:$|[_\-.])')


def _sensitive_key_label(k):
    """Return the hard-FLOOR label for a sensitive-NAMED key (so its value is force-redacted regardless of the
    value's own shape), or None. Secret credentials -> 'secret'; card components -> card_cvv/card_expiry/payment_card;
    gov-ID keys -> 'government_id'; birth-date keys -> 'date_of_birth'."""
    if not isinstance(k, str):
        return None
    if _SECRET_KEY_RE.search(k):
        return 'secret'
    if _CARD_KEY_RE.search(k):
        kl = k.lower()
        if 'cvv' in kl or 'cvc' in kl or 'sec' in kl:
            return 'card_cvv'
        if 'exp' in kl:
            return 'card_expiry'
        return 'payment_card'
    if _GOVID_KEY_RE.search(k):
        return 'government_id'
    if _DOB_KEY_RE.search(k):
        return 'date_of_birth'
    return None


def force_redact_secret_keys(node, emap):
    """Force-redact a STRING value sitting under a sensitive-NAMED key (credentials: password/api_key/secret/
    auth_token/... incl French motdepasse/mdp/jeton; AND card components: card_number/cvv/card_expiry) to the
    matching floor placeholder. Covers the tool_use.input / function_call.arguments leak: {"input": {"password":
    "R00tPass!verySecret2"}} or {"card_expiry": "11/29"} carries no cue the text floor can latch onto.

    Also descends into a JSON OBJECT/ARRAY ENCODED AS A STRING -- OpenAI/Codex tool_calls.arguments and
    function_call.arguments are JSON-in-a-string, an unscanned blind spot where an opaque credential under a
    secret key (no pattern, no cue) reaches upstream verbatim. Such a string is parsed, recursed, and
    re-serialized ONLY when a redaction happened inside (non-JSON strings are never touched).

    Sensitive keys are never request-structural (routing ids are separate), so this is leak-safe; a schema
    property DEFINITION is a dict value (not a string) and is skipped. Already-redacted values (any placeholder
    present) are left alone. Mutates `node` in place; returns the count redacted."""
    n = 0
    if isinstance(node, dict):
        for k, v in list(node.items()):
            lab = _sensitive_key_label(k)
            if lab and isinstance(v, (int, float)) and not isinstance(v, bool):
                # A NUMERIC value under a sensitive key -- {"cvv": 834}, {"card_number": 4539148803436467},
                # {"password": 12345678}, {"ssn": 123456789}. JSON numbers carry no text cue and the str-only
                # path below skipped them, so the digits shipped to the upstream verbatim (the A1 tool-args leak).
                # Coerce to str and force-redact to the key's floor label.
                ph, _ = emap.placeholder_for(str(v), lab)
                node[k] = ph
                n += 1
            elif isinstance(v, str) and v.strip() and lab and not _PH_TOKEN_RE.search(v):
                ph, _ = emap.placeholder_for(v, lab)
                node[k] = ph
                n += 1
            elif isinstance(v, str):
                vs = v.lstrip()
                if vs[:1] in ('{', '['):   # a JSON object/array carried as a string (tool-call arguments)
                    try:
                        parsed = json.loads(v)
                    except Exception:
                        parsed = None
                    if isinstance(parsed, (dict, list)):
                        cnt = force_redact_secret_keys(parsed, emap)
                        if cnt:
                            node[k] = json.dumps(parsed)
                            n += cnt
            else:
                n += force_redact_secret_keys(v, emap)
    elif isinstance(node, list):
        for item in node:
            n += force_redact_secret_keys(item, emap)
    return n


build_known_re = redact_core.build_known_re
sweep_known = redact_core.sweep_known


async def redact_body(body, ctx, extract=extract_text_fields, detector=None):
    """Mutate body in place; return (meta, replay). replay = placeholder->value for response rehydration.
    `extract` selects the request schema (Anthropic default; openai_adapter.extract_text_fields_openai for the
    OpenAI route). detector is an optional async callable/object with detect(text, min_score). NEVER logs/returns
    PII or secret VALUES (except replay, gated behind dryrun+EXPOSE_MAP)."""
    fields = extract(body)
    per_field = []
    any_scannable = False     # any extracted field carries non-trivial text (stripped len >= the pass-1 floor)
    sys_text = ''
    for f in fields:
        t = f.text
        if f.kind == 'system' and not sys_text:
            sys_text = t
        t0 = cheap_gate(t)
        # 'system' is prose-eligible too: `instructions` and system/developer input content are natural-language
        # prose. (prose is no longer the neural-scan trigger -- see pass 1 -- but kept as metadata for clarity.)
        prose = f.kind in ('message', 'tool_result', 'system') and _looks_like_prose(t)
        if len(t.strip()) >= 2:
            any_scannable = True
        per_field.append((f, t, t0, prose))

    session = derive_session(ctx.get('session', ''), sys_text, ctx.get('auth_fp', ''))
    ctx['session_resolved'] = session
    project = ctx.get('project', 'default')
    # truly-nothing fast-path: ONLY when there are literally zero non-empty extracted text fields. A request with
    # ANY scannable field is neural-scanned below (FIX 2): an NER-only name (no Tier-0 hit, below the prose-length
    # bar -- e.g. a 2-word name in a short field) must NOT skip the scan. has_known (prior session entities to
    # backstop) is consulted ONLY on this no-scannable-fields branch, so on the COMMON path (any scannable text)
    # we skip the file lock + full session-map load/decrypt here entirely -- pass 2 re-loads the map under the lock
    # authoritatively anyway, so nothing but this empty-body decision ever depended on the early read. (perf)
    if not any_scannable:
        # Load only long enough to decide the true empty fast-path; release the lock immediately (no awaited
        # detector calls happen on this branch). When prior session entities exist we still fall through to the
        # full mint/sweep pass below to backstop any in-request repeats.
        with map_file_lock(session, project):
            has_known = bool(EntityMap(session, project).v2p)
        if not has_known:
            # FAIL-CLOSED backstop (prime directive): a body that surfaced ZERO scannable text fields but still
            # carries a deterministic SECRET in some shape the walker did not recognize must NOT be forwarded raw.
            # Scan the serialized body for the secret floor; on a hit, raise -> _redact_or_block returns 503
            # (refuse) instead of leaking. Secret-floor precision (keyword/provider/entropy + benign filter) keeps
            # structural JSON from false-blocking. Last line behind the input_text/array/unknown-block coverage.
            if secret_spans(json.dumps(body, ensure_ascii=False)):
                raise RuntimeError('fail-closed: unscannable body shape carries a secret')
            return {'n_fields': len(fields), 'redaction': 'skip', 'n_spans': 0}, {}

    allow = current_allowlist()   # user do-not-redact values (secrets stay non-exempt below)
    deny = current_denylist()     # user always-redact terms (force-redacted even when the model misses them)

    async def collect_detected_fields(detect_text):
        # Detection is READ-ONLY (the entity map is only mutated in pass 2, under the file lock) and every field is
        # scanned independently, so the per-field neural calls run CONCURRENTLY under a bounded semaphore instead of
        # one serial /detect round-trip after another. Results are reassembled in the ORIGINAL field order so pass-2
        # placeholder minting is byte-identical to the serial version (order drives <LABEL_NNN> numbering, which must
        # not change or the redacted prefix diverges turn-to-turn and busts the upstream prompt cache).
        sem = asyncio.Semaphore(DETECT_CONCURRENCY)

        async def process_field(fi, f, t, t0):
            spans = list(t0)
            # NER-only PII (a NAME with no Tier-0 regex fallback) leaks if a SHORT non-prose field (e.g. a 2-word
            # name "Jane Roy" in a short tool description or a short arg value) is never neural-scanned. The
            # EXTRACTOR already decided every surfaced field is redactable free text; that decision -- not a
            # prose-length heuristic -- drives scanning. So neural-scan EVERY field carrying non-trivial text
            # (stripped length above a tiny floor), regardless of Tier-0/prose. (Tier-0 hits still scan too.)
            if len(t.strip()) >= 2:
                async with sem:
                    neural = await detect_text(t)
                if neural is None:
                    # gate unreachable: keep Tier-0 spans for this field and FLAG degraded. Tier-0 still redacts
                    # what it can (so this stays rehydratable), but an NER-only name with no Tier-0 fallback is NOT
                    # masked here -- the route FAILS CLOSED on meta['degraded'] (see _degraded_block) rather than
                    # forwarding the unredacted body upstream (FIX-ROUND-3 HIGH). Default-on; GATEWAY_FAIL_OPEN=1
                    # opts back into Tier-0-only egress when availability must win over the NER-only-PII risk.
                    ctx['_degraded'] = True
                else:
                    if neural:
                        spans += neural
                    # carrier-wrap booster (plan 026 option A): the model returns ZERO person spans for a RARE
                    # name in a BARE structural value (a JSON value / short tool-arg) -- no surrounding prose to
                    # cue it, and there is NO Tier-0 name floor, so it would leak. When a short name-shaped value
                    # drew no person from the bare scan, re-scan it inside a prose carrier and map the verdict
                    # back to the value's own offsets. Detection-only (redaction still targets the real value).
                    # Holding `sem` across the carrier scan keeps total in-flight /detect calls bounded.
                    stripped = t.strip()
                    if name_shaped(stripped) and not any(s.get('label') == 'person' for s in neural):
                        lead = len(t) - len(t.lstrip())
                        async with sem:
                            carrier_spans = await carrier_person_spans(lambda x: detect_text(x), stripped)
                        if carrier_spans is None:
                            ctx['_degraded'] = True
                        else:
                            for s in carrier_spans:
                                s['start'] += lead
                                s['end'] += lead
                                spans.append(s)
            dspans = _denylist_spans(t, deny)
            if not spans and not dspans:
                return None
            # fat-floor diet (2026-07-02): strip unearned floor privilege off MODEL spans BEFORE merge_spans,
            # so a junk model label can never become merge-sticky / un-allowlistable / tool-arg-withheld.
            # Tier-0 spans pass through untouched (the deterministic floor is never weakened).
            spans = demote_model_floor(spans, t)
            spans = _narrow_path_spans(spans, t)  # file_path over-redaction precision (GATEWAY_PATH_POLICY)
            spans = expand_word_spans(t, spans)   # cover the whole word when the model tagged only a fragment
            spans = post_merge_address(merge_spans(spans), t)
            spans = [s for s in spans if not _BENIGN_HASH.fullmatch(t[s['start']:s['end']])]  # allowlist hashes
            if allow:
                # user do-not-redact dictionary: drop spans whose exact text the user declared safe, so the
                # value passes through verbatim (never minted -> never swept -> never case-mangled). The hard
                # floor (credentials + card/account/government/tax/DOB) is NEVER exempt -- FLOOR_NEVER_EXEMPT.
                spans = [s for s in spans if s['label'] in FLOOR_NEVER_EXEMPT
                         or not allowlist_mod.is_allowlisted(t[s['start']:s['end']], allow)]
            if dspans:
                # user ALWAYS-redact dictionary: injected AFTER the allowlist filter so an always-redact term
                # WINS over a do-not-redact one, and re-merged so it unions with any overlap. Floor stays sticky
                # (a denylisted value that is also a card stays labeled payment_card). Deterministic -> these
                # terms are caught even when the neural gate is down (degraded), extending the fail-closed floor.
                spans = post_merge_address(merge_spans(spans + dspans), t)
            if spans:
                return (fi, f, t, spans)
            return None

        # asyncio.gather preserves input order, so filtering None yields detected_fields in ascending fi order --
        # identical to the serial loop -> deterministic pass-2 minting.
        results = await asyncio.gather(*[
            process_field(fi, f, t, t0) for fi, (f, t, t0, prose) in enumerate(per_field)])
        return [r for r in results if r is not None]

    # pass 1: detect (Tier-0 + targeted neural). Substitution waits until pass 2, under the map file lock.
    if detector is None:
        async with httpx.AsyncClient(timeout=60) as aclient:
            async def detect_text(text, min_score=0.5):
                return await _detect_neural(aclient, text, min_score)
            detected_fields = await collect_detected_fields(detect_text)
    else:
        if hasattr(detector, 'detect'):
            async def detect_text(text, min_score=0.5):
                return await detector.detect(text, min_score)
        else:
            async def detect_text(text, min_score=0.5):
                return await detector(text, min_score)
        detected_fields = await collect_detected_fields(detect_text)

    by_label = {}
    by_rule = {}
    explain_recs = []
    total = 0
    # pass 2: mutate the entity map and body under one inter-process map lock so concurrent fresh EntityMap
    # instances cannot clobber each other's load->mint->save cycles.
    with map_file_lock(session, project):
        emap = EntityMap(session, project)
        # pass 2a: sensitive-NAMED-key backstop FIRST, while keys are still intact. A credential/card value
        # under a key the text-floor can't cue (tool_use.input password/mdp/card_expiry, tool_calls.arguments
        # creds incl. JSON-string args) is force-redacted here -- BEFORE field substitution, because the NER can
        # tag the KEY itself (e.g. 'mdp'/'card_expiry' -> organization) and pass 2 would rewrite the key, after
        # which a key-name backstop would miss the value entirely (a confirmed leak). Mints into the map so the
        # pass-3 sweep also catches any other occurrence.
        n_keyed = force_redact_secret_keys(body, emap)
        if n_keyed:
            total += n_keyed
            by_label['secret'] = by_label.get('secret', 0) + n_keyed
            by_rule['secret:keyed'] = by_rule.get('secret:keyed', 0) + n_keyed

        for fi, f, t, spans in detected_fields:
            red, n = substitute(t, spans, emap, ctx)
            if red != t:
                f.write(red)
                total += n
                for s in spans:
                    by_label[s['label']] = by_label.get(s['label'], 0) + 1
                    by_rule[s.get('rule', '?')] = by_rule.get(s.get('rule', '?'), 0) + 1
                if EXPLAIN:
                    for rec in explain(spans):
                        rec['field'] = fi
                        explain_recs.append(rec)

        # pass 3: known-entity backstop with the now-complete map (catches model misses, cross-turn + in-request),
        # then FREEZE each field's final redacted bytes for this session so a re-sent prefix replays verbatim next
        # turn (Anthropic prompt-cache stability -- see _FREEZE_CACHE). A field whose exact source text was already
        # redacted this session+generation replays the stored output and SKIPS the growing sweep; brand-new text
        # runs the full sweep and is then memoized. Degraded turns (gate unreachable -> fail-closed) are never
        # memoized, so a partial redaction can't be frozen and replayed.
        n_swept = 0
        gen = emap.created
        cfg = _config_fingerprint()   # RC3: invalidates the freeze on any mode / allow / deny / policy change
        degraded = bool(ctx.get('_degraded'))
        can_freeze = FREEZE_PREFIX and not degraded
        orig_by_id = {id(fo): to for (fo, to, _t0, _pr) in per_field}
        # Values tagged under a REAL (non-file_path) PII label this request. A path username that collides exactly
        # with one of these (e.g. an NER-tagged lowercase person 'mason') must stay in the sweep even though the
        # path mint gave it a file_path placeholder, so an untagged recurrence elsewhere cannot leak (see redact_core).
        keep_values = {t[s['start']:s['end']] for (_fi, _f, t, spans) in detected_fields
                       for s in spans if not _is_filepath_label(s.get('label'))}
        # RC3: the cross-turn sweep must honor CURRENT policy/allowlist, else a value minted under an older mode
        # (e.g. an org minted in privacy) is replayed to its placeholder forever -- undoing what pass-2 correctly
        # let through after a 'coding' toggle, and ignoring a value the user just allowlisted. keep_sweep mirrors
        # the pass-2 span policy via the placeholder's own label; the hard floor is never exempt.
        # PERF (review 2026-07-02): policy resolution is constant within one request but keep_sweep runs once
        # per map entry per unfrozen field (a migrated 3k-entry map x 100 fields paid ~5us each in mode-file
        # stats + dict copies = seconds on the first post-restart turn). Memoize per label for this request;
        # the config fingerprint above already pins the policy for the whole pass.
        _pol_memo = {}
        def _pol_cached(label):
            got = _pol_memo.get(label)
            if got is None:
                got = _pol_memo[label] = policy_allows_pii(label, ctx)
            return got
        keep_sweep = lambda value, ph: _sweep_keeps(value, ph, ctx, allow, _pol_cached)
        known_re = build_known_re(emap, keep_values=keep_values, keep_placeholder=keep_sweep)
        for f in fields:
            src = orig_by_id.get(id(f))
            if can_freeze and src is not None:
                frozen = _freeze_get(session, project, gen, cfg, src)
                if frozen is not None:
                    if f.text != frozen:
                        f.write(frozen)          # replay first-sight redaction -> prefix bytes stay identical
                    continue
            if known_re is not None:
                red2, kn = sweep_known(f.text, known_re, emap, keep_values=keep_values, keep_placeholder=keep_sweep)
                if kn:
                    f.write(red2)
                    n_swept += kn
            if can_freeze and src is not None:
                _freeze_put(session, project, gen, cfg, src, f.text)

        total += n_swept
        # Save on redaction, OR touch-save a long-lived active session so its idle-TTL clock advances even
        # across PII-free turns (otherwise an in-use session idle-expires and every placeholder re-mints =
        # prompt-cache miss). needs_touch() is debounced, so clean turns do not write on every request.
        if total or emap.needs_touch():
            emap.save()
        meta = {'n_fields': len(fields),
                'redaction': 'redacted' if total else 'scanned-clean',
                'n_spans': total, 'n_new': emap.new_this_load, 'n_swept': n_swept,
                'n_map_total': len(emap.p2v), 'by_label': by_label, 'by_rule': by_rule,
                'degraded': ctx.get('_degraded', False)}
        if EXPLAIN:
            meta['explain'] = explain_recs   # per-span provenance, no values (Presidio decision-process analogue)
        # Scope replay to placeholders that ACTUALLY appear in the outbound body. The upstream model can only
        # emit a placeholder it received, so this is sufficient for rehydration (incl. cross-turn -- re-sent
        # history carries its placeholders) while preventing a SHARED session map (e.g. two header-less clients
        # that hash to the same sys-prompt session) from rehydrating values THIS request never sent. Fail-safe:
        # an unknown placeholder stays raw, never rehydrates to another flow's value.
        full_replay = emap.replay()
        present = set(_PH_TOKEN_RE.findall(json.dumps(body, ensure_ascii=False)))
        replay = {ph: full_replay[ph] for ph in present if ph in full_replay}
        evicted_present = sorted(ph for ph in getattr(emap, 'evicted_this_load', set()) if ph in present)
        if evicted_present:
            meta['map_evicted_present'] = evicted_present
            meta['map_evicted_present_count'] = len(evicted_present)
    return meta, replay


# ----------------------------------------------------------------------------
# Response rehydration (non-streaming here; S6 adds the SSE variant). Walk the
# Anthropic response: text blocks + tool_use inputs -> swap placeholders back to
# real values, so the LOCAL client writes/displays the real data.
# ----------------------------------------------------------------------------
def rehydrate_text(s, replay):
    return redact_core.rehydrate(s, replay)


def _rehydrate_json(v, replay, tool_replay=None, floor_safe=False, withheld=None):
    # B5 Half A: `floor_safe` marks that we are inside a tool-call ARGUMENT subtree (an Anthropic tool_use /
    # server_tool_use block's `input`, recursively). In that subtree we rehydrate with `tool_replay` -- the map
    # with FLOOR/secret-class tokens withheld -- so a secret left in an executed tool argument stays the inert
    # <LABEL_NNN> literal instead of the real value. Assistant TEXT and tool RESULTS keep the full `replay`.
    # `withheld` (optional set, 2026-07-02): collects the tokens that suppression left literal in tool-arg
    # output, so the caller can surface a 'tool_arg_withheld' live event instead of the agent receiving an
    # inert token SILENTLY (the Write(<SENSITIVEACCOUNTID_004>/...) incident). Observation only -- it never
    # changes what is rehydrated. (Withheld tokens in rehydrated KEYS are not tallied -- a floor token as an
    # object key is not a value the agent executes; accepted blind spot.)
    if tool_replay is None:
        tool_replay = tool_arg_policy.tool_arg_replay(replay)
    if isinstance(v, str):
        if floor_safe:
            out = rehydrate_text(v, tool_replay)
            if withheld is not None:
                withheld.update(_withheld_tokens(out, replay, tool_replay))
            return out
        return rehydrate_text(v, replay)
    if isinstance(v, list):
        return [_rehydrate_json(x, replay, tool_replay, floor_safe, withheld) for x in v]
    if isinstance(v, dict):
        # OPAQUE REASONING block: never rehydrate a thinking/redacted_thinking block. Its `thinking` text is
        # covered by the `signature` MAC and the client re-sends the block verbatim next turn; rehydrating it
        # would inject REAL PII into a signed block, which (a) is forwarded upstream as-is (the gate no longer
        # redacts thinking) and (b) desyncs content<->signature on the re-send. The block only carries
        # placeholders generated from already-redacted input, so passing it through untouched loses nothing.
        # STRUCTURAL match (not a bare type=='thinking' check): a real thinking block always carries the
        # `signature` MAC, and a redacted_thinking block the opaque `data` blob. Requiring that field means a
        # coincidental tool-argument sub-object literally tagged {"type":"thinking", ...} (with no signature) is
        # still rehydrated normally instead of being left as a placeholder -- the walk runs at arbitrary depth.
        _bt = v.get('type')
        if ((_bt == 'thinking' and isinstance(v.get('signature'), str))
                or (_bt == 'redacted_thinking' and isinstance(v.get('data'), str))):
            return v
        # A tool_use/server_tool_use block: its `input` subtree is the EXECUTED tool argument -> floor-suppress
        # it (but NOT an echoed result subtree). Once floor_safe, it propagates to every nested value.
        node_is_call = (not floor_safe) and tool_arg_policy.is_tool_call_node(v)
        key_replay = tool_replay if floor_safe else replay
        rebuilt = {}
        for k, x in v.items():
            # Key-based (is_tool_arg_key) catches an `input`/`arguments` argument whose block type is not matched
            # by is_tool_call_node (Anthropic's mcp_tool_use block); type-based catches tool_use/server_tool_use.
            child_fs = (floor_safe or tool_arg_policy.is_tool_arg_key(k)
                        or (node_is_call and not tool_arg_policy.is_tool_result_key(k)))
            nk = rehydrate_text(k, key_replay) if isinstance(k, str) else k
            if nk in rebuilt and nk != k:
                nk = _disambiguate_key(nk if isinstance(nk, str) else k, rebuilt, k)
            rebuilt[nk] = _rehydrate_json(x, replay, tool_replay, child_fs, withheld)
        return rebuilt
    return v


def _disambiguate_key(new_key, node, old_key):
    if new_key not in node or new_key == old_key:
        return new_key
    n = 1
    candidate = '{}.dup{}'.format(new_key, n)
    while candidate in node and candidate != old_key:
        n += 1
        candidate = '{}.dup{}'.format(new_key, n)
    return candidate


class _DupObj:
    __slots__ = ('pairs',)

    def __init__(self, pairs):
        self.pairs = [list(p) for p in pairs]


def _dup_preserving_pairs(pairs):
    seen = set()
    has_dup = False
    for k, _ in pairs:
        if k in seen:
            has_dup = True
            break
        seen.add(k)
    if has_dup:
        return _DupObj(list(pairs))
    return dict(pairs)


def _dump_rehydrated_dup_safe(v, replay):
    if isinstance(v, _DupObj):
        parts = []
        for k, x in v.pairs:
            nk = rehydrate_text(k, replay) if isinstance(k, str) else k
            parts.append(json.dumps(nk, ensure_ascii=False) + ': ' + _dump_rehydrated_dup_safe(x, replay))
        return '{' + ', '.join(parts) + '}'
    if isinstance(v, dict):
        seen_keys = set()
        parts = []
        for k, x in v.items():
            nk = rehydrate_text(k, replay) if isinstance(k, str) else k
            if nk in seen_keys:
                nk = _disambiguate_key(nk if isinstance(nk, str) else k, {kk: None for kk in seen_keys}, k)
            seen_keys.add(nk)
            parts.append(json.dumps(nk, ensure_ascii=False) + ': ' + _dump_rehydrated_dup_safe(x, replay))
        return '{' + ', '.join(parts) + '}'
    if isinstance(v, list):
        return '[' + ', '.join(_dump_rehydrated_dup_safe(x, replay) for x in v) + ']'
    if isinstance(v, str):
        return json.dumps(rehydrate_text(v, replay), ensure_ascii=False)
    return json.dumps(v, ensure_ascii=False)


def rehydrate_anthropic_response(obj, replay, withheld=None):
    # `withheld` (optional set): tool-arg suppression visibility -- see _rehydrate_json / _live_tool_arg_withheld.
    if not replay or not isinstance(obj, (dict, list)):
        return obj
    rehydrated = _rehydrate_json(obj, replay, withheld=withheld)
    if isinstance(obj, dict) and isinstance(rehydrated, dict):
        obj.clear()
        obj.update(rehydrated)
        return obj
    if isinstance(obj, list) and isinstance(rehydrated, list):
        obj[:] = rehydrated
        return obj
    return rehydrated


# Capability marker read by the shared forwarders (_finalize_upstream_response / _stream_or_error_response):
# this rehydrator accepts a `withheld` collector, so the caller with live-emit context can surface the
# 'tool_arg_withheld' event. The OpenAI/Responses adapter rehydrators do not carry the marker (yet), so the
# forwarders call them with the unchanged 2-arg shape -- no signature break across adapters.
rehydrate_anthropic_response._accepts_withheld = True


def rehydrate_json_string(acc, replay):
    """Rehydrate placeholders inside assembled tool_use arguments JSON, including object keys. This is the
    streaming tool_use input_json_delta funnel, so it is ALWAYS tool-argument context: B5 withholds FLOOR/
    secret-class tokens (and, under strict mode, every token) so a secret left in an executed argument stays
    the inert <LABEL_NNN> literal."""
    if not acc or not acc.strip():
        return acc
    replay = tool_arg_policy.tool_arg_replay(replay)
    try:
        obj = json.loads(acc, object_pairs_hook=_dup_preserving_pairs)
    except Exception:
        return rehydrate_text(acc, replay)
    return _dump_rehydrated_dup_safe(obj, replay)


# ----------------------------------------------------------------------------
# Streaming (SSE) rehydration (SPECS §2.3). A placeholder <LABEL_NNN> can split
# across deltas, so we tail-buffer per content block: emit the safe prefix, hold
# a possible partial placeholder (from the last unclosed '<') until the next
# delta or block stop. tool_use args stream as input_json_delta fragments -> we
# accumulate per block index and rehydrate the assembled JSON at block stop.
# ----------------------------------------------------------------------------
# A placeholder label may carry INTERNAL underscores (gate-form labels such as PHONE_NUMBER / SENSITIVE_ACCOUNT_ID
# -> <PHONE_NUMBER_001> / <SENSITIVE_ACCOUNT_ID_001>), so a partial split like "<PHONE_NUM" must be held back. The
# old [A-Z0-9]*_?\d* allowed at most ONE underscore and dropped multi-underscore partials (FIX-ROUND-2 MEDIUM).
_PH_PREFIX_RE = re.compile(r'[A-Z0-9_]*')


def split_safe(carry):
    """(safe_prefix, held_tail): hold back a possible partial placeholder at the tail (from the last
    unclosed '<' that looks like the start of <LABEL_NNN). Leave non-placeholder '<' (e.g. 'a < b') alone."""
    idx = carry.rfind('<')
    if idx == -1:
        return carry, ''
    tail = carry[idx:]
    if '>' in tail:
        return carry, ''
    if _PH_PREFIX_RE.fullmatch(tail[1:]):
        return carry[:idx], tail
    return carry, ''


def _emit(ev_type, obj):
    data = json.dumps(obj, ensure_ascii=False)
    if ev_type:
        return f"event: {ev_type}\ndata: {data}".encode('utf-8')
    return f"data: {data}".encode('utf-8')


def _transform_event(raw, replay, carry, block_type, json_acc, withheld=None, tool_replay_memo=None):
    # `withheld` (optional set, 2026-07-02): tool-arg suppression visibility. rehydrate_json_string stays PURE
    # (tests call it directly); the tally happens here, where the assembled tool-arg output exists, and is
    # surfaced by the caller holding live-emit context (_stream_or_error_response). Observation only.
    ev_type = None
    data_raw = None
    for ln in raw.split(b'\n'):
        ln = ln.rstrip(b'\r')
        if ln.startswith(b'event:'):
            ev_type = ln[6:].strip().decode('utf-8', 'ignore')
        elif ln.startswith(b'data:'):
            data_raw = ln[5:].strip()
    if data_raw is None:
        return raw if raw.strip() else None
    try:
        obj = json.loads(data_raw)
    except Exception:
        return raw
    t = obj.get('type')

    if t == 'content_block_start':
        idx = obj.get('index')
        bt = (obj.get('content_block') or {}).get('type')
        block_type[idx] = bt
        if bt == 'text':
            carry[idx] = ''
        elif bt == 'tool_use':
            json_acc[idx] = ''
        return _emit(ev_type, obj)

    if t == 'content_block_delta':
        idx = obj.get('index')
        d = obj.get('delta') or {}
        dt = d.get('type')
        if dt == 'text_delta':
            carry[idx] = carry.get(idx, '') + d.get('text', '')
            safe, held = split_safe(carry[idx])
            carry[idx] = held
            if not safe:
                return None
            d['text'] = rehydrate_text(safe, replay)
            return _emit(ev_type, obj)
        if dt == 'input_json_delta':
            json_acc[idx] = json_acc.get(idx, '') + d.get('partial_json', '')
            return None   # buffer; emit the rehydrated assembled JSON at block stop
        return _emit(ev_type, obj)

    if t == 'content_block_stop':
        idx = obj.get('index')
        bt = block_type.get(idx)
        emits = []
        if bt == 'text':
            rem = carry.pop(idx, '')
            if rem:
                de = {'type': 'content_block_delta', 'index': idx,
                      'delta': {'type': 'text_delta', 'text': rehydrate_text(rem, replay)}}
                emits.append(_emit('content_block_delta', de))
        elif bt == 'tool_use':
            acc = json_acc.pop(idx, '')
            rehydrated_args = rehydrate_json_string(acc, replay)
            if withheld is not None and replay:
                # tokens the tool-arg suppression left literal in the EXECUTED arguments (B5) -- tallied
                # against the suppressed map so a restored VALUE that merely looks like a placeholder of
                # another entry is never miscounted as withheld. The suppressed map is computed ONCE per
                # stream (hoisted, perf review 2026-07-02), not per tool_use block.
                if tool_replay_memo is not None:
                    withheld.update(_withheld_tokens(rehydrated_args, replay, tool_replay_memo))
            de = {'type': 'content_block_delta', 'index': idx,
                  'delta': {'type': 'input_json_delta', 'partial_json': rehydrated_args}}
            emits.append(_emit('content_block_delta', de))
        emits.append(_emit(ev_type, obj))
        return b'\n\n'.join(emits)

    return _emit(ev_type, obj)   # message_start / message_delta / message_stop / ping / error -> passthrough


async def stream_rehydrate(upstream_aiter, replay, withheld=None):
    carry = {}
    block_type = {}
    json_acc = {}
    buf = b''
    # One suppressed-replay computation for the whole stream (perf review 2026-07-02): tool_arg_replay is
    # O(|replay|); rebuilding it per tool_use block multiplied that by the number of tool calls per response.
    tool_replay_memo = tool_arg_policy.tool_arg_replay(replay) if (withheld is not None and replay) else None
    async for chunk in upstream_aiter:
        buf += chunk
        while b'\n\n' in buf:
            raw_event, buf = buf.split(b'\n\n', 1)
            out = _transform_event(raw_event, replay, carry, block_type, json_acc, withheld, tool_replay_memo)
            if out:
                yield out + b'\n\n'
    if buf.strip():
        out = _transform_event(buf, replay, carry, block_type, json_acc, withheld, tool_replay_memo)
        if out:
            yield out + b'\n\n'


# Capability marker (see rehydrate_anthropic_response._accepts_withheld): the shared streaming forwarder only
# threads the withheld collector into transforms that declare support, so the adapter transforms (untouched
# 2-arg signatures) keep working unchanged.
stream_rehydrate._accepts_withheld = True


# ----------------------------------------------------------------------------
# Upstream forwarding: pass auth + anthropic-* + content-type verbatim. Drop
# hop-by-hop / host / content-length (httpx recomputes). Never store auth.
# ----------------------------------------------------------------------------
# Plan/OAuth FINGERPRINT passthrough (2026-06-21): Anthropic's subscription enforcement (live since Jan 2026)
# classifies a Max/Pro OAuth request by its CLIENT FINGERPRINT -- the Claude Code user-agent (claude-cli/<ver>),
# the x-app identity, and the Stainless SDK telemetry (x-stainless-lang/os/arch/runtime/package-version/...). The
# original allowlist dropped all three, so httpx synthesized `user-agent: python-httpx` and the request looked
# like a non-Claude-Code tool -> the OAuth token was rejected. That is the "blocked on the plan but fine with an
# API key" symptom (an API key is not fingerprint-gated, so the same allowlist is harmless there). We now forward
# the GENUINE fingerprint headers verbatim, so a proxied request is header-identical to the official client it IS
# (Anthropic explicitly permits a custom base_url / gateway in front of the real client). We never pin fake values.
# CAVEAT: this does NOT make the request transport-identical -- the TLS/JA3 + HTTP/2 fingerprint is still httpx's,
# not the client's. If header passthrough alone proves insufficient against Anthropic's multi-signal enforcement,
# the documented next step is a curl_cffi (curl-impersonate) upstream leg; see plans/ + the review writeup.
FWD_HEADERS = {'authorization', 'anthropic-version', 'anthropic-beta',
               'anthropic-dangerous-direct-browser-access', 'content-type', 'x-api-key',
               'user-agent', 'x-app'}
# Prefix-matched families (the allowlist is otherwise exact-match). x-stainless-* is the Stainless SDK telemetry
# Claude Code sends; forwarding the family keeps it intact as new x-stainless-* members appear across CLI versions.
FWD_HEADER_PREFIXES = ('x-stainless-',)


def fwd_headers(req):
    return {k: v for k, v in req.headers.items()
            if k.lower() in FWD_HEADERS or k.lower().startswith(FWD_HEADER_PREFIXES)}


def is_codex_plan_request(headers):
    """True if a /v1/responses request is Codex ChatGPT/Codex-PLAN traffic (-> chatgpt.com backend) rather than
    Platform API-key traffic (-> api.openai.com). MULTI-SIGNAL on purpose: a ChatGPT OAuth token has no
    api.responses.write scope, so a plan request that reaches api.openai.com 401s with "missing scopes". The
    original code keyed on chatgpt-account-id ALONE, so a plan request that dropped that one header silently
    misrouted to the platform API and failed. Any one of the Codex-plan markers below identifies the plan path,
    so the routing is resilient to any single header changing across Codex versions."""
    return bool(headers.get('chatgpt-account-id')
                or (headers.get('originator', '') or '').lower() == 'codex_cli_rs'
                or headers.get('openai-sentinel-token'))


_DROP_UPSTREAM_RESPONSE_HEADERS = {
    'connection', 'content-encoding', 'content-length', 'content-type', 'keep-alive',
    'proxy-authenticate', 'proxy-authorization', 'set-cookie', 'te', 'trailer',
    'transfer-encoding', 'upgrade',
}
_SAFE_UPSTREAM_RESPONSE_HEADERS = {
    'anthropic-organization-id', 'anthropic-version', 'openai-organization',
    'openai-processing-ms', 'openai-version', 'request-id', 'retry-after', 'x-request-id',
}
_SAFE_UPSTREAM_RESPONSE_HEADER_PREFIXES = (
    'anthropic-ratelimit-', 'openai-', 'ratelimit-', 'x-ratelimit-',
)


def _upstream_response_headers(headers):
    """Forward operational upstream response headers only. Never forward cookies or hop-by-hop headers."""
    out = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in _DROP_UPSTREAM_RESPONSE_HEADERS:
            continue
        if lk in _SAFE_UPSTREAM_RESPONSE_HEADERS or lk.startswith(_SAFE_UPSTREAM_RESPONSE_HEADER_PREFIXES):
            out[k] = v
    return out


# Usage/cache observability: log the upstream response's token usage so prompt-cache seamlessness is MEASURABLE
# (cache_read > 0 on turn 2+ = the redacted prefix is hitting Anthropic's cache; cache_read == 0 every turn = the
# prefix is busting). Usage numbers carry no PII. Toggle with GATEWAY_LOG_USAGE=0.
LOG_USAGE = os.environ.get('GATEWAY_LOG_USAGE', '1') == '1'


# --- RC1 / context-window instrumentation (PII-FREE, sentinel-gated) -------------------------------------------
# Enable with `touch ~/.ossredact/instrument.on`; disable by removing it (checked live per request, like the mode
# file -- so it works no matter how the gate process is launched). Appends JSON lines to ~/.ossredact/instrument.jsonl:
#   - inbound vs forwarded `anthropic-beta`  -> does CC even SEND the 1M beta (context-1m-*) to a non-first-party
#     base_url, and does the gate forward it verbatim? (RC1: CC gates 1M behind a first-party base_url check.)
#   - RAW upstream response header NAMES + which are dropped by _SAFE_UPSTREAM_RESPONSE_HEADERS -> is Anthropic
#     sending a window/context-signalling header that the response allow-list strips? (Codex's RC1 sub-hypothesis.)
#   - usage (input/cache_read/cache_creation) per turn -> cache_read>0 on turn 2+ = redacted prefix is cache-STABLE
#     (growth is benign tail); cache_read==0 every turn = prefix is BUSTING (the operator's "balloon"/growth).
# Logs header NAMES, anthropic-* header VALUES (operational, non-PII), and token COUNTS only. NEVER bodies/PII.
_INSTR_FLAG = os.path.expanduser('~/.ossredact/instrument.on')
_INSTR_FILE = os.environ.get('GATEWAY_INSTRUMENT_FILE') or os.path.expanduser('~/.ossredact/instrument.jsonl')


def _instr_on():
    try:
        return os.path.exists(_INSTR_FLAG)
    except Exception:
        return False


def _beta_view(headers):
    """PII-free view of the context/feature flags CC sent (anthropic-beta is a CSV of feature tokens, not PII)."""
    return {'anthropic_beta': headers.get('anthropic-beta'),
            'anthropic_version': headers.get('anthropic-version'),
            'has_session': bool(headers.get('x-claude-code-session-id')),
            'user_agent': (headers.get('user-agent') or '')[:80]}


def _resp_header_view(headers):
    """Upstream response header NAMES (all) + VALUES for anthropic-*/request-id, and which names the response
    allow-list would DROP -- to surface any window-signalling header Anthropic sends that never reaches CC."""
    names = sorted(k.lower() for k in headers.keys())
    vals = {k.lower(): v for k, v in headers.items()
            if k.lower().startswith('anthropic-') or k.lower() in ('request-id', 'x-request-id')}
    dropped = [n for n in names if n not in _SAFE_UPSTREAM_RESPONSE_HEADERS
               and not n.startswith(_SAFE_UPSTREAM_RESPONSE_HEADER_PREFIXES)
               and n not in _DROP_UPSTREAM_RESPONSE_HEADERS]
    return {'resp_header_names': names, 'anthropic_resp_headers': vals, 'dropped_by_allowlist': dropped}


def _instr(event):
    if not _instr_on():
        return
    try:
        event['ts'] = round(time.time(), 3)
        with open(_INSTR_FILE, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + '\n')
    except Exception:
        pass
# --------------------------------------------------------------------------------------------------------------


def _find_usage_obj(text):
    """Extract the first balanced {...} after a "usage" key (Anthropic puts it in the non-stream body and in the
    streaming message_start event). Bounded scan; returns a dict or None. Never raises."""
    i = text.find('"usage"')
    if i == -1:
        return None
    j = text.find('{', i)
    if j == -1:
        return None
    depth = 0
    for k in range(j, min(len(text), j + 4000)):
        c = text[k]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[j:k + 1])
                except Exception:
                    return None
    return None


def _log_usage(label, usage):
    if not (LOG_USAGE and isinstance(usage, dict)):
        return
    it = usage.get('input_tokens')
    cr = usage.get('cache_read_input_tokens')
    cc = usage.get('cache_creation_input_tokens')
    cc_n = cc if isinstance(cc, int) else (sum(v for v in cc.values() if isinstance(v, int)) if isinstance(cc, dict) else 0)
    cr_n = cr if isinstance(cr, int) else 0
    if it is None and cr_n == 0 and cc_n == 0:
        return
    verdict = 'HIT' if cr_n > 0 else 'MISS'
    print(f"[egress] usage {label} input={it} cache_read={cr_n} cache_creation={cc_n} prompt_cache={verdict}", flush=True)


def _finalize_upstream_response(r, replay, json_rehydrate, live_ctx=None):
    ct = r.headers.get('content-type', 'application/json')
    resp_headers = _upstream_response_headers(r.headers)
    if replay and 'json' in ct.lower():
        try:
            # Tool-arg suppression visibility (2026-07-02): when the rehydrator supports it and we have live
            # context, collect the floor tokens left literal in EXECUTED tool args and emit the distinct
            # 'tool_arg_withheld' event -- the agent otherwise receives the inert token silently.
            if LIVE_VIEW and live_ctx and getattr(json_rehydrate, '_accepts_withheld', False):
                sink = set()
                obj = json_rehydrate(json.loads(r.content), replay, withheld=sink)
                _live_tool_arg_withheld(live_ctx, sink)
            else:
                obj = json_rehydrate(json.loads(r.content), replay)
            return JSONResponse(obj, status_code=r.status_code, headers=resp_headers)
        except Exception:
            pass
    return Response(content=r.content, status_code=r.status_code, media_type=ct, headers=resp_headers)


async def _open_stream(url, payload, headers):
    """Open an upstream stream before returning the client response, so status/content-type are known."""
    client = httpx.AsyncClient(timeout=600)
    try:
        req = client.build_request('POST', url, content=payload, headers=headers)
        r = await client.send(req, stream=True)
    except Exception:
        await client.aclose()
        raise
    return client, r


async def _stream_or_error_response(url, payload, headers, replay, stream_transform, json_rehydrate, live_ctx=None):
    client, r = await _open_stream(url, payload, headers)
    ct = r.headers.get('content-type', '')
    resp_headers = _upstream_response_headers(r.headers)
    if _instr_on():
        ev = {'route': (live_ctx or {}).get('route', 'stream'), 'phase': 'response', 'status': r.status_code,
              'stream': True}
        ev.update(_resp_header_view(r.headers))
        _instr(ev)

    if 'text/event-stream' not in ct.lower():
        try:
            content = await r.aread()
        finally:
            await r.aclose()
            await client.aclose()
        if live_ctx and replay:
            present = set(_PH_TOKEN_RE.findall(content.decode('utf-8', 'ignore')))
            _live_response(live_ctx['route'], live_ctx['client'], live_ctx['ctx'], replay, present)
        if replay and 'json' in ct.lower():
            try:
                # tool-arg suppression visibility (2026-07-02) -- see _finalize_upstream_response.
                if LIVE_VIEW and live_ctx and getattr(json_rehydrate, '_accepts_withheld', False):
                    sink = set()
                    obj = json_rehydrate(json.loads(content), replay, withheld=sink)
                    _live_tool_arg_withheld(live_ctx, sink)
                else:
                    obj = json_rehydrate(json.loads(content), replay)
                return JSONResponse(obj, status_code=r.status_code, headers=resp_headers)
            except Exception:
                pass
        return Response(content=content, status_code=r.status_code,
                        media_type=ct or 'application/octet-stream', headers=resp_headers)

    route_label = (live_ctx or {}).get('route', 'stream')

    async def gen():
        ubuf = []
        ustate = {'size': 0, 'logged': False}

        def _maybe_log(b):
            if ustate['logged'] or not LOG_USAGE or ustate['size'] > 32768:
                return
            bb = b if isinstance(b, (bytes, bytearray)) else str(b).encode('utf-8', 'ignore')
            ubuf.append(bb)
            ustate['size'] += len(bb)
            u = _find_usage_obj(b''.join(ubuf).decode('utf-8', 'ignore'))
            if u is not None:
                _log_usage(route_label, u)
                ustate['logged'] = True
                ubuf.clear()

        # tool-arg suppression visibility (2026-07-02): thread a withheld-token collector into transforms
        # that declare support (capability marker -- the Anthropic stream_rehydrate today; the adapter
        # transforms keep their unchanged 2-arg call). Emitted once the stream drains, as its own distinct
        # live event, so an inert <LABEL_NNN> handed to the executing agent is never silent again.
        withheld_sink = (set() if (LIVE_VIEW and replay and live_ctx
                                   and getattr(stream_transform, '_accepts_withheld', False)) else None)
        try:
            if not replay:
                async for chunk in r.aiter_raw():
                    _maybe_log(chunk)
                    yield chunk
            else:
                src = _tally_rehydrations(r.aiter_raw(), replay, live_ctx) if live_ctx else r.aiter_raw()
                agen = (stream_transform(src, replay, withheld=withheld_sink)
                        if withheld_sink is not None else stream_transform(src, replay))
                async for out in agen:
                    _maybe_log(out)
                    yield out
        finally:
            if withheld_sink:
                _live_tool_arg_withheld(live_ctx, withheld_sink)
            await r.aclose()
            await client.aclose()

    return StreamingResponse(gen(), status_code=r.status_code,
                             media_type=ct or 'text/event-stream', headers=resp_headers)


def _degraded_block(meta):
    """FAIL CLOSED (FIX-ROUND-3 HIGH): if the neural gate was unreachable while scanning this request (degraded),
    forwarding the body would leak any NER-only PII that has no Tier-0 fallback. Return a 503 JSONResponse to
    refuse the forward, or None to proceed. No-op when GATEWAY_FAIL_OPEN=1. Carries NO PII -- only the flag."""
    if FAIL_CLOSED and meta.get('degraded'):
        if LOG_REQUESTS:
            print(f"[egress] DEGRADED blocked (gate unreachable): redaction={meta.get('redaction')} "
                  f"spans={meta.get('n_spans')} labels={meta.get('by_label', {})}", flush=True)
        return JSONResponse(
            {'error': 'pii_gate_unavailable',
             'message': 'PII detection gate unreachable; refusing to forward to avoid leaking unredacted data. '
                        'Retry once the gate is healthy (or set GATEWAY_FAIL_OPEN=1 to allow Tier-0-only egress).'},
            status_code=503)
    return None


def _safe_diagnostic_url(url):
    """Health output must not disclose credentials or tokenized env-configured URL components."""
    try:
        p = urlsplit(url)
    except Exception:
        return '<invalid>'
    host = p.hostname or ''
    if not host:
        return '<invalid>'
    netloc = host
    if p.port is not None:
        netloc += f':{p.port}'
    return urlunsplit((p.scheme, netloc, '', '', ''))


async def _redact_or_block(body, ctx, **kw):
    """FAIL CLOSED around redaction: if redact_body raises (e.g. the inter-process map lock / fs op throws), do
    NOT let the request fall through to an upstream forward. Return an explicit 503 redaction_failed so clients
    and monitoring see the redaction layer refused (not an ambiguous upstream 500). Carries no PII."""
    try:
        meta, replay = await redact_body(body, ctx, **kw)
        return meta, replay, None
    except Exception as e:
        print(f"[egress] redaction_failed: {type(e).__name__}", flush=True)
        return None, None, JSONResponse({'error': 'redaction_failed', 'detail': type(e).__name__}, status_code=503)


async def _read_json_body(req: Request):
    """Read + parse a request body under the size cap. Returns (body, None) on success, or (None, error_response)
    with a 413 (too large) or 400 (bad JSON). The Content-Length header is checked first so an honest oversized
    client is rejected before the body is buffered; the post-read length check is the belt-and-suspenders backstop
    for a missing/lying Content-Length. Applied to every route that fans a body out to the detector."""
    if MAX_BODY_BYTES:
        clen = req.headers.get('content-length')
        if clen and clen.isdigit() and int(clen) > MAX_BODY_BYTES:
            return None, JSONResponse({'error': 'request body too large', 'max_bytes': MAX_BODY_BYTES}, status_code=413)
    raw = await req.body()
    if MAX_BODY_BYTES and len(raw) > MAX_BODY_BYTES:
        return None, JSONResponse({'error': 'request body too large', 'max_bytes': MAX_BODY_BYTES}, status_code=413)
    try:
        return json.loads(raw), None
    except Exception:
        return None, JSONResponse({'error': 'invalid json body'}, status_code=400)


@app.post('/v1/messages')
async def messages(req: Request):
    body, err = await _read_json_body(req)
    if err is not None:
        return err
    ctx = {'session': req.headers.get('x-claude-code-session-id', ''),
           'project': req.headers.get('x-ossredact-project', 'default'),
           'auth_fp': _auth_fingerprint(req.headers)}
    meta, replay, fail = await _redact_or_block(body, ctx)
    if fail is not None:
        return fail
    stream = bool(body.get('stream'))
    client = _client_label(req, '/v1/messages')
    _live_request('/v1/messages', client, ctx, meta, replay, stream)

    if LOG_REQUESTS and meta.get('redaction') not in ('skip', None) and not meta.get('degraded'):
        wire_phs = sorted(set(_PH_TOKEN_RE.findall(json.dumps(body, ensure_ascii=False))))
        print(f"[egress] redaction={meta['redaction']} spans={meta['n_spans']} labels={meta.get('by_label', {})} "
              f"rules={meta.get('by_rule', {})} wire_placeholders={wire_phs} stream={stream} degraded={meta.get('degraded')}", flush=True)

    if DRYRUN:
        resp = {'_dryrun': True, 'meta': meta, 'stream': stream, 'upstream_body': body}
        if EXPOSE_MAP:
            resp['_replay'] = replay
        return JSONResponse(resp)

    blocked = _degraded_block(meta)
    if blocked is not None:
        return blocked

    headers = fwd_headers(req)
    url = ANTHROPIC_UPSTREAM + '/v1/messages'
    payload = json.dumps(body)
    live_ctx = {'route': '/v1/messages', 'client': client, 'ctx': ctx}
    if _instr_on():
        _instr({'route': '/v1/messages', 'phase': 'request', 'inbound': _beta_view(req.headers),
                'forwarded_anthropic_beta': headers.get('anthropic-beta'),
                'beta_forwarded_verbatim': req.headers.get('anthropic-beta') == headers.get('anthropic-beta'),
                'stream': stream, 'n_spans': meta.get('n_spans'), 'req_bytes': len(payload)})
    if not stream:
        async with httpx.AsyncClient(timeout=600) as hclient:
            r = await hclient.post(url, content=payload, headers=headers)
        if _instr_on():
            ev = {'route': '/v1/messages', 'phase': 'response', 'status': r.status_code}
            ev.update(_resp_header_view(r.headers))
            ev['usage'] = _find_usage_obj(r.content.decode('utf-8', 'ignore'))
            _instr(ev)
        if replay:
            _live_response('/v1/messages', client, ctx, replay, set(_PH_TOKEN_RE.findall(r.content.decode('utf-8', 'ignore'))))
        if LOG_USAGE:
            _log_usage('/v1/messages', _find_usage_obj(r.content.decode('utf-8', 'ignore')))
        return _finalize_upstream_response(r, replay, rehydrate_anthropic_response, live_ctx=live_ctx)

    # streaming: open upstream first so upstream auth/rate-limit/error statuses are not masked as local 200s.
    return await _stream_or_error_response(url, payload, headers, replay, stream_rehydrate,
                                           rehydrate_anthropic_response, live_ctx=live_ctx)


@app.post('/v1/messages/count_tokens')
async def messages_count_tokens(req: Request):
    """Anthropic token-counting pre-flight. Claude Code calls this before a turn to size its context bar; with
    no route here it 404s and CC falls back to inflated completion-usage estimates. The body carries the SAME
    message content as /v1/messages, so it is redacted on the same contract (same session/auth_fp keying, so the
    placeholders match the real turn) before being forwarded -- both to keep PII off the count endpoint and so the
    returned count reflects the redacted payload that will actually be sent. The response is just {input_tokens: N}
    with no PII, so it is returned verbatim (no rehydration). An explicit redacted route, never a generic /v1/*
    passthrough, so a count request can never bypass redaction. Always non-streaming."""
    body, err = await _read_json_body(req)
    if err is not None:
        return err
    ctx = {'session': req.headers.get('x-claude-code-session-id', ''),
           'project': req.headers.get('x-ossredact-project', 'default'),
           'auth_fp': _auth_fingerprint(req.headers)}
    meta, replay, fail = await _redact_or_block(body, ctx)
    if fail is not None:
        return fail
    client = _client_label(req, '/v1/messages/count_tokens')
    _live_request('/v1/messages/count_tokens', client, ctx, meta, replay, False)

    if LOG_REQUESTS and meta.get('redaction') not in ('skip', None) and not meta.get('degraded'):
        wire_phs = sorted(set(_PH_TOKEN_RE.findall(json.dumps(body, ensure_ascii=False))))
        print(f"[egress] count_tokens redaction={meta['redaction']} spans={meta['n_spans']} "
              f"labels={meta.get('by_label', {})} wire_placeholders={wire_phs} degraded={meta.get('degraded')}", flush=True)

    if DRYRUN:
        resp = {'_dryrun': True, 'meta': meta, 'upstream_body': body}
        if EXPOSE_MAP:
            resp['_replay'] = replay
        return JSONResponse(resp)

    blocked = _degraded_block(meta)
    if blocked is not None:
        return blocked

    headers = fwd_headers(req)
    url = ANTHROPIC_UPSTREAM + '/v1/messages/count_tokens'
    payload = json.dumps(body)
    async with httpx.AsyncClient(timeout=600) as hclient:
        r = await hclient.post(url, content=payload, headers=headers)
    # The count response ({input_tokens: N}) carries no PII -> empty replay returns it verbatim (with the
    # standard upstream-header sanitisation), no rehydration.
    return _finalize_upstream_response(r, {}, rehydrate_anthropic_response)


# Claude Code's bootstrap request sends exactly these query keys (binary buildBootstrapRequestConfig/nza:
# {params:{entrypoint, model}}). We forward ONLY these upstream -- `model` is required (it selects which model's
# autocompact window the clientdata returns); anything else is dropped so the un-redacted bootstrap route can never
# be used to smuggle PII upstream via the query string.
_BOOTSTRAP_QUERY_ALLOW = frozenset({'entrypoint', 'model'})


@app.get('/api/claude_cli/bootstrap')
async def claude_cli_bootstrap(req: Request):
    """Claude Code CLIENT-CONFIG passthrough (NOT a redaction route, NOT a loopback control route).

    On startup Claude Code fetches GET ${ANTHROPIC_BASE_URL}/api/claude_cli/bootstrap to populate its clientdata,
    which includes the per-model autocompact context window (CC's autoCompactWindowsCache). With NO route here the
    request 404s, so for a model that is NOT in CC's hardcoded fallback window set -- notably the default
    claude-opus-4-8 -- the autocompact-window SOURCE resolves to "auto", and CC enables compaction only when
    source != "auto" (its `nLe()` predicate gates BOTH the proactive and reactive autocompaction paths). The
    conversation then grows unbounded: we observed a cached prefix marching to ~579k tokens, prompt-cache HIT every
    turn, that NEVER auto-compacted -- the operator's "context balloons one-shot / coherent past 100% / no
    autocompact, nothing like gate-off" symptom. Gate-OFF this exact fetch hits api.anthropic.com directly and
    succeeds, which is precisely why the blowup is gate-specific. (Forwarding clientdata also fixes the 1M-context
    case: in CC's resolver the clientdata branch precedes the model-default branch, so a real window arrives even
    when the 1M path would otherwise skip the model-default fallback into "auto".)

    Privacy: this is config metadata. The REQUEST carries only auth + client-fingerprint headers (via fwd_headers)
    and version/config query selectors -- NO conversation content, NO user PII -- and the RESPONSE is CC's own
    account/client config coming BACK from Anthropic (not user data going TO it). So it is forwarded VERBATIM
    (query string + fingerprint headers out, bytes in) and NEVER redacted (redaction would corrupt the config and
    protects nothing). It is an EXACT GET route, never a generic /api/* catch-all: every other unhandled /api path
    still 404s and any non-GET method here returns 405 -- both fail CLOSED, so no arbitrary path or request body
    can reach upstream unredacted through this addition. Mirrors the explicit-route precedent of
    /v1/messages/count_tokens (B2): an allowlisted upstream forward, never a blanket passthrough.

    Query is ALLOWLISTED, not passed through verbatim: CC's bootstrap request config (binary nza()) sends exactly
    `?entrypoint=<cli>&model=<model-id>` -- non-PII config selectors, and `model` is REQUIRED (it tells Anthropic
    which model's autocompact window to return). Forwarding only those two keys (dropping any other param) closes
    the theoretical bypass where an arbitrary caller could smuggle PII upstream via `?x=<pii>` on this un-redacted
    route, while keeping the real client working. A 30s timeout: CC blocks on this fetch at startup, so a fast
    failure (-> CC's own fallback) beats a long hang."""
    url = ANTHROPIC_UPSTREAM + '/api/claude_cli/bootstrap'
    allowed = [(k, v) for k, v in req.query_params.multi_items() if k in _BOOTSTRAP_QUERY_ALLOW]
    if allowed:
        url += '?' + urlencode(allowed)  # entrypoint/model only -- never the raw query (no PII smuggling vector)
    headers = fwd_headers(req)            # auth + anthropic-* + user-agent + x-stainless-* fingerprint, no body
    async with httpx.AsyncClient(timeout=30) as hclient:
        r = await hclient.get(url, headers=headers)
    if _instr_on():
        ev = {'route': '/api/claude_cli/bootstrap', 'phase': 'response', 'status': r.status_code,
              'inbound': _beta_view(req.headers), 'forwarded_anthropic_beta': headers.get('anthropic-beta'),
              'query_forwarded': allowed, 'resp_bytes': len(r.content)}
        ev.update(_resp_header_view(r.headers))
        _instr(ev)
    # Verbatim config bytes (empty replay -> no rehydration), with the standard upstream-header sanitisation.
    return _finalize_upstream_response(r, {}, rehydrate_anthropic_response)


@app.post('/v1/chat/completions')
async def chat_completions(req: Request):
    """OpenAI-compatible route. Same redact-on-egress / rehydrate-on-response contract as /v1/messages, using
    the shared redact_body() with the OpenAI field extractor + the OpenAI response/stream rehydrators."""
    body, err = await _read_json_body(req)
    if err is not None:
        return err
    ctx = {'session': req.headers.get('x-session-id') or req.headers.get('x-claude-code-session-id', ''),
           'project': req.headers.get('x-ossredact-project', 'default'),
           'auth_fp': _auth_fingerprint(req.headers)}
    meta, replay, fail = await _redact_or_block(body, ctx, extract=openai_adapter.extract_text_fields_openai)
    if fail is not None:
        return fail
    stream = bool(body.get('stream'))
    client = _client_label(req, '/v1/chat/completions')
    _live_request('/v1/chat/completions', client, ctx, meta, replay, stream)

    if LOG_REQUESTS and meta.get('redaction') not in ('skip', None) and not meta.get('degraded'):
        wire_phs = sorted(set(_PH_TOKEN_RE.findall(json.dumps(body, ensure_ascii=False))))
        print(f"[egress:openai] redaction={meta['redaction']} spans={meta['n_spans']} labels={meta.get('by_label', {})} "
              f"rules={meta.get('by_rule', {})} wire_placeholders={wire_phs} stream={stream} degraded={meta.get('degraded')}", flush=True)

    if DRYRUN:
        resp = {'_dryrun': True, 'meta': meta, 'stream': stream, 'upstream_body': body}
        if EXPOSE_MAP:
            resp['_replay'] = replay
        return JSONResponse(resp)

    blocked = _degraded_block(meta)
    if blocked is not None:
        return blocked

    headers = openai_adapter.fwd_headers_openai(req)
    url = OPENAI_UPSTREAM + '/v1/chat/completions'
    payload = json.dumps(body)
    live_ctx = {'route': '/v1/chat/completions', 'client': client, 'ctx': ctx}
    if not stream:
        async with httpx.AsyncClient(timeout=600) as hclient:
            r = await hclient.post(url, content=payload, headers=headers)
        if replay:
            _live_response('/v1/chat/completions', client, ctx, replay, set(_PH_TOKEN_RE.findall(r.content.decode('utf-8', 'ignore'))))
        return _finalize_upstream_response(r, replay, openai_adapter.rehydrate_openai_response)

    return await _stream_or_error_response(url, payload, headers, replay,
                                           openai_adapter.stream_rehydrate_openai,
                                           openai_adapter.rehydrate_openai_response, live_ctx=live_ctx)


@app.post('/v1/responses')
async def responses(req: Request):
    """OpenAI Responses-API route -- Codex CLI speaks /v1/responses ONLY. Same redact-on-egress /
    rehydrate-on-response contract as /v1/chat/completions, using the shared redact_body() with the Responses
    field extractor (string/array `input` + `instructions`) and the Responses response/stream rehydrators."""
    body, err = await _read_json_body(req)
    if err is not None:
        return err
    ctx = {'session': req.headers.get('x-session-id') or req.headers.get('x-claude-code-session-id', ''),
           'project': req.headers.get('x-ossredact-project', 'default'),
           'auth_fp': _auth_fingerprint(req.headers)}
    meta, replay, fail = await _redact_or_block(body, ctx, extract=responses_adapter.extract_text_fields_responses)
    if fail is not None:
        return fail
    # File bytes that were NOT scanned (binary/undetermined inline file_data) are a DOCUMENTED+LOGGED limitation,
    # never a silent pass. pop_file_passthrough_notes() also strips the private marker so it never reaches upstream.
    file_notes = responses_adapter.pop_file_passthrough_notes(body)
    stream = bool(body.get('stream'))
    client = _client_label(req, '/v1/responses')
    _live_request('/v1/responses', client, ctx, meta, replay, stream)

    if LOG_REQUESTS and meta.get('redaction') not in ('skip', None) and not meta.get('degraded'):
        wire_phs = sorted(set(_PH_TOKEN_RE.findall(json.dumps(body, ensure_ascii=False))))
        print(f"[egress:responses] redaction={meta['redaction']} spans={meta['n_spans']} labels={meta.get('by_label', {})} "
              f"rules={meta.get('by_rule', {})} wire_placeholders={wire_phs} stream={stream} degraded={meta.get('degraded')}", flush=True)
    if LOG_REQUESTS and file_notes:
        for fn in file_notes:
            print(f"[egress:responses] file bytes not scanned: mime={fn.get('mime')} "
                  f"filename={fn.get('filename')} reason={fn.get('reason')}", flush=True)

    if DRYRUN:
        resp = {'_dryrun': True, 'meta': meta, 'stream': stream, 'upstream_body': body}
        if EXPOSE_MAP:
            resp['_replay'] = replay
        return JSONResponse(resp)

    blocked = _degraded_block(meta)
    if blocked is not None:
        return blocked

    headers = responses_adapter.fwd_headers_responses(req)
    # Plan path (Codex ChatGPT/Codex subscription) -> ChatGPT backend /responses; API-key path -> platform
    # /v1/responses. Detection is multi-signal (chatgpt-account-id OR originator=codex_cli_rs OR a sentinel
    # token); see is_codex_plan_request() for why a single-header discriminator silently misrouted plan traffic.
    if is_codex_plan_request(req.headers):
        url = CHATGPT_UPSTREAM + '/responses'
    else:
        url = OPENAI_UPSTREAM + '/v1/responses'
    payload = json.dumps(body)
    live_ctx = {'route': '/v1/responses', 'client': client, 'ctx': ctx}
    if not stream:
        async with httpx.AsyncClient(timeout=600) as hclient:
            r = await hclient.post(url, content=payload, headers=headers)
        if replay:
            _live_response('/v1/responses', client, ctx, replay, set(_PH_TOKEN_RE.findall(r.content.decode('utf-8', 'ignore'))))
        return _finalize_upstream_response(r, replay, responses_adapter.rehydrate_responses_response)

    return await _stream_or_error_response(url, payload, headers, replay,
                                           responses_adapter.stream_rehydrate_responses,
                                           responses_adapter.rehydrate_responses_response, live_ctx=live_ctx)


@app.get('/healthz')
def healthz():
    # Public (no guard): liveness + positive identification for GUI discovery. `service` lets a probing
    # console confirm it really found an OSSRedact gate; `remote_control` tells it whether this gate accepts
    # authenticated off-device control (token configured) or is loopback-only. No secret is ever exposed.
    out = {'status': 'ok', 'service': 'ossredact-egress', 'version': SERVICE_VERSION, 'dryrun': DRYRUN,
           'gate': _safe_diagnostic_url(GATE_URL), 'remote_control': bool(CONTROL_TOKEN),
           'uptime_s': round(time.time() - START, 1)}
    if GATE_FALLBACK_URL and GATE_FALLBACK_URL != GATE_URL:
        out['gate_fallback'] = _safe_diagnostic_url(GATE_FALLBACK_URL)   # visible so an operator can see the failover target
    return out


def _start_maps_gc():
    """Garbage-collect the entity-map dir on launch, then every GATEWAY_MAPS_GC_INTERVAL_H hours, on a daemon
    thread. The maps dir accumulated one persistent .lock per session forever (orphaned after the .enc TTL'd out)
    plus stale at-rest maps; this bounds it. Runs off the event loop so a slow dir scan never delays serving.
    Started from __main__ (the real server launch), so it is inert during tests. GATEWAY_MAPS_TTL_DAYS=0 disables
    the sweep; GATEWAY_MAPS_GC_INTERVAL_H=0 runs it once at launch and not again."""
    def _sweep(tag):
        try:
            r = gc_maps()
            if r['enc'] or r['lock']:
                print(f"[egress] maps GC ({tag}): removed {r['enc']} expired maps + {r['lock']} locks", flush=True)
        except Exception as e:
            print(f"[egress] maps GC error: {type(e).__name__}", flush=True)

    interval_h = float(os.environ.get('GATEWAY_MAPS_GC_INTERVAL_H', '6'))

    def _run():
        _sweep('startup')
        while interval_h > 0:
            time.sleep(interval_h * 3600)
            _sweep('periodic')

    threading.Thread(target=_run, name='ossredact-maps-gc', daemon=True).start()


# ---------------------------------------------------------------------------
# Control-plane access. The gate may listen on 0.0.0.0 to serve a fleet of agents, but MANAGING it (editing
# the allowlist, flipping the mode, reading the live PII proof feed) must never be open to the network by
# default -- that would let a remote actor weaken redaction or read real PII. So control access requires a
# LOOPBACK peer, OR (opt-in) a valid GATEWAY_CONTROL_TOKEN for authenticated off-device management. The bundled
# settings HTML page (GET /) stays loopback-only regardless (the desktop console is the remote surface). Writes
# go to the UI-managed files, live-reloaded on mtime (no restart, config untouched).
# ---------------------------------------------------------------------------
def _is_loopback(req: Request):
    host = (req.client.host if req.client else '') or ''
    return host in ('127.0.0.1', '::1', 'localhost')


def _control_token_ok(req: Request):
    """True iff a control token is configured AND the request presents the matching secret (constant-time).
    The `x-ossredact-control-token` header authenticates ANY control route. The `?token=` query param is
    honored ONLY for the SSE feed (/api/stream), where the browser EventSource cannot set a header -- every
    other control route uses fetch and MUST use the header, keeping the leakier URL-token path (access/proxy
    logs, Referer, caches) off all routes but the one that has no alternative. Returns False when no token is
    configured (loopback-only stays the default)."""
    if not CONTROL_TOKEN:
        return False
    presented = req.headers.get('x-ossredact-control-token') or ''
    if not presented and req.url.path == '/api/stream':
        presented = req.query_params.get('token') or ''
    return bool(presented) and hmac.compare_digest(presented, CONTROL_TOKEN)


def _control_allowed(req: Request):
    """Authorization for the control API. A LOOPBACK peer is always trusted (the local settings UI / console
    send no token -- unchanged). A REMOTE peer is allowed ONLY when a shared control token is configured and
    presented. So with GATEWAY_CONTROL_TOKEN unset this is identical to the prior loopback-only behaviour."""
    return _is_loopback(req) or _control_token_ok(req)


_LOCAL_ONLY_403 = JSONResponse({'error': 'local-only (set GATEWAY_CONTROL_TOKEN for authenticated remote control)'},
                               status_code=403)


# CSRF guard for state-changing control routes. _is_loopback alone is a confused-deputy hole: a hostile web
# page in the victim's browser can issue a CORS "simple request" (text/plain, no custom header => no preflight)
# to http://127.0.0.1:8011/api/settings and flip the firewall to 'off' -- the browser's own loopback socket
# satisfies _is_loopback, and CORS only blocks READING the response, not the WRITE. Requiring a non-safelisted
# custom header forces a preflight the daemon answers only for allow-listed origins (loopback/Tauri), so a
# cross-origin attacker page can never send it. Same-origin (settings UI) + the workbench client set it directly.
def _has_control_token(req: Request):
    return req.headers.get('x-ossredact-control') == '1'


_CSRF_403 = JSONResponse({'error': 'missing X-OSSRedact-Control header (CSRF guard)'}, status_code=403)


_MAX_ALLOW_VALUES = 1000
_MAX_ALLOW_LEN = 200


def _clean_allow_values(vals):
    """Strip, drop empties / over-long, de-dupe case-insensitively (preserving first spelling + order)."""
    seen, out = set(), []
    for v in vals:
        if not isinstance(v, str):
            continue
        s = v.strip()
        if not s or len(s) > _MAX_ALLOW_LEN:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
        if len(out) >= _MAX_ALLOW_VALUES:
            break
    return out


@app.get('/', response_class=HTMLResponse)
def settings_ui(req: Request):
    if not _is_loopback(req):
        return PlainTextResponse('The OSSRedact settings UI is local-only (loopback).', status_code=403)
    return HTMLResponse(_SETTINGS_HTML)


# Gate-served FULL console (the React workbench/console build) -- the browser GUI for a gate host that
# does not run the desktop app. Serving it FROM the gate makes every control fetch same-origin: no CORS
# grant, no token, and nothing for a hosted web page to be trusted with (the PUBLIC site deliberately
# cannot drive a gate: an allowlisted public origin would hand the control plane to whatever script the
# site's next deploy ships). Loopback-only, same posture as the settings UI above. Files resolve at
# request time, so a console rebuild is picked up without restarting the gate.
CONSOLE_DIR = os.environ.get(
    'GATEWAY_CONSOLE_DIR',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'workbench', 'dist'))
_CONSOLE_LOCAL_ONLY = PlainTextResponse('The OSSRedact console is local-only (loopback).', status_code=403)
_CONSOLE_MISSING = {
    'error': 'console build not found',
    'hint': 'build it once (cd workbench && npm ci && npm run build) or point GATEWAY_CONSOLE_DIR at a build'}


@app.get('/console')
def console_redirect(req: Request):
    # The build uses RELATIVE asset URLs (vite base './'), which only resolve under a trailing slash.
    if not _is_loopback(req):
        return _CONSOLE_LOCAL_ONLY
    return RedirectResponse('/console/', status_code=307)


@app.get('/console/{rest:path}')
def console_static(req: Request, rest: str = ''):
    if not _is_loopback(req):
        return _CONSOLE_LOCAL_ONLY
    root = os.path.realpath(CONSOLE_DIR)
    if not os.path.isfile(os.path.join(root, 'index.html')):
        return JSONResponse(_CONSOLE_MISSING, status_code=404)
    # Containment: resolve symlinks BEFORE the prefix check so neither ../ nor a link escapes the build dir.
    target = os.path.realpath(os.path.join(root, rest)) if rest else root
    if not (target == root or target.startswith(root + os.sep)):
        return JSONResponse({'error': 'not found'}, status_code=404)
    if not os.path.isfile(target):
        target = os.path.join(root, 'index.html')   # SPA shell for '' and unknown paths (deep links stay harmless)
    return FileResponse(target)


@app.get('/api/allowlist')
def api_allowlist_get(req: Request):
    if not _control_allowed(req):
        return _LOCAL_ONLY_403
    current_allowlist()  # ensure the in-memory set reflects the file
    return JSONResponse({'values': _read_allowlist_file(), 'active_total': len(_ALLOWLIST),
                         'config_values': len(load_config().get('allowlist') or []), 'path': _ALLOWLIST_FILE})


@app.post('/api/allowlist')
async def api_allowlist_set(req: Request):
    if not _control_allowed(req):
        return _LOCAL_ONLY_403
    if not _has_control_token(req):
        return _CSRF_403
    try:
        body = await req.json()
    except Exception:
        return JSONResponse({'error': 'invalid json body'}, status_code=400)
    if not isinstance(body, dict) or not isinstance(body.get('values'), list):
        return JSONResponse({'error': 'expected {"values": [...]}'}, status_code=400)
    clean = _clean_allow_values(body['values'])
    try:
        os.makedirs(os.path.dirname(_ALLOWLIST_FILE) or '.', exist_ok=True)
        tmp = _ALLOWLIST_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write('# OSSRedact do-not-redact allowlist -- managed by the settings UI (GET /). One value per line.\n')
            fh.write('# These values pass through to the model verbatim. Secrets/cards/IBANs/gov-IDs are never exempt.\n')
            for v in clean:
                fh.write(v + '\n')
        os.replace(tmp, _ALLOWLIST_FILE)
    except Exception as e:
        return JSONResponse({'error': f'write failed: {type(e).__name__}'}, status_code=500)
    current_allowlist()  # rebuild the live set now
    return JSONResponse({'ok': True, 'values': clean, 'active_total': len(_ALLOWLIST)})


@app.get('/api/denylist')
def api_denylist_get(req: Request):
    if not _control_allowed(req):
        return _LOCAL_ONLY_403
    current_denylist()  # ensure the compiled pattern reflects the file
    vals = _read_denylist_file()
    return JSONResponse({'values': vals, 'active_total': len(denylist_mod.build_terms(_load_denylist_values(load_config()))),
                         'config_values': len(load_config().get('denylist') or []), 'path': _DENYLIST_FILE})


@app.post('/api/denylist')
async def api_denylist_set(req: Request):
    if not _control_allowed(req):
        return _LOCAL_ONLY_403
    if not _has_control_token(req):
        return _CSRF_403
    try:
        body = await req.json()
    except Exception:
        return JSONResponse({'error': 'invalid json body'}, status_code=400)
    if not isinstance(body, dict) or not isinstance(body.get('values'), list):
        return JSONResponse({'error': 'expected {"values": [...]}'}, status_code=400)
    clean = _clean_allow_values(body['values'])   # same strip/dedup/cap rules (terms < 2 chars dropped at compile)
    try:
        os.makedirs(os.path.dirname(_DENYLIST_FILE) or '.', exist_ok=True)
        tmp = _DENYLIST_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write('# OSSRedact always-redact denylist -- managed by the settings UI (GET /). One term per line.\n')
            fh.write('# These terms are ALWAYS redacted, even when the model misses them. Only adds redaction.\n')
            for v in clean:
                fh.write(v + '\n')
        os.replace(tmp, _DENYLIST_FILE)
    except Exception as e:
        return JSONResponse({'error': f'write failed: {type(e).__name__}'}, status_code=500)
    current_denylist()  # recompile the live pattern now
    return JSONResponse({'ok': True, 'values': clean, 'active_total': len(denylist_mod.build_terms(clean))})


@app.get('/api/settings')
def api_settings_get(req: Request):
    if not _control_allowed(req):
        return _LOCAL_ONLY_403
    # floor_always_on documents to the UI that the deterministic floor (secrets/cards/IDs) redacts in every
    # mode, so the 'off' option can be presented honestly as "soft PII off, credentials still protected".
    return JSONResponse({'mode': current_mode(), 'modes': list(_MODES), 'floor_always_on': True,
                         'path': _MODE_FILE})


@app.post('/api/settings')
async def api_settings_set(req: Request):
    if not _control_allowed(req):
        return _LOCAL_ONLY_403
    if not _has_control_token(req):
        return _CSRF_403
    try:
        body = await req.json()
    except Exception:
        return JSONResponse({'error': 'invalid json body'}, status_code=400)
    mode = (body or {}).get('mode') if isinstance(body, dict) else None
    if mode not in _MODES:
        return JSONResponse({'error': f'mode must be one of {list(_MODES)}'}, status_code=400)
    try:
        _write_mode(mode)
    except Exception as e:
        return JSONResponse({'error': f'write failed: {type(e).__name__}'}, status_code=500)
    # A mode change is security-relevant (esp. 'off' / 'coding'); always log it (no PII).
    print(f"[egress] redaction mode set to '{mode}'", flush=True)
    return JSONResponse({'ok': True, 'mode': mode})


# ---------------------------------------------------------------------------
# Live activity API. /api/stream is a Server-Sent Events feed of the in-memory
# redaction ring; it shows real PII values (the proof), so it is never persisted
# and is loopback-guarded by default. With GATEWAY_CONTROL_TOKEN set, an
# authenticated remote console may also read it (token via ?token= -- EventSource
# cannot set headers). The UI's Live tab consumes it.
# ---------------------------------------------------------------------------
def _sse(ev):
    return ('data: ' + json.dumps(ev, ensure_ascii=False) + '\n\n').encode('utf-8')


@app.get('/api/stream')
async def api_stream(req: Request):
    if not _control_allowed(req):
        return _LOCAL_ONLY_403
    if not LIVE_VIEW:
        return JSONResponse({'error': 'live view disabled (GATEWAY_LIVE_VIEW=0)'}, status_code=404)
    q: asyncio.Queue = asyncio.Queue(maxsize=2000)
    backlog = list(_live_ring)
    _live_subscribers.add(q)

    async def gen():
        try:
            yield b': connected\n\n'
            for ev in backlog:
                yield _sse(ev)
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=15)
                    yield _sse(ev)
                except asyncio.TimeoutError:
                    yield b': ping\n\n'   # keep-alive; also lets a dead client surface as a write error
        finally:
            _live_subscribers.discard(q)

    return StreamingResponse(gen(), media_type='text/event-stream',
                             headers={'cache-control': 'no-cache', 'x-accel-buffering': 'no',
                                      'connection': 'keep-alive'})


@app.get('/api/live/status')
def api_live_status(req: Request):
    if not _control_allowed(req):
        return _LOCAL_ONLY_403
    return JSONResponse({'enabled': LIVE_VIEW, 'buffered': len(_live_ring), 'max': _LIVE_MAX,
                         'subscribers': len(_live_subscribers), 'mode': current_mode()})


@app.post('/api/live/clear')
def api_live_clear(req: Request):
    if not _control_allowed(req):
        return _LOCAL_ONLY_403
    if not _has_control_token(req):
        return _CSRF_403
    _live_ring.clear()
    return JSONResponse({'ok': True})


_SETTINGS_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSSRedact · Console</title>
<style>
  :root { --teal:#0d9488; --teal-d:#0f766e; --teal-50:#f0fdfa; --teal-100:#ccfbf1; --ink:#111827;
          --muted:#6b7280; --line:#e5e7eb; --bg:#f6f7f8; --danger:#ef4444; --indigo:#4f46e5; --indigo-50:#eef2ff; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  .wrap { max-width:860px; margin:40px auto; padding:0 20px; }
  .card { background:#fff; border:1px solid var(--line); border-radius:14px; padding:26px 28px 22px;
          box-shadow:0 1px 2px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.04); }
  h1 { font-size:19px; margin:0 0 14px; letter-spacing:-.01em; }
  h1 .dot { color:var(--teal); }
  .tabs { display:flex; gap:4px; border-bottom:1px solid var(--line); margin:0 0 20px; }
  .tab { appearance:none; background:none; border:0; border-bottom:2px solid transparent; padding:9px 14px 11px;
         font-size:14px; font-weight:600; color:var(--muted); cursor:pointer; margin-bottom:-1px; display:flex; align-items:center; gap:7px; }
  .tab[aria-selected=true] { color:var(--teal-d); border-bottom-color:var(--teal); }
  .tab:focus-visible { outline:3px solid rgba(13,148,136,.35); outline-offset:1px; border-radius:6px; }
  .tab .live { width:7px; height:7px; border-radius:50%; background:#cbd5e1; }
  .tab .live.on { background:var(--teal); box-shadow:0 0 0 3px rgba(13,148,136,.18); }
  .panel[hidden] { display:none; }
  .sub { color:var(--muted); font-size:13.5px; margin:0 0 16px; }
  .note { background:var(--teal-50); border:1px solid var(--teal-100); color:#115e59; border-radius:10px;
          padding:10px 12px; font-size:13px; margin:0 0 18px; }
  .note b { color:#134e4a; }
  form#f { display:flex; gap:8px; margin:0 0 14px; }
  input[type=text] { flex:1; padding:11px 13px; border:1px solid var(--line); border-radius:10px; font-size:15px;
                     outline:none; transition:border-color .12s,box-shadow .12s; }
  input[type=text]:focus { border-color:var(--teal); box-shadow:0 0 0 3px rgba(13,148,136,.15); }
  button.add { background:var(--teal); color:#fff; border:0; border-radius:10px; padding:0 18px; font-size:15px;
               font-weight:600; cursor:pointer; transition:background .12s; }
  button.add:hover { background:var(--teal-d); }
  button.add:focus-visible { outline:3px solid rgba(13,148,136,.4); outline-offset:2px; }
  ul { list-style:none; margin:0; padding:0; }
  li { display:flex; align-items:center; gap:10px; padding:10px 4px 10px 12px; border:1px solid var(--line);
       border-radius:10px; margin-bottom:8px; background:#fff; }
  li .val { flex:1; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13.5px; word-break:break-all; }
  li .rm { background:none; border:0; color:var(--muted); font-size:20px; line-height:1; cursor:pointer;
           padding:4px 10px; border-radius:8px; }
  li .rm:hover { color:var(--danger); background:#fef2f2; }
  .empty { color:var(--muted); font-size:13.5px; text-align:center; padding:26px 14px; line-height:1.6; }
  .status { display:flex; align-items:center; gap:8px; margin-top:16px; padding-top:14px; border-top:1px solid var(--line);
            color:var(--muted); font-size:13px; }
  .dotled { width:8px; height:8px; border-radius:50%; background:var(--teal); box-shadow:0 0 0 3px rgba(13,148,136,.18); }
  .path { margin-left:auto; font-family:ui-monospace,monospace; font-size:11.5px; color:#9ca3af; }
  /* live tab */
  .bar { display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin:0 0 14px; }
  .bar .conn { display:flex; align-items:center; gap:7px; font-size:13px; color:var(--muted); margin-right:auto; }
  .bar .conn b { color:var(--ink); font-weight:600; }
  .cdot { width:8px; height:8px; border-radius:50%; background:#cbd5e1; }
  .cdot.ok { background:var(--teal); box-shadow:0 0 0 3px rgba(13,148,136,.18); }
  .cdot.err { background:var(--danger); }
  .btn { appearance:none; border:1px solid var(--line); background:#fff; color:var(--ink); border-radius:9px;
         padding:6px 11px; font-size:13px; font-weight:600; cursor:pointer; display:inline-flex; align-items:center; gap:6px; }
  .btn:hover { background:#f9fafb; } .btn:focus-visible { outline:3px solid rgba(13,148,136,.3); outline-offset:1px; }
  .btn[aria-pressed=true] { background:var(--teal-50); border-color:var(--teal-100); color:var(--teal-d); }
  .feed { display:flex; flex-direction:column; gap:10px; max-height:62vh; overflow:auto; padding:2px; }
  .ev { border:1px solid var(--line); border-left:3px solid var(--teal); border-radius:11px; padding:11px 13px; background:#fff; }
  .ev.response { border-left-color:var(--indigo); }
  .ev.clean { border-left-color:#cbd5e1; }
  .ev-h { display:flex; align-items:center; gap:9px; flex-wrap:wrap; font-size:12.5px; color:var(--muted); }
  .ev-h .dir { font-weight:700; font-size:11px; letter-spacing:.03em; color:var(--teal-d); }
  .ev.response .ev-h .dir { color:var(--indigo); }
  .ev-h .cl { font-weight:600; color:var(--ink); }
  .ev-h .rt { font-family:ui-monospace,monospace; font-size:11px; color:#9ca3af; }
  .ev-h .sess { font-family:ui-monospace,monospace; font-size:10.5px; color:#94a3b8; border:1px solid var(--line); border-radius:6px; padding:0 5px; }
  .ev-h .n { margin-left:auto; font-weight:700; color:var(--ink); }
  .ev-h .n.warn { color:var(--danger); }
  .ents { margin:9px 0 0; display:flex; flex-direction:column; gap:5px; }
  .ent { display:grid; grid-template-columns:1fr auto 1fr auto; align-items:center; gap:9px; font-size:13px; }
  .ent .val { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; }
  .ent .real { color:var(--ink); }
  .ent .ph { font-family:ui-monospace,monospace; color:var(--teal-d); background:var(--teal-50); border-radius:6px; padding:1px 6px; justify-self:start; word-break:break-all; }
  .ev.response .ent .ph { color:var(--indigo); background:var(--indigo-50); }
  .ent .arrow { color:#cbd5e1; font-weight:700; }
  .ent .lab { font-size:10.5px; font-weight:700; letter-spacing:.02em; text-transform:uppercase; color:#fff; border-radius:999px; padding:2px 8px; justify-self:end; white-space:nowrap; }
  .feed.blur .ent .real { filter:blur(5px); transition:filter .1s; cursor:pointer; }
  .feed.blur .ent .real:hover { filter:none; }
  .deg { color:var(--danger); font-weight:700; }
  .legend { font-size:12px; color:var(--muted); background:#f9fafb; border:1px solid var(--line); border-radius:9px;
            padding:9px 11px; margin:0 0 14px; line-height:1.55; }
  .legend b { color:var(--ink); }
  .legend .sw { display:inline-block; width:9px; height:9px; border-radius:3px; vertical-align:middle; margin:0 3px 0 8px; }
  .toast { position:fixed; bottom:24px; left:50%; transform:translateX(-50%) translateY(20px); opacity:0;
           background:var(--ink); color:#fff; padding:9px 16px; border-radius:999px; font-size:13px;
           transition:opacity .18s,transform .18s; pointer-events:none; }
  .toast.show { opacity:1; transform:translateX(-50%) translateY(0); }
  /* mode switch + always-on floor banner */
  .modebar { display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin:0 0 12px; }
  .modelabel { font-size:13px; font-weight:600; color:var(--muted); }
  .seg { display:inline-flex; background:#eef0f2; border:1px solid var(--line); border-radius:10px; padding:3px; gap:2px; }
  .seg-b { appearance:none; border:0; background:none; color:var(--muted); font:600 13px/1 system-ui,sans-serif;
           padding:7px 14px; border-radius:8px; cursor:pointer; }
  .seg-b[aria-pressed=true] { background:#fff; color:var(--teal-d); box-shadow:0 1px 2px rgba(0,0,0,.1); }
  .seg-b.off[aria-pressed=true] { color:var(--danger); }
  .seg-b:focus-visible { outline:3px solid rgba(13,148,136,.35); outline-offset:1px; }
  .modehint { font-size:12.5px; color:var(--muted); flex-basis:100%; margin:-4px 0 0; }
  .floorbanner { background:#ecfdf5; border:1px solid var(--teal-100); color:#115e59; border-radius:10px;
                 padding:9px 12px; font-size:12.5px; line-height:1.5; margin:0 0 18px; display:flex; gap:8px; align-items:flex-start; }
  .floorbanner b { color:#134e4a; }
  .floorbanner .lk { flex-shrink:0; width:15px; height:15px; margin-top:1px; }
  .note.deny { background:#fff7ed; border-color:#fed7aa; color:#9a3412; }
  .note.deny b { color:#7c2d12; }
  @media (prefers-reduced-motion: reduce) { * { transition:none !important; } }
</style></head>
<body><div class="wrap"><div class="card">
  <h1>OSSRedact <span class="dot">·</span> Local console</h1>
  <div class="modebar">
    <span class="modelabel">Redaction mode</span>
    <div class="seg" role="group" aria-label="Redaction mode">
      <button class="seg-b" id="mode-privacy" data-mode="privacy" type="button" aria-pressed="false">Privacy</button>
      <button class="seg-b" id="mode-coding" data-mode="coding" type="button" aria-pressed="false">Coding</button>
      <button class="seg-b off" id="mode-off" data-mode="off" type="button" aria-pressed="false">Off</button>
    </div>
    <span class="modehint" id="modehint"></span>
  </div>
  <div class="floorbanner">
    <svg class="lk" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
    <span><b>Floor always on.</b> Secrets, passwords, API keys, payment cards, IBANs, bank accounts and government / tax IDs are redacted in <b>every</b> mode, including Off.</span>
  </div>
  <div class="tabs" role="tablist" aria-label="Console sections">
    <button class="tab" id="tab-allow" role="tab" aria-selected="true" aria-controls="panel-allow">Do-not-redact</button>
    <button class="tab" id="tab-deny" role="tab" aria-selected="false" aria-controls="panel-deny">Always-redact</button>
    <button class="tab" id="tab-live" role="tab" aria-selected="false" aria-controls="panel-live">Live activity <span class="live" id="livedot"></span></button>
  </div>

  <section class="panel" id="panel-allow" role="tabpanel" aria-labelledby="tab-allow">
    <p class="sub">Your own known-safe values -- your name, your email, your file paths -- that the gate should let through instead of redacting.</p>
    <div class="note"><b>These values reach the model verbatim.</b> Secrets, passwords, API keys, payment cards, IBANs, bank accounts and government / tax IDs are <b>never</b> exempt, even if listed.</div>
    <form id="f-allow"><input id="v-allow" type="text" autocomplete="off" autocapitalize="off" spellcheck="false"
          placeholder="add a name, email, or path…" aria-label="value to allowlist"><button class="add" type="submit">Add</button></form>
    <ul id="list-allow" aria-live="polite"></ul>
    <div class="status"><span class="dotled"></span><span id="count-allow">…</span><span class="path" id="path-allow"></span></div>
  </section>

  <section class="panel" id="panel-deny" role="tabpanel" aria-labelledby="tab-deny" hidden>
    <p class="sub">Your own must-mask terms -- internal codenames, client names, hostnames -- redacted everywhere they appear, even when no detector flags them.</p>
    <div class="note deny"><b>These terms are always redacted.</b> Matched case-insensitively on word boundaries. This only ADDS redaction -- it can never weaken the floor or release anything.</div>
    <form id="f-deny"><input id="v-deny" type="text" autocomplete="off" autocapitalize="off" spellcheck="false"
          placeholder="add a codename, client, or hostname…" aria-label="term to always redact"><button class="add" type="submit">Add</button></form>
    <ul id="list-deny" aria-live="polite"></ul>
    <div class="status"><span class="dotled"></span><span id="count-deny">…</span><span class="path" id="path-deny"></span></div>
  </section>

  <section class="panel" id="panel-live" role="tabpanel" aria-labelledby="tab-live" hidden>
    <p class="sub">Live, local proof the firewall is working: every request your tools send through the gate, and exactly what it masked.</p>
    <div class="legend">
      <b>Outbound</b><span class="sw" style="background:var(--teal)"></span>your real data → the placeholder the model actually receives.
      <b>Inbound</b><span class="sw" style="background:var(--indigo)"></span>placeholders in the reply → swapped back to your real data.
      The upstream model only ever sees the right-hand placeholders -- never the left column. Nothing here is written to disk.
    </div>
    <div class="bar">
      <span class="conn"><span class="cdot" id="cdot"></span><span id="connlabel">connecting…</span> · <b id="evcount">0</b> events</span>
      <button class="btn" id="pause" aria-pressed="false" title="Pause the live feed">⏸ Pause</button>
      <button class="btn" id="blur" aria-pressed="false" title="Blur real values for screen-sharing">🕶 Blur values</button>
      <button class="btn" id="filter" aria-pressed="false" title="Show only requests that redacted something">Redactions only</button>
      <button class="btn" id="clear" title="Clear the on-screen and buffered events">Clear</button>
    </div>
    <div class="feed" id="feed" aria-live="polite"></div>
  </section>
</div></div>
<div class="toast" id="toast"></div>
<script>
const $ = s => document.querySelector(s);
function toast(t){ const e=$('#toast'); e.textContent=t; e.classList.add('show'); clearTimeout(e._t); e._t=setTimeout(()=>e.classList.remove('show'),1400); }
function el(tag, cls, txt){ const e=document.createElement(tag); if(cls) e.className=cls; if(txt!=null) e.textContent=txt; return e; }

/* ---- tabs (roving tablist, N tabs) ---- */
const TABS=['allow','deny','live'];
const tabEls=TABS.map(k=>$('#tab-'+k));
function selectTab(which){
  TABS.forEach(k=>{ const on=k===which;
    $('#tab-'+k).setAttribute('aria-selected', on?'true':'false');
    $('#panel-'+k).hidden=!on; });
  if(which==='live' && !window._streamStarted) startStream();
  location.hash=which;
}
tabEls.forEach((t,i)=>{
  t.onclick=()=>selectTab(TABS[i]);
  t.addEventListener('keydown',e=>{ if(e.key==='ArrowRight'||e.key==='ArrowLeft'){ e.preventDefault();
    const dir=e.key==='ArrowRight'?1:-1; const n=tabEls[(i+dir+tabEls.length)%tabEls.length]; n.focus(); n.click(); }});
});
const _h=(location.hash||'').replace('#','');
selectTab(TABS.includes(_h)?_h:'allow');

/* ---- dictionaries (allowlist + denylist share one implementation) ---- */
function makeDict(opts){
  let values=[];
  const list=$('#list-'+opts.key), countEl=$('#count-'+opts.key), pathEl=$('#path-'+opts.key);
  function render(){
    if(!values.length){ list.innerHTML='<div class="empty">'+opts.empty+'</div>'; return; }
    list.innerHTML=''; values.forEach(v=>{ const li=el('li'); li.appendChild(el('span','val',v));
      const b=el('button','rm','×'); b.type='button'; b.title='Remove'; b.setAttribute('aria-label','Remove '+v);
      b.onclick=()=>{ values=values.filter(x=>x!==v); save(); }; li.appendChild(b); list.appendChild(li); });
  }
  function setCount(d,extra){ countEl.textContent=(d.active_total||0)+' '+opts.noun+((d.active_total===1)?'':'s')+' active in the gate'+(extra||''); }
  async function load(){ const r=await fetch(opts.endpoint); const d=await r.json();
    values=d.values||[]; render(); setCount(d, d.config_values?(' (+'+d.config_values+' from config)'):''); pathEl.textContent=d.path||''; }
  async function save(){ render();
    const r=await fetch(opts.endpoint,{method:'POST',headers:{'content-type':'application/json','x-ossredact-control':'1'},body:JSON.stringify({values})});
    const d=await r.json(); if(d.ok){ values=d.values; render(); setCount(d,''); toast('Saved -- live in the gate'); }
    else { toast('Error: '+(d.error||'save failed')); load(); } }
  $('#f-'+opts.key).addEventListener('submit',e=>{ e.preventDefault(); const i=$('#v-'+opts.key); const t=i.value.trim();
    if(!t) return; if(!values.some(x=>x.toLowerCase()===t.toLowerCase())){ values.push(t); save(); } i.value=''; i.focus(); });
  load();
}
makeDict({key:'allow', endpoint:'/api/allowlist', noun:'value', empty:'No values yet. Add your name, email, or a path above.'});
makeDict({key:'deny', endpoint:'/api/denylist', noun:'term', empty:'No terms yet. Add a codename, client name, or hostname above.'});

/* ---- redaction mode (privacy | coding | off) ---- */
const MODE_HINT={ privacy:'Redacts all detected PII and secrets.',
  coding:'Redacts PII, but lets organization & tech names through so coding agents keep context.',
  off:'Soft PII passes through. The floor still redacts secrets, cards, bank / IBAN and government IDs.' };
const MODE_KEYS=['privacy','coding','off']; let curMode=null;
function paintMode(m){ curMode=m; MODE_KEYS.forEach(k=>$('#mode-'+k).setAttribute('aria-pressed', k===m?'true':'false')); $('#modehint').textContent=MODE_HINT[m]||''; }
async function loadMode(){ try{ const d=await (await fetch('/api/settings')).json(); paintMode(d.mode||'privacy'); }catch(_){ } }
async function setMode(m){ if(m===curMode) return;
  if(m==='off' && !confirm('Turn redaction OFF? Soft PII (names, emails, phones, addresses) will pass through to the model. Secrets, cards, bank / IBAN and government IDs stay protected by the always-on floor.')) return;
  const prev=curMode; paintMode(m);
  const r=await fetch('/api/settings',{method:'POST',headers:{'content-type':'application/json','x-ossredact-control':'1'},body:JSON.stringify({mode:m})});
  const d=await r.json(); if(d.ok){ toast('Mode: '+m); } else { toast('Error: '+(d.error||'failed')); paintMode(prev); } }
MODE_KEYS.forEach(k=>$('#mode-'+k).onclick=()=>setMode(k));
loadMode();

/* ---- live activity ---- */
const LABEL_HUE={person:200,name:200,email:265,phone:25,phone_number:25,address:140,organization:300,
  account_number:15,sensitive_account_id:0,iban:0,payment_card:0,card_cvv:0,card_expiry:0,bank_account:0,
  routing_number:10,government_id:350,tax_id:330,date_of_birth:50,secret:0,password:0,api_key:0,access_token:0,
  filepath:175,file_path:175,path:175,ip_address:190,username:230,url:210};
function hueFor(label){ if(label in LABEL_HUE) return LABEL_HUE[label]; let h=0; for(const c of label) h=(h*31+c.charCodeAt(0))%360; return h; }
function fmtTime(ts){ const d=new Date(ts*1000); const p=n=>String(n).padStart(2,'0'); return p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds()); }
function trunc(s,n){ s=String(s); return s.length>n ? s.slice(0,n)+'…' : s; }

let lastSeq=0, paused=false, pausedBuf=[], filterOnly=false, evCount=0;
function entRow(ev, e){
  const row=el('div','ent');
  const left = ev.kind==='request' ? el('span','val real',trunc(e.value,140)) : el('span','val ph',e.placeholder);
  if(ev.kind==='request') left.title=e.value;
  const right = ev.kind==='request' ? el('span','val ph',e.placeholder) : el('span','val real',trunc(e.value,140));
  if(ev.kind==='response') right.title=e.value;
  const lab=el('span','lab',(e.label||'value').replace(/_/g,' ')); const h=hueFor(e.label||'value');
  lab.style.background='hsl('+h+',62%,42%)';
  row.appendChild(left); row.appendChild(el('span','arrow','→')); row.appendChild(right); row.appendChild(lab);
  return row;
}
function buildCard(ev){
  const isReq = ev.kind==='request';
  const nEnt = (ev.entities||[]).length;
  const clean = isReq && nEnt===0;
  const card=el('div','ev '+(isReq?(clean?'clean':'request'):'response'));
  const h=el('div','ev-h');
  h.appendChild(el('span','dir', isReq?'→ OUT':'← IN'));
  h.appendChild(el('span','t', fmtTime(ev.ts)));
  h.appendChild(el('span','cl', ev.client||'client'));
  h.appendChild(el('span','rt', ev.route||''));
  if(ev.session) h.appendChild(el('span','sess', ev.session));
  if(ev.degraded){ const d=el('span','deg','⚠ degraded'); h.appendChild(d); }
  const n=el('span','n');
  if(isReq){ n.textContent = nEnt? (nEnt+' redacted') : (ev.redaction==='scanned-clean'?'scanned · clean ✓':'no PII'); }
  else { n.textContent = (ev.n_rehydrated||nEnt)+' rehydrated'; }
  h.appendChild(n);
  card.appendChild(h);
  if(nEnt){ const ents=el('div','ents'); (ev.entities||[]).forEach(e=>ents.appendChild(entRow(ev,e))); card.appendChild(ents); }
  return card;
}
function showEvent(ev){
  if(filterOnly){ const nEnt=(ev.entities||[]).length; if(ev.kind==='request'&&nEnt===0) return; }
  const feed=$('#feed'); const empty=feed.querySelector('.empty'); if(empty) empty.remove();
  feed.insertBefore(buildCard(ev), feed.firstChild);
  while(feed.childNodes.length>400) feed.removeChild(feed.lastChild);
  evCount++; $('#evcount').textContent=evCount;
}
function onEvent(ev){
  if(ev.seq && ev.seq<=lastSeq) return; if(ev.seq) lastSeq=ev.seq;
  if(paused){ pausedBuf.push(ev); $('#pause').textContent='▶ Resume ('+pausedBuf.length+')'; return; }
  showEvent(ev);
}
function emptyFeed(msg){ const feed=$('#feed'); feed.innerHTML=''; feed.appendChild(el('div','empty',msg)); }
function startStream(){
  window._streamStarted=true;
  emptyFeed('Waiting for traffic… send a request through the gate from any of your tools and it appears here, live.');
  const conn=(state,label)=>{ const c=$('#cdot'); c.className='cdot'+(state==='ok'?' ok':state==='err'?' err':''); $('#connlabel').textContent=label; $('#livedot').className='live'+(state==='ok'?' on':''); };
  conn('','connecting…');
  const es=new EventSource('/api/stream');
  es.onopen=()=>conn('ok','connected');
  es.onerror=()=>conn('err','reconnecting…');
  es.onmessage=m=>{ try{ const ev=JSON.parse(m.data); if(ev && ev.kind) onEvent(ev); }catch(_){} };
}
$('#pause').onclick=()=>{ paused=!paused; const b=$('#pause'); b.setAttribute('aria-pressed',paused?'true':'false');
  if(!paused){ const buf=pausedBuf; pausedBuf=[]; buf.forEach(showEvent); b.textContent='⏸ Pause'; } else { b.textContent='⏸ Paused'; } };
$('#blur').onclick=()=>{ const on=$('#feed').classList.toggle('blur'); $('#blur').setAttribute('aria-pressed',on?'true':'false'); };
$('#filter').onclick=()=>{ filterOnly=!filterOnly; $('#filter').setAttribute('aria-pressed',filterOnly?'true':'false'); toast(filterOnly?'Showing redactions only':'Showing all traffic'); };
$('#clear').onclick=async()=>{ try{ await fetch('/api/live/clear',{method:'POST',headers:{'x-ossredact-control':'1'}});}catch(_){}
  pausedBuf=[]; evCount=0; $('#evcount').textContent='0'; emptyFeed('Cleared. New traffic will appear here.'); toast('Cleared'); };

if(location.hash==='#live') selectTab('live');
</script>
</body></html>"""


def _startup_warnings():
    """Surface the two postures that silently widen exposure, at the real launch (this __main__ path; not on
    import, so tests stay quiet). No values -- only the flags."""
    if not FAIL_CLOSED:
        print('[egress] WARNING: GATEWAY_FAIL_OPEN=1 -- Tier-0-only egress. If the neural gate is unreachable, '
              'requests are forwarded ANYWAY, so NER-only PII (names/org/address) can leak. Unset for the '
              'fail-closed default (recommended).', flush=True)
    if HOST not in ('127.0.0.1', '::1', 'localhost'):
        print(f'[egress] WARNING: bound {HOST}:{PORT} on a NON-loopback interface. The redaction routes (/v1/*) '
              'are an UNAUTHENTICATED relay -- anyone who can reach this port can proxy through it (only /api/* '
              'is token-gated). There is NO TLS and /api/stream carries REAL PII in cleartext. Run this ONLY on a '
              'trusted, encrypted network (a tailnet), never the open internet, ideally behind an https underlay '
              '(e.g. tailscale serve).', flush=True)
        if not CONTROL_TOKEN:
            print('[egress] note: GATEWAY_CONTROL_TOKEN is unset, so the control API (/api/*) stays loopback-only '
                  'even though the proxy is bound non-loopback (a remote console cannot manage this gate).', flush=True)


if __name__ == '__main__':
    _startup_warnings()
    _start_maps_gc()
    uvicorn.run(app, host=HOST, port=PORT, log_level='warning')
