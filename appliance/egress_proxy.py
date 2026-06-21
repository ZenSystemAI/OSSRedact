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
import os, sys, json, time, re, hashlib, asyncio
from collections import deque
from urllib.parse import urlsplit, urlunsplit
import yaml
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse, PlainTextResponse
import uvicorn

APPLIANCE_DIR = os.environ.get('GATEWAY_APPLIANCE_DIR') or os.path.dirname(os.path.abspath(__file__))
if APPLIANCE_DIR not in sys.path:
    sys.path.insert(0, APPLIANCE_DIR)
from privacy_gate import tier0_spans, merge_spans, post_merge_address, explain, FLOOR_LABELS  # cheap Tier-0 (no model load)
from entity_map import EntityMap, derive_session, map_file_lock
import redact_core
import allowlist as allowlist_mod   # the do-not-redact dictionary (value-exact, opt-in)
import denylist as denylist_mod     # the always-redact dictionary (term scanner, opt-in)
from secrets_scan import secret_spans                                   # deterministic secrets (always-on)
import openai_adapter   # OpenAI /v1/chat/completions schema translation (Codex / omp / OpenAI-compatible)
import responses_adapter   # OpenAI /v1/responses schema translation (Codex CLI speaks /v1/responses ONLY)
from name_carrier import name_shaped, carrier_person_spans   # plan 026: rare-name carrier-wrap booster (NER recall)

ANTHROPIC_UPSTREAM = os.environ.get('GATEWAY_ANTHROPIC_UPSTREAM', 'https://api.anthropic.com')
OPENAI_UPSTREAM = os.environ.get('GATEWAY_OPENAI_UPSTREAM', 'https://api.openai.com')
# Codex with a ChatGPT/Codex PLAN (no platform API key) authenticates against the ChatGPT backend, not the
# platform API -- its OAuth token has no `api.responses.write` scope, so api.openai.com 401s it. Plan
# requests are routed here instead (see /v1/responses), keyed on the chatgpt-account-id header Codex sends
# only on the plan path. Override for a self-hosted/enterprise ChatGPT backend.
CHATGPT_UPSTREAM = os.environ.get('GATEWAY_CHATGPT_UPSTREAM', 'https://chatgpt.com/backend-api/codex')
GATE_URL = os.environ.get('GATEWAY_GATE_URL', 'http://127.0.0.1:8001')
DRYRUN = os.environ.get('GATEWAY_DRYRUN', '0') == '1'        # don't forward upstream; echo would-be-upstream body
EXPOSE_MAP = os.environ.get('GATEWAY_TEST_EXPOSE_MAP', '0') == '1'   # test-only: include replay map in dryrun
PORT = int(os.environ.get('GATEWAY_PORT', '8011'))
HOST = os.environ.get('GATEWAY_HOST', '127.0.0.1')
LOG_REQUESTS = os.environ.get('GATEWAY_LOG_REQUESTS', '1') == '1'   # logs COUNTS/LABELS/placeholder TOKENS only
EXPLAIN = os.environ.get('GATEWAY_EXPLAIN', '0') == '1'   # opt-in: per-span provenance (no values) in meta['explain']
# FAIL CLOSED when the neural gate is unreachable (FIX-ROUND-3 HIGH). Post-FIX-2 EVERY non-trivial field is
# neural-scanned, so a gate outage means an NER-only name (no Tier-0 fallback) in ANY scanned field would pass
# upstream RAW. When degraded (a field needed the gate and got None back), the route refuses to forward and returns
# 503 instead of leaking. Default ON; set GATEWAY_FAIL_OPEN=1 ONLY to deliberately trade privacy for availability.
FAIL_CLOSED = os.environ.get('GATEWAY_FAIL_OPEN', '0') != '1'
START = time.time()
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
# SSE feed. This does NOT widen access: every control route is ALSO loopback-PEER
# guarded (_is_loopback on req.client.host), so a remote origin can never reach them
# regardless of CORS. The redaction routes (/v1/*) are deliberately untouched -- they
# get no CORS headers and pass straight through. Origins are allow-listed to localhost
# / 127.0.0.1 / [::1] / tauri.localhost only (never reflected for arbitrary origins).
# ---------------------------------------------------------------------------
_CORS_ORIGIN_RE = re.compile(
    r'^(https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?|https?://tauri\.localhost|tauri://localhost)$', re.I)


def _is_control_path(path):
    return path == '/healthz' or path.startswith('/api')


@app.middleware('http')
async def _control_cors(request: Request, call_next):
    # Fast path: anything that is not a control route is forwarded with ZERO header changes.
    try:
        if not _is_control_path(request.url.path):
            return await call_next(request)
        origin = request.headers.get('origin')
        allow = bool(origin and _CORS_ORIGIN_RE.match(origin))
        if request.method == 'OPTIONS':
            # CORS preflight (e.g. POST /api/allowlist with content-type: application/json). Answer here
            # without touching the route; only emit allow-headers when the origin is permitted.
            hdrs = {}
            if allow:
                hdrs = {'access-control-allow-origin': origin, 'vary': 'Origin',
                        'access-control-allow-methods': 'GET, POST, OPTIONS',
                        'access-control-allow-headers': 'content-type, x-ossredact-control',
                        'access-control-max-age': '600'}
            return PlainTextResponse('', status_code=204, headers=hdrs)
        resp = await call_next(request)
        if allow:
            resp.headers['access-control-allow-origin'] = origin
            resp.headers['vary'] = 'Origin'
        return resp
    except Exception as e:
        # A CORS bug must never break the firewall. Log for observability, then fall back to the raw response.
        print(f"[cors middleware error] {type(e).__name__}", flush=True)
        return await call_next(request)


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
                 'path', 'filepath', 'phone']
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
_BINARY_BLOCK_TYPES = ('image', 'input_image', 'image_url', 'document', 'redacted_thinking')


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
                elif t == 'thinking' and isinstance(blk.get('thinking'), str):
                    # Extended-thinking: the model's thinking is rehydrated on the response (see
                    # rehydrate_anthropic_response -> _rehydrate_json walks ALL strings), so a multi-turn client
                    # re-sends a thinking block carrying REAL PII. Scan it so the known-value sweep re-redacts.
                    # Only `thinking` is extracted -- the `signature` is never touched (no placeholder tokens).
                    fields.append(Field(blk, 'thinking', 'message'))
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


_DETECT_CACHE = {}
_CACHE_MAX = 4096


def _detect_cache_key(text, min_score):
    digest = hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()
    return digest, len(text), float(min_score)


async def _detect_neural(aclient, text, min_score=0.5):
    """Call the NPU gate /detect (chunked); offset spans back to field coords. Cache by a digest of text+score so
    repeating prompts / prior turns aren't re-scanned while raw text is not retained as a cache key. Returns spans,
    or None if the gate is unreachable (caller then keeps Tier-0 only and flags degraded)."""
    key = _detect_cache_key(text, min_score)
    cached = _DETECT_CACHE.get(key)
    if cached is not None:
        return cached
    allspans = []
    try:
        for off, chunk in _chunks(text):
            r = await aclient.post(GATE_URL + '/detect', json={'text': chunk, 'min_score': min_score})
            r.raise_for_status()
            for s in r.json().get('spans', []):
                sp = {'start': s['start'] + off, 'end': s['end'] + off, 'label': s['label'],
                      'tier': s.get('tier', 1), 'conf': s.get('conf', 0.5), 'rule': s.get('rule', 'npu')}
                for k in ('validator', 'cue', 'subtype', 'members'):
                    if s.get(k) is not None:
                        sp[k] = s[k]
                allspans.append(sp)
    except Exception as e:
        print(f"[gate /detect error] {type(e).__name__}", flush=True)   # never log text
        return None
    if len(_DETECT_CACHE) < _CACHE_MAX:
        _DETECT_CACHE[key] = allspans
    return allspans


# ----------------------------------------------------------------------------
# Policy (SPECS §4): per-project + per-session PII config, secrets always on.
# Resolution: session override > project override > default. Config is mtime-watched (live edits).
# ----------------------------------------------------------------------------
CONFIG_PATH = os.environ.get('GATEWAY_CONFIG', os.path.expanduser('~/.ossredact/gateway-config.yaml'))
# operational labels excluded by DEFAULT (high-volume, low-sensitivity; redacting them adds noise + can
# degrade the coding assistant -- e.g. file paths break agent file ops). Toggle per-project if a DLP setup needs them.
# organization is deliberately NOT excluded: the v11r9c+ model detects it reliably and leaking an employer/client
# defeats the firewall's purpose. Code-heavy sessions can re-add 'org' per-project/session if it's noise there.
DEFAULT_EXCLUDE = ['filepath', 'username']
DEFAULT_CONFIG = {'secrets': {'enabled': True, 'entropy_backstop': True},
                  'pii': {'default': {'enabled': True, 'exclude': DEFAULT_EXCLUDE}, 'projects': {}, 'sessions': {}}}
# friendly category -> model/Tier-0 labels (for the optional restrictive allowlist + the exclude list)
CATEGORY_LABELS = {
    'person': ['person'], 'address': ['address'], 'phone': ['phone_number'], 'email': ['email'],
    'account': ['sensitive_account_id', 'bank_account', 'iban', 'routing_number'],
    'nas': ['government_id'], 'tax': ['tax_id'], 'card': ['payment_card', 'card_cvv', 'card_expiry'],
    'dob': ['date_of_birth'], 'date': ['sensitive_date'], 'postal': ['postal_code'], 'ip': ['ip_address'],
    'org': ['organization'], 'filepath': ['file_path'], 'username': ['username'],
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
#   privacy : redact ALL detected PII (default, strongest).
#   coding  : let organizations / tech names through (org excluded) so a coding agent keeps framework
#             context -- everything else (names, addresses, emails, the floor) still redacts.
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
    # soft-PII redaction wholesale (the floor stays -- see policy_allows_pii); 'coding' lets organizations
    # through; 'privacy' is the default (no change). The floor is never affected here.
    mode = current_mode()
    if mode == 'off':
        pol = {**pol, 'enabled': False}
    elif mode == 'coding' and 'org' not in (pol.get('exclude') or []):
        pol = {**pol, 'exclude': list(pol.get('exclude') or []) + ['org']}
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
    # Load only long enough to decide the true empty fast-path. Do not hold a blocking file lock across the
    # awaited detector calls below; the fresh load/mint/sweep/save mutation happens under the lock after detection.
    with map_file_lock(session, project):
        has_known = bool(EntityMap(session, project).v2p)

    # truly-nothing path: ONLY skip when there are literally zero non-empty extracted text fields AND no prior
    # session entities to backstop. A request with ANY scannable field is neural-scanned below (FIX 2): an NER-only
    # name (no Tier-0 hit, below the prose-length bar -- e.g. a 2-word name in a short field) must NOT skip the scan.
    if not any_scannable and not has_known:
        # FAIL-CLOSED backstop (prime directive): a body that surfaced ZERO scannable text fields but still carries
        # a deterministic SECRET in some shape the walker did not recognize must NOT be forwarded raw. Scan the
        # serialized body for the secret floor; on a hit, raise -> _redact_or_block returns 503 (refuse) instead of
        # leaking. Secret-floor precision (keyword/provider/entropy + benign filter) keeps structural JSON from
        # false-blocking. This is the last line behind the input_text/array-of-strings/unknown-block coverage above.
        if secret_spans(json.dumps(body, ensure_ascii=False)):
            raise RuntimeError('fail-closed: unscannable body shape carries a secret')
        return {'n_fields': len(fields), 'redaction': 'skip', 'n_spans': 0}, {}

    allow = current_allowlist()   # user do-not-redact values (secrets stay non-exempt below)
    deny = current_denylist()     # user always-redact terms (force-redacted even when the model misses them)

    async def collect_detected_fields(detect_text):
        detected_fields = []
        for fi, (f, t, t0, prose) in enumerate(per_field):
            spans = list(t0)
            # NER-only PII (a NAME with no Tier-0 regex fallback) leaks if a SHORT non-prose field (e.g. a 2-word
            # name "Jane Roy" in a short tool description or a short arg value) is never neural-scanned. The
            # EXTRACTOR already decided every surfaced field is redactable free text; that decision -- not a
            # prose-length heuristic -- drives scanning. So neural-scan EVERY field carrying non-trivial text
            # (stripped length above a tiny floor), regardless of Tier-0/prose. (Tier-0 hits still scan too.)
            if len(t.strip()) >= 2:
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
                    stripped = t.strip()
                    if name_shaped(stripped) and not any(s.get('label') == 'person' for s in neural):
                        lead = len(t) - len(t.lstrip())
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
                continue
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
                detected_fields.append((fi, f, t, spans))
        return detected_fields

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

        # pass 3: known-entity backstop with the now-complete map (catches model misses, cross-turn + in-request)
        n_swept = 0
        known_re = build_known_re(emap)
        if known_re is not None:
            for f in fields:
                cur = f.text
                red2, kn = sweep_known(cur, known_re, emap)
                if kn:
                    f.write(red2)
                    n_swept += kn

        total += n_swept
        if total:
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


def _rehydrate_json(v, replay):
    if isinstance(v, str):
        return rehydrate_text(v, replay)
    if isinstance(v, list):
        return [_rehydrate_json(x, replay) for x in v]
    if isinstance(v, dict):
        rebuilt = {}
        for k, x in v.items():
            nk = rehydrate_text(k, replay) if isinstance(k, str) else k
            if nk in rebuilt and nk != k:
                nk = _disambiguate_key(nk if isinstance(nk, str) else k, rebuilt, k)
            rebuilt[nk] = _rehydrate_json(x, replay)
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


def rehydrate_anthropic_response(obj, replay):
    if not replay or not isinstance(obj, (dict, list)):
        return obj
    rehydrated = _rehydrate_json(obj, replay)
    if isinstance(obj, dict) and isinstance(rehydrated, dict):
        obj.clear()
        obj.update(rehydrated)
        return obj
    if isinstance(obj, list) and isinstance(rehydrated, list):
        obj[:] = rehydrated
        return obj
    return rehydrated


def rehydrate_json_string(acc, replay):
    """Rehydrate placeholders inside assembled tool_use arguments JSON, including object keys."""
    if not acc or not acc.strip():
        return acc
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


def _transform_event(raw, replay, carry, block_type, json_acc):
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
            de = {'type': 'content_block_delta', 'index': idx,
                  'delta': {'type': 'input_json_delta', 'partial_json': rehydrate_json_string(acc, replay)}}
            emits.append(_emit('content_block_delta', de))
        emits.append(_emit(ev_type, obj))
        return b'\n\n'.join(emits)

    return _emit(ev_type, obj)   # message_start / message_delta / message_stop / ping / error -> passthrough


async def stream_rehydrate(upstream_aiter, replay):
    carry = {}
    block_type = {}
    json_acc = {}
    buf = b''
    async for chunk in upstream_aiter:
        buf += chunk
        while b'\n\n' in buf:
            raw_event, buf = buf.split(b'\n\n', 1)
            out = _transform_event(raw_event, replay, carry, block_type, json_acc)
            if out:
                yield out + b'\n\n'
    if buf.strip():
        out = _transform_event(buf, replay, carry, block_type, json_acc)
        if out:
            yield out + b'\n\n'


# ----------------------------------------------------------------------------
# Upstream forwarding: pass auth + anthropic-* + content-type verbatim. Drop
# hop-by-hop / host / content-length (httpx recomputes). Never store auth.
# ----------------------------------------------------------------------------
FWD_HEADERS = {'authorization', 'anthropic-version', 'anthropic-beta',
               'anthropic-dangerous-direct-browser-access', 'content-type', 'x-api-key'}


def fwd_headers(req):
    return {k: v for k, v in req.headers.items() if k.lower() in FWD_HEADERS}


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


def _finalize_upstream_response(r, replay, json_rehydrate):
    ct = r.headers.get('content-type', 'application/json')
    resp_headers = _upstream_response_headers(r.headers)
    if replay and 'json' in ct.lower():
        try:
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
                obj = json_rehydrate(json.loads(content), replay)
                return JSONResponse(obj, status_code=r.status_code, headers=resp_headers)
            except Exception:
                pass
        return Response(content=content, status_code=r.status_code,
                        media_type=ct or 'application/octet-stream', headers=resp_headers)

    async def gen():
        try:
            if not replay:
                async for chunk in r.aiter_raw():
                    yield chunk
            else:
                src = _tally_rehydrations(r.aiter_raw(), replay, live_ctx) if live_ctx else r.aiter_raw()
                async for out in stream_transform(src, replay):
                    yield out
        finally:
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


@app.post('/v1/messages')
async def messages(req: Request):
    raw = await req.body()
    try:
        body = json.loads(raw)
    except Exception:
        return JSONResponse({'error': 'invalid json body'}, status_code=400)
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
    if not stream:
        async with httpx.AsyncClient(timeout=600) as hclient:
            r = await hclient.post(url, content=payload, headers=headers)
        if replay:
            _live_response('/v1/messages', client, ctx, replay, set(_PH_TOKEN_RE.findall(r.content.decode('utf-8', 'ignore'))))
        return _finalize_upstream_response(r, replay, rehydrate_anthropic_response)

    # streaming: open upstream first so upstream auth/rate-limit/error statuses are not masked as local 200s.
    return await _stream_or_error_response(url, payload, headers, replay, stream_rehydrate,
                                           rehydrate_anthropic_response, live_ctx=live_ctx)


@app.post('/v1/chat/completions')
async def chat_completions(req: Request):
    """OpenAI-compatible route. Same redact-on-egress / rehydrate-on-response contract as /v1/messages, using
    the shared redact_body() with the OpenAI field extractor + the OpenAI response/stream rehydrators."""
    raw = await req.body()
    try:
        body = json.loads(raw)
    except Exception:
        return JSONResponse({'error': 'invalid json body'}, status_code=400)
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
    raw = await req.body()
    try:
        body = json.loads(raw)
    except Exception:
        return JSONResponse({'error': 'invalid json body'}, status_code=400)
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
    # /v1/responses. The chatgpt-account-id header is present only on the plan path (Codex forwards it for
    # plan authorization; the OAuth token alone is rejected without it), so it is the reliable discriminator.
    if req.headers.get('chatgpt-account-id'):
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
    return {'status': 'ok', 'service': 'ossredact-egress', 'dryrun': DRYRUN,
            'gate': _safe_diagnostic_url(GATE_URL), 'uptime_s': round(time.time() - START, 1)}


# ---------------------------------------------------------------------------
# Local settings UI: the do-not-redact dictionary editor (GET /). The gate may listen on 0.0.0.0 to serve a
# fleet of agents, but EDITING the allowlist must never be reachable over the network (it would let a remote
# actor weaken redaction), so the UI + its API are LOOPBACK-ONLY. Writes go to the UI-managed allowlist file,
# live-reloaded on its mtime (no restart, config untouched).
# ---------------------------------------------------------------------------
def _is_loopback(req: Request):
    host = (req.client.host if req.client else '') or ''
    return host in ('127.0.0.1', '::1', 'localhost')


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


@app.get('/api/allowlist')
def api_allowlist_get(req: Request):
    if not _is_loopback(req):
        return JSONResponse({'error': 'local-only'}, status_code=403)
    current_allowlist()  # ensure the in-memory set reflects the file
    return JSONResponse({'values': _read_allowlist_file(), 'active_total': len(_ALLOWLIST),
                         'config_values': len(load_config().get('allowlist') or []), 'path': _ALLOWLIST_FILE})


@app.post('/api/allowlist')
async def api_allowlist_set(req: Request):
    if not _is_loopback(req):
        return JSONResponse({'error': 'local-only'}, status_code=403)
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
    if not _is_loopback(req):
        return JSONResponse({'error': 'local-only'}, status_code=403)
    current_denylist()  # ensure the compiled pattern reflects the file
    vals = _read_denylist_file()
    return JSONResponse({'values': vals, 'active_total': len(denylist_mod.build_terms(_load_denylist_values(load_config()))),
                         'config_values': len(load_config().get('denylist') or []), 'path': _DENYLIST_FILE})


@app.post('/api/denylist')
async def api_denylist_set(req: Request):
    if not _is_loopback(req):
        return JSONResponse({'error': 'local-only'}, status_code=403)
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
    if not _is_loopback(req):
        return JSONResponse({'error': 'local-only'}, status_code=403)
    # floor_always_on documents to the UI that the deterministic floor (secrets/cards/IDs) redacts in every
    # mode, so the 'off' option can be presented honestly as "soft PII off, credentials still protected".
    return JSONResponse({'mode': current_mode(), 'modes': list(_MODES), 'floor_always_on': True,
                         'path': _MODE_FILE})


@app.post('/api/settings')
async def api_settings_set(req: Request):
    if not _is_loopback(req):
        return JSONResponse({'error': 'local-only'}, status_code=403)
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
# Live activity API (LOOPBACK-ONLY). /api/stream is a Server-Sent Events feed of
# the in-memory redaction ring; it shows real PII values (the proof), so it is
# loopback-guarded and never persisted. The UI's Live tab consumes it.
# ---------------------------------------------------------------------------
def _sse(ev):
    return ('data: ' + json.dumps(ev, ensure_ascii=False) + '\n\n').encode('utf-8')


@app.get('/api/stream')
async def api_stream(req: Request):
    if not _is_loopback(req):
        return JSONResponse({'error': 'local-only'}, status_code=403)
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
    if not _is_loopback(req):
        return JSONResponse({'error': 'local-only'}, status_code=403)
    return JSONResponse({'enabled': LIVE_VIEW, 'buffered': len(_live_ring), 'max': _LIVE_MAX,
                         'subscribers': len(_live_subscribers), 'mode': current_mode()})


@app.post('/api/live/clear')
def api_live_clear(req: Request):
    if not _is_loopback(req):
        return JSONResponse({'error': 'local-only'}, status_code=403)
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


if __name__ == '__main__':
    uvicorn.run(app, host=HOST, port=PORT, log_level='warning')
