#!/usr/bin/env python3
"""qc-pii egress privacy proxy -- the appliance (SPECS.md §2).

Sits in front of cloud LLM APIs. On egress it redacts PII + secrets in the request's free-text/data
fields to stable placeholders; on the response it rehydrates the placeholders back to the real values, so
the LOCAL client (Claude Code) sees real data while the upstream model only ever reasons over placeholders.

Co-located with the NPU NER gate (:8001) on the Beelink; binds :8011. Built up across RUNBOOK steps:
  S2 : /v1/messages field extraction + passthrough + DRYRUN echo.
  S3 : cheap deterministic gate (Tier-0) inline + forward-unchanged-if-clean fast path.
  S4 : targeted NPU pass (gate /detect, chunked, cached) + union merge + span substitution + non-stream rehydrate.
  S5 : session+project entity map (AES-GCM) for cross-turn placeholder stability  [pending].
  S6 : streaming (SSE) rehydration with placeholder reassembly across deltas       [pending].
  S7 : secrets layer wired into the cheap gate (always-on, ignores PII policy)      [pending].
  S8 : gateway-config.yaml policy resolution (session > project > default)          [pending].
"""
import os, sys, json, time, re
import yaml
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
import uvicorn

sys.path.insert(0, '/home/steven/sparx-npu')
from privacy_gate import tier0_spans, merge_spans, post_merge_address, explain   # cheap Tier-0 (no model load)
from entity_map import EntityMap, derive_session
from secrets_scan import secret_spans                                   # deterministic secrets (always-on)
import openai_adapter   # OpenAI /v1/chat/completions schema translation (Codex / omp / OpenAI-compatible)
import responses_adapter   # OpenAI /v1/responses schema translation (Codex CLI speaks /v1/responses ONLY)

ANTHROPIC_UPSTREAM = os.environ.get('GATEWAY_ANTHROPIC_UPSTREAM', 'https://api.anthropic.com')
OPENAI_UPSTREAM = os.environ.get('GATEWAY_OPENAI_UPSTREAM', 'https://api.openai.com')
GATE_URL = os.environ.get('GATEWAY_GATE_URL', 'http://127.0.0.1:8001')
DRYRUN = os.environ.get('GATEWAY_DRYRUN', '0') == '1'        # don't forward upstream; echo would-be-upstream body
EXPOSE_MAP = os.environ.get('GATEWAY_TEST_EXPOSE_MAP', '0') == '1'   # test-only: include replay map in dryrun
PORT = int(os.environ.get('GATEWAY_PORT', '8011'))
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
PROSE_MIN_WORDS = 8               # a field with >= this many word tokens of natural language → neural-scan it

app = FastAPI(title='qc-pii egress proxy')


# ----------------------------------------------------------------------------
# Field extraction (SPECS §2.1 step 1): isolate the redactable free-text/data
# fields. We descend to the leaf dict holding each text string and keep a
# (container, key) handle so substitution writes the redacted value back IN
# PLACE. We never touch tool_use input, tool schemas, image blocks, or model.
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


def extract_text_fields(body):
    fields = []
    sysv = body.get('system')
    if isinstance(sysv, str):
        fields.append(Field(body, 'system', 'system'))
    elif isinstance(sysv, list):
        for blk in sysv:
            if isinstance(blk, dict) and blk.get('type') == 'text' and isinstance(blk.get('text'), str):
                fields.append(Field(blk, 'text', 'system'))
    for msg in (body.get('messages') or []):
        if not isinstance(msg, dict):
            continue
        c = msg.get('content')
        if isinstance(c, str):
            fields.append(Field(msg, 'content', 'message'))
        elif isinstance(c, list):
            for blk in c:
                if not isinstance(blk, dict):
                    continue
                t = blk.get('type')
                if t == 'text' and isinstance(blk.get('text'), str):
                    fields.append(Field(blk, 'text', 'message'))
                elif t == 'tool_result':
                    cc = blk.get('content')
                    if isinstance(cc, str):
                        fields.append(Field(blk, 'content', 'tool_result'))
                    elif isinstance(cc, list):
                        for cb in cc:
                            if isinstance(cb, dict) and cb.get('type') == 'text' and isinstance(cb.get('text'), str):
                                fields.append(Field(cb, 'text', 'tool_result'))
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


async def _detect_neural(aclient, text, min_score=0.5):
    """Call the NPU gate /detect (chunked); offset spans back to field coords. Cache by text+score so the
    repeating system prompt / prior turns aren't re-scanned each request. Returns spans, or None if the gate
    is unreachable (caller then keeps Tier-0 only and flags degraded)."""
    key = (text, min_score)
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
CONFIG_PATH = os.environ.get('GATEWAY_CONFIG', '/home/steven/sparx-npu/gateway-config.yaml')
# operational labels excluded by DEFAULT (high-volume, low-sensitivity; redacting them adds noise + can
# degrade the coding assistant). Toggle per-project if a DLP setup needs them.
DEFAULT_EXCLUDE = ['filepath', 'username', 'org']
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


def load_config():
    global _CONFIG, _CONFIG_MTIME
    try:
        mt = os.path.getmtime(CONFIG_PATH)
        if mt != _CONFIG_MTIME:
            with open(CONFIG_PATH) as fh:
                _CONFIG = yaml.safe_load(fh) or {}
            _CONFIG_MTIME = mt
    except FileNotFoundError:
        if not _CONFIG:
            _CONFIG = DEFAULT_CONFIG
    except Exception as e:
        print(f"[config load err] {type(e).__name__}", flush=True)
        if not _CONFIG:
            _CONFIG = DEFAULT_CONFIG
    return _CONFIG


def resolve_pii_policy(ctx):
    cfg = load_config().get('pii') or {}
    pol = dict(cfg.get('default') or {'enabled': True, 'exclude': DEFAULT_EXCLUDE})
    proj = (cfg.get('projects') or {}).get(ctx.get('project'))
    if proj:
        pol = {**pol, **proj}
    sess = (cfg.get('sessions') or {}).get(ctx.get('session_resolved') or ctx.get('session'))
    if sess:
        pol = {**pol, **sess}
    return pol


def policy_allows_pii(label, ctx):
    """Default: redact every detected PII label EXCEPT the exclude list (so no sensitive label is silently
    dropped). Credentials always redact. An optional `categories` allowlist makes it restrictive instead."""
    if label in ALWAYS_REDACT:
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


def substitute(text, spans, emap, ctx):
    """Replace span VALUES with stable placeholders via the session entity map. Secret spans always redact;
    PII spans honor policy. Returns (redacted_text, n_redacted)."""
    spans = sorted(spans, key=lambda s: s['start'])
    out = []
    last = 0
    n = 0
    for s in spans:
        if s['start'] < last:
            continue
        label = s['label']
        if not policy_allows_pii(label, ctx):   # credentials short-circuit to True inside
            continue
        v = text[s['start']:s['end']]
        ph, _ = emap.placeholder_for(v, label)
        out.append(text[last:s['start']])
        out.append(ph)
        last = s['end']
        n += 1
    out.append(text[last:])
    return ''.join(out), n


def build_known_re(emap):
    """Regex over already-known session entity VALUES (len>=4, word-boundary-guarded, longest-first).
    The known-entity backstop: a once-identified entity must never leak later in the session even if the
    model misses it in a new context. Pure deterministic, no model.
    Compiled IGNORECASE (Codex HIGH-1): a known value must be masked regardless of case, else "John" detected
    once leaks as "JOHN"/"john" elsewhere. sweep_known resolves the placeholder via a casefolded lookup."""
    vals = [v for v in emap.v2p.keys() if len(v) >= 4]
    if not vals:
        return None
    vals.sort(key=len, reverse=True)
    parts = []
    for v in vals:
        esc = re.escape(v)
        if v[0].isalnum():
            esc = r'(?<!\w)' + esc
        if v[-1].isalnum():
            esc = esc + r'(?!\w)'
        parts.append(esc)
    return re.compile('|'.join(parts), re.IGNORECASE)


def sweep_known(text, known_re, emap):
    """Replace any literal occurrence of a known value with its existing placeholder. Cannot mint a wrong
    placeholder (uses the exact value->placeholder already in the map). Returns (text, n_swept)."""
    # Case-insensitive resolution (Codex HIGH-1): known_re matches any case, so look up the placeholder by the
    # casefolded match against emap.v2p. If two differently-cased values collide on casefold, first-wins is
    # fine -- it still masks, and rehydrate restores a same-PII value.
    cf_lookup = {}
    for v, ph in emap.v2p.items():
        cf_lookup.setdefault(v.casefold(), ph)
    n = 0

    def repl(m):
        nonlocal n
        ph = cf_lookup.get(m.group().casefold())
        if ph is None:
            return m.group()
        n += 1
        return ph
    return known_re.sub(repl, text), n


async def redact_body(body, ctx, extract=extract_text_fields):
    """Mutate body in place; return (meta, replay). replay = placeholder->value for response rehydration.
    `extract` selects the request schema (Anthropic default; openai_adapter.extract_text_fields_openai for the
    OpenAI route). NEVER logs/returns PII or secret VALUES (except replay, gated behind dryrun+EXPOSE_MAP)."""
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

    session = derive_session(ctx.get('session', ''), sys_text)
    ctx['session_resolved'] = session
    emap = EntityMap(session, ctx.get('project', 'default'))   # load is cheap; needed for the known-entity sweep
    has_known = bool(emap.v2p)

    # truly-nothing path: ONLY skip when there are literally zero non-empty extracted text fields AND no prior
    # session entities to backstop. A request with ANY scannable field is neural-scanned below (FIX 2): an NER-only
    # name (no Tier-0 hit, below the prose-length bar -- e.g. a 2-word name in a short field) must NOT skip the scan.
    if not any_scannable and not has_known:
        return {'n_fields': len(fields), 'redaction': 'skip', 'n_spans': 0}, {}

    by_label = {}
    by_rule = {}
    explain_recs = []
    total = 0
    # pass 1: detect (Tier-0 + targeted neural) + substitute spans
    async with httpx.AsyncClient(timeout=60) as aclient:
        for fi, (f, t, t0, prose) in enumerate(per_field):
            spans = list(t0)
            # NER-only PII (a NAME with no Tier-0 regex fallback) leaks if a SHORT non-prose field (e.g. a 2-word
            # name "Jane Roy" in a short tool description or a short arg value) is never neural-scanned. The
            # EXTRACTOR already decided every surfaced field is redactable free text; that decision -- not a
            # prose-length heuristic -- drives scanning. So neural-scan EVERY field carrying non-trivial text
            # (stripped length above a tiny floor), regardless of Tier-0/prose. (Tier-0 hits still scan too.)
            if len(t.strip()) >= 2:
                neural = await _detect_neural(aclient, t)
                if neural is None:
                    # gate unreachable: keep Tier-0 spans for this field and FLAG degraded. Tier-0 still redacts
                    # what it can (so this stays rehydratable), but an NER-only name with no Tier-0 fallback is NOT
                    # masked here -- the route FAILS CLOSED on meta['degraded'] (see _degraded_block) rather than
                    # forwarding the unredacted body upstream (FIX-ROUND-3 HIGH). Default-on; GATEWAY_FAIL_OPEN=1
                    # opts back into Tier-0-only egress when availability must win over the NER-only-PII risk.
                    ctx['_degraded'] = True
                elif neural:
                    spans += neural
            if not spans:
                continue
            spans = post_merge_address(merge_spans(spans), t)
            spans = [s for s in spans if not _BENIGN_HASH.fullmatch(t[s['start']:s['end']])]  # allowlist hashes
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

    # pass 2: known-entity backstop with the now-complete map (catches model misses, cross-turn + in-request)
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
    return meta, emap.replay()


# ----------------------------------------------------------------------------
# Response rehydration (non-streaming here; S6 adds the SSE variant). Walk the
# Anthropic response: text blocks + tool_use inputs -> swap placeholders back to
# real values, so the LOCAL client writes/displays the real data.
# ----------------------------------------------------------------------------
def rehydrate_text(s, replay):
    if not replay or not isinstance(s, str):
        return s
    for ph, v in replay.items():
        if ph in s:
            s = s.replace(ph, v)
    return s


def _rehydrate_json(v, replay):
    if isinstance(v, str):
        return rehydrate_text(v, replay)
    if isinstance(v, list):
        return [_rehydrate_json(x, replay) for x in v]
    if isinstance(v, dict):
        return {k: _rehydrate_json(x, replay) for k, x in v.items()}
    return v


def rehydrate_anthropic_response(obj, replay):
    for blk in (obj.get('content') or []):
        if not isinstance(blk, dict):
            continue
        if blk.get('type') == 'text' and isinstance(blk.get('text'), str):
            blk['text'] = rehydrate_text(blk['text'], replay)
        elif blk.get('type') == 'tool_use':
            blk['input'] = _rehydrate_json(blk.get('input'), replay)
    return obj


def rehydrate_json_string(acc, replay):
    """Rehydrate placeholders inside an assembled tool_use arguments JSON string. Done at the VALUE level
    (parse -> walk -> replace -> re-serialize) so a real value containing quotes/backslashes can't break
    the JSON. Falls back to text rehydrate only if the accumulator isn't valid JSON yet."""
    if not acc or not acc.strip():
        return acc
    try:
        obj = json.loads(acc)
    except Exception:
        return rehydrate_text(acc, replay)
    return json.dumps(_rehydrate_json(obj, replay), ensure_ascii=False)


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


def _degraded_block(meta):
    """FAIL CLOSED (FIX-ROUND-3 HIGH): if the neural gate was unreachable while scanning this request (degraded),
    forwarding the body would leak any NER-only PII that has no Tier-0 fallback. Return a 503 JSONResponse to
    refuse the forward, or None to proceed. No-op when GATEWAY_FAIL_OPEN=1. Carries NO PII -- only the flag."""
    if FAIL_CLOSED and meta.get('degraded'):
        return JSONResponse(
            {'error': 'pii_gate_unavailable',
             'message': 'PII detection gate unreachable; refusing to forward to avoid leaking unredacted data. '
                        'Retry once the gate is healthy (or set GATEWAY_FAIL_OPEN=1 to allow Tier-0-only egress).'},
            status_code=503)
    return None


@app.post('/v1/messages')
async def messages(req: Request):
    raw = await req.body()
    try:
        body = json.loads(raw)
    except Exception:
        return JSONResponse({'error': 'invalid json body'}, status_code=400)
    ctx = {'session': req.headers.get('x-claude-code-session-id', ''),
           'project': req.headers.get('x-qc-pii-project', 'default')}
    meta, replay = await redact_body(body, ctx)
    stream = bool(body.get('stream'))

    if LOG_REQUESTS and meta.get('redaction') not in ('skip', None):
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
    if not stream:
        async with httpx.AsyncClient(timeout=600) as client:
            r = await client.post(url, content=payload, headers=headers)
        ct = r.headers.get('content-type', 'application/json')
        if replay and 'json' in ct:
            try:
                obj = rehydrate_anthropic_response(r.json(), replay)
                return JSONResponse(obj, status_code=r.status_code)
            except Exception:
                pass
        return Response(content=r.content, status_code=r.status_code, media_type=ct)

    # streaming: rehydrate the SSE response (placeholders -> real values) for the local client.
    async def gen():
        async with httpx.AsyncClient(timeout=600) as client:
            async with client.stream('POST', url, content=payload, headers=headers) as r:
                if not replay:
                    async for chunk in r.aiter_raw():   # nothing redacted -> zero-overhead passthrough
                        yield chunk
                else:
                    async for out in stream_rehydrate(r.aiter_raw(), replay):
                        yield out
    return StreamingResponse(gen(), media_type='text/event-stream')


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
           'project': req.headers.get('x-qc-pii-project', 'default')}
    meta, replay = await redact_body(body, ctx, extract=openai_adapter.extract_text_fields_openai)
    stream = bool(body.get('stream'))

    if LOG_REQUESTS and meta.get('redaction') not in ('skip', None):
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
    if not stream:
        async with httpx.AsyncClient(timeout=600) as client:
            r = await client.post(url, content=payload, headers=headers)
        ct = r.headers.get('content-type', 'application/json')
        if replay and 'json' in ct:
            try:
                obj = openai_adapter.rehydrate_openai_response(r.json(), replay)
                return JSONResponse(obj, status_code=r.status_code)
            except Exception:
                pass
        return Response(content=r.content, status_code=r.status_code, media_type=ct)

    async def gen():
        async with httpx.AsyncClient(timeout=600) as client:
            async with client.stream('POST', url, content=payload, headers=headers) as r:
                if not replay:
                    async for chunk in r.aiter_raw():
                        yield chunk
                else:
                    async for out in openai_adapter.stream_rehydrate_openai(r.aiter_raw(), replay):
                        yield out
    return StreamingResponse(gen(), media_type='text/event-stream')


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
           'project': req.headers.get('x-qc-pii-project', 'default')}
    meta, replay = await redact_body(body, ctx, extract=responses_adapter.extract_text_fields_responses)
    # File bytes that were NOT scanned (binary/undetermined inline file_data) are a DOCUMENTED+LOGGED limitation,
    # never a silent pass. pop_file_passthrough_notes() also strips the private marker so it never reaches upstream.
    file_notes = responses_adapter.pop_file_passthrough_notes(body)
    stream = bool(body.get('stream'))

    if LOG_REQUESTS and meta.get('redaction') not in ('skip', None):
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
    url = OPENAI_UPSTREAM + '/v1/responses'
    payload = json.dumps(body)
    if not stream:
        async with httpx.AsyncClient(timeout=600) as client:
            r = await client.post(url, content=payload, headers=headers)
        ct = r.headers.get('content-type', 'application/json')
        if replay and 'json' in ct:
            try:
                obj = responses_adapter.rehydrate_responses_response(r.json(), replay)
                return JSONResponse(obj, status_code=r.status_code)
            except Exception:
                pass
        return Response(content=r.content, status_code=r.status_code, media_type=ct)

    async def gen():
        async with httpx.AsyncClient(timeout=600) as client:
            async with client.stream('POST', url, content=payload, headers=headers) as r:
                if not replay:
                    async for chunk in r.aiter_raw():
                        yield chunk
                else:
                    async for out in responses_adapter.stream_rehydrate_responses(r.aiter_raw(), replay):
                        yield out
    return StreamingResponse(gen(), media_type='text/event-stream')


@app.get('/healthz')
def healthz():
    return {'status': 'ok', 'service': 'qc-pii-egress', 'dryrun': DRYRUN,
            'gate': GATE_URL, 'uptime_s': round(time.time() - START, 1)}


if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=PORT, log_level='warning')
