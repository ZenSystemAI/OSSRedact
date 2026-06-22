#!/usr/bin/env python3
"""OpenAI chat-completions adapter for the OSSRedact egress proxy.

Same privacy contract as the Anthropic /v1/messages path: redact PII + secrets in the OUTBOUND request's
free-text fields to stable placeholders, and rehydrate the placeholders back to real values on the response --
so an OpenAI-compatible client (Codex, omp, any /v1/chat/completions caller) sees real data while the upstream
model only ever reasons over placeholders.

The detection/redaction itself is SHARED: the /v1/chat/completions route in egress_proxy.py calls the same
redact_body() it uses for Anthropic, passing extract_text_fields_openai as the field extractor. This module
adds only the OpenAI <-> placeholder schema translation (request fields, response, and SSE stream).

Mostly self-contained on purpose: the small pure helpers below (rehydrate_text / _rehydrate_json /
rehydrate_json_string / split_safe / Field) MIRROR the identical ones in egress_proxy.py. Request-side
tool-call argument extraction reuses the Responses adapter's pure JSON walkers so prior assistant tool-call
history is parsed at value/key granularity instead of scanned as a hard-to-detect JSON blob. If you change the
placeholder grammar or the JSON-safe rehydration in egress_proxy.py, mirror it here.
"""
import json, re

import responses_adapter

# Free-text block-type aliases (mirror egress_proxy.py): only `text` was recognized, so an `input_text` /
# `output_text` block or a bare-string content element extracted ZERO fields -> whole body forwarded UNSCANNED.
_TEXT_BLOCK_TYPES = ('text', 'input_text', 'output_text')
# `image_url` is the Chat Completions image part ({type:'image_url', image_url:{url:'data:...'|'https://...'}}).
# It is opaque binary like `image`/`input_image`: recursing into it surfaced the data-URI / URL string for
# PII scanning, an incoherent boundary that could over-rewrite an image blob or a routing URL. Treat it as
# binary and skip it (matching the documented "image/audio/binary bytes are out of scope" contract).
# `thinking` / `redacted_thinking` are kept here ONLY to stay byte-identical with egress_proxy._BINARY_BLOCK_TYPES
# (the sync invariant); the Chat Completions schema has no thinking content-part, so they are inert on this path.
_BINARY_BLOCK_TYPES = ('image', 'input_image', 'image_url', 'document', 'redacted_thinking', 'thinking')

# matches the tail of a partial placeholder still being streamed (e.g. "<EMAIL_00" before its ">" arrives).
# A label may carry INTERNAL underscores (gate-form labels such as PHONE_NUMBER / SENSITIVE_ACCOUNT_ID ->
# <PHONE_NUMBER_001> / <SENSITIVE_ACCOUNT_ID_001>), so any run of label chars must be held until completion.
_PH_PREFIX_RE = re.compile(r'[A-Z0-9_]*')


class Field:
    """A (container, key) handle onto one redactable string so substitution writes back IN PLACE."""
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


# ---------------------------------------------------------------------------
# Request field extraction (OpenAI /v1/chat/completions).
# ---------------------------------------------------------------------------
def extract_text_fields_openai(body):
    """messages[].content is a string OR a list of parts ({type:'text',text:...} plus image/audio parts we
    never touch). Roles are mapped to the SAME kind vocabulary redact_body expects so the prose heuristic +
    session derivation behave exactly as on the Anthropic path: system->'system', tool->'tool_result',
    developer->'system', everything else->'message'. Prior-turn assistant tool_call arguments are model-visible
    conversation history after local rehydration, so they are parsed and redacted on the next outbound request.
    Tool/function SCHEMAS are walked structurally: descriptions and enum/const literal values are scanned,
    while function names, property names, routing ids, and other schema structure stay untouched."""
    fields = []
    claimed = set()
    notes = []
    for msg in (body.get('messages') or []):
        if not isinstance(msg, dict):
            continue
        role = msg.get('role')
        kind = 'system' if role in ('system', 'developer') else 'tool_result' if role == 'tool' else 'message'
        c = msg.get('content')
        if isinstance(c, str):
            fields.append(Field(msg, 'content', kind))
        elif isinstance(c, list):
            for idx, blk in enumerate(c):
                if isinstance(blk, str):
                    if blk.strip():       # array-of-strings content (C2)
                        fields.append(Field(c, idx, kind))
                elif isinstance(blk, dict):
                    if blk.get('type') in _TEXT_BLOCK_TYPES and isinstance(blk.get('text'), str):  # text/input_text/output_text (C1)
                        fields.append(Field(blk, 'text', kind))
                    elif blk.get('type') not in _BINARY_BLOCK_TYPES:
                        responses_adapter._recurse_collect(blk, kind, fields, notes, claimed, struct_scope=False)
        # The optional participant `name` on user/assistant/system/developer messages is free-form developer-set
        # metadata that can carry PII (a real customer name, an email-shaped handle) -- it was forwarded RAW to
        # api.openai.com (a leak). Scan it as user data. EXCLUDE role 'function'/'tool': there `name` is the tool
        # identifier the API routes the call on and MUST reach upstream verbatim, so it is never redacted.
        nm = msg.get('name')
        if isinstance(nm, str) and nm and role not in ('function', 'tool'):
            fields.append(Field(msg, 'name', kind))
        for tc in (msg.get('tool_calls') or []):
            if not isinstance(tc, dict):
                continue
            fn = tc.get('function')
            if isinstance(fn, dict):
                if isinstance(fn.get('arguments'), str):
                    responses_adapter._surface_json_args(fn, 'arguments', 'tool_result', fields, claimed)
                elif isinstance(fn.get('arguments'), (dict, list)):
                    responses_adapter._recurse_collect(
                        fn['arguments'], 'tool_result', fields, notes, claimed, struct_scope=False)
        fc = msg.get('function_call')
        if isinstance(fc, dict):
            if isinstance(fc.get('arguments'), str):
                responses_adapter._surface_json_args(fc, 'arguments', 'tool_result', fields, claimed)
            elif isinstance(fc.get('arguments'), (dict, list)):
                responses_adapter._recurse_collect(
                    fc['arguments'], 'tool_result', fields, notes, claimed, struct_scope=False)
    tools = body.get('tools')
    if isinstance(tools, list):
        responses_adapter._recurse_collect(tools, 'tool_result', fields, notes, claimed)
    functions = body.get('functions')
    if isinstance(functions, list):
        responses_adapter._recurse_collect(functions, 'tool_result', fields, notes, claimed)
    # top-level `metadata`: the Chat Completions API round-trips a developer-defined map of up to 16 arbitrary
    # string key/value pairs -- the SAME free-form user-data shape the Responses path redacts. It was forwarded
    # RAW here (adapter-parity leak): a metadata value (or PII used as a key) reached api.openai.com un-redacted.
    # Walk it as user data (struct_scope=False) exactly like extract_text_fields_responses does.
    metadata = body.get('metadata')
    if isinstance(metadata, dict):
        responses_adapter._recurse_collect(metadata, 'tool_result', fields, notes, claimed, struct_scope=False)
    # response_format.json_schema: schema descriptions + enum/const LITERALS can carry PII (parity with the
    # Responses adapter, which walks text.format). struct_scope=True scans descriptions/literals, not property names.
    rf = body.get('response_format')
    if isinstance(rf, dict):
        responses_adapter._recurse_collect(rf, 'tool_result', fields, notes, claimed)
    # prediction.content (speculative decoding): developer-supplied predicted output -- free-form, can carry PII.
    pred = body.get('prediction')
    if isinstance(pred, dict):
        pc = pred.get('content')
        if isinstance(pc, str):
            fields.append(Field(pred, 'content', 'message'))
        elif isinstance(pc, list):
            responses_adapter._recurse_collect(pc, 'tool_result', fields, notes, claimed, struct_scope=False)
    # top-level `user`: an end-user identifier. Meant to be opaque, but a caller may set it to an email/handle;
    # scan it so a PII value is redacted (an opaque hash simply yields no spans).
    user = body.get('user')
    if isinstance(user, str) and user:
        fields.append(Field(body, 'user', 'message'))
    return fields


# ---------------------------------------------------------------------------
# Pure rehydrate helpers (mirror egress_proxy.py).
# ---------------------------------------------------------------------------
def rehydrate_text(s, replay):
    if not replay or not isinstance(s, str):
        return s
    tokens = [ph for ph in replay if isinstance(ph, str) and ph in s]
    if not tokens:
        return s
    pat = re.compile('|'.join(re.escape(ph) for ph in sorted(tokens, key=len, reverse=True)))
    return pat.sub(lambda m: replay[m.group()], s)


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


def rehydrate_json_string(acc, replay):
    """Rehydrate placeholders inside a tool-call arguments JSON string, including object keys."""
    if not acc or not acc.strip():
        return acc
    try:
        obj = json.loads(acc, object_pairs_hook=_dup_preserving_pairs)
    except Exception:
        return rehydrate_text(acc, replay)
    return _dump_rehydrated_dup_safe(obj, replay)


def split_safe(carry):
    """(safe_prefix, held_tail): hold back a possible partial placeholder at the tail (an unclosed '<' that
    looks like the start of <LABEL_NNN>). Leave a real '<' (e.g. 'a < b') alone."""
    idx = carry.rfind('<')
    if idx == -1:
        return carry, ''
    tail = carry[idx:]
    if '>' in tail:
        return carry, ''
    if _PH_PREFIX_RE.fullmatch(tail[1:]):
        return carry[:idx], tail
    return carry, ''


# ---------------------------------------------------------------------------
# Non-streaming response rehydration.
# ---------------------------------------------------------------------------
def rehydrate_openai_response(obj, replay):
    """Blanket-rehydrate the response once, with JSON-safe handling for tool-call argument strings."""
    if not replay:
        return obj
    if not isinstance(obj, (dict, list)):
        return obj
    return responses_adapter._rehydrate_recursive(obj, replay)


# ---------------------------------------------------------------------------
# Streaming (SSE) rehydration. OpenAI streams single `data: {chunk}` events ending with `data: [DONE]`.
# Text deltas (choices[].delta.content) are rehydrated incrementally with split-safe tail buffering so a
# placeholder split across deltas is never half-emitted. tool_call argument fragments
# (choices[].delta.tool_calls[].function.arguments) are buffered per (choice, tool) index and flushed as one
# rehydrated chunk at finish_reason (a placeholder can straddle fragments, and a tool call is only acted on
# once complete) -- the structural first fragment (id/name) passes through with empty args so the client still
# learns the call early.
# ---------------------------------------------------------------------------
def _chunk_bytes(template, choice_index, delta):
    out = {'object': 'chat.completion.chunk',
           'choices': [{'index': choice_index, 'delta': delta, 'finish_reason': None}]}
    for k in ('id', 'created', 'model'):
        if template and template.get(k) is not None:
            out[k] = template[k]
    return b'data: ' + json.dumps(out, ensure_ascii=False).encode('utf-8')


def _flush_choice(template, ci, carry, tool_acc, replay):
    """Emit (as a list of SSE chunk bytes) any held text + buffered tool args for choice ci, rehydrated."""
    emits = []
    rem = carry.pop(ci, '')
    if rem:
        emits.append(_chunk_bytes(template, ci, {'content': rehydrate_text(rem, replay)}))
    for key in [k for k in tool_acc if k[0] == ci]:
        _, ti = key
        args = rehydrate_json_string(tool_acc.pop(key), replay)
        emits.append(_chunk_bytes(template, ci, {'tool_calls': [{'index': ti, 'function': {'arguments': args}}]}))
    return emits


def transform_openai_event(raw, replay, carry, tool_acc):
    """Transform one SSE event (bytes). Returns transformed bytes (no trailing blank line) or None to swallow."""
    line = None
    for ln in raw.split(b'\n'):
        ln = ln.rstrip(b'\r')
        if ln.startswith(b'data:'):
            line = ln[5:].strip()
    if line is None:
        return raw if raw.strip() else None
    if line == b'[DONE]':
        emits = []
        for ci in sorted({k[0] for k in tool_acc} | set(carry)):
            emits += _flush_choice(None, ci, carry, tool_acc, replay)
        emits.append(b'data: [DONE]')
        return b'\n\n'.join(emits)
    try:
        obj = json.loads(line)
    except Exception:
        return raw

    extra = []
    for ch in obj.get('choices') or []:
        if not isinstance(ch, dict):
            continue
        ci = ch.get('index', 0)
        delta = ch.get('delta') or {}
        if isinstance(delta.get('content'), str):
            carry[ci] = carry.get(ci, '') + delta['content']
            safe, held = split_safe(carry[ci])
            carry[ci] = held
            delta['content'] = rehydrate_text(safe, replay)
        tcs = delta.get('tool_calls')
        if isinstance(tcs, list):
            for tc in tcs:
                if not isinstance(tc, dict):
                    continue
                ti = tc.get('index', 0)
                fn = tc.get('function')
                if isinstance(fn, dict) and 'arguments' in fn:
                    tool_acc[(ci, ti)] = tool_acc.get((ci, ti), '') + (fn.get('arguments') or '')
                    fn['arguments'] = ''  # suppress raw fragment; full rehydrated args flushed at finish
        if ch.get('finish_reason') is not None:
            extra += _flush_choice(obj, ci, carry, tool_acc, replay)

    out = b'data: ' + json.dumps(obj, ensure_ascii=False).encode('utf-8')
    return b'\n\n'.join(extra + [out]) if extra else out


async def stream_rehydrate_openai(upstream_aiter, replay):
    carry, tool_acc, buf = {}, {}, b''
    async for chunk in upstream_aiter:
        buf += chunk
        while b'\n\n' in buf:
            raw, buf = buf.split(b'\n\n', 1)
            out = transform_openai_event(raw, replay, carry, tool_acc)
            if out:
                yield out + b'\n\n'
    if buf.strip():
        out = transform_openai_event(buf, replay, carry, tool_acc)
        if out:
            yield out + b'\n\n'


# ---------------------------------------------------------------------------
# Upstream forwarding headers (OpenAI uses Authorization: Bearer + optional org/project/beta).
# ---------------------------------------------------------------------------
FWD_HEADERS_OPENAI = {'authorization', 'content-type', 'openai-organization', 'openai-project', 'openai-beta'}


def fwd_headers_openai(req):
    return {k: v for k, v in req.headers.items() if k.lower() in FWD_HEADERS_OPENAI}
