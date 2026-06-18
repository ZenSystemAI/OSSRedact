#!/usr/bin/env python3
"""OpenAI chat-completions adapter for the OSSRedact egress proxy.

Same privacy contract as the Anthropic /v1/messages path: redact PII + secrets in the OUTBOUND request's
free-text fields to stable placeholders, and rehydrate the placeholders back to real values on the response --
so an OpenAI-compatible client (Codex, omp, any /v1/chat/completions caller) sees real data while the upstream
model only ever reasons over placeholders.

The detection/redaction itself is SHARED: the /v1/chat/completions route in egress_proxy.py calls the same
redact_body() it uses for Anthropic, passing extract_text_fields_openai as the field extractor. This module
adds only the OpenAI <-> placeholder schema translation (request fields, response, and SSE stream).

Self-contained ON PURPOSE: the small pure helpers below (rehydrate_text / _rehydrate_json /
rehydrate_json_string / split_safe / Field) MIRROR the identical ones in egress_proxy.py. Duplicated so this
module imports nothing heavy (no fastapi/httpx/the NPU stack) and stays unit-testable in isolation. If you
change the placeholder grammar or the JSON-safe rehydration in egress_proxy.py, mirror it here.
"""
import json, re

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
    everything else->'message'. Tool/function SCHEMAS (body['tools']) and prior-turn tool_call arguments are
    left untouched -- parity with the Anthropic path, which never redacts tool_use input/schemas (the
    known-entity backstop in redact_body re-catches any known value that reappears in a text field)."""
    fields = []
    for msg in (body.get('messages') or []):
        if not isinstance(msg, dict):
            continue
        role = msg.get('role')
        kind = 'system' if role == 'system' else 'tool_result' if role == 'tool' else 'message'
        c = msg.get('content')
        if isinstance(c, str):
            fields.append(Field(msg, 'content', kind))
        elif isinstance(c, list):
            for blk in c:
                if isinstance(blk, dict) and blk.get('type') == 'text' and isinstance(blk.get('text'), str):
                    fields.append(Field(blk, 'text', kind))
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
    """Walk choices[].message: content (str or content-part list) + tool_calls[].function.arguments (JSON
    string) + legacy function_call.arguments -> swap placeholders back to real values."""
    if not replay:
        return obj
    for ch in (obj.get('choices') or []):
        if not isinstance(ch, dict):
            continue
        msg = ch.get('message')
        if not isinstance(msg, dict):
            continue
        c = msg.get('content')
        if isinstance(c, str):
            msg['content'] = rehydrate_text(c, replay)
        elif isinstance(c, list):
            msg['content'] = _rehydrate_json(c, replay)
        for tc in (msg.get('tool_calls') or []):
            if isinstance(tc, dict):
                fn = tc.get('function')
                if isinstance(fn, dict) and isinstance(fn.get('arguments'), str):
                    fn['arguments'] = rehydrate_json_string(fn['arguments'], replay)
        fc = msg.get('function_call')
        if isinstance(fc, dict) and isinstance(fc.get('arguments'), str):
            fc['arguments'] = rehydrate_json_string(fc['arguments'], replay)
    return obj


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
