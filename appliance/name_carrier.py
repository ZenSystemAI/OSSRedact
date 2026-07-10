"""Carrier-wrap booster for the egress neural scan (plan 026, option A).

The xlm-roberta person detector is recall-strong on names in PROSE but drops to ZERO on a
rare name presented as a BARE STRUCTURAL VALUE -- a JSON `"key":"value"`, a short tool-arg, a
CSV cell -- because there is no surrounding sentence to cue it. Real customer DBs are full of
rare/diverse surnames, the egress's actual traffic is heavily structural (Codex tool-call args,
function outputs, prompt.variables), and there is NO Tier-0 floor for person names -- so a bare
rare name in a structured payload leaks. Measured: 8/10 realistic diverse names miss in bare/
JSON form (validation `/detect` probes, plan 026 Findings 2 & 4).

Fix (measured, NO retraining): when a short, name-shaped field value gets zero person spans
from the bare scan, re-scan it inside a synthetic prose carrier and map any person verdict back
to the value's own offsets. Detection-only transform -- redaction still targets the original
value, so offsets/rehydration are unchanged. Measured recovery: 9/10 realistic diverse names;
ZERO false positives on enum/code/date/bool/org values (the model does not invent persons on a
non-name carrier). The residual (extremely out-of-distribution surnames that miss even in prose)
is the retrain-augment track (plan 026 option B), not closable here.

This module is pure + detect-fn-injected so it unit-tests with a stub gate (no live gate).
"""

import re

# Carrier chosen by the plan-026 design probe (recall 9/10, 0 FP; beat 'Account holder: {v}').
# Prefix length is fixed so a returned person span maps back to value coords by subtraction.
CARRIER_PREFIX = 'The customer is '
CARRIER_SUFFIX = '.'

# A token is one unicode letter run (accents included) with internal apostrophes/hyphens, no
# digits or symbols. `[^\W\d_]` = a unicode word char that is not a digit or underscore = a letter.
_NAME_TOKEN = re.compile(r"^[^\W\d_](?:[^\W\d_]|['\-])*$")


def name_shaped(value):
    """True iff `value` is a plausible bare personal name: 1-4 letter-tokens, 2-60 chars, no
    digits/symbols. This is a LATENCY gate (skip codes/dates/ids/long text -- they would never be
    a person and the model already returns 0 FP on them), NOT a correctness gate. Whitespace-tolerant."""
    v = value.strip()
    if not (2 <= len(v) <= 60):
        return False
    toks = v.split()
    if not (1 <= len(toks) <= 4):
        return False
    return all(_NAME_TOKEN.match(t) for t in toks)


async def carrier_person_spans(detect_fn, value):
    """Recover person spans for a bare `value` via the prose carrier.

    `detect_fn(text)` is the egress `_detect_neural`-shaped coroutine: returns a list of span
    dicts (offsets relative to `text`), or None if the gate is unreachable. Returns person spans
    in `value` coordinates (rule tagged `gpu:carrier`), [] when the gate was healthy and found no person, or
    None when the carrier scan itself could not reach the gate.

    The caller is expected to have already checked `name_shaped(value)` and that the bare scan
    found no person, but this function is safe to call unconditionally. Only spans landing inside
    the value region are kept (the carrier scaffold words are never emitted as PII)."""
    carrier = CARRIER_PREFIX + value + CARRIER_SUFFIX
    spans = await detect_fn(carrier)
    if spans is None:
        return None
    if not spans:
        return []
    p = len(CARRIER_PREFIX)
    vlen = len(value)
    out = []
    for s in spans:
        if s.get('label') != 'person':
            continue
        st = s['start'] - p
        en = s['end'] - p
        # keep only the part of the span that falls within the value (never the scaffold)
        st = max(st, 0)
        en = min(en, vlen)
        if en > st:
            out.append({**s, 'start': st, 'end': en, 'rule': 'gpu:carrier'})
    return out
