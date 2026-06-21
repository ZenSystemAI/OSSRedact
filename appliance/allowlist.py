"""Allowlist -- the "do-not-redact" dictionary. Python mirror of @ossredact/core src/allowlist.ts.

A user-declared set of KNOWN-SAFE exact values that must NEVER be redacted, even when a detector flags
them. The INVERSE of detection: the user opts specific values OUT of redaction so the gate stops
interfering with their own workflow (their name inside file paths, their own email, internal project
codenames). OPT-IN; the default set is empty (fail toward redaction).

VALUE-EXACT, never substring: a span is dropped only when its WHOLE text equals a declared value, so
allowlisting "alex" can never accidentally un-redact a larger sensitive string that merely contains it.

Matching is Unicode-NFC + whitespace-strip + lowercase (mirroring the TS `.normalize('NFC').trim()
.toLowerCase()`), so a value declared once passes through in every casing it appears -- prose "Alex",
path "/home/alex", shout "ALEX". This also dissolves the case-mangle the known-value sweep would
otherwise inflict on coding-agent paths: an allowlisted name is never redacted, so it never enters the
entity map, is never swept, and is never rehydrated to a different case.

SECURITY CONTRACT: allowlisted values DO reach the cloud verbatim -- that is the explicit point. The gate
applies the allowlist to detected PII spans only; the secret floor (passwords/keys/tokens) is applied by
the caller BEFORE this filter and is never exempted here. Kept 1:1 with the TS module for detector-twin
parity (D1).
"""
from __future__ import annotations
import unicodedata
from typing import Iterable

from privacy_gate import FLOOR_LABELS   # the hard floor -- never allowlist-exempt (single source of truth)


def normalize_allow_value(v: str) -> str:
    # NFC, then strip, then lowercase -- same order + ops as the TS mirror.
    return unicodedata.normalize('NFC', v).strip().lower()


def build_allow_set(values: Iterable[str]) -> set:
    out = set()
    for v in values:
        n = normalize_allow_value(v)
        if n:
            out.add(n)
    return out


def is_allowlisted(value: str, allow: set) -> bool:
    return bool(allow) and normalize_allow_value(value) in allow


def apply_allowlist(spans, text: str, allow: set):
    """Drop every span (dict with 'start'/'end') whose exact normalized text is in the allowlist.
    Returns a new list; a falsy/empty allowlist returns spans unchanged.

    FLOOR GUARD: a hard-floor span (credential / card / bank / government / tax / DOB) is NEVER exempt, even
    when its exact text is allowlisted. The guard is baked into the shared filter -- not left to the caller
    -- so a future consumer cannot lose the floor by forgetting it (mirrors the TS applyAllowlist guard and
    the gate's inline FLOOR_NEVER_EXEMPT). Label-less spans are unaffected."""
    if not allow:
        return spans
    return [s for s in spans
            if s.get('label') in FLOOR_LABELS
            or normalize_allow_value(text[s['start']:s['end']]) not in allow]
