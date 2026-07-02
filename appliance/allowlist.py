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

POSSESSIVE-TOLERANT (live 2026-07-02): normalization also strips ONE trailing possessive suffix --
ASCII "'s" or typographic U+2019 "'s" -- so allowlisting "steven" covers the span "Steven's" (and
"Steven's" with a curly quote) instead of burning a fresh PERSON map entry on a near-identical string.
Because DECLARED values and SPAN lookups flow through the SAME normalizer, the fold widens both ways:
declaring "McDonald's" also covers bare "mcdonald" (and vice versa). That widening is deliberate and
safe under the security contract -- it only ever REDUCES redaction of strings the user already chose to
expose (base vs possessive of the SAME identifier); it never touches detection, and hard-floor spans
remain never-exempt regardless of what is declared (guard below is untouched).

SECURITY CONTRACT: allowlisted values DO reach the cloud verbatim -- that is the explicit point. The gate
applies the allowlist to detected PII spans only; the secret floor (passwords/keys/tokens) is applied by
the caller BEFORE this filter and is never exempted here. Kept 1:1 with the TS module for detector-twin
parity (D1).
"""
from __future__ import annotations
import unicodedata
from typing import Iterable

from privacy_gate import FLOOR_LABELS   # the hard floor -- never allowlist-exempt (single source of truth)
from denylist import DENY_LABEL         # always-redact 'custom' -- never allowlist-exempt either (see guard)


# One trailing possessive suffix is folded away AFTER lowercasing: ASCII apostrophe+s and the
# typographic RIGHT SINGLE QUOTATION MARK (U+2019)+s -- the two forms real editors/IMEs emit. NFC does
# not unify U+0027 with U+2019, so both are listed explicitly. ONE strip only (no loop): "alex's's"
# folds to "alex's", never all the way to "alex" -- a double possessive is not a near-identical variant.
#
# DIRECTION (tightened after adversarial review, 2026-07-02): the fold applies to the LOOKUP side only.
# Folding declared values too made allowlisting "Sam's" (a brand) silently exempt every unrelated person
# named "Sam" -- a widening the user never asked for. Now: declaring "steven" covers the spans "steven" AND
# "Steven's" (span-side fold), but declaring "Sam's" covers only "Sam's" (and "Sam's's"), never bare "Sam".
_POSSESSIVE_SUFFIXES = ("'s", "’s")


def normalize_allow_value(v: str) -> str:
    # NFC, then strip, then lowercase -- same order + ops as the TS mirror. NO possessive fold here: this
    # normalizer shapes DECLARED values; the fold is a lookup-side extra (see is_allowlisted).
    return unicodedata.normalize('NFC', v).strip().lower()


def _fold_possessive(n: str) -> str:
    for suf in _POSSESSIVE_SUFFIXES:
        if n.endswith(suf):
            return n[:-len(suf)]
    return n


def build_allow_set(values: Iterable[str]) -> set:
    out = set()
    for v in values:
        n = normalize_allow_value(v)
        if n:
            out.add(n)
    return out


def is_allowlisted(value: str, allow: set) -> bool:
    if not allow:
        return False
    n = normalize_allow_value(value)
    return n in allow or _fold_possessive(n) in allow


def apply_allowlist(spans, text: str, allow: set):
    """Drop every span (dict with 'start'/'end') whose exact normalized text is in the allowlist.
    Returns a new list; a falsy/empty allowlist returns spans unchanged.

    FLOOR GUARD: a hard-floor span (credential / card / bank / government / tax / DOB) is NEVER exempt, even
    when its exact text is allowlisted. The guard is baked into the shared filter -- not left to the caller
    -- so a future consumer cannot lose the floor by forgetting it (mirrors the TS applyAllowlist guard and
    the gate's inline FLOOR_NEVER_EXEMPT). Label-less spans are unaffected."""
    if not allow:
        return spans
    # DENYLIST GUARD (defense in depth, 2026-07-02): an always-redact 'custom' span is never allowlist-exempt
    # either -- a must-redact declaration beats a known-safe one. The egress pipeline already enforces this
    # ordering (denylist spans are injected AFTER this filter); baking it in here too means no future consumer
    # can invert the precedence by calling the shared helper alone. Mirrors the TS applyAllowlist guard.
    return [s for s in spans
            if s.get('label') in FLOOR_LABELS
            or s.get('label') == DENY_LABEL
            or not is_allowlisted(text[s['start']:s['end']], allow)]
