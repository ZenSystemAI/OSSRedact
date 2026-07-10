"""Denylist -- the "always-redact" dictionary. Python mirror of @ossredact/core src/denylist.ts.

The TWIN/INVERSE of the allowlist: a user-declared set of exact terms/phrases that must ALWAYS be
redacted, even when no detector flags them (internal codenames, client names, hostnames the NER model
does not recognize as PII). OPT-IN; the default set is empty. It ONLY ADDS redaction, so it can never
weaken the firewall -- a bad entry over-redacts (safe), never under-redacts.

KEY DIFFERENCE FROM THE ALLOWLIST: the allowlist is a value-exact FILTER on already-detected spans. The
denylist is a SCANNER over raw field text -- it must FIND occurrences of declared terms, because the
whole point is that the detector did NOT flag them. So instead of a normalized set the denylist compiles
the terms into one boundary-aware regex and walks the text for matches.

Matching is Unicode-NFC + whitespace-trimmed + CASE-INSENSITIVE (mirroring the TS `.normalize('NFC')
.trim()`), so a term declared once ("Bluebird") is caught in every casing it appears -- prose "Bluebird",
shout "BLUEBIRD", path "bluebird". Unlike the allowlist the stored form is NOT lowercased; case-folding
is delegated to the compiled pattern's IGNORECASE flag so the original declared casing survives for
display while matching stays insensitive.

TOKEN BOUNDARIES: a term must NOT match inside a larger word. The pattern wraps the alternation in
`(?<!\\w)(?:...)(?!\\w)` lookarounds, so "acme" matches standalone "Acme", "acme.", "acme-corp" but NOT
"acmecorp". Multi-word phrases ("Project Falcon") match literally -- every regex metacharacter in each
term is escaped. LONGEST-FIRST: when terms overlap the longest declared term wins, so the alternation is
sorted by term length descending (then alphabetical) before compiling.

MIN_TERM_LEN guards against a 1-char term redacting the inside of everything: terms shorter than 2 chars
after normalization are silently ignored.

SECURITY CONTRACT: the denylist only ever ADDS redaction; it can never exempt a value the way the
allowlist can, so it cannot weaken the secret floor or any detected span -- the worst a stray entry does
is over-redact (safe). Every denylist span carries label 'custom' (downstream this mints a <CUSTOM_n>
placeholder; that wiring is not this module's job). Kept 1:1 with the TS module for detector-twin
parity (D1).
"""
from __future__ import annotations
import re
import unicodedata
from typing import Iterable

MIN_TERM_LEN = 2
DENY_LABEL = 'custom'


def normalize_term(v: str) -> str:
    # NFC then strip -- same order + ops as the TS mirror. Do NOT lowercase: case-folding is the
    # compiled pattern's IGNORECASE flag, so the declared casing is preserved for display.
    return unicodedata.normalize('NFC', v).strip()


def build_terms(values: Iterable[str]) -> list[str]:
    """Normalize each value, drop empties + terms shorter than MIN_TERM_LEN, dedup case-insensitively,
    then sort longest-first (then alphabetical) so the compiled alternation prefers the longest match."""
    seen = set()
    out = []
    for v in values:
        n = normalize_term(v)
        if len(n) < MIN_TERM_LEN:
            continue
        key = n.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    out.sort(key=lambda t: (-len(t), t))
    return out


def compile_denylist(values: Iterable[str]) -> 're.Pattern | None':
    """Compile declared terms into one boundary-aware, case-insensitive pattern. Returns None when no
    usable term survives normalization (mirrors the TS `null`)."""
    terms = build_terms(values)
    if not terms:
        return None
    alternation = '|'.join(re.escape(t) for t in terms)
    return re.compile(r'(?<!\w)(?:' + alternation + r')(?!\w)', re.IGNORECASE | re.UNICODE)


def _nfc_with_map(text: str):
    """NFC-normalize `text`, DROP zero-width/format/control (Cf/Cc) codepoints, and return (nfc, idx_map) where
    idx_map[i] is the ORIGINAL start index of the unit that produced nfc[i], plus a trailing sentinel
    idx_map[len(nfc)] = len(text). Each base char plus its trailing combining marks is composed as one unit, so
    a match on the cleaned NFC string always aligns on unit boundaries and maps back cleanly:
    span [m.start(), m.end()) -> original [idx_map[m.start()], idx_map[m.end())].

    Dropping Cf/Cc closes the denylist analogue of the floor's zero-width bypass: an input that injects a ZWSP
    between the letters of a declared term ("fiddle<ZWSP>head") would otherwise slip the boundary-aware scan."""
    nfc_chars, idx_map = [], []
    i, n = 0, len(text)
    while i < n:
        if unicodedata.category(text[i]) in ('Cf', 'Cc'):
            i += 1
            continue
        j = i + 1
        while j < n and unicodedata.combining(text[j]):
            j += 1
        for c in unicodedata.normalize('NFC', text[i:j]):
            nfc_chars.append(c); idx_map.append(i)
        i = j
    idx_map.append(n)
    return ''.join(nfc_chars), idx_map


def find_spans(text: str, pattern, label: str = DENY_LABEL) -> list[dict]:
    """Scan text for every declared-term occurrence. Returns a list of span dicts
    {start, end, label, score, source} -- empty when the pattern is None (no terms declared).

    The text is matched in Unicode-NFC form so a term declared as 'café-secret' or 'café-secret'
    is caught whichever way the INPUT encodes the accent (NFC composed vs NFD decomposed) -- the terms are
    stored NFC, so an NFD input would otherwise slip the scanner entirely (a confirmed denylist bypass).
    Match offsets are mapped back onto the ORIGINAL text so the caller masks the right bytes."""
    if pattern is None:
        return []
    nfc, idx_map = _nfc_with_map(text)
    if nfc == text:   # fast path: already NFC, no remap needed
        return [
            {'start': m.start(), 'end': m.end(), 'label': label, 'score': 1.0, 'source': 'denylist'}
            for m in pattern.finditer(text)
        ]
    return [
        {'start': idx_map[m.start()], 'end': idx_map[m.end()], 'label': label, 'score': 1.0, 'source': 'denylist'}
        for m in pattern.finditer(nfc)
    ]
