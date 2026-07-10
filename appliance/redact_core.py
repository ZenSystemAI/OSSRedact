#!/usr/bin/env python3
"""Pure text redaction primitives for appliance egress and future MITM adapters.

No network, no filesystem, no web framework imports. Callers provide detector spans and an EntityMap-like
object with placeholder_for(value, label), v2p, and replay()/p2v support.
"""
import re

_CASE_SENSITIVE_LABEL_KEYS = {'password', 'secret', 'username', 'person', 'name', 'accesstoken', 'apikey', 'filepath'}
_PH_LABEL_RE = re.compile(r'^<([A-Z0-9_]+)_\d{3,}>$')
# Non-anchored placeholder-token matcher (mirrors egress_proxy._PH_TOKEN_RE). Used for the placeholder
# invariant in redact_text: a span whose text already contains a <LABEL_NNN> token is ALREADY redacted, so
# minting a NEW placeholder over it would nest one placeholder inside another's value -- which single-pass
# rehydrate cannot unwind, leaking a raw <LABEL_NNN> to the local chat (the RC4 remint that breaks file ops).
_PH_TOKEN_RE = re.compile(r'<[A-Z0-9_]+_\d{3,}>')
_RE_SPECIAL = re.compile(r'([.*+?^${}()|[\]\\])')


def _label_key(label):
    return re.sub(r'[^a-z0-9]', '', str(label).casefold())


def _placeholder_label(ph):
    m = _PH_LABEL_RE.match(str(ph))
    return m.group(1) if m else ''


def _case_sensitive_label(label):
    return _label_key(label) in _CASE_SENSITIVE_LABEL_KEYS


def _case_sensitive_placeholder(ph):
    return _case_sensitive_label(_placeholder_label(ph))


def _is_filepath_placeholder(ph):
    """A home-dir username narrowed from a file_path span (label file_path). It is substituted at its OWN path
    offset by redact_text (pass 1/2); it must NOT enter the cross-field known-value sweep, because a short/common
    username (build, test, node, runner) would then rewrite unrelated directories, CLI flags (--build), and English
    prose body-wide -- degrading the coding agent AND re-introducing the prompt-cache churn the narrowing removes.
    Paths are tagged reliably per-occurrence by the NER, so they do not need the cross-field sweep backstop."""
    return _label_key(_placeholder_label(ph)) in ('filepath', 'path')


def _inside_placeholder(text, start, end):
    """True when [start, end) sits INSIDE an enclosing <LABEL_NNN> placeholder token. The neural tier tags
    the token's inner text without the angle brackets ("SENSITIVEACCOUNTID_016" as password/id), which slips
    past the containment check on the span value alone -- the RC4 veto must look at the surrounding token.
    Placeholder tokens are short, so a bounded neighborhood scan suffices."""
    lo = text.rfind('<', max(0, start - 40), start + 1)
    if lo == -1:
        return False
    hi = text.find('>', max(end - 1, lo + 1), end + 40)
    if hi == -1:
        return False
    return _PH_TOKEN_RE.fullmatch(text, lo, hi + 1) is not None


def redact_text(text, spans, emap, allow_label=None):
    """Replace detector spans with stable placeholders, updating emap in memory.

    Returns (redacted_text, n_redacted). allow_label(label) may veto non-secret policy choices at the caller
    boundary; the pure core does not know project/session policy.
    """
    spans = sorted(spans, key=lambda s: s['start'])
    out = []
    last = 0
    n = 0
    for s in spans:
        if s['start'] < last:
            continue
        label = s['label']
        if allow_label is not None and not allow_label(label):
            continue
        value = text[s['start']:s['end']]
        if _PH_TOKEN_RE.search(value) or _inside_placeholder(text, s['start'], s['end']):
            continue   # placeholder invariant: never re-redact text that is already a placeholder (RC4 remint)
        ph, _ = emap.placeholder_for(value, label)
        out.append(text[last:s['start']])
        out.append(ph)
        last = s['end']
        n += 1
    out.append(text[last:])
    return ''.join(out), n


def _compile_known_re(vals, ignore_case=True):
    vals = [v for v in vals if v and len(v) >= 4]
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
    return re.compile('|'.join(parts), re.IGNORECASE if ignore_case else 0)


def build_known_re(emap, keep_values=(), keep_placeholder=None):
    """Regexes over already-known session entity values, split by case sensitivity. `keep_values` is the set of
    values tagged under a real (non-file_path) PII label this request; such a value stays in the sweep even if its
    placeholder happens to be file_path (collision case), so its untagged recurrences cannot leak. `keep_placeholder`
    (value, ph) -> bool, when given, VETOES a value from the sweep so the cross-turn replay honors the CURRENT
    policy/allowlist (RC3) instead of replaying a placeholder minted under an older mode forever."""
    exact_vals = []
    ci_vals = []
    for value, ph in emap.v2p.items():
        if _is_filepath_placeholder(ph) and value not in keep_values:
            continue   # file_path username: substitute at its own path offset, never sweep body-wide -- UNLESS the
                       # value was ALSO tagged under a real PII label (keep_values), e.g. a path username that
                       # collides exactly with an NER-tagged person; then it MUST stay in the sweep so an untagged
                       # recurrence elsewhere does not leak (placeholder_for is value-keyed and the path mint can win).
        if keep_placeholder is not None and not keep_placeholder(value, ph):
            continue   # current policy/allowlist now exempts this label/value -> drop from the sweep (config change took effect)
        if _case_sensitive_placeholder(ph):
            exact_vals.append(value)
        else:
            ci_vals.append(value)
    exact_re = _compile_known_re(exact_vals, ignore_case=False)
    ci_re = _compile_known_re(ci_vals, ignore_case=True)
    if exact_re is None and ci_re is None:
        return None
    return exact_re, ci_re


def sweep_known(text, known_re, emap, keep_values=(), keep_placeholder=None):
    """Replace literal occurrences of known values with existing placeholders. `keep_values` mirrors build_known_re
    (a file_path-placeholder value that was also tagged as real PII stays sweepable). `keep_placeholder` mirrors
    build_known_re too: a vetoed value is not looked up, so it is never replaced (RC3 policy/allowlist scoping)."""
    if known_re is None:
        return text, 0
    if isinstance(known_re, tuple):
        exact_re, ci_re = known_re
    else:
        exact_re, ci_re = None, known_re
    exact_lookup = {}
    cf_lookup = {}
    for value, ph in emap.v2p.items():
        if _is_filepath_placeholder(ph) and value not in keep_values:
            continue   # mirror build_known_re: file_path usernames are never swept body-wide unless also real PII
        if keep_placeholder is not None and not keep_placeholder(value, ph):
            continue   # mirror build_known_re: current policy/allowlist exempts this value -> never replace it
        if _case_sensitive_placeholder(ph):
            exact_lookup.setdefault(value, ph)
        else:
            cf_lookup.setdefault(value.casefold(), ph)
    n = 0

    def repl_exact(m):
        nonlocal n
        ph = exact_lookup.get(m.group())
        if ph is None:
            return m.group()
        n += 1
        return ph

    def repl_ci(m):
        nonlocal n
        ph = cf_lookup.get(m.group().casefold())
        if ph is None:
            return m.group()
        n += 1
        return ph

    if exact_re is not None:
        text = exact_re.sub(repl_exact, text)
    if ci_re is not None:
        text = ci_re.sub(repl_ci, text)
    return text, n


def rehydrate(text, replay):
    """Exact-only placeholder rehydration. Never fuzzy-match a mutated placeholder."""
    if not replay or not isinstance(text, str):
        return text
    tokens = [ph for ph in replay if isinstance(ph, str) and ph in text]
    if not tokens:
        return text
    pat = re.compile('|'.join(re.escape(ph) for ph in sorted(tokens, key=len, reverse=True)))
    return pat.sub(lambda m: replay[m.group()], text)
