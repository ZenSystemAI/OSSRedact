#!/usr/bin/env python3
"""Pure text redaction primitives for appliance egress and future MITM adapters.

No network, no filesystem, no web framework imports. Callers provide detector spans and an EntityMap-like
object with placeholder_for(value, label), v2p, and replay()/p2v support.
"""
import re

_CASE_SENSITIVE_LABEL_KEYS = {'password', 'secret', 'username', 'person', 'name', 'accesstoken', 'apikey', 'filepath'}
_PH_LABEL_RE = re.compile(r'^<([A-Z0-9_]+)_\d{3,}>$')
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


def build_known_re(emap):
    """Regexes over already-known session entity values, split by case sensitivity."""
    exact_vals = []
    ci_vals = []
    for value, ph in emap.v2p.items():
        if _case_sensitive_placeholder(ph):
            exact_vals.append(value)
        else:
            ci_vals.append(value)
    exact_re = _compile_known_re(exact_vals, ignore_case=False)
    ci_re = _compile_known_re(ci_vals, ignore_case=True)
    if exact_re is None and ci_re is None:
        return None
    return exact_re, ci_re


def sweep_known(text, known_re, emap):
    """Replace literal occurrences of known values with existing placeholders."""
    if known_re is None:
        return text, 0
    if isinstance(known_re, tuple):
        exact_re, ci_re = known_re
    else:
        exact_re, ci_re = None, known_re
    exact_lookup = {}
    cf_lookup = {}
    for value, ph in emap.v2p.items():
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
