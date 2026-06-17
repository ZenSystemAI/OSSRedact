#!/usr/bin/env python3
"""Deterministic secrets detector for the egress proxy (SPECS §3) -- ALWAYS on, ignores PII policy.

Ports the high-value, high-precision gitleaks provider regexes + a context-aware generic-assignment rule
+ an AWS-secret-shaped entropy backstop, with detect-secrets-style false-positive filters (UUID, git-SHA,
sequential, all-digit) so we do NOT nuke benign high-entropy tokens (commit SHAs, content hashes) and break
the coding-assistant use case. NO model, zero training. Returns spans labeled 'secret' (subtype in metadata),
conf 1.0 so they win any merge cluster -> always redacted.

Refs (verified 2026-06-14, see PRIOR-ART.md): gitleaks config/gitleaks.toml (MIT); detect-secrets
filters/heuristic.py + high_entropy_strings.py (Apache-2.0).
"""
import re
from math import log2

# ---- high-precision provider patterns (low FP; always fire). (name, regex, group|None) ----
_P = []


def _add(name, pat, group=None, flags=0):
    _P.append((name, re.compile(pat, flags), group))


_add('aws_access_key', r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b')
_add('gcp_api_key', r'\bAIza[0-9A-Za-z_\-]{35}\b')
_add('github_token', r'\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b')
_add('github_pat', r'\bgithub_pat_[0-9A-Za-z_]{22,}\b')
_add('slack_token', r'\bxox[baprs]-[0-9A-Za-z-]{10,}\b')
_add('slack_webhook', r'https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}')
_add('stripe_key', r'\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b')
_add('openai_key', r'\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b')
_add('anthropic_key', r'\bsk-ant-[A-Za-z0-9_\-]{20,}\b')
_add('google_oauth', r'\bya29\.[0-9A-Za-z_\-]{20,}\b')
_add('jwt', r'\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b')
_add('private_key_block', r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----'
                          r'[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----')
# connection string with embedded credentials -> flag the password group(1)
_add('conn_string', r'(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|https?)://'
                    r'[^\s:@/]+:([^\s@/]{3,})@', 1)
# generic assignment: secret-ish key = value -> flag the value group(2).
# The keyword may sit inside a snake_case / SCREAMING_SNAKE / dotted identifier (JWT_SECRET, AWS_ACCESS_KEY_ID,
# app.apiKey), so allow leading prefix segments and trailing suffix segments around the cue instead of a bare
# \b (the old \b failed on `JWT_SECRET=` because the cue `secret` was glued to `_`). Still keyword-gated +
# value-shape gated (8+ opaque chars, benign-filtered) so it does not nuke ordinary `name = value` code.
_add('generic_assign', r'(?i)(?<![A-Za-z])(?:[A-Za-z0-9]+[_\-.])*'
                       r'(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|'
                       r'client[_-]?secret|auth[_-]?token|bearer|credential|private[_-]?key)'
                       r'(?:[_\-.][A-Za-z0-9]+)*'
                       r'["\']?\s*[:=]\s*["\']?([^\s"\',;}{]{8,})', 2)

# entropy backstop: AWS-secret-shaped bare base64 (40 chars). Hex-only of that length is a SHA -> filtered.
# '=' is NOT excluded at the boundary: a bare token right after `KEY=` (the common assignment shape) must still
# be eligible. Padding-'=' inside a blob is rare and low-entropy base64 is filtered by the shannon gate below.
_B64_40 = re.compile(r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])')

# ---- false-positive filters (detect-secrets heuristics) ----
_UUID = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_GITSHA = re.compile(r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')   # lowercase-hex commit / content hash = benign


def shannon(s):
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def _is_sequential(tok):
    if len(tok) < 4:
        return False
    diffs = {ord(b) - ord(a) for a, b in zip(tok, tok[1:])}
    return diffs <= {0, 1} or diffs <= {0, -1}


def is_benign_token(tok):
    if _UUID.match(tok):
        return True            # UUID is structured PII, handled by Tier-0; not a secret
    if _GITSHA.match(tok):
        return True            # git SHA / content hash
    if tok.isdigit():
        return True
    if len(set(tok)) <= 2:
        return True            # all-same / two-char
    if _is_sequential(tok):
        return True
    return False


def secret_spans(text, entropy_backstop=True):
    spans = []
    seen = set()

    def add(s, e, sub, conf=1.0):
        if s >= e or (s, e) in seen:
            return
        seen.add((s, e))
        spans.append({'start': s, 'end': e, 'label': 'secret', 'subtype': sub, 'tier': 0, 'conf': conf, 'rule': 'secret:' + sub})

    for name, rx, group in _P:
        for m in rx.finditer(text):
            if group:
                s, e = m.start(group), m.end(group)
            else:
                s, e = m.start(), m.end()
            val = text[s:e]
            if name in ('generic_assign', 'conn_string') and is_benign_token(val):
                continue
            add(s, e, name)

    if entropy_backstop:
        for m in _B64_40.finditer(text):
            tok = m.group()
            if is_benign_token(tok):
                continue
            if shannon(tok) >= 4.2:
                add(m.start(), m.end(), 'high_entropy')

    return spans


if __name__ == '__main__':
    import sys
    samples = [
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and secret stuff",
        "api_key = 'sk-test-1234567890abcdefABCDEF'",
        "DATABASE_URL=postgres://user:Sup3rSecret@db.host:5432/app",
        "commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b is fine (sha, benign)",
        "uuid ea36fc28-1234-4abc-9def-0123456789ab is PII not secret",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 token",
    ]
    for s in (samples if len(sys.argv) < 2 else [' '.join(sys.argv[1:])]):
        sp = secret_spans(s)
        print(s)
        print('  ->', [(s[x['start']:x['end']], x['subtype']) for x in sp])
