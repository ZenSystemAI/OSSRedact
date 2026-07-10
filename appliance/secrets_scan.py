#!/usr/bin/env python3
"""Deterministic secrets detector for the egress proxy (SPECS §3) -- ALWAYS on, ignores PII policy.

Ports the high-value, high-precision gitleaks provider regexes + a context-aware generic-assignment rule
+ an AWS-secret-shaped entropy backstop, with detect-secrets-style false-positive filters (UUID, git-SHA,
sequential, all-digit) so we do NOT nuke benign high-entropy tokens (commit SHAs, content hashes) and break
the coding-assistant use case. NO model, zero training. Returns spans labeled 'secret' (subtype in metadata),
conf 1.0 so they win any merge cluster -> always redacted.

Refs (verified 2026-06-14): gitleaks config/gitleaks.toml (MIT); detect-secrets
filters/heuristic.py + high_entropy_strings.py (Apache-2.0).
"""
import re
from math import log2
from privacy_gate import _has_format_chars, _strip_format_chars  # zero-width/format-char resistance (shared)

# ---- high-precision provider patterns (low FP; always fire). (name, regex, group|None) ----
_P = []


def _add(name, pat, group=None, flags=0):
    _P.append((name, re.compile(pat, flags), group))


_add('aws_access_key', r'(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16,}')  # AKIA prefix self-anchors; glue-safe
# GCP key charset includes `_` and `-`, so `\b` boundaries fail when the key is glued after/before an
# underscore (var_AIza..._suffix). Anchor on alphanumeric-only boundaries instead: `_ - " '` etc. are valid
# delimiters, so the fixed 39-char key is caught even inside an identifier.
_add('gcp_api_key', r'(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}(?![A-Za-z0-9])')
_add('github_token', r'(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}')  # ghp_ prefix self-anchors; glue-safe
_add('github_pat', r'github_pat_[0-9A-Za-z_]{22,}')
_add('slack_token', r'xox[baprs]-[0-9A-Za-z-]{10,}')
_add('slack_webhook', r'https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}')
_add('stripe_key', r'\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b')
_add('openai_key', r'\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b')
_add('anthropic_key', r'\bsk-ant-[A-Za-z0-9_\-]{20,}\b')
_add('google_oauth', r'ya29\.[0-9A-Za-z_\-]{20,}')
# Twilio API key (secret): SK + 32 hex. AC (account SID) is not secret, so only SK is flagged.
_add('twilio_key', r'(?<![A-Za-z0-9])SK[0-9a-f]{32}(?![A-Za-z0-9])')
# npm automation/access token (npm_ + 36 base62). Alphanumeric-only boundaries so it is caught when glued
# after an underscore (//registry.npmjs.org/:_authToken=npm_...) which the generic_assign rule may not bound.
_add('npm_token', r'(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])')
# PyPI upload token: always 'pypi-' + 'AgEI...' macaroon, long base64url.
_add('pypi_token', r'(?<![A-Za-z0-9])pypi-AgEI[A-Za-z0-9_\-]{30,}')
_add('jwt', r'eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}')
_add('private_key_block', r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----'
                          r'[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----')
# connection string with embedded credentials -> flag the password group(1). The password may itself contain
# '@' (P@ssw0rd) -- the OLD [^\s@/]{3,} stopped at the first '@' and leaked the tail. Allow '@' in the password
# and anchor on the LAST '@' before a hostname (greedy + backtrack to the rightmost @host).
_add('conn_string', r'(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|https?)://'
                    r'[^\s:@/]+:([^\s/]{3,})@[\w.\-]+', 1)
# header / SPACE-delimited credential: `Authorization: Bearer <opaque>`, `Basic <b64>`, `Token <x>`,
# `apikey <x>`, `jeton <x>`. The generic_assign rule needs `=`/`:`, so opaque tokens in HTTP-header / curl / log
# form (the canonical leak shape) slip through. Keyword-gated + 16+ continuous opaque chars so ordinary prose
# after the word ("api key generation", "bearer of bad news") -- whose next token is short or has spaces --
# cannot trip it. Value charset covers base64url / base64 / JWT (`. + / = _ -`).
_add('auth_space_secret',
     r'(?i)(?<![A-Za-z])(?:bearer|basic|token|api[_-]?key|access[_-]?key|secret|jeton)\s+'
     r'([A-Za-z0-9_\-./+=]{16,})', 1)
# generic assignment: secret-ish key = value -> flag the value group(2).
# The keyword may sit inside a snake_case / SCREAMING_SNAKE / dotted identifier (JWT_SECRET, AWS_ACCESS_KEY_ID,
# app.apiKey), so allow leading prefix segments and trailing suffix segments around the cue instead of a bare
# \b (the old \b failed on `JWT_SECRET=` because the cue `secret` was glued to `_`). Still keyword-gated +
# value-shape gated (8+ opaque chars, benign-filtered) so it does not nuke ordinary `name = value` code.
_add('generic_assign', r'(?i)(?<![A-Za-z])(?:[A-Za-z0-9]+[_\-.])*'
                       r'(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|'
                       r'client[_-]?secret|auth[_-]?token|bearer|credential|private[_-]?key|'
                       # French / Quebec credential keywords (this is an FR-first product): mot de passe, mdp,
                       # jeton (token), cle/clef secrete/api
                       r'motdepasse|mot[_\-.]?de[_\-.]?passe|mdp|jeton|cl[eé]f?[_\-.]?(?:api|secr[eè]te?))'
                       r'(?:[_\-.][A-Za-z0-9]+)*'
                       # the value's opening quote is CAPTURED (group 2): a quoted value is a string literal by
                       # construction, so the code-expression veto below never applies to it. Value = group 3.
                       r'["\']?\s*[:=]\s*(["\'])?([^\s"\',;}{]{8,})', 3)

# entropy backstop: AWS-secret-shaped bare base64 (40 chars). Hex-only of that length is a SHA -> filtered.
# '=' is NOT excluded at the boundary: a bare token right after `KEY=` (the common assignment shape) must still
# be eligible. Padding-'=' inside a blob is rare and low-entropy base64 is filtered by the shannon gate below.
_B64_40 = re.compile(r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])')

# ---- false-positive filters (detect-secrets heuristics) ----
_UUID = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_GITSHA = re.compile(r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')   # lowercase-hex commit / content hash = benign
# Code-expression value veto (generic_assign FP, live incident 2026-07-02): a cue-bearing IDENTIFIER assigned
# a CODE EXPRESSION -- `_NUM_SECRET_RE = re.compile(r'...` -- captured `re.compile(r` as the "value" and
# floor-minted a code fragment as a secret. Downstream that placeholder is withheld from tool arguments
# (B5 Half A), so every later agent edit of the source line failed against a literal <SECRET_NNN>.
# SCOPE (tightened after adversarial review, same night): applies ONLY to UNQUOTED generic_assign captures --
# a QUOTED value is a string literal by construction (never code), and a conn-string password is positionally
# always a credential. Three code shapes are vetoed:
#   (a) truncated call/subscript: identifier head + '('/'[' with NO closing bracket in the capture
#       (`re.compile(r`, `os.environ.get('...` -- the capture stops at the quote);
#   (b) balanced-TERMINAL call/subscript: the token ENDS at the closing bracket (`base64.b64encode(payload)`,
#       `config[env_name]`) -- a password does not stop exactly at a closing bracket, a call does;
#       a value whose tail continues PAST the close (`admin(2024)prod`, `Winter[2024]extra`) stays a secret;
#   (c) constant/dotted identifier reference: SCREAMING_SNAKE (`MY_OTHER_CONST`) or a dotted path
#       (`settings.secret_key`) -- config indirection, not a literal secret. lowercase snake_case is NOT
#       vetoed (real passwords are sometimes snake-ish; over-redaction is the safe error).
_CODE_CALL_OPEN = re.compile(r'^[A-Za-z_][\w.]*([([])')
_SCREAMING_CONST = re.compile(r'^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$')
_DOTTED_IDENT = re.compile(r'^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$')


def code_call_shape(tok):
    """A truncated or balanced-terminal call/subscript expression: `re.compile(r`, `config[env_name]`,
    `base64.b64encode(x)`. Unambiguously CODE at any entropy -- the exact incident shape (a cue-bearing
    identifier assigned a call). This is the ONLY veto applied on the DETERMINISTIC generic_assign floor:
    a bare SCREAMING_CONST / dotted value after a credential cue is NOT vetoed there, so a real dotted key
    (`api_key = SG.aB3cD4eF.gH5iJ6kL`) keeps its floor (adversarial re-review 2026-07-02)."""
    m = _CODE_CALL_OPEN.match(tok)
    if not m:
        return False
    close = ')' if m.group(1) == '(' else ']'
    if close not in tok:
        return True                     # truncated call: `re.compile(r`
    return tok.endswith(close)          # balanced-terminal call/subscript = code; tail past close = secret


def looks_like_code_expr(tok):
    """Call/subscript OR a bare SCREAMING_CONST / dotted-identifier reference. Used by the MODEL-credential
    verdict ONLY, which floors a high-entropy token BEFORE calling this -- so only a LOW-entropy token
    reaches here, and a bare CONST/dotted name at low entropy is config indirection (MY_OTHER_CONST,
    settings.secret_key), not a literal secret. The deterministic floor uses code_call_shape (above), which
    never un-floors a bare dotted/const value, so this broader shape can never weaken that hard guarantee."""
    return code_call_shape(tok) or bool(_SCREAMING_CONST.fullmatch(tok) or _DOTTED_IDENT.fullmatch(tok))


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
            if name in ('generic_assign', 'conn_string'):
                # A UUID-valued CUED assignment is a bearer credential (session=<uuid>, sid: <uuid> --
                # adversarial review 2026-07-02): the benign-UUID filter must not suppress it there. The
                # other benign shapes (git SHA, all-digit, sequential) stay suppressed as before.
                if is_benign_token(val) and not _UUID.match(val):
                    continue
                # Code-expression veto: UNQUOTED generic_assign captures only (a quoted value is a string
                # literal, never code; a conn-string password is positionally always a credential), and ONLY
                # the unambiguous call/subscript shape (code_call_shape) -- a bare dotted/const value after a
                # credential cue is asserted-secret and must keep its floor (re-review 2026-07-02).
                if name == 'generic_assign' and not m.group(2) and code_call_shape(val):
                    continue
            add(s, e, name)

    if entropy_backstop:
        for m in _B64_40.finditer(text):
            tok = m.group()
            if is_benign_token(tok):
                continue
            if shannon(tok) >= 4.2:
                add(m.start(), m.end(), 'high_entropy')

    # Zero-width/format-char obfuscation: an api_key/token interleaved with Cf codepoints ("sk<U+200B>-..."),
    # invisible to a human and the upstream LLM, slips every regex above. Re-scan a Cf-stripped copy and map
    # the span back onto the original offsets (covers the value + interleaved invisibles). clean has no Cf
    # chars so this recursion runs the regex pass exactly once more, never re-entering this branch.
    if _has_format_chars(text):
        clean, idx_map = _strip_format_chars(text)
        if clean and clean != text:
            for s in secret_spans(clean, entropy_backstop=entropy_backstop):
                add(idx_map[s['start']], idx_map[s['end'] - 1] + 1, s.get('subtype', 'secret') + '+cf', s.get('conf', 1.0))

    return spans


if __name__ == '__main__':
    import sys
    samples = [
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and secret stuff",
        "api_key = 'sk-test-1234567890abcdefABCDEF'",
        "DATABASE_URL=postgres://user:Sup3rSecret@db.host:5432/app",
        "commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b is fine (sha, benign)",
        "uuid ab12cd34-1234-4abc-9def-0123456789ab is PII not secret",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 token",
    ]
    for s in (samples if len(sys.argv) < 2 else [' '.join(sys.argv[1:])]):
        sp = secret_spans(s)
        print(s)
        print('  ->', [(s[x['start']:x['end']], x['subtype']) for x in sp])
