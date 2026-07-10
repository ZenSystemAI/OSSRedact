#!/usr/bin/env python3
"""Tiered local PII privacy gate -- sanitize text before egress to a hosted LLM.

Architecture (informed by this project's benchmarks):
  Tier 0  Deterministic pre-scan (regex + Luhn, ~0 latency). OWNS the digit-spacing / structured-ID case
          where the neural models had low recall: normalizes separators and flags number-shaped PII (SIN,
          card, phone, postal, IP, email) regardless of spacing. Highest-recall safety net for that axis.
  Tier 1  NPU always-on token-classifier (INT8 ONNX XLM-R, Quebec full-FT). General PII: names, addresses,
          dates, account ids, tax ids, secrets. ~11-22 ms/row CPU, near-lossless INT8.
  Tier 2  GLiNER2 v5-pa escalation (optional, GPU) for max-recall / flexible labels on sensitive payloads.

Reversible redaction: typed placeholders + a local map. detect() -> spans; redact() -> (text, map);
rehydrate() reverses. No external deps required for tiers 0-1 (onnxruntime + transformers tokenizer only).
"""
from __future__ import annotations
import re, json, unicodedata
from collections import defaultdict

# ---------------- Tier 0: thin validated floor (checksum/format-exact catastrophic shapes only) ----------------
# Phase 2 (2026-06-14): the floor emits ONLY shapes that are checksum- or format-exact, so it is a
# never-leak safety net with near-zero false positives. Loose shapes (dates, amounts, bare digit runs,
# postal codes, phone numbers, IPs) are LEFT for the neural model, which owns recall AND labeling. This
# REMOVES the precision tax the old tier0 imposed (it over-fired on every number/date/postal/phone shape).
# Alphabetic-TLD requirement mirrors appliance/privacy_gate.py: the old tail matched npm/version
# strings ("unpkg@1.1.0" -> EMAIL). A real deliverable address ends in a letters-only label.
EMAIL_RE = re.compile(r'\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b')
# UUID (8-4-4-4-12 hex) = connection/session/request IDs (e.g. Flinks login id). Never occurs by accident
# in natural text, so it is a deterministic catch at ~1.0 confidence, independent of the model threshold.
# LABEL DEMOTED 2026-07-02 (mirrors appliance/privacy_gate.py tier0:uuid): minted as the SOFT label 'uuid',
# no longer 'sensitive_account_id'. UUIDs are load-bearing session/request ids in coding traffic, and the
# old floor label made them merge-sticky, un-allowlistable, redacted even in 'off' mode, AND withheld from
# tool-call arguments -- a live agent received a literal <SENSITIVEACCOUNTID_004> as a file path and wrote a
# junk directory. Floor privileges require deterministic provenance of a CATASTROPHIC shape; a UUID is
# deterministic but not catastrophic, so it stays detected (stable placeholder when policy redacts it) while
# the label lets modes/allowlist exempt it. The egress keeps a back-compat guard relabeling incoming
# account-id-labeled UUID-shaped spans until every deployed gate copy carries this change.
UUID_RE = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
# IBAN: 2-letter country + 2 check digits + 11-30 alphanumerics (internal spaces/hyphens allowed). Validated
# by the ISO 7064 mod-97 checksum (_iban_ok), so a match is a near-certain real IBAN with no precision risk.
IBAN_RE = re.compile(r'\b([A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?:[ -][A-Z0-9]{2,4}){3,8}))\b', re.I)
# Shape-specific numeric candidates. EXACT digit counts (with optional single space/dash separators between
# digits, matching the real 4-4-4-4 / 4-6-5 / 3-3-3 groupings) so a candidate can NEVER bridge two adjacent
# numbers across a separator (a generic greedy digit-run would swallow "card<space>SIN" into one blob and
# drop both). The (?<![\w]) / (?![\w]) anchors also stop a 9-digit window from matching INSIDE a 16-digit
# card. Each candidate is still Luhn-gated below before it is emitted.
_CARD_CAND_RE = re.compile(r'(?<![\w])(\d(?:[ -]?\d){14,15})(?![\w])')   # 15 or 16 digits -> payment_card
_SIN_CAND_RE = re.compile(r'(?<![\w])(\d(?:[ -]?\d){8})(?![\w])')        # exactly 9 digits -> government_id
# Canadian Business Number program-account suffix (RT=GST/HST, RP=payroll, RC=corp income tax,
# RZ/RM/RR/RG=info/other). A 9-digit Luhn number IMMEDIATELY followed by this is a Business Number, NOT a
# SIN -- it is printed publicly on every Quebec/Canada invoice as the GST/QST registration. Validated on 88
# real expense docs (validation/RESULT-realworld-expenses.md, Finding A): 40/85 9-digit-Luhn floor hits
# carried this suffix (definitive BN); 0 had a SIN cue. Suppressing it removes the mislabel + over-redaction.
# Separator is a single space/hyphen ONLY (not \s -- a newline/tab must never bridge the gap), and (?!\d)
# not \b, so the pattern behaves IDENTICALLY in this regex and the JS twin (avoids \w-is-unicode-in-Python).
_BN_PROGRAM_SUFFIX_RE = re.compile(r'^[ \-]?(?:RT|RP|RC|RZ|RM|RR|RG)[ \-]?\d{4}(?!\d)', re.I)
# SIN-cue OVERRIDE (never-leak guarantee, per Codex review): if a SIN cue sits just before the number, do NOT
# suppress -- emit government_id even if a BN-looking suffix follows. A real SIN must always win; a number
# cannot be both a SIN and a BN program account, so this override only ever ADDS a redaction (safe error).
# The acronyms nas/sin are ASCII-word-boundary-gated (else "BUSINESS"/"casino"/"using" would falsely fire the
# override and un-suppress a real BN -- Codex round 2) and tolerate dotted forms (N.A.S., S.I.N.).
_SIN_CUE_RE = re.compile(
    r'(?i)(?:(?<![a-z])(?:n\.?a\.?s|s\.?i\.?n)(?![a-z])|social\s*insurance|assurance\s*sociale|num[ée]ro\s*d.?assurance)')

# Unicode dash variants -> ASCII hyphen. PDF text extraction (pdfplumber/pypdf) routinely emits en-dash
# (U+2013) or others as separators, which broke the digit-run/phone/date regexes: "006–02761–1234567"
# (en-dash) was seen as 3 short groups and only the last was caught, leaking the institution+transit.
# Every replacement is single-char -> single-char, so it is LENGTH-PRESERVING and offsets map 1:1 back.
_DASH_RE = re.compile('[\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u2043\ufe58\ufe63\uff0d]')
def _normdash(s: str) -> str:
    return _DASH_RE.sub('-', s)

# Unicode space variants -> ASCII space. NBSP (U+00A0) and friends defeated the digit-run/phone/postal
# regexes: a NBSP-separated SIN in a cue-less cell ("653 956 771") never matched DIGIT_RUN_RE's
# [\d .\-] class, so the deterministic SIN floor never fired and the value could leak when the NER tier
# also missed it (no context cue, e.g. a bare CSV cell). Single-char -> single-char = LENGTH-PRESERVING.
_SPACE_RE = re.compile('[            　]')
def _normspace(s: str) -> str:
    return _SPACE_RE.sub(' ', s)
# Unicode DIGIT homoglyphs that aren't ASCII 0-9 (SUPERSCRIPT/SUBSCRIPT/circled = category No, which \d never
# matches): map every single-codepoint digit-valued char to its ASCII digit so "card ⁴¹¹¹..." engages the
# digit floor. LENGTH-PRESERVING; also folds non-ASCII Nd (fullwidth, Arabic-Indic) to ASCII for an exact Luhn.
def _normdigits(s: str) -> str:
    if s.isascii():
        return s
    out = []
    for ch in s:
        if '0' <= ch <= '9':
            out.append(ch); continue
        try:
            out.append(str(unicodedata.digit(ch)))
        except (ValueError, TypeError):
            out.append(ch)
    return ''.join(out)

def _normseps(s: str) -> str:
    return _normdigits(_normspace(_normdash(s)))

# Zero-width / format (Unicode category Cf) + control (Cc) + soft-hyphen interleaving INVISIBLY breaks every
# Tier-0 number/identifier regex: "4<U+200B>1<U+200B>1<U+200B>1..." has the digit-run separators a human and
# the upstream LLM never see, so the deterministic floor returns n_spans=0 and the real card/IBAN/SIN ships raw
# in EVERY mode incl 'off' (the floor is supposed to be un-bypassable). Two codepoint classes do this:
#   Cf (format)  -- ZWSP/ZWNJ/ZWJ/WORD-JOINER/BOM/soft-hyphen (U+200B.., U+00AD)
#   Cc (control) -- TAB/LF/VT/FF/CR (U+0009-000D) and the C0/C1 separators (FS/GS/RS/US U+001C-001F)
# _normseps only maps Zs spaces + dashes, never these. Fix: strip BOTH classes to a clean copy, re-run the
# Tier-0 scan there, and map each span back onto the ORIGINAL offsets so the mask covers the value AND the
# interleaved invisibles. (Soft hyphen U+00AD is category Cf; ZWSP/ZWNJ/ZWJ/WORD-JOINER/BOM are too; TAB/CR/LF
# and the C0 separators are Cc -- a single category-membership test covers them all.)
_INVISIBLE_CATS = ('Cf', 'Cc')

def _has_format_chars(s: str) -> bool:
    return any(unicodedata.category(ch) in _INVISIBLE_CATS for ch in s)

def _strip_format_chars(text: str):
    """Return (clean, idx_map): clean has every Cf/Cc codepoint removed; idx_map[i] = original index of
    clean[i], with a trailing sentinel idx_map[len(clean)] = len(text) so an end offset always maps."""
    chars, idx_map = [], []
    for i, ch in enumerate(text):
        if unicodedata.category(ch) in _INVISIBLE_CATS:
            continue
        chars.append(ch); idx_map.append(i)
    idx_map.append(len(text))
    return ''.join(chars), idx_map

def _luhn_ok(digits: str) -> bool:
    s = 0
    for i, c in enumerate(reversed(digits)):
        d = int(c)
        if i % 2 == 1:
            d *= 2
            if d > 9: d -= 9
        s += d
    return s % 10 == 0

def _iban_ok(s: str) -> bool:
    """ISO 7064 mod-97 IBAN checksum: strip spaces, move the first 4 chars to the end, map letters A-Z to
    10-35, then the integer value mod 97 must equal 1. A pass is a near-certain real IBAN (no FP risk)."""
    s = re.sub(r'[\s-]', '', s).upper()
    if not re.fullmatch(r'[A-Z]{2}\d{2}[A-Z0-9]+', s):
        return False
    s2 = s[4:] + s[:4]
    digits = ''.join(str(ord(c) - 55) if c.isalpha() else c for c in s2)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False

def _valid_iban_candidate(raw: str):
    """Return the checksum-valid prefix of an IBAN candidate, trimming only trailing separated groups.

    The regex is case-insensitive so a prose word after a grouped IBAN can look like one more group
    (for example "... 32 fin"). Try the full candidate first, then drop separator-delimited tail groups.
    """
    candidate = raw
    while candidate:
        if _iban_ok(candidate):
            return candidate
        cut = max(candidate.rfind(' '), candidate.rfind('-'))
        if cut <= 4:
            break
        candidate = candidate[:cut]
    return None

def validated_floor(text: str):
    """The thin never-leak floor: emit ONLY checksum/format-exact catastrophic shapes (email, UUID,
    mod-97 IBAN, Luhn card, Luhn SIN). Loose shapes (dates, amounts, bare digit runs, postal, phone, IP)
    are LEFT for the neural model, which owns recall AND labeling. Matching runs on a length-preserving
    _normseps copy, so the returned offsets index the ORIGINAL text the caller redacts.
    NOTE (2026-07-02): the UUID hit is deterministic but carries the SOFT label 'uuid' (not a FLOOR_LABEL),
    so mode/allowlist policy at the egress can exempt it -- see the UUID_RE rationale above."""
    spans = []
    t = _normseps(text)
    def add(s, e, lab, conf, rule, **extra):
        spans.append({'start': s, 'end': e, 'label': lab, 'tier': 0, 'conf': conf, 'rule': rule, **extra})
    for m in EMAIL_RE.finditer(t):
        add(m.start(), m.end(), 'email', 0.99, 'floor:email')
    for m in UUID_RE.finditer(t):
        # 'uuid' is deterministic-but-SOFT (2026-07-02, see UUID_RE note): rule renamed 'floor:uuid' ->
        # 'tier0:uuid' to match the appliance twin and stop implying floor privilege in /redact stats + audits.
        add(m.start(), m.end(), 'uuid', 0.99, 'tier0:uuid')
    for m in IBAN_RE.finditer(t):
        iban = _valid_iban_candidate(m.group(1))
        if iban:
            add(m.start(1), m.start(1) + len(iban), 'iban', 0.99, 'floor:iban', validator='mod97_ok')
    for m in _CARD_CAND_RE.finditer(t):
        digits = re.sub(r'\D', '', m.group(1))
        if len(digits) in (15, 16) and _luhn_ok(digits):
            add(m.start(1), m.end(1), 'payment_card', 0.97, 'floor:card', validator='luhn_ok')
    for m in _SIN_CAND_RE.finditer(t):
        digits = re.sub(r'\D', '', m.group(1))
        if len(digits) == 9 and _luhn_ok(digits):
            s0, e0 = m.start(1), m.end(1)
            if _BN_PROGRAM_SUFFIX_RE.match(t[e0:e0 + 12]) and not _SIN_CUE_RE.search(t[max(0, s0 - 40):s0]):
                continue  # Business Number (GST/QST), not a SIN, and no SIN cue forces emission -- Finding A
            add(s0, e0, 'government_id', 0.9, 'floor:sin', validator='luhn_ok')
    spans += glued_digit_spans(t)       # Luhn-valid 9-digit SIN glued to letters (no cue; Luhn-precise)
    spans += separated_card_spans(t)    # dot/space/dash-grouped Luhn card + dotted SSN (sep DIGIT_RUN rejects)
    spans += card_aux_spans(t)          # cue-anchored card_cvv + card_expiry (no standalone Tier-0 before)
    # Zero-width/format-char obfuscation resistance: if the ORIGINAL carries Cf codepoints, re-scan a stripped
    # copy and map the spans back. clean has no Cf chars, so validated_floor(clean) cannot re-enter this branch.
    if _has_format_chars(text):
        clean, idx_map = _strip_format_chars(text)
        if clean and clean != text:
            for s in validated_floor(clean):
                a, b = idx_map[s['start']], idx_map[s['end'] - 1] + 1
                spans.append({**s, 'start': a, 'end': b, 'rule': (s.get('rule') or 'tier0') + '+cf'})
    return spans


# Glued NON-checksum digit-run floor. DIGIT_RUN_RE rejects digit runs glued to letters (precision for code).
# A confirmed leak was a 9-digit SIN glued to a word ("JaneDoe046454286"). The naive fix (promote ANY 9-19
# digit run glued to a letter) over-redacts real coding traffic badly -- translateY(123456789px), seed1234567890,
# unix timestamps createdAt1700000000 (FP audit). So glued promotion is PRECISION-GATED:
#   - 9 digits + LUHN-valid -> government_id. Canadian SINs carry a Luhn check digit, so this catches the real
#     SIN ("046454286" passes Luhn) while rejecting code numbers ("123456789" fails Luhn). No cue needed.
#   - everything else glued (incl. non-Luhn SSN, 10-19 account runs) is left to context_cued_id_spans, which
#     fires ONLY when a financial/identity cue is adjacent (its _LONG_ID_RE now covers 9-19 digits). A bank
#     account glued to a NON-cue word relies on the neural tier -- accepted residual vs. nuking every code id.
# Luhn cards stay with glued_checksum_spans. Letter-adjacency REQUIRED.
_GLUED_DIGIT_RE = re.compile(r'(?<!\d)(\d{9})(?!\d)')

def glued_digit_spans(text: str):
    out = []
    t = _normseps(text)
    for m in _GLUED_DIGIT_RE.finditer(t):
        s, e, digits = m.start(1), m.end(1), m.group(1)
        left = t[s - 1] if s > 0 else ' '
        right = t[e] if e < len(t) else ' '
        if not (left.isalpha() or right.isalpha()):
            continue                                  # clean boundary -> already owned by DIGIT_RUN_RE
        if _luhn_ok(digits):                          # Luhn-valid 9-digit glued to a word = a SIN, not a code id
            # Business Number suppression (mirrors validated_floor's _SIN_CAND_RE path): a glued RT/RP/RC...
            # program-account suffix ("046454286RT0001") is a public GST/QST registration, not a personal SIN.
            # Suppress UNLESS a SIN cue forces emission (never-leak override). A clean SIN glued to a non-suffix
            # word ("JaneDoe046454286") is unaffected and still emits.
            if _BN_PROGRAM_SUFFIX_RE.match(t[e:e + 12]) and not _SIN_CUE_RE.search(t[max(0, s - 40):s]):
                continue
            out.append({'start': s, 'end': e, 'label': 'government_id', 'tier': 0, 'conf': 0.8,
                        'rule': 'tier0:digit_glued', 'validator': 'luhn_ok'})
    return out


# Separator-tolerant payment card: DIGIT_RUN_RE / glued_checksum reject '.'-separated groups (a confirmed leak:
# "4111.1111.1111.1111") and percent-encoded spaces ("4111%201111%201111%201111"). A 4-4-4-4 (or amex 4-6-5)
# grouping joined by '.', '-', space, or the literal "%20" whose digits are a Luhn-valid 15/16-run is a card
# with near-zero FP (Luhn-gated). Space/dash forms re-emit harmlessly (merged).
_CARD_SEP = r'(?:[ .\-]|%20)'
_SEP_CARD_RE = re.compile(r'(?<![\d.])(\d{4}(?:' + _CARD_SEP + r'\d{4}){3}|\d{4}' + _CARD_SEP + r'\d{6}' + _CARD_SEP + r'\d{5})(?![\d.])')
# US SSN written with dot separators ("123.45.6789"): a 3-2-4 digit grouping joined by dots. The boundary
# rejects longer dotted sequences (IPs/versions never group 3-2-4). government_id floor.
_DOT_SSN_RE = re.compile(r'(?<![\d.])(\d{3}\.\d{2}\.\d{4})(?![\d.])')

def separated_card_spans(text: str):
    out = []
    t = _normseps(text)
    for m in _SEP_CARD_RE.finditer(t):
        digits = re.sub(r'\D', '', m.group(1).replace('%20', ' '))   # decode %20 before digit extraction (its 2,0 are not card digits)
        if len(digits) in (15, 16) and _luhn_ok(digits):
            out.append({'start': m.start(1), 'end': m.end(1), 'label': 'payment_card', 'tier': 0,
                        'conf': 0.95, 'rule': 'tier0:card_sep', 'validator': 'luhn_ok'})
    for m in _DOT_SSN_RE.finditer(t):
        out.append({'start': m.start(1), 'end': m.end(1), 'label': 'government_id', 'tier': 0,
                    'conf': 0.8, 'rule': 'tier0:ssn_dotted'})
    return out


# card_cvv + card_expiry are FLOOR_LABELS but had NO deterministic Tier-0 regex -- they fired only when the
# neural tier happened to tag them, so a bare CVV ("security code 123", "cvc: 123") or a short expiry
# ("expiry 08/27", "exp 12/2026") leaked verbatim in privacy AND off mode, even alongside a redacted card (a
# false sense the whole card block is protected). Both are CUE-ANCHORED so a stray 3-digit number or a generic
# date never blanket-redacts: a card-verification / expiry keyword (EN+FR) must sit immediately before.
# Cue words are CVV-SPECIFIC: cvv/cvc(+2), 'security code' (a real CVV synonym -- kept; the rare 'security code
# 401' HTTP-status collision is accepted over-redaction), card-verification, FR code-de-securite / cryptogramme.
# DROPPED 'cid' (correlation/customer/container id -- a ubiquitous dev abbreviation that mis-fired) and bare 'sec code'.
# The cue->value separator tolerates a JSON closing-quote on the key and an optional quote on the value
# (`["']?`), so a CVV/expiry pasted as JSON TEXT in a prompt ("cvv": 834, "expiry": "08/27") is caught --
# not just the bare prose form (cvv: 834). Without it the quote between key and ':' broke the match and the
# value leaked verbatim (confirmed live 2026-06-21). Structural JSON keys are force-redacted separately.
_QSEP = r'\s*(?:no\.?|num(?:[ée]ro)?|#)?\s*["\']?\s*[:=#-]?\s*["\']?\s*'
_CVV_RE = re.compile(r'(?i)(?:cvv2?|cvc2?|security[\s_]*code|card[\s_]*verification(?:[\s_]*(?:code|value))?|'
                     r'code\s*de\s*s[eé]curit[eé]|cryptogramme(?:\s*visuel)?)' + _QSEP + r'(\d{3,4})(?!\d)')
_EXPIRY_RE = re.compile(r'(?i)(?:exp(?:iry|ires?|iration)?|exp\.?\s*date|valid\s*thru|valid\s*through|good\s*thru|'
                        r'valable\s*jusqu.?(?:au)?|[ée]ch[ée]ance|date\s*d.?expiration)\s*["\']?\s*[:=#-]?\s*["\']?\s*'
                        r'((?:0[1-9]|1[0-2])\s*[/\-]\s*(?:\d{4}|\d{2}))(?!\d)')
# PIN / passcode / OTP numeric secrets (EN + FR 'NIP'). Cue-anchored with WORD boundaries so 'pinned'/'spinning'
# never fire, and the same JSON-quote-tolerant separator so "pin": 5571 (pasted JSON) is caught, not just
# 'pin 5571'. 3-8 digits. Emits the enforced FLOOR_LABEL 'password'. A bare cue-less number stays the NER's job.
_NUM_SECRET_RE = re.compile(r'(?i)(?:(?:\b\w+_)?pin\b|\bnip\b|\bpasscode\b|\bpass[\s_]*code\b|\botp\b|'
                            r'\bone[\s_-]?time[\s_]*(?:code|password|passcode|pin)\b|\baccess[\s_]*code\b)'
                            + _QSEP + r'(\d{3,8})(?!\d)')

def card_aux_spans(text: str):
    out = []
    t = _normseps(text)
    for m in _CVV_RE.finditer(t):
        out.append({'start': m.start(1), 'end': m.end(1), 'label': 'card_cvv', 'tier': 0,
                    'conf': 0.9, 'rule': 'tier0:cvv'})
    for m in _EXPIRY_RE.finditer(t):
        out.append({'start': m.start(1), 'end': m.end(1), 'label': 'card_expiry', 'tier': 0,
                    'conf': 0.9, 'rule': 'tier0:expiry'})
    for m in _NUM_SECRET_RE.finditer(t):
        out.append({'start': m.start(1), 'end': m.end(1), 'label': 'password', 'tier': 0,
                    'conf': 0.9, 'rule': 'tier0:num_secret'})
    return out


# ---- Tier-0 person backstop: deterministic where a strong CUE exists ----
# Person names have NO checksum/regex floor, so the NER owns them -- EXCEPT the RFC5322 mailbox form
# "Display Name <addr@domain>" (email From/To/Cc headers, git Author/Signed-off-by lines), where the email
# adjacency destabilizes the NER span (it truncates or drops the name -- measured 4/25 real-world name forms).
# There the '<email>' / header cue IS deterministic, so we hard-guarantee the preceding name. Cue-LESS prose
# names stay the model's job (the NER catches those well). Offsets index the _normseps copy = original text.
_EMAIL_ANCHOR_RE = re.compile(r'<[ \t]*[\w.+-]+@[\w-]+\.[\w.-]+[ \t]*>')
_HDR_CUE_RE = re.compile(
    r'(?im)^[ \t]*(?:from|to|cc|bcc|reply-to|sender|author|co-authored-by|signed-off-by|owner|'
    r'titulaire|propri[ée]taire|attn|attention|'
    # statement-header cues (2026-07-08, plan 049): the account holder / member name printed at the top of a
    # bank statement, colon-anchored and line-anchored exactly like the mail headers above.
    r'nom|client(?:e)?|membre|member|account\s+holder|prepared\s+for|pr[ée]par[ée]\s+pour)[ \t]*:[ \t]*')
# a name token: unicode letters with internal apostrophe / hyphen / period, NO digits
_NAME_TOKEN_RE = re.compile(r"[^\W\d_]+(?:['’.\-][^\W\d_]+)*", re.UNICODE)
_NAME_PARTICLES = {'van', 'von', 'de', 'der', 'den', 'del', 'della', 'di', 'da', 'du', 'la', 'le',
                   'el', 'bin', 'ibn', 'al', 'dos', 'das', 'do', 'of', 'and'}
_NAME_ROLE_DENY = {'support', 'sales', 'billing', 'info', 'admin', 'noreply', 'no-reply', 'notifications',
                   'notification', 'team', 'contact', 'hello', 'help', 'marketing', 'security', 'abuse',
                   'postmaster', 'mailer-daemon', 'do-not-reply', 'donotreply', 'newsletter', 'accounts',
                   'service', 'services', 'sender', 'recipient', 'no_reply'}

def _name_shaped(s: str) -> bool:
    """True if s looks like a personal name (1-5 capitalized alpha tokens, lowercase particles allowed,
    no digits, not a role/distribution-list word). Permissive on purpose: a cue-anchored over-mask of a
    display name is privacy-safe; a missed name is a leak."""
    s = s.strip().strip('"').strip()
    words = s.split()
    if not (2 <= len(s) <= 60) or not (1 <= len(words) <= 5) or any(c.isdigit() for c in s):
        return False
    if s.lower() in _NAME_ROLE_DENY or all(w.lower() in _NAME_ROLE_DENY for w in words):
        return False
    has_cap = False
    for w in words:
        core = w.replace('-', '').replace("'", '').replace('’', '').replace('.', '')
        if not core or not all(c.isalpha() for c in core):
            return False
        if w[0].isupper():
            has_cap = True
        elif w.lower() not in _NAME_PARTICLES:
            return False
    return has_cap

def _is_name_tok(tok: str) -> bool:
    return (tok[:1].isupper() or tok.lower() in _NAME_PARTICLES) and tok.lower() not in _NAME_ROLE_DENY

def _name_run_before(t: str, end: int):
    """Maximal run of contiguous name-shaped tokens ending right before index `end` (the '<' of an email).
    Only whitespace/quotes may sit between tokens (and between the last token and `end`)."""
    toks = [(m.group(0), m.start(), m.end()) for m in _NAME_TOKEN_RE.finditer(t[:end])]
    if not toks or t[toks[-1][2]:end].strip(' \t"\'’') != '':
        return None
    chosen, nxt = [], end
    for tok, s, e in reversed(toks):
        if t[e:nxt].strip(' \t"\'’') != '' or not _is_name_tok(tok):
            break
        chosen.append((s, e)); nxt = s
        if len(chosen) >= 5:
            break
    while chosen and t[chosen[-1][0]:chosen[-1][1]].lower() in _NAME_PARTICLES:  # don't start on a particle
        chosen.pop()
    return (chosen[-1][0], chosen[0][1]) if chosen else None

def _name_run_after(t: str, start: int, stop: int):
    """Maximal run of contiguous name-shaped tokens beginning at `start` (just past a header cue)."""
    toks = [(m.group(0), m.start(), m.end()) for m in _NAME_TOKEN_RE.finditer(t, start, stop)]
    chosen, prev = [], start
    for tok, s, e in toks:
        if t[prev:s].strip(' \t"\'’') != '' or not _is_name_tok(tok):
            break
        chosen.append((s, e)); prev = e
        if len(chosen) >= 5:
            break
    while chosen and t[chosen[0][0]:chosen[0][1]].lower() in _NAME_PARTICLES:
        chosen.pop(0)
    return (chosen[0][0], chosen[-1][1]) if chosen else None

# ---- e-transfer / bank-ledger counterparty-name floor (2026-07-08, plan 049) ----
# A whole class of counterparty NAMES leaks from bank statements: they sit after a bank-specific ledger cue
# ("VIR INTERAC RECU <name>", "E-TRANSFER <ref> <name>", "Depot auto - virements par courriel <name> <ref>",
# Desjardins slash fields "Interac e-Transfer from /<name> /"). The neural tier misses them (no prose context,
# often lowercase, ALL-CAPS, or truncated by a following reference id). The cue grammar IS deterministic, so we
# hard-guarantee the adjacent name. These cues are SPECIFIC multi-word financial phrases -- this floor also runs
# on the coding-traffic wire, so no bare generic word is a cue. Emission is over-mask-on-a-cue = the safe error.
_LEDGER_STOPWORDS = frozenset({
    # what follows a counterparty name in real ledger cells (refs/amounts/currency/markers) -- a name run ENDS here
    'fonds', 'admis', 'ca', 'no', 'ref', 'reference', 'cad', 'usd', 'id', 'conf', 'confirmation',
    # ledger-grammar keywords (also a backstop: if a generic cue starts a run on one, it stops immediately)
    'interac', 'etrnsr', 'etransfer', 'transfer', 'transfert', 'virement', 'virements', 'vir', 'dep', 'auto',
    'rec', 'recu', 'reçu', 'recvd', 'received', 'sent', 'envoye', 'envoyé', 'envoi', 'annule', 'annulé',
    'autodeposit', 'deposit', 'depot', 'dépôt', 'courriel', 'par', 'en', 'ligne', 'from', 'to', 'cancellation',
    'rent', 'lease', 'prepared', 'préparé', 'pour', 'nom', 'client', 'cliente', 'membre', 'member',
    # entity suffixes -- never part of a personal-name span ('me' = Maître stays here: too common a word)
    'me', 'ing', 'inc', 'ltd', 'ltee', 'ltée', 'corp',
    # amount/currency words (an "E-TRANSFER 123456 dollars" prose form must not mint a person)
    'dollars', 'dollar', 'euros', 'euro', 'cents', 'cts',
    # function words / generic nouns after a prose colon-cue -- never part of a name
    'the', 'a', 'an', 'my', 'your', 'this', 'that', 'account', 'compte', 'amount', 'montant',
    # capitalized ledger transaction-type words that can precede a name (leftward growth guard)
    'solde', 'achat', 'paiement', 'retrait', 'frais', 'cheque', 'chèque', 'facture', 'remboursement',
    'retour', 'total', 'balance', 'depot',
})
# Honorifics are NOT stopwords: "VIR INTERAC RECU MME MARIE DUPUIS" must still floor the name (Codex review
# 2026-07-08 HIGH: a leading honorific used to terminate the run and drop the whole name). The ledger scanner
# SKIPS leading honorifics (kept out of the span); mid-run they ride along as ordinary tokens (safe over-mask).
_LEDGER_HONORIFICS = frozenset({'mme', 'mlle', 'mr', 'mrs', 'ms', 'dr', 'madame', 'monsieur'})
# Log/code status words a person span must never GROW over (and never propagate as name tokens): the model
# tags "John" in "INFO user=John Error Retrying" and unguarded absorption would mask "Error" document-wide
# (Codex review 2026-07-08 MEDIUM -- the fat-floor lesson applied to growth).
_GROW_STATUS_DENY = frozenset({
    'error', 'errors', 'warning', 'warn', 'info', 'debug', 'trace', 'fatal', 'panic', 'exception',
    'traceback', 'failed', 'failure', 'fail', 'retry', 'retrying', 'timeout', 'denied', 'invalid',
    'unknown', 'null', 'none', 'true', 'false', 'undefined', 'nan', 'success', 'started', 'stopped',
    'killed', 'deprecated', 'todo', 'fixme', 'notice', 'pending', 'alert', 'critical', 'severe',
    # French log/status vocabulary (Codex re-verify: 'John Erreur Reessayer' absorbed+propagated)
    'erreur', 'erreurs', 'avertissement', 'attention', 'reessayer', 'réessayer',
    'succes', 'succès', 'echec', 'échec', 'demarre', 'démarré', 'arrete', 'arrêté', 'termine', 'terminé',
    'annulation', 'refuse', 'refusé', 'valide', 'validé', 'expire', 'expiré',
})

# NON-slash cues, case-insensitive, NOT line-anchored (they appear mid-cell). Each alternative consumes up to
# (and including) the whitespace before the name -- incl. a leading numeric reference for the CIBC E-TRANSFER
# form, whose ref PRECEDES the name. Specific keyword forms are ordered BEFORE the generic E-TRANSFER catch so
# "e-Transfer sent <name>" is not read as name "sent". Trailing whitespace is skipped by the name scanner.
_ETRANSFER_CUE_RE = re.compile(
    r'(?i)(?:'
    r'vir\s+interac\s+(?:dep\s+auto\s+rec|recu|re[çc]u|envoy[eé]|annul[eé])'          # BMO / National
    r'|interac\s+(?:etrnsfr|etrnsr)\s+(?:ad\s+recvd|recvd|sent)'                        # TD / BMO alt
    r'|d[eé]p[oô]t\s+auto\s*-\s*virements?\s+par\s+courriel'                            # RBC autodeposit
    r'|virement\s+(?:en\s+ligne\s+)?(?:envoy[eé]|recu|re[çc]u)'                         # RBC virement
    r'|e-?transfer\s*-\s*autodeposit'                                                    # RBC e-Transfer autodeposit
    r'|e-?transfer\s+sent'                                                               # RBC e-Transfer sent
    r'|e-?transfer\s+(?:to|from)\s*:'                                                   # Tangerine e-Transfer To:/From:
    r'|e-?transfer\s+\d{6,}(?:\s*[;:,]\s*|\s+)'                                          # CIBC E-TRANSFER <ref> <name>
    r')[ \t]*')
# Desjardins slash fields: the name is between slashes ("from /<name> /", "to /<name> /") or after one
# ("Rent/lease /<name>"). The cue below ends right after the OPENING slash; the name runs to the next '/'.
_ETRANSFER_SLASH_RE = re.compile(
    r'(?i)(?:(?:cancellation[ \-]*)?interac\s+e-?transfer\s+(?:from|to)|rent\s*/\s*lease)\s*/\s*')

# A run of >=2 spaces OR any tab = a column gap in a statement layout: it terminates a ledger name run/field.
_LEDGER_COLGAP_RE = re.compile(r'  +|\t')
_LEDGER_INITIALS_RE = re.compile(r'[A-Z](?:\.?[A-Z])*\.?$')
# NARROW initial: a single letter or a dotted run (A, A., M.C.) -- NOT an all-caps word (FONDS).
# Used where the check must run BEFORE the stopword test, so 'A' beats the article but 'FONDS' cannot.
_LEDGER_INITIAL_NARROW_RE = re.compile(r'[A-Z](?:\.[A-Z])*\.?$')

def _name_shaped_relaxed(s: str) -> bool:
    """Like _name_shaped but WITHOUT the leading-capital requirement -- for cue-anchored ledger fields where
    lowercase counterparty names are common (CIBC 'delyna morvan', RBC 'barb'). Cue-anchored, so a lowercase
    over-mask is the safe error; _name_shaped itself is left unchanged for the header/email paths."""
    s = s.strip().strip('"').strip()
    words = [w for w in s.split() if w != '-']   # a lone hyphen is a run CONNECTOR (DBA form), not a word
    if not (2 <= len(s) <= 60) or not (1 <= len(words) <= 5) or any(c.isdigit() for c in s):
        return False
    if s.lower() in _NAME_ROLE_DENY or all(w.lower() in _NAME_ROLE_DENY for w in words):
        return False
    for w in words:
        core = w.replace('-', '').replace("'", '').replace('’', '').replace('.', '')
        if not core or not all(c.isalpha() for c in core):
            return False
    return True

def _ledger_tok_stop(tok: str) -> bool:
    """True if a whitespace-delimited token TERMINATES a ledger name run: contains a digit (a reference id),
    a '/', is a ledger stopword, or is not name-shaped (letters + internal apostrophe/hyphen/period)."""
    if any(c.isdigit() for c in tok) or '/' in tok:
        return True
    low = tok.strip(".,;:()'\"’-").casefold()
    if not low or low in _LEDGER_STOPWORDS:
        return True
    core = re.sub(r"['’.\-]", '', tok)
    return not core or not core.isalpha()

def _ledger_name_run(t: str, start: int, stop: int):
    """Maximal counterparty-name run at/after `start` (just past an e-transfer cue), bounded by `stop` (line
    end). Relaxed vs _name_run_after: lowercase alpha tokens are accepted; whitespace-tokenized so a whole
    'CA7QzWvk' reference token is rejected by the digit test. Stops at a digit/'/'/stopword token, a >=2-space
    column gap, or the cap (5 tokens / 60 chars). Leading honorifics (MME/MR/...) are skipped, not included.
    A '\\r' ends the line like '\\n' does (CRLF ledgers: 'DUPUIS\\r' must not fail the alpha check)."""
    cr = t.find('\r', start, stop)
    if cr != -1:
        stop = cr
    gap = _LEDGER_COLGAP_RE.search(t, start, stop)
    if gap:
        stop = min(stop, gap.start())
    chosen, i = [], start
    while i < stop and len(chosen) < 5:
        while i < stop and t[i] in ' \t':
            i += 1
        if i >= stop:
            break
        j = i
        while j < stop and t[j] not in ' \t':
            j += 1
        if not chosen and t[i:j].strip(".,;:()'\"’-").casefold() in _LEDGER_HONORIFICS:
            i = j
            continue   # skip a leading honorific; the span starts at the name itself
        if t[i:j] == '-' and chosen:
            i = j
            continue   # lone hyphen CONNECTOR inside a run ("Traduction - Lise Charbonnel" DBA form)
        if _LEDGER_INITIAL_NARROW_RE.fullmatch(t[i:j]) and (
                chosen or '.' in t[i:j] or t[j:stop].lstrip(' \t')[:1].isupper()):
            # an uppercase initial is a name token -- mid-run always ("DEREK A MARTEL"), leading when dotted
            # ("A. MARTEL") or followed by a capitalized token ("A MARTEL"). It must win over the 'a'/'an'
            # article stopwords added for the prose colon-cue; "e-transfer to: A friend" still stops.
            chosen.append((i, j)); i = j
            continue
        if _ledger_tok_stop(t[i:j]):
            break
        chosen.append((i, j)); i = j
        if chosen[-1][1] - chosen[0][0] >= 60:
            break
    while chosen and t[chosen[-1][0]:chosen[-1][1]].casefold() in _NAME_PARTICLES:
        chosen.pop()
    while chosen and t[chosen[0][0]:chosen[0][1]].casefold() in _NAME_PARTICLES:
        chosen.pop(0)
    return (chosen[0][0], chosen[-1][1]) if chosen else None

def _ledger_slash_name(t: str, start: int, stop: int):
    """Desjardins slash field: the name is everything from `start` up to the next '/', a >=2-space column gap,
    or line end (trimmed; '\\r' ends the line like '\\n'). Validated by _name_shaped_relaxed by the caller
    (rejects digits)."""
    cr = t.find('\r', start, stop)
    if cr != -1:
        stop = cr
    slash = t.find('/', start, stop)
    if slash != -1:
        stop = slash
    gap = _LEDGER_COLGAP_RE.search(t, start, stop)
    if gap:
        stop = gap.start()
    ls = start
    while ls < stop and t[ls] in ' \t':
        ls += 1
    rs = stop
    while rs > ls and t[rs - 1] in ' \t':
        rs -= 1
    return (ls, rs) if rs > ls else None

def cue_name_spans(text: str):
    """Deterministic person spans for the cue-bearing forms the NER wobbles on: the name immediately
    before an <email> anchor (RFC5322 mailbox / git-author), the name right after a From:/To:/Author:/owner:
    header cue, and the bank-ledger counterparty forms (e-transfer / Interac / Desjardins slash fields).
    Offsets index the _normseps copy = the original text."""
    spans, t, seen = [], _normseps(text), set()
    def emit(rng, shaped=_name_shaped, rule='floor:cue_name'):
        if rng and rng not in seen and shaped(t[rng[0]:rng[1]]):
            seen.add(rng)
            spans.append({'start': rng[0], 'end': rng[1], 'label': 'person', 'tier': 0,
                          'conf': 0.95, 'rule': rule})
    for m in _EMAIL_ANCHOR_RE.finditer(t):           # "<name> <email>"
        emit(_name_run_before(t, m.start()))
    for m in _HDR_CUE_RE.finditer(t):                # "From:/Author:/owner: <name>"
        le = t.find('\n', m.end())
        emit(_name_run_after(t, m.end(), len(t) if le == -1 else le))
    for m in _ETRANSFER_CUE_RE.finditer(t):          # "VIR INTERAC RECU <name>", "E-TRANSFER <ref> <name>", ...
        le = t.find('\n', m.end())
        emit(_ledger_name_run(t, m.end(), len(t) if le == -1 else le), _name_shaped_relaxed)
    for m in _ETRANSFER_SLASH_RE.finditer(t):        # Desjardins "Interac e-Transfer from /<name> /"
        le = t.find('\n', m.end())
        emit(_ledger_slash_name(t, m.end(), len(t) if le == -1 else le), _name_shaped_relaxed)
    return spans


# ---------------- Tier 0.5: cue-gated ID backstop (2026-07-07, plan 048 code-side round) ----------------
# The v12 miss inventory (full-stack over the v11r5 heldout) showed the neural misses on digit/ID
# categories cluster behind a SMALL set of document cues: "code d'acces NETFILE : 6XKDHZJ6",
# "numero de police : ...", "telephone 450.555.0194", "ne(e) le 11 janvier 1979". A cue plus an
# ID/phone/date-shaped value right after it is deterministic provenance, so it earns a floor-style
# emission (same pattern as cue_name_spans). PRECISION RULES (floor-diet): every emission is
# cue-GATED (never a bare shape), the value shape is per-label strict, and BN program accounts
# (9-digit Luhn + RT/RP/... suffix) stay suppressed -- they are public GST/QST registrations.
# NEQ / TVQ registration numbers are deliberately NOT backstopped: public registry identifiers
# (same adjudication as the BN, RESULT-realworld-expenses Finding A).
_CUE_SEP = r"[ \t]*[:#=|]?[ \t]*"   # what may sit between the cue and the value (same line)
_MONTHS = (r"janv(?:ier)?|f[ée]vr(?:ier)?|mars|avril|mai|juin|juil(?:let)?|ao[ûu]t|sept(?:embre)?|"
           r"oct(?:obre)?|nov(?:embre)?|d[ée]c(?:embre)?|january|february|march|april|may|june|july|"
           r"august|september|october|november|december")
_DATE_SHAPE = (r"(?:\d{4}-\d{2}-\d{2}|\d{1,2}[/.]\d{1,2}[/.]\d{2,4}|"
               r"(?:%(m)s)\.?\s+\d{1,2},?\s+\d{4}|\d{1,2}(?:er)?\s+(?:%(m)s)\.?\s+\d{4})" % {"m": _MONTHS})
_CUE_RULES = [
    # (label, cue regex, value-shape regex, min_digits). Cues match case-insensitively at a word
    # start; the value must follow on the same line within _CUE_SEP. min_digits is a code-side
    # post-filter so a letters-only word after a cue ("policy number is required") can never match.
    ('sensitive_account_id',
     r"(?:code\s+d[' ]acc[eè]s\s+netfile|netfile\s+access\s+code)",
     r"[A-Z0-9]{6,12}", 1),
    ('sensitive_account_id',
     r"(?:num[ée]ro\s+de\s+police|no\.?\s+de\s+police|policy\s+(?:number|no\.?)|"
     r"num[ée]ro\s+du\s+document(?:\s+d[ée]livr[ée])?|issued\s+document\s+number|"
     r"num[ée]ro\s+de\s+dossier|no\.?\s+de\s+dossier|(?:credit\s+)?file\s+(?:number|no\.?))",
     r"[A-Z0-9][\dA-Z -]{3,20}[\dA-Z]", 2),
    ('account_number',
     r"(?:num[ée]ro\s+de\s+compte|no\.?\s+de\s+compte|compte(?:\s+ch[eè]que)?|account\s+(?:number|no\.?)|acct\.?|folio)",
     r"\d(?:[ -]?\d){4,16}", 5),
    ('phone_number',
     r"(?:t[ée]l[ée]phone|t[ée]l\.?|telephone|cellular|cellulaire|mobile|"
     r"num[ée]ro\s+de\s+service|(?:subscriber\s+)?service\s+number)[,]?",
     r"(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]\d{4}", 10),
    ('date_of_birth',
     r"(?:n[ée]\(?e?\)?\s+le|born(?:\s+on)?|date\s+de\s+naissance|date\s+of\s+birth|dob|naissance)",
     _DATE_SHAPE, 4),
]
_CUE_DIGIT_RES = [
    (label, re.compile(r"(?<![\w])(?:%s)%s(%s)" % (cue, _CUE_SEP, shape), re.I), min_digits)
    for label, cue, shape, min_digits in _CUE_RULES
]


def cue_digit_spans(text: str):
    """Deterministic ID/phone/DOB spans for cue-bearing forms the NER wobbles on (miss-inventory-driven).
    Same emission contract as cue_name_spans: tier 0, rule 'floor:cue_digit'."""
    spans, seen = [], set()
    for label, rx, min_digits in _CUE_DIGIT_RES:
        for m in rx.finditer(text):
            s, e = m.start(1), m.end(1)
            val = m.group(1)
            if '\n' in text[m.start():s]:
                continue   # cue and value must share a line
            if sum(c.isdigit() for c in val) < min_digits:
                continue   # letters-only (or too few digits) after a cue is prose, not an ID
            if label == 'account_number':
                digits = re.sub(r'\D', '', val)
                # BN program account (public GST/QST registration): 9 digits + RT/RP/... suffix stays out,
                # unless a SIN cue overrides upstream (validated_floor owns that interaction).
                if len(digits) == 9 and _BN_PROGRAM_SUFFIX_RE.match(text[e:e + 9] or ''):
                    continue
            key = (s, e)
            if key in seen:
                continue
            seen.add(key)
            spans.append({'start': s, 'end': e, 'label': label, 'tier': 0,
                          'conf': 0.92, 'rule': 'floor:cue_digit'})
    return spans


# ---------------- Tier 1: NPU INT8 ONNX ----------------
class NPUTier:
    # max_len=512 (not 256): the prod gate chunks at 600 chars, and a token-DENSE 600-char chunk (secrets,
    # hashes, long IDs) reaches ~300 tokens; max_len 256 truncated the chunk tail and dropped PII there
    # (measured: password recall 0.85 -> 0.99 when 256 -> 512, 46% of dense chunks exceeded 256 tokens).
    def __init__(self, model_dir, max_len=512):
        import onnxruntime as ort
        from transformers import AutoTokenizer
        import json as _json
        from pathlib import Path
        self.tok = AutoTokenizer.from_pretrained(model_dir)
        cfg = _json.loads((Path(model_dir) / 'config.json').read_text())
        self.id2label = {int(k): v for k, v in cfg['id2label'].items()}
        self.sess = ort.InferenceSession(str(Path(model_dir) / 'model.int8.onnx'), providers=['CPUExecutionProvider'])
        self.max_len = max_len
    def spans(self, text, min_score=0.5):
        import numpy as np
        enc = self.tok(text, return_offsets_mapping=True, truncation=True, max_length=self.max_len, return_tensors='np')
        off = enc['offset_mapping'][0]
        logits = self.sess.run(None, {'input_ids': enc['input_ids'].astype(np.int64),
                                      'attention_mask': enc['attention_mask'].astype(np.int64)})[0][0]
        x = logits - logits.max(-1, keepdims=True); p = np.exp(x); p = p / p.sum(-1, keepdims=True)
        ids = p.argmax(-1); out = []; cur = None
        for i, (a, b) in enumerate(off):
            if a == b: continue
            tag = self.id2label[int(ids[i])]; sc = float(p[i, ids[i]])
            if tag == 'O':
                if cur: out.append(cur); cur = None
                continue
            pref, lab = tag.split('-', 1)
            if pref == 'B' or cur is None or cur['label'] != lab:
                if cur: out.append(cur)
                cur = {'start': int(a), 'end': int(b), 'label': lab, 'tier': 1, 'conf': sc, 'rule': 'npu'}
            else:
                cur['end'] = int(b); cur['conf'] = min(cur['conf'], sc)
        if cur: out.append(cur)
        return [s for s in out if s['conf'] >= min_score]

# ---------------- Tier 2: GPU fp16 (the large always-on tier) ----------------
class GPUTier:
    """fp16 safetensors token-classifier on CUDA = the strongest tier. Same .spans() interface as NPUTier
    (duck-typed into PrivacyGate.npu). Loads the model in its deployment form (fp16 on GPU), not INT8."""
    def __init__(self, model_dir, device='cuda', max_len=512, trust_remote_code=False):  # 512: see NPUTier note
        import os as _os
        import torch
        from transformers import AutoTokenizer, AutoModelForTokenClassification
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_dir, trust_remote_code=trust_remote_code)
        # GPU_GATE_DTYPE=bfloat16 for bf16-trained bases (v12 openai/privacy-filter MoE: fp16
        # inference risks activation overflow in expert/router paths). Default float16 unchanged
        # for the xlm-r family.
        dtype = getattr(torch, _os.environ.get('GPU_GATE_DTYPE', 'float16'))
        self.model = AutoModelForTokenClassification.from_pretrained(
            model_dir, torch_dtype=dtype, trust_remote_code=trust_remote_code).to(device).eval()
        self.id2label = {int(k): v for k, v in self.model.config.id2label.items()}
        self.device = device; self.max_len = max_len
    def spans(self, text, min_score=0.5):
        enc = self.tok(text, return_offsets_mapping=True, truncation=True, max_length=self.max_len, return_tensors='pt')
        off = enc.pop('offset_mapping')[0].tolist()
        with self.torch.no_grad():
            logits = self.model(input_ids=enc['input_ids'].to(self.device),
                                attention_mask=enc['attention_mask'].to(self.device)).logits[0]
            p = self.torch.softmax(logits.float(), -1).cpu().numpy()
        ids = p.argmax(-1); out = []; cur = None
        for i, (a, b) in enumerate(off):
            if a == b: continue
            tag = self.id2label[int(ids[i])]; sc = float(p[i, ids[i]])
            if tag == 'O':
                if cur: out.append(cur); cur = None
                continue
            pref, lab = tag.split('-', 1)
            if pref == 'B' or cur is None or cur['label'] != lab:
                if cur: out.append(cur)
                cur = {'start': int(a), 'end': int(b), 'label': lab, 'tier': 2, 'conf': sc, 'rule': 'gpu'}
            else:
                cur['end'] = int(b); cur['conf'] = min(cur['conf'], sc)
        if cur: out.append(cur)
        return [s for s in out if s['conf'] >= min_score]

# ---------------- merge + redact ----------------
# The deterministic HARD FLOOR: credential + money/government/identity labels. Single source of truth for
# merge stickiness below (and mirrored by the egress FLOOR_NEVER_EXEMPT guards). A floor label must never be
# downgraded to a soft label by an overlapping higher-confidence neural guess.
FLOOR_LABELS = frozenset({
    'secret', 'password', 'api_key', 'access_token',                  # credentials
    'payment_card', 'card_cvv', 'card_expiry',                        # cards
    'sensitive_account_id', 'account_number', 'bank_account', 'iban', 'routing_number', # bank / account
    'government_id', 'tax_id', 'date_of_birth',                       # government / identity
})


def merge_spans(spans, sticky=FLOOR_LABELS):
    # CONNECTED-COMPONENT UNION. A privacy gate must never leave a PII fragment exposed between two
    # overlapping detections. Greedy drop-the-loser does exactly that: model emits "21" inside a date, or a
    # spurious "password" on a UUID partially overlaps "21 mai 2026" -> whichever is dropped, half the date
    # leaks. So instead: any cluster of overlapping spans is redacted as ONE span covering their union. The
    # cluster's PRIMARY label is the highest-confidence (then longest) member's (used for the placeholder),
    # but ALL distinct member labels are recorded in 'labels' so a category filter / audit is not lied to.
    # The union text is what gets masked and stored for rehydration. Over-redaction is the safe error.
    #
    # FLOOR STICKINESS: a deterministic hard-floor label (credentials, cards, bank/IBAN, government/tax IDs,
    # DOB) must NEVER be downgraded to a soft neural label just because an overlapping guess scored higher --
    # the egress floor guards key off the post-merge primary LABEL, so a relabeled floor value would lose its
    # protection and leak. If any cluster member carries a floor label, the primary stays the highest-conf
    # FLOOR member's (the soft label is still recorded in 'labels'). Strictly safer: floor only ever wins.
    if not spans:
        return []
    spans = sorted(spans, key=lambda s: (s['start'], -(s['end'] - s['start'])))
    out = []
    for s in spans:
        floor = s['label'] in sticky
        if out and s['start'] < out[-1]['end']:  # overlaps the current cluster
            cur = out[-1]
            cur['members'] = cur.get('members', 1) + 1
            cur['_labels'].add(s['label'])
            cand = (s['conf'], s['end'] - s['start'])
            if cand > (cur['_bc'], cur['_bl']):  # better label-bearer -> its provenance wins the cluster
                cur['label'] = s['label']; cur['tier'] = s['tier']; cur['_bc'], cur['_bl'] = cand
                cur['rule'] = s.get('rule'); cur['validator'] = s.get('validator')
                cur['cue'] = s.get('cue'); cur['subtype'] = s.get('subtype')
            if floor and s['conf'] > cur.get('_fc', -1.0):  # remember the strongest floor member
                cur['_floor'] = s; cur['_fc'] = s['conf']
            cur['end'] = max(cur['end'], s['end'])
            cur['conf'] = max(cur['conf'], s['conf'])
        else:
            nc = {**s, '_bc': s['conf'], '_bl': s['end'] - s['start'], 'members': 1,
                  '_labels': {s['label']}}
            if floor:
                nc['_floor'] = s; nc['_fc'] = s['conf']
            out.append(nc)
    for m in out:
        fl = m.pop('_floor', None); m.pop('_fc', None)
        if fl is not None and m['label'] not in sticky:
            # a floor value got out-scored by an overlapping soft guess -> restore the floor member as the
            # cluster's primary so the egress floor guards see a floor label (the soft label stays in 'labels').
            m['label'] = fl['label']; m['tier'] = fl['tier']
            m['rule'] = fl.get('rule'); m['validator'] = fl.get('validator')
            m['cue'] = fl.get('cue'); m['subtype'] = fl.get('subtype')
        m.pop('_bc', None); m.pop('_bl', None)
        labset = m.pop('_labels', None)
        if labset and len(labset) > 1:
            # union spanned >1 category: keep the elected primary in 'label' for the placeholder, but record
            # ALL categories so a downstream category filter / Law 25 audit sees the true set, not just one.
            m['labels'] = sorted(labset)
        for k in ('validator', 'cue', 'subtype'):
            if m.get(k) is None:
                m.pop(k, None)   # drop null provenance keys for a clean record
    return out

def post_merge_address(spans, text):
    # Stitch adjacent address+address fragments separated only by a short separator gap. The composite-address
    # model sometimes emits one address as 2 fragments across a comma/newline; this is deterministic recall
    # insurance (gap <=12 chars, separator-only). Phase 2.2: a following postal_code is NO LONGER absorbed
    # into the address; it stays its OWN redaction so the postal_code category survives (it was being relabeled
    # away). ~0 latency.
    out = []
    for s in sorted(spans, key=lambda s: s['start']):
        if out and out[-1]['label'] == 'address' and s['label'] == 'address':
            gap = text[out[-1]['end']:s['start']]
            if len(gap) <= 12 and re.fullmatch(r"[\s,\-()A-Za-z]*", gap or '') is not None:
                out[-1]['end'] = s['end']; out[-1]['conf'] = min(out[-1]['conf'], s['conf']); continue
        out.append(s)
    return out

def explain(spans):
    """Privacy-safe per-span provenance (the Presidio AnalysisExplanation / return_decision_process analogue):
    which recognizer fired, its tier + confidence, the validator result and the context cue that promoted it,
    and how many raw spans merged into this redaction. NEVER includes the redacted value -- offsets + metadata
    only, so it is safe to log / surface in a review UI / Law 25 audit trail."""
    out = []
    for s in spans:
        rec = {'label': s['label'], 'tier': s.get('tier'), 'rule': s.get('rule'),
               'conf': round(float(s.get('conf', 0)), 3), 'start': s['start'], 'end': s['end'],
               'members': s.get('members', 1)}
        for k in ('validator', 'cue', 'subtype'):
            if s.get(k):
                rec[k] = s[k]
        out.append(rec)
    return out

# ---------------- detect-time repeat propagation (workbench mid-doc name misses) ----------------
# 2026-07-05: the neural tier scans chunks independently, so "Client: Jean Tremblay" detects where the cue
# is and a bare "TREMBLAY" in a table row 40 chunks later has nothing to anchor it. Once a value IS detected
# in a document there is no reason to ever miss its literal repeats: every other occurrence (case-insensitive,
# word-boundary-guarded) becomes a span with the same label, rule='repeat'. Only name-ish neural labels
# propagate (structured/floor shapes are already deterministic at every occurrence) and a low-confidence
# source does not propagate, so one bad guess cannot paint a common word across the whole document.
# Called by the gate services' detect_chunked over the FULL request text (pre-merge; merge_spans unions
# duplicates). Mirrored in redaction-core propagateRepeats (the workbench client twin).
_PROPAGATE_LABELS = frozenset({'person', 'organization', 'username', 'address'})
_MIN_PROPAGATE_CONF = 0.75


# ---- Class B: person-span GROWTH (2026-07-08, plan 049) ----
# The neural tier frequently catches PART of a counterparty name and the redaction bar clips mid-name:
# "OLIV|IER DE FERLANDAIS", "MAELLE DORVALIN|NE", "|MY VALCOURTIER" (first token barred). Before repeat
# propagation collects its sources, GROW every high-conf person span to the full name so (a) the whole name
# is masked and (b) the completed tokens feed propagation (that is what catches a partial name doc-wide after
# one hit). Growth is deterministic edge-completion + rightward name-token absorption -- capitalized/initial
# tokens or particles only, never across a >=2-space column gap, a stopword, or a digit.
_GROW_MIN_CONF = 0.75

def _grow_complete_token_right(text: str, end: int) -> int:
    n = len(text)
    while end < n and (text[end].isalpha() or (text[end] in "'’.-" and end + 1 < n and text[end + 1].isalpha())):
        end += 1
    return end

def _grow_complete_token_left(text: str, start: int) -> int:
    while start > 0 and (text[start - 1].isalpha() or
                         (text[start - 1] in "'’.-" and start - 2 >= 0 and text[start - 2].isalpha())):
        start -= 1
    return start

def _grow_absorbable(tok: str) -> bool:
    """True if `tok` is a name token growth may absorb: a capitalized name word (no trailing '.'), a
    single/dotted uppercase initial (S, M.C.), or a lowercase particle. Never a stopword, a role/distribution
    word ('Contact'/'Support'/...), or a digit-bearer -- those bound a grown name on either side."""
    if not tok or any(c.isdigit() for c in tok) or '/' in tok:
        return False
    if _LEDGER_INITIAL_NARROW_RE.fullmatch(tok):    # A, A., M.C. -- before stopwords: 'A' is an initial, not the article
        return True
    low = tok.strip(".,;:()'\"’-").casefold()
    if not low or low in _LEDGER_STOPWORDS or low in _NAME_ROLE_DENY or low in _GROW_STATUS_DENY:
        return False
    if low in _NAME_PARTICLES:
        return True
    if _LEDGER_INITIALS_RE.fullmatch(tok):          # S, SJ, M.C. (broad -- safe after the stopword gate)
        return True
    if tok[0].isupper() and '.' not in tok:
        core = re.sub(r"['’\-]", '', tok)
        return bool(core) and core.isalpha()
    return False

def _grow_person_span(text, s):
    """Return a grown copy of person span `s`, or `s` unchanged if growth does not improve/validate.
    Edge-completion runs both directions (finish a partially-covered token); token absorption runs both
    directions across EXACTLY ONE space (a capitalized/initial/particle token; never a >=2-space column gap)."""
    n = len(text)
    o_start, o_end = s['start'], s['end']
    start = _grow_complete_token_left(text, o_start)
    end = _grow_complete_token_right(text, o_end)
    ntok = len(text[start:end].split())
    while ntok < 5 and end < n and text[end] == ' ' and end + 1 < n and text[end + 1] not in ' \t\n\r':
        j = end + 1
        k = j
        while k < n and text[k] not in ' \t\n\r':
            k += 1
        if not _grow_absorbable(text[j:k]) or (k - start) > 60:
            break
        end = k; ntok += 1
    while ntok < 5 and start > 0 and text[start - 1] == ' ' and start - 2 >= 0 and text[start - 2] not in ' \t\n\r':
        k = start - 1
        j = k
        while j > 0 and text[j - 1] not in ' \t\n\r':
            j -= 1
        if not _grow_absorbable(text[j:k]) or (end - j) > 60:
            break
        start = j; ntok += 1
    if (start, end) == (o_start, o_end):
        return s
    grown = text[start:end]
    orig = text[o_start:o_end]
    shaped = _name_shaped_relaxed if not any(c.isupper() for c in orig) else _name_shaped
    if not shaped(grown):
        return s
    return {**s, 'start': start, 'end': end, 'rule': (s.get('rule') or 'gpu') + '+grow'}

def _grow_person_spans(text, spans):
    out = []
    for s in spans:
        if s.get('label') == 'person' and float(s.get('conf', 0.0)) >= _GROW_MIN_CONF:
            out.append(_grow_person_span(text, s))
        else:
            out.append(s)
    return out


def propagate_repeats(text, spans):
    spans = _grow_person_spans(text, spans)   # Class B: complete partially-caught names BEFORE collecting sources
    sources = {}
    for s in spans:
        if s.get('label') not in _PROPAGATE_LABELS or float(s.get('conf', 0.0)) < _MIN_PROPAGATE_CONF:
            continue
        value = text[s['start']:s['end']].strip()
        if len(value) < _MIN_SWEEP_LEN:
            continue
        sources.setdefault(value.casefold(), (value, s))
        # A person span's individual NAME TOKENS propagate too: the model emits "Jean Tremblay" once and
        # the repeats downstream are bare "TREMBLAY" / "tremblay" -- not the full-value literal. len>=4
        # keeps particles (De, La) out; over-redaction stays the safe error on a reviewed document.
        if s['label'] == 'person':
            for tok in re.split(r'\W+', value):
                if len(tok) >= _MIN_SWEEP_LEN and tok.casefold() not in _GROW_STATUS_DENY:
                    sources.setdefault(tok.casefold(), (tok, s))
    if not sources:
        return spans
    out = list(spans)
    for value, src in sources.values():
        pat = re.compile(r'(?<!\w)' + re.escape(value) + r'(?!\w)', re.IGNORECASE)
        for m in pat.finditer(text):
            if src['start'] <= m.start() < src['end']:
                continue   # inside the source span (already covered; growth can leave a token mid-span)
            out.append({'start': m.start(), 'end': m.end(), 'label': src['label'],
                        'tier': src.get('tier', 2), 'conf': src.get('conf', 0.75), 'rule': 'repeat'})
    return out


# ---------------- repeated-value sweep (Finding C backstop) ----------------
# A <LABEL_NNN> placeholder token (the canonical angle-bracket form, matching entity_map.py and the
# redaction-core twin). The positional pass inserts these; the sweep must PRESERVE them verbatim and never
# rewrite inside one (else a value equal to a label-like token, e.g. an org literally named "EMAIL", would
# corrupt "<EMAIL_001>" -- Codex review 2026-06-17). Counter is 3+ digits to also match larger sessions.
# Accepted low-risk edge (Codex MEDIUM-1, mirrors the TS twin): a RAW detected value shaped exactly like
# <LABEL_NNN> is skipped by this split and not swept -- over-masking is the safe error and real PII almost
# never takes this exact shape, so we do not add handling.
_PLACEHOLDER_TOKEN_RE = re.compile(r'<[A-Z][A-Z0-9_]*_\d{3,}>')
# Minimum value length to sweep -- below this a value is too generic to mask globally without spurious
# matches (and tiny tokens are rarely uniquely-identifying on their own). Mirrors the egress proxy len>=4.
_MIN_SWEEP_LEN = 4
_CASE_SENSITIVE_LABELS = {'password', 'secret', 'username', 'person', 'name', 'access_token', 'api_key', 'file_path'}


def _case_sensitive_label(label):
    return str(label).casefold() in _CASE_SENSITIVE_LABELS


def _dedup_key(label, value):
    norm = value if _case_sensitive_label(label) else value.casefold()
    return (str(label).casefold(), norm)


def _build_known_re(values, ignore_case=True):
    """Regex over already-known session entity VALUES (len>=4, word-boundary-guarded, longest-first).
    The known-entity backstop (Finding C): positional redaction masks only DETECTED span positions, so a value
    that repeats across a long/multi-page document (footers, repeated headers, line items) leaks at the
    occurrences the detector skipped. Pure deterministic, no model. Longest-first alternation makes the engine
    prefer the longer value at any position (so a 7-digit value can not be matched as a prefix of an 8-digit one).
    NOTE: Python stdlib re has no \\p{M}; we use \\w boundaries (letter/digit/underscore, ASCII-by-default), so a
    DECOMPOSED combining accent immediately adjacent to a value is not part of the guard. The egress proxy twin
    has the same limitation; the JS twin uses \\p{M}. Acceptable: over-masking is the safe error here anyway.
    By default this is compiled IGNORECASE (Codex HIGH-1): ordinary known values must be masked regardless of
    case, else "John" detected once leaks as "JOHN"/"john" elsewhere. Case-significant labels use an exact-case
    companion regex so case-significant values that differ only by case stay lossless."""
    vals = [v for v in values if v and len(v) >= _MIN_SWEEP_LEN]
    if not vals:
        return None
    vals.sort(key=len, reverse=True)
    parts = []
    for v in vals:
        esc = re.escape(v)
        if v[0].isalnum():
            esc = r'(?<!\w)' + esc   # do not match a value that starts alnum inside a longer word/number
        if v[-1].isalnum():
            esc = esc + r'(?!\w)'    # ...nor one that ends alnum
        parts.append(esc)
    return re.compile('|'.join(parts), re.IGNORECASE if ignore_case else 0)

def _sweep_known(text, known_re, value_to_placeholder, protected_placeholders=None, case_sensitive=False):
    """Replace every literal occurrence of a known value with its EXISTING placeholder (never mint a new one),
    running ONLY on the literal segments BETWEEN already-inserted placeholders so it can never rewrite a
    placeholder the positional pass produced. Returns (text, n_swept). Over-masking an already-detected value
    is the safe error; rehydrate() restores every occurrence regardless of which pass inserted it."""
    if known_re is None:
        return text, 0
    # Ordinary PII resolves case-insensitively. Case-significant labels resolve by exact text so values that
    # differ only by case never collapse to one placeholder during the repeated-value sweep.
    if case_sensitive:
        lookup = dict(value_to_placeholder)
        lookup_key = lambda s: s
    else:
        lookup = {}
        for v, ph in value_to_placeholder.items():
            lookup.setdefault(v.casefold(), ph)
        lookup_key = lambda s: s.casefold()
    n = 0
    def repl(m):
        nonlocal n
        ph = lookup.get(lookup_key(m.group()))
        if ph is None:
            return m.group()
        n += 1
        return ph
    # Split into literal gaps (swept) and placeholder tokens (preserved verbatim). A capture-free split drops
    # the delimiters, so parts.length == tokens.length + 1; reassemble interleaved so a value equal to a
    # placeholder token can never corrupt the token itself.
    # Protect ONLY the placeholders THIS redaction actually inserted (value_to_placeholder.values()), NOT the generic
    # placeholder SHAPE. Splitting on the generic _PLACEHOLDER_TOKEN_RE treats placeholder-shaped text that was in the
    # ORIGINAL user content (a literal "<EMAIL_001>" the user wrote, or a known value that itself contains one) as an
    # inserted token and SKIPS sweeping it -> a repeated known value sitting in/next to such text leaks (Codex FINDING
    # 2, 2026-06-17). The inserted placeholders are known exactly, so split on THEM and sweep every other segment.
    inserted = sorted(set(protected_placeholders or value_to_placeholder.values()), key=len, reverse=True)
    if not inserted:
        return known_re.sub(repl, text), n
    token_re = re.compile('|'.join(re.escape(ph) for ph in inserted))
    parts = token_re.split(text)
    tokens = token_re.findall(text)
    out = [known_re.sub(repl, parts[0])]
    for i, tok in enumerate(tokens):
        out.append(tok)
        out.append(known_re.sub(repl, parts[i + 1]))
    return ''.join(out), n

class PrivacyGate:
    def __init__(self, npu_model_dir=None):
        self.npu = NPUTier(npu_model_dir) if npu_model_dir else None
    def detect(self, text, min_score=0.5):
        # Phase 2.2: the casenorm second pass (re-run on a Title-cased copy to recover ALL-CAPS) was removed.
        # The model is trained on ALL-CAPS in Phase 3, so it owns case-robustness; the double pass only added
        # latency and merge noise.
        spans = validated_floor(text) + cue_name_spans(text) + cue_digit_spans(text)
        if self.npu:
            spans += self.npu.spans(text, min_score)
        return post_merge_address(merge_spans(spans), text)
    def redact(self, text, min_score=0.5, spans=None):
        # spans may be supplied pre-computed (e.g. the gate service chunks long text via detect_chunked,
        # which self.detect does NOT do); when None we detect here. Passing spans keeps the placeholder-dedup +
        # Finding-C sweep below as the SINGLE source of redaction logic for every caller (service /redact too).
        if spans is None:
            spans = self.detect(text, min_score)
        # The positional pass below assumes start-ordered, NON-OVERLAPPING spans. detect()/detect_chunked already
        # run merge_spans, but an external caller (the new spans= API) may pass raw, out-of-order, or OVERLAPPING
        # spans -- and an overlapping pair makes `last` jump backward, re-appending covered text -> a leak (Codex
        # FINDING 1). merge_spans is the contract: it sorts AND unions overlaps into one span, so coverage is
        # monotonic and nothing covered survives. Idempotent on already-merged input (only label/rule -- used by the
        # /redact stats -- matter downstream; the recomputed members/labels are not consumed on the redact path).
        spans = merge_spans(spans)
        mapping = {}; counters = defaultdict(int); out = []; last = 0
        # Dedup placeholders by label + value. Ordinary non-name PII keeps casefold dedup so case-variant
        # emails share a stable placeholder. Case-significant labels keep exact-case values distinct so
        # rehydrate is lossless for "AbC123" vs "abc123" and "Nadia" vs "nadia".
        seen = {}
        label_by_ph = {}
        for s in spans:
            value = text[s['start']:s['end']]
            ph = seen.get(_dedup_key(s['label'], value))
            if ph is None:
                counters[s['label']] += 1
                # Canonical angle-bracket placeholder (entity_map.py:116 / gate_service.py:94 / redaction-core):
                # UPPERCASE label, underscores preserved, 3-digit zero-padded counter. round-trips via rehydrate().
                ph = f"<{s['label'].upper()}_{counters[s['label']]:03d}>"
                seen[_dedup_key(s['label'], value)] = ph
                mapping[ph] = value
                label_by_ph[ph] = s['label']
            out.append(text[last:s['start']]); out.append(ph); last = s['end']
        out.append(text[last:])
        redacted = ''.join(out)
        # Finding C backstop: after the positional pass, sweep the redacted text for any repeated occurrence of
        # an already-known value the detector missed at OTHER positions, masking it with its EXISTING placeholder.
        # Ordinary non-name PII sweeps case-insensitively. Case-significant labels sweep exact-case only to
        # preserve lossless rehydration when two distinct known values differ only by case.
        exact_v2p = {v: ph for ph, v in mapping.items() if _case_sensitive_label(label_by_ph.get(ph, ''))}
        ci_v2p = {v: ph for ph, v in mapping.items() if not _case_sensitive_label(label_by_ph.get(ph, ''))}
        protected = set(mapping.keys())
        redacted, _ = _sweep_known(redacted, _build_known_re(exact_v2p.keys(), ignore_case=False),
                                   exact_v2p, protected_placeholders=protected, case_sensitive=True)
        redacted, _ = _sweep_known(redacted, _build_known_re(ci_v2p.keys(), ignore_case=True),
                                   ci_v2p, protected_placeholders=protected)
        return redacted, mapping, spans
    @staticmethod
    def rehydrate(text, mapping):
        # Single-pass substitution (Codex MEDIUM-2): a naive per-key str.replace in map-iteration order can
        # recursively corrupt a round-trip if a restored value itself contains another placeholder string.
        # One alternation over the placeholder tokens (longest-first, so no token is a prefix of another)
        # replaces each match exactly once; restored text is never re-scanned.
        if not mapping:
            return text
        pat = re.compile('|'.join(re.escape(ph) for ph in sorted(mapping, key=len, reverse=True)))
        return pat.sub(lambda m: mapping[m.group()], text)

def _norm(s):
    s = re.sub(r'\s+', ' ', s.strip().lower())
    return re.sub(r'\s+([,.;:!?%)])', r'\1', s)

def gate_eval(gate, path, min_score=0.5):
    """Recall of full-gate (t0+t1) vs tier-1-only, label-agnostic substring match. Recall = leak prevention."""
    rows = [json.loads(l) for l in open(path, encoding='utf-8') if l.strip()]
    res = {}
    for mode in ('tier1_only', 'full_gate'):
        tp = fn = clean_fp = 0
        for r in rows:
            text = r['input']
            gold = [_norm(v) for vals in r['output']['entities'].values() for v in vals if v]
            if mode == 'full_gate':
                spans = gate.detect(text, min_score)
            else:
                spans = gate.npu.spans(text, min_score)
            pred = [_norm(text[s['start']:s['end']]) for s in spans]
            for g in gold:
                if any(g == p or g in p or p in g for p in pred if p): tp += 1
                else: fn += 1
            if not gold: clean_fp += len(spans)
        rec = round(tp / (tp + fn), 4) if tp + fn else 0.0
        res[mode] = {'recall': rec, 'tp': tp, 'fn': fn, 'clean_fp': clean_fp}
    return res

def show(gate, s, min_score=0.5):
    red, mp, spans = gate.redact(s, min_score)
    print('INPUT_CHARS:', len(s))
    print('OUT :', red)
    print('MAP_KEYS:', sorted(mp))
    print('TIERS:', [(sp['label'], 't%d' % sp['tier']) for sp in spans])
    print('ROUNDTRIP OK:', PrivacyGate.rehydrate(red, mp) == s)
    print()

if __name__ == '__main__':
    import argparse, sys
    ap = argparse.ArgumentParser()
    ap.add_argument('--model', default='models/ossredact-pii-quebec')
    ap.add_argument('--eval', default='')
    ap.add_argument('--text', default='', help='redact this string and exit')
    ap.add_argument('--repl', action='store_true', help='load model once, then redact each line of stdin')
    ap.add_argument('--min-score', type=float, default=0.5)
    args = ap.parse_args()
    gate = PrivacyGate(args.model)
    if args.eval:
        print(json.dumps(gate_eval(gate, args.eval), indent=2)); raise SystemExit
    if args.text:
        show(gate, args.text, args.min_score); raise SystemExit
    if args.repl:
        print('PII gate ready. Type/paste text, Enter to redact (Ctrl-D or empty line to quit).', flush=True)
        for line in sys.stdin:
            line = line.rstrip('\n')
            if not line.strip(): break
            show(gate, line, args.min_score)
        raise SystemExit
    if not sys.stdin.isatty():  # piped input: redact each non-empty line
        for line in sys.stdin:
            if line.strip(): show(gate, line.rstrip('\n'), args.min_score)
        raise SystemExit
    samples = [
        "Bonjour, Marie Tremblay (NAS 5 8 1 6 5 3 6 1 2) au 4567 boulevard René-Lévesque, Montréal H3B 1A1; carte 4539-1488-0343-6467.",
        "Hi, this is jean.cote@videotron.ca, my account 81234567 and phone (514) 555-0188, DOB 1985-03-12.",
        "Le service tourne sur le port 8080, GPU 3090, aucune donnée personnelle ici.",
    ]
    for s in samples:
        show(gate, s, args.min_score)
