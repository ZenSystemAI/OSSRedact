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

# ---------------- Tier 0: deterministic ----------------
EMAIL_RE = re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b')
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
# IPv6 (the tier-0 IP rule was IPv4-only). Standard comprehensive form: matches ONLY a full 8-group address or
# a `::`-compressed address, so times (12:34:56) and version strings never match. Hex-only groups, so C++ scope
# resolution on non-hex identifiers (std::vector) never matches.
IPV6_RE = re.compile(
    r'(?<![\w:.])('
    r'(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}'
    r'|(?:[0-9A-Fa-f]{1,4}:){1,7}:'
    r'|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}'
    r'|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}'
    r'|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}'
    r'|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}'
    r'|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}'
    r'|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}'
    r'|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)'
    r')(?![\w:.])')
POSTAL_RE = re.compile(r'\b[A-Za-z]\d[A-Za-z]\s?\d[A-Za-z]\d\b')
# UUID (8-4-4-4-12 hex) = connection/session/request IDs (e.g. Flinks login id). Never occurs by accident
# in natural text, so it is a deterministic catch at ~1.0 confidence, independent of the model threshold.
UUID_RE = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
# digit runs with optional separators (space/dot/dash). Floor = 7 chars so a bare 7-digit bank account
# (common Canadian format) is caught deterministically, not left to the model. The digit-count gate below
# decides the label and rejects too-short noise.
DIGIT_RUN_RE = re.compile(r'(?<![\w])(\d[\d \-]{5,}\d)(?![\w])')   # space/hyphen groups only (D1: no '.', matches tier0.ts + gate -- '.' over-matched decimals/versions)
PHONE_RE = re.compile(r'(?<![\w])(\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}(?![\w])')
# Dates: FR/EN month-name dates, ISO, and numeric. The model catches dates in clean prose but is
# unreliable in tabular statement noise (e.g. "21 mai 2026" -> only "21"), so own them deterministically.
_MONTHS = (r'jan(?:vier|uary)?|f[eé]v(?:rier)?|feb(?:ruary)?|mar(?:s|ch)?|avr(?:il)?|apr(?:il)?|mai|may|'
           r'juin|june|juil(?:let)?|jul(?:y)?|ao[uû]t|aug(?:ust)?|sep(?:t(?:embre|ember)?)?|'
           r'oct(?:obre|ober)?|nov(?:embre|ember)?|d[eé]c(?:embre|ember)?')
DATE_RE = re.compile(r'\b(\d{1,2}\s+(?:' + _MONTHS + r')\s+\d{4}|(?:' + _MONTHS + r')\.?\s+\d{1,2},?\s+\d{4}'
                     r'|\d{4}-\d{2}-\d{2}|\d{1,2}[/.]\d{1,2}[/.]\d{2,4})\b', re.IGNORECASE)

# Case-normalize runs of >=2 uppercase letters to Title case for a second model pass. .title() of an
# all-caps word is the SAME length, so char offsets are preserved 1:1 and spans map back onto the original.
# This recovers ALL-CAPS names/addresses (bank statements, forms) the case-sensitive model misses.
CAPS_RUN = re.compile(r'[A-ZÀ-ÖØ-Þ]{2,}')
def _normcase(s: str) -> str:
    return CAPS_RUN.sub(lambda m: m.group().title(), s)

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
# Unicode DIGIT homoglyphs that aren't ASCII 0-9. \d / [0-9] match only category Nd, and even within Nd the
# Luhn int() needs an ASCII digit -- but SUPERSCRIPT/SUBSCRIPT/circled digits are category No (isdecimal()
# False), so `\d` never matches them and a card rendered "card ⁴¹¹¹¹¹¹¹¹¹¹¹¹¹¹¹" slips the whole digit floor
# (NFKC-reconstructable to the real PAN). Map every single-codepoint digit-valued char to its ASCII digit;
# this is LENGTH-PRESERVING (one codepoint -> one ASCII char) so offsets map 1:1. Covers No (super/subscript,
# circled, etc.) and folds non-ASCII Nd (fullwidth, Arabic-Indic) to ASCII so the Luhn check is exact.
def _normdigits(s: str) -> str:
    if s.isascii():
        return s
    out = []
    for ch in s:
        if '0' <= ch <= '9':
            out.append(ch); continue
        try:
            out.append(str(unicodedata.digit(ch)))   # ValueError if ch has no single-digit value
        except (ValueError, TypeError):
            out.append(ch)
    return ''.join(out)

def _normseps(s: str) -> str:
    return _normdigits(_normspace(_normdash(s)))

# INVISIBLE / control interleaving breaks every Tier-0 number regex: "4<sep>1<sep>1<sep>1..." has digit-run
# separators a human and the upstream LLM never see, so the floor returns n_spans=0 and the real card/IBAN/SIN
# ships raw in EVERY mode incl 'off' (the floor is supposed to be un-bypassable). Two codepoint classes do this:
#   Cf (format)  -- ZWSP/ZWNJ/ZWJ/WORD-JOINER/BOM/soft-hyphen (U+200B.., U+00AD)
#   Cc (control) -- TAB/LF/VT/FF/CR (U+0009-000D) and the C0/C1 separators (FS/GS/RS/US U+001C-001F)
# _normseps only maps Zs spaces + dashes, never these. Fix: strip BOTH classes to a clean copy, re-run the
# Tier-0 scan there, and map each span back onto the ORIGINAL offsets so the mask covers the value AND the
# interleaved invisibles. Letter-boundary digit rules (glued_digit) still protect code identifiers in the
# stripped copy; the only added over-redaction is adjacent bare numbers separated solely by a control char
# (e.g. a tab-delimited row of short numbers) merging into one redacted run -- the safe direction.
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

# IBAN mod-97 deterministic backstop. BACKPORTED from gate/privacy_gate.py to close F14: the deployed floor
# had NO IBAN catch, so an IBAN the NER model missed had no deterministic guarantee (a catastrophic-tier
# financial ID with no backstop). A mod-97 pass is a near-certain real IBAN, so there is no precision risk.
IBAN_RE = re.compile(r'\b([A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?:[ -][A-Z0-9]{2,4}){3,8}))\b', re.I)
def _iban_ok(s: str) -> bool:
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
    candidate = raw
    while candidate:
        if _iban_ok(candidate):
            return candidate
        cut = max(candidate.rfind(' '), candidate.rfind('-'))
        if cut <= 4:
            break
        candidate = candidate[:cut]
    return None

# Canadian Business Number program-account suppression (real-doc Finding A + Codex review) -- mirrors
# gate/privacy_gate.py. A 9-digit Luhn number immediately followed by an RT/RP/RC... program account is a
# Business Number (GST/QST registration printed on invoices), NOT a SIN; suppress it UNLESS a SIN cue
# precedes the number (then a real SIN must always win the never-leak guarantee).
_BN_PROGRAM_SUFFIX_RE = re.compile(r'^[ \-]?(?:RT|RP|RC|RZ|RM|RR|RG)[ \-]?\d{4}(?!\d)', re.I)
_SIN_CUE_RE = re.compile(
    r'(?i)(?:(?<![a-z])(?:n\.?a\.?s|s\.?i\.?n)(?![a-z])|social\s*insurance|assurance\s*sociale|num[ée]ro\s*d.?assurance)')

# ---------------- Context-cued structured IDs (Presidio LemmaContextAwareEnhancer pattern) ----------------
# A long digit run GLUED to letters is deliberately rejected by DIGIT_RUN_RE's word boundary (else every
# digit-bearing code identifier / version string / hex tail would redact). But when a financial / reference /
# identity-document CUE word sits just before such a run (or right after), it is almost certainly a sensitive
# reference / account / confirmation number, so we PROMOTE it. Cue-gated => a recall win on real prose
# ("Confirmation no XXXX", "compte XXXX", "numero de reference XXXX") with NO false-positive blowup on bare
# alphanumerics in code. High-precision FR/EN financial + identity cues only (no amount/date words).
_ID_CUE = re.compile(
    r'(?<![a-z0-9é])(?:r[ée]f(?:[ée]rence)?|confirmation|transaction|virement|transfert|transfer|interac|'
    r'paiement|payment|ch[èe]que|cheque|facture|invoice|dossier|folio|compte|account|acct|transit|'
    r'autorisation|authorization|mandat|num[ée]ro|n°|nas|sin|sdi|imp[oô]t|ramq|iban)(?![a-z])',
    re.IGNORECASE)
# 9-19 digit run; letter-adjacency ALLOWED (that is the gap DIGIT_RUN_RE leaves). Not digit-bounded. The 9-10
# digit low end is cue-gated here (a financial/identity cue must be adjacent) so it does NOT over-redact code
# identifiers -- a non-Luhn SSN/account glued to a CUE word ("account 0781234567") is caught; glued to a
# non-cue word it is not (that residual is accepted to keep coding traffic clean -- see glued_digit_spans).
_LONG_ID_RE = re.compile(r'(?<!\d)(\d(?:[ \-]?\d){8,18})(?!\d)')
_CUE_BEFORE = 24   # chars before the run scanned for a cue
_CUE_AFTER = 12    # chars after

def context_cued_id_spans(text: str):
    """Catch 11-19 digit runs that DIGIT_RUN_RE's letter-boundary rejects, but ONLY when a financial /
    reference / identity cue is adjacent. Presidio's context-promotion idea in ~20 lines: a weak signal
    (letter-glued long run) becomes a redaction only on contextual evidence. Recall up, code FP near zero."""
    out = []
    t = _normseps(text)
    for m in _LONG_ID_RE.finditer(t):
        s, e = m.start(1), m.end(1)
        left = t[s - 1] if s > 0 else ' '
        right = t[e] if e < len(t) else ' '
        if not (left.isalpha() or right.isalpha()):
            continue   # clean-boundary run -> already owned by DIGIT_RUN_RE in tier0_spans
        mcue = _ID_CUE.search(t[max(0, s - _CUE_BEFORE):s]) or _ID_CUE.search(t[e:e + _CUE_AFTER])
        if mcue:
            out.append({'start': s, 'end': e, 'label': 'sensitive_account_id', 'tier': 0, 'conf': 0.55,
                        'rule': 'tier0:context_cue', 'cue': mcue.group().lower()})
    return out


# ---- Tier-0 person backstop: deterministic where a strong CUE exists ----
# Names normally remain the neural tier's job. The exception is cue-bearing mail/header forms such as
# "Display Name <addr@domain>", From:/To:/Author:/owner:, and git trailers, where the email/header cue
# makes the adjacent name deterministic enough to redact without waiting for the model.
_EMAIL_ANCHOR_RE = re.compile(r'<[ \t]*[\w.+-]+@[\w-]+\.[\w.-]+[ \t]*>')
_HDR_CUE_RE = re.compile(
    r'(?im)^[ \t]*(?:from|to|cc|bcc|reply-to|sender|author|co-authored-by|signed-off-by|owner|'
    r'titulaire|propri[ée]taire|attn|attention)[ \t]*:[ \t]*')
_NAME_TOKEN_RE = re.compile(r"[^\W\d_]+(?:['’.\-][^\W\d_]+)*", re.UNICODE)
_NAME_PARTICLES = {'van', 'von', 'de', 'der', 'den', 'del', 'della', 'di', 'da', 'du', 'la', 'le',
                   'el', 'bin', 'ibn', 'al', 'dos', 'das', 'do', 'of', 'and'}
_NAME_ROLE_DENY = {'support', 'sales', 'billing', 'info', 'admin', 'noreply', 'no-reply', 'notifications',
                   'notification', 'team', 'contact', 'hello', 'help', 'marketing', 'security', 'abuse',
                   'postmaster', 'mailer-daemon', 'do-not-reply', 'donotreply', 'newsletter', 'accounts',
                   'service', 'services', 'sender', 'recipient', 'no_reply'}

def _name_shaped(s: str) -> bool:
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
    while chosen and t[chosen[-1][0]:chosen[-1][1]].lower() in _NAME_PARTICLES:
        chosen.pop()
    return (chosen[-1][0], chosen[0][1]) if chosen else None

def _name_run_after(t: str, start: int, stop: int):
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

def cue_name_spans(text: str):
    spans, t, seen = [], _normseps(text), set()
    def emit(rng):
        if rng and rng not in seen and _name_shaped(t[rng[0]:rng[1]]):
            seen.add(rng)
            spans.append({'start': rng[0], 'end': rng[1], 'label': 'person', 'tier': 0,
                          'conf': 0.95, 'rule': 'tier0:cue_name'})
    for m in _EMAIL_ANCHOR_RE.finditer(t):
        emit(_name_run_before(t, m.start()))
    for m in _HDR_CUE_RE.finditer(t):
        le = t.find('\n', m.end())
        emit(_name_run_after(t, m.end(), len(t) if le == -1 else le))
    return spans


# Glued CHECKSUM-validated identifiers. DIGIT_RUN_RE / IBAN_RE deliberately reject runs glued to letters
# (precision for code hashes/ids), so a card or IBAN with no separator boundary (card4111111111111111expires,
# ibanGB29NWBK60161331926819) slips the floor. A CHECKSUM pass is near-certainly real even glued -> recover it.
# Only Luhn-card (15/16) and mod-97-IBAN are recovered; 9-digit SIN is NOT (Luhn-9 is too weak -> FP), it stays
# cue-gated. The digit-boundary (?<!\d)(?!\d) (not \w) lets a letter-adjacent run match while still refusing a
# sub-run of a longer number. Clean (boundary) cards/IBANs are also re-emitted here and union-merged (no harm).
_GLUED_CARD_RE = re.compile(r'(?<!\d)(\d[\d -]{13,18}\d)(?!\d)')
_GLUED_IBAN_RE = re.compile(r'[A-Z]{2}\d{2}[A-Z0-9]{11,30}(?![A-Z0-9])', re.I)


def glued_checksum_spans(text: str):
    out = []
    for m in _GLUED_CARD_RE.finditer(text):
        digits = re.sub(r'\D', '', m.group(1))
        if len(digits) in (15, 16) and _luhn_ok(digits):
            out.append({'start': m.start(1), 'end': m.end(1), 'label': 'payment_card', 'tier': 0,
                        'conf': 0.95, 'rule': 'tier0:card_glued', 'validator': 'luhn_ok'})
    for m in _GLUED_IBAN_RE.finditer(text):
        s = m.start()
        if s > 0 and text[s - 1].isalnum() and _iban_ok(m.group()):   # left-glued (\b would have blocked it)
            out.append({'start': s, 'end': m.end(), 'label': 'iban', 'tier': 0,
                        'conf': 0.99, 'rule': 'tier0:iban_glued', 'validator': 'mod97_ok'})
    return out


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
        if not _luhn_ok(digits):                      # Luhn-valid 9-digit glued to a word = a SIN, not a code id
            continue
        # Business Number suppression (parity with the clean DIGIT_RUN path + the gate): a 9-digit Luhn run
        # immediately followed by an RT/RP/RC.. program account is a GST/QST Business Number, not a SIN --
        # suppress UNLESS a SIN cue precedes (then the never-leak SIN guarantee wins).
        if _BN_PROGRAM_SUFFIX_RE.match(t[e:e + 12]) and not _SIN_CUE_RE.search(t[max(0, s - 40):s]):
            continue
        out.append({'start': s, 'end': e, 'label': 'government_id', 'tier': 0, 'conf': 0.8,
                    'rule': 'tier0:digit_glued', 'validator': 'luhn_ok'})
    return out


# Separator-tolerant payment card: DIGIT_RUN_RE / glued_checksum reject '.'-separated groups (a confirmed leak:
# "4111.1111.1111.1111") and percent-encoded spaces ("4111%201111%201111%201111" in a URL query, also confirmed).
# A 4-4-4-4 (or amex 4-6-5) grouping joined by '.', '-', space, or the literal "%20" sequence whose digits are a
# Luhn-valid 15/16-run is a card with near-zero FP (Luhn-gated). Space/dash forms re-emit harmlessly (merged).
_CARD_SEP = r'(?:[ .\-]|%20)'
_SEP_CARD_RE = re.compile(r'(?<![\d.])(\d{4}(?:' + _CARD_SEP + r'\d{4}){3}|\d{4}' + _CARD_SEP + r'\d{6}' + _CARD_SEP + r'\d{5})(?![\d.])')
# US SSN written with dot separators ("123.45.6789"): a 3-2-4 digit grouping joined by dots. The boundary
# rejects longer dotted sequences (IPs/versions never group 3-2-4). government_id floor.
_DOT_SSN_RE = re.compile(r'(?<![\d.])(\d{3}\.\d{2}\.\d{4})(?![\d.])')

def separated_card_spans(text: str):
    out = []
    t = _normseps(text)
    for m in _SEP_CARD_RE.finditer(t):
        digits = re.sub(r'\D', '', m.group(1).replace('%20', ' '))   # decode %20 BEFORE digit extraction (its 2,0 are not card digits)
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
_CVV_RE = re.compile(r'(?i)(?:cvv2?|cvc2?|security\s*code|card\s*verification(?:\s*(?:code|value))?|'
                     r'code\s*de\s*s[eé]curit[eé]|cryptogramme(?:\s*visuel)?)\s*(?:no\.?|num(?:[ée]ro)?|#)?\s*[:=#-]?\s*(\d{3,4})(?!\d)')
_EXPIRY_RE = re.compile(r'(?i)(?:exp(?:iry|ires?|iration)?|exp\.?\s*date|valid\s*thru|valid\s*through|good\s*thru|'
                        r'valable\s*jusqu.?(?:au)?|[ée]ch[ée]ance|date\s*d.?expiration)\s*[:=#-]?\s*'
                        r'((?:0[1-9]|1[0-2])\s*[/\-]\s*(?:\d{4}|\d{2}))(?!\d)')

def card_aux_spans(text: str):
    out = []
    t = _normseps(text)
    for m in _CVV_RE.finditer(t):
        out.append({'start': m.start(1), 'end': m.end(1), 'label': 'card_cvv', 'tier': 0,
                    'conf': 0.9, 'rule': 'tier0:cvv'})
    for m in _EXPIRY_RE.finditer(t):
        out.append({'start': m.start(1), 'end': m.end(1), 'label': 'card_expiry', 'tier': 0,
                    'conf': 0.9, 'rule': 'tier0:expiry'})
    return out


# US ZIP (postal_code): a bare 5-digit number is far too ambiguous to redact, so gate it on a US-address cue --
# the canonical "City, ST 12345" tail (comma + a REAL 2-letter state code + 5 digits, optionally ZIP+4) or an
# explicit zip/zipcode keyword. CA postal codes (A#A #A#) are owned by POSTAL_RE; QC etc. are not US states so a
# Canadian "Montreal, QC H2X 1Y4" never matches here. Quebec product, so US ZIP is best-effort, cue-gated only.
_US_STATES = {'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DC', 'DE', 'FL', 'GA', 'HI', 'ID', 'IL', 'IN', 'IA',
              'KS', 'KY', 'LA', 'ME', 'MD', 'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ', 'NM',
              'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC', 'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA',
              'WV', 'WI', 'WY'}
_US_ZIP_CUE_RE = re.compile(r',\s*([A-Z]{2})\s+(\d{5}(?:-\d{4})?)(?!\d)')
_US_ZIP_KW_RE = re.compile(r'(?i)\bzip(?:\s?code)?\s*:?\s*(\d{5}(?:-\d{4})?)(?!\d)')


def us_zip_spans(text: str):
    out = []
    for m in _US_ZIP_CUE_RE.finditer(text):
        if m.group(1) in _US_STATES:
            out.append({'start': m.start(2), 'end': m.end(2), 'label': 'postal_code', 'tier': 0,
                        'conf': 0.85, 'rule': 'tier0:us_zip'})
    for m in _US_ZIP_KW_RE.finditer(text):
        out.append({'start': m.start(1), 'end': m.end(1), 'label': 'postal_code', 'tier': 0,
                    'conf': 0.9, 'rule': 'tier0:us_zip'})
    return out


def tier0_spans(text: str):
    spans = []
    # Match on a dash-normalized copy (length-preserving) so unicode dashes from PDF extraction don't split
    # structured IDs; offsets map 1:1 back onto the original text the caller redacts.
    t = _normseps(text)
    def add(s, e, lab, conf, rule, **extra):
        spans.append({'start': s, 'end': e, 'label': lab, 'tier': 0, 'conf': conf, 'rule': rule, **extra})
    for m in EMAIL_RE.finditer(t): add(m.start(), m.end(), 'email', 0.99, 'tier0:email')
    for m in IP_RE.finditer(t):
        if all(0 <= int(o) <= 255 for o in m.group().split('.')): add(m.start(), m.end(), 'ip_address', 0.95, 'tier0:ip')
    for m in IPV6_RE.finditer(t):
        if m.group(1).count(':') >= 2: add(m.start(1), m.end(1), 'ip_address', 0.9, 'tier0:ipv6')   # >=2 colons rules out a stray 'a:b'
    for m in POSTAL_RE.finditer(t): add(m.start(), m.end(), 'postal_code', 0.9, 'tier0:postal')
    for m in UUID_RE.finditer(t): add(m.start(), m.end(), 'sensitive_account_id', 0.99, 'tier0:uuid')
    for m in IBAN_RE.finditer(t):
        iban = _valid_iban_candidate(m.group(1))
        if iban: add(m.start(1), m.start(1) + len(iban), 'iban', 0.99, 'tier0:iban', validator='mod97_ok')
    for m in PHONE_RE.finditer(t): add(m.start(), m.end(), 'phone_number', 0.85, 'tier0:phone')
    for m in DATE_RE.finditer(t): add(m.start(1), m.end(1), 'sensitive_date', 0.8, 'tier0:date')
    for m in DIGIT_RUN_RE.finditer(t):
        raw = m.group(1); digits = re.sub(r'\D', '', raw)
        n = len(digits); val = None
        if n == 16 or n == 15:
            ok = _luhn_ok(digits); lab, conf, val = 'payment_card', (0.97 if ok else 0.7), ('luhn_ok' if ok else 'luhn_fail')
        elif n == 9:
            e9 = m.end(1)
            if _BN_PROGRAM_SUFFIX_RE.match(t[e9:e9 + 12]) and not _SIN_CUE_RE.search(t[max(0, m.start(1) - 40):m.start(1)]):
                continue  # Business Number (GST/QST), not a SIN, and no SIN cue forces emission -- Finding A
            ok = _luhn_ok(digits); lab, conf, val = 'government_id', (0.9 if ok else 0.75), ('luhn_ok' if ok else 'luhn_fail')  # SIN
        elif 7 <= n <= 19:
            lab, conf = ('sensitive_account_id', 0.6)  # generic structured id (account/transit/reference/etc.)
        else:
            continue
        add(m.start(1), m.end(1), lab, conf, 'tier0:digit_run', **({'validator': val} if val else {}))
    spans += context_cued_id_spans(t)   # Presidio-style: promote cue-introduced letter-glued long IDs
    spans += glued_checksum_spans(t)    # checksum-valid card/IBAN glued to letters (no cue needed)
    spans += glued_digit_spans(t)       # Luhn-valid 9-digit SIN glued to letters (no cue; Luhn-precise)
    spans += separated_card_spans(t)    # dot/space/dash-grouped Luhn card + dotted SSN (sep DIGIT_RUN rejects)
    spans += card_aux_spans(t)          # cue-anchored card_cvv + card_expiry (no standalone Tier-0 before)
    spans += us_zip_spans(t)            # US ZIP, cue-gated (City, ST 12345 / zip: 12345)
    spans += cue_name_spans(t)
    # Zero-width/format-char obfuscation resistance: if the ORIGINAL carries Cf codepoints, re-scan a stripped
    # copy and map the spans back. clean has no Cf chars, so tier0_spans(clean) cannot re-enter this branch.
    if _has_format_chars(text):
        clean, idx_map = _strip_format_chars(text)
        if clean and clean != text:
            for s in tier0_spans(clean):
                a, b = idx_map[s['start']], idx_map[s['end'] - 1] + 1
                spans.append({**s, 'start': a, 'end': b, 'rule': (s.get('rule') or 'tier0') + '+cf'})
    return spans

# ---------------- Tier 1: NPU INT8 ONNX ----------------
class NPUTier:
    # max_len=512 (not 256): the prod gate chunks at 600 chars, and a token-DENSE 600-char chunk (secrets,
    # hashes, long IDs) reaches ~300 tokens; max_len 256 truncated the chunk tail and dropped PII there
    # (measured: password recall 0.85 -> 0.99 when 256 -> 512, 46% of dense chunks exceeded 256 tokens).
    # Mirrors gate/privacy_gate.py NPUTier.
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
    def __init__(self, model_dir, device='cuda', max_len=256):
        import torch
        from transformers import AutoTokenizer, AutoModelForTokenClassification
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModelForTokenClassification.from_pretrained(
            model_dir, torch_dtype=torch.float16).to(device).eval()
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
# (1) merge stickiness below, (2) the egress force-redact-in-every-mode policy, and (3) the never-allowlist-
# exempt guard -- egress_proxy.py imports this exact set as FLOOR_NEVER_EXEMPT so the three can never drift.
FLOOR_LABELS = frozenset({
    'secret', 'password', 'api_key', 'access_token',                  # credentials
    'payment_card', 'card_cvv', 'card_expiry',                        # cards
    'sensitive_account_id', 'bank_account', 'iban', 'routing_number', # bank / account
    'government_id', 'tax_id', 'date_of_birth',                       # government / identity
})


def merge_spans(spans, sticky=FLOOR_LABELS):
    # CONNECTED-COMPONENT UNION. A privacy gate must never leave a PII fragment exposed between two
    # overlapping detections. Greedy drop-the-loser does exactly that: model emits "21" inside a date, or a
    # spurious "password" on a UUID partially overlaps "21 mai 2026" -> whichever is dropped, half the date
    # leaks. So instead: any cluster of overlapping spans is redacted as ONE span covering their union. The
    # cluster's label is the highest-confidence (then longest) member's; the union text is what gets masked
    # and stored for rehydration. Over-redaction (a UUID swallowed with an adjacent date) is the safe error.
    #
    # FLOOR STICKINESS: a deterministic hard-floor label (credentials, payment cards, bank/IBAN, government/
    # tax IDs, DOB) must NEVER be downgraded to a soft neural label just because an overlapping model guess
    # scored higher. The downstream floor guards (the allowlist drop and 'off' mode) key off the post-merge
    # LABEL, so a real card tagged 'person' at conf 0.98 over the 0.97 card floor would lose its protection
    # and leak. So if any cluster member carries a floor label, the cluster's primary label stays the
    # highest-confidence FLOOR member's, whatever the soft spans claim. Strictly safer: stickiness only ever
    # KEEPS more redaction (floor wins), never less.
    if not spans:
        return []
    spans = sorted(spans, key=lambda s: (s['start'], -(s['end'] - s['start'])))
    out = []
    for s in spans:
        floor = s['label'] in sticky
        if out and s['start'] < out[-1]['end']:  # overlaps the current cluster
            cur = out[-1]
            cur['members'] = cur.get('members', 1) + 1
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
            nc = {**s, '_bc': s['conf'], '_bl': s['end'] - s['start'], 'members': 1}
            if floor:
                nc['_floor'] = s; nc['_fc'] = s['conf']
            out.append(nc)
    for m in out:
        fl = m.pop('_floor', None); m.pop('_fc', None)
        if fl is not None and m['label'] not in sticky:
            # a floor value got out-scored by an overlapping soft guess -> restore the floor member as the
            # cluster's primary so the downstream floor guards (policy + allowlist) see a floor label.
            m['label'] = fl['label']; m['tier'] = fl['tier']
            m['rule'] = fl.get('rule'); m['validator'] = fl.get('validator')
            m['cue'] = fl.get('cue'); m['subtype'] = fl.get('subtype')
        m.pop('_bc', None); m.pop('_bl', None)
        for k in ('validator', 'cue', 'subtype'):
            if m.get(k) is None:
                m.pop(k, None)   # drop null provenance keys for a clean record
    return out

def post_merge_address(spans, text):
    # Stitch adjacent address spans (and an immediately-following postal_code) separated only by a short
    # separator gap. The composite-address v6 model sometimes emits an address as 2 fragments across a
    # comma/newline; this is deterministic recall insurance (gap <=12 chars, separator-only). ~0 latency.
    out = []
    for s in sorted(spans, key=lambda s: s['start']):
        if out and out[-1]['label'] == 'address' and s['label'] in ('address', 'postal_code'):
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
    def detect(self, text, min_score=0.5, casenorm=True):
        spans = tier0_spans(text)
        if self.npu:
            spans += self.npu.spans(text, min_score)
            if casenorm:
                norm = _normcase(text)
                if norm != text:  # offsets identical (length-preserving) -> spans map onto original
                    spans += self.npu.spans(norm, min_score)
        return post_merge_address(merge_spans(spans), text)
    def redact(self, text, min_score=0.5):
        spans = self.detect(text, min_score)
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
