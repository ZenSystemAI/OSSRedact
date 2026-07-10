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
# Email requires an ALPHABETIC TLD: the old tail ([\w.-]+) matched npm/version strings ("unpkg@1.1.0",
# "core@0.2.0" -> EMAIL placeholders, observed live 2026-07-02), burning map entries on every package pin.
# A real deliverable address always ends in a letters-only label; user@192.168.1.1 loses its email span but
# the IP part stays owned by IP_RE.
EMAIL_RE = re.compile(r'\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b')
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
# LABEL DEMOTED 2026-07-02 (RC2 fat-floor diet; mirrors gate/privacy_gate.py): minted as the SOFT label
# 'uuid', no longer 'sensitive_account_id'. The old floor label made every UUID merge-sticky,
# un-allowlistable, redacted even in 'off' mode, AND withheld from tool-call arguments -- but UUIDs are
# load-bearing session/request ids in agent traffic, so redacting them broke file ops and churned the
# prompt cache (a live agent received a literal <SENSITIVEACCOUNTID_004> as a file path and wrote a junk
# directory). Floor privileges require deterministic provenance of a CATASTROPHIC shape; a UUID is
# deterministic but not catastrophic. Privacy mode still redacts 'uuid' (soft default); coding/off pass it.
# 'uuid' must NEVER enter FLOOR_LABELS.
UUID_RE = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
# digit runs with optional separators (space/dot/dash). Floor = 7 chars so a bare 7-digit bank account
# (common Canadian format) is caught deterministically, not left to the model. The digit-count gate below
# decides the label and rejects too-short noise.
DIGIT_RUN_RE = re.compile(r'(?<![\w])(\d[\d \-]{5,}\d)(?![\w])')   # space/hyphen groups only (D1: no '.', matches tier0.ts + gate -- '.' over-matched decimals/versions)
# Date-shaped digit runs. DIGIT_RUN_RE also swallows dates ("2026-07-01" -> 8 digits -> the 7-19 bucket),
# minting sensitive_account_id for every datestamp/filename/beta tag even though tier0:date emitted
# sensitive_date for the same span -- the account label then survives coding mode's `date` category
# exclusion and re-redacts it (the RC5 gap: `context-1m-2025-08-07` -> <SENSITIVEACCOUNTID_nnn>).
# Classify these runs as sensitive_date instead: privacy mode still redacts them (date category),
# coding mode passes them. Hyphenated forms only -- space-grouped runs ("2026 07 01") stay account-shaped
# because real account/transit groupings use spaces. Compact YYYYMMDD is included (build/date stamps);
# a labeled account number that happens to look like one is still caught by the cue/keyed rules.
_DATE_SHAPED_RES = (
    re.compile(r'(19|20)\d{2}-(\d{1,2})-(\d{1,2})( \d{1,2})?$'),   # Y-M-D (+ optional glued log hour)
    re.compile(r'(\d{1,2})-(\d{1,2})-((?:19|20)\d{2})$'),          # D-M-Y / M-D-Y
    re.compile(r'(19|20)(\d{2})(\d{2})(\d{2})$'),                  # compact YYYYMMDD
)


def _date_shaped(raw: str) -> bool:
    m = _DATE_SHAPED_RES[0].match(raw)
    if m:
        return 1 <= int(m.group(2)) <= 12 and 1 <= int(m.group(3)) <= 31
    m = _DATE_SHAPED_RES[1].match(raw)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        return (1 <= a <= 31 and 1 <= b <= 12) or (1 <= a <= 12 and 1 <= b <= 31)
    m = _DATE_SHAPED_RES[2].match(raw)
    if m:
        return 1 <= int(m.group(3)) <= 12 and 1 <= int(m.group(4)) <= 31
    return False
PHONE_RE = re.compile(r'(?<![\w])(\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}(?![\w])')
# A separator-bearing NANP phone ("514-444-4444", "1 514 444 4444", "(514) 444-4444") ALSO matches the
# generic digit run wholly or in part, minting a second span labeled sensitive_account_id -- and since that
# label is FLOOR-sticky, the merge relabeled the phone as an account id (observed live 2026-07-02: a phone
# typed as sensitive_account_id, turning soft PII into an un-allowlistable floor value that redacts even in
# 'off' mode). The digit-run mint is skipped by CONTAINMENT: a separator-bearing run that lies entirely
# inside a PHONE_RE match is the phone's own digits (the paren form splits the run to just '444-4444', so a
# shape test on the run alone missed it -- adversarial review, same night). Separator-LESS runs stay
# account-shaped on purpose (compact bank accounts are 7-12 digits); a compact phone is still caught by
# PHONE_RE itself, it just doesn't displace the account label.
# Birth cue for the DOB backstop: a date preceded (within _DOB_CUE_WINDOW chars) by a birth keyword is a
# date_of_birth (FLOOR), not a bare sensitive_date -- required since the 2026-07-02 wire-level date policy
# passes bare dates in every mode. EN + FR (Quebec-first product). Word-bounded so 'newborn'/'airborne'
# never fire. The FR "born" form is `n(?:ée?|ee)` -- matches né/née/nee but NOT the bare negation "ne", one
# of the commonest words in French (the old `n[eé]e?` matched "ne" and force-floored dates all over
# Quebec-French prose, defeating the wire-date-pass policy -- adversarial re-review 2026-07-02).
_DOB_CUE_RE = re.compile(r"(?i)(?:\bn(?:ée?|ee)\b|\bnaissance\b|\bborn\b|\bbirth(?:day|date)?\b|\bdob\b|"
                         r"date\s+de\s+naissance|date\s+of\s+birth)")
# Window widened 32 -> 48 (re-review): a cue in a table header / long field label ("date de naissance du
# titulaire du compte: <date>") sits > 32 chars before the value. 48 covers the common Quebec-statement
# forms without ballooning the false-positive window now that the "ne" negation match is fixed.
_DOB_CUE_WINDOW = 48
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
    r'titulaire|propri[ée]taire|attn|attention|'
    # statement-header cues (2026-07-08, plan 049): the account holder / member name printed at the top of a
    # bank statement, colon-anchored and line-anchored exactly like the mail headers above.
    r'nom|client(?:e)?|membre|member|account\s+holder|prepared\s+for|pr[ée]par[ée]\s+pour)[ \t]*:[ \t]*')
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
    spans, t, seen = [], _normseps(text), set()
    def emit(rng, shaped=_name_shaped, rule='tier0:cue_name'):
        if rng and rng not in seen and shaped(t[rng[0]:rng[1]]):
            seen.add(rng)
            spans.append({'start': rng[0], 'end': rng[1], 'label': 'person', 'tier': 0,
                          'conf': 0.95, 'rule': rule})
    for m in _EMAIL_ANCHOR_RE.finditer(t):
        emit(_name_run_before(t, m.start()))
    for m in _HDR_CUE_RE.finditer(t):
        le = t.find('\n', m.end())
        emit(_name_run_after(t, m.end(), len(t) if le == -1 else le))
    for m in _ETRANSFER_CUE_RE.finditer(t):          # "VIR INTERAC RECU <name>", "E-TRANSFER <ref> <name>", ...
        le = t.find('\n', m.end())
        emit(_ledger_name_run(t, m.end(), len(t) if le == -1 else le), _name_shaped_relaxed)
    for m in _ETRANSFER_SLASH_RE.finditer(t):        # Desjardins "Interac e-Transfer from /<name> /"
        le = t.find('\n', m.end())
        emit(_ledger_slash_name(t, m.end(), len(t) if le == -1 else le), _name_shaped_relaxed)
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
    for m in UUID_RE.finditer(t): add(m.start(), m.end(), 'uuid', 0.99, 'tier0:uuid')   # SOFT since 2026-07-02 (see UUID_RE note)
    for m in IBAN_RE.finditer(t):
        iban = _valid_iban_candidate(m.group(1))
        if iban: add(m.start(1), m.start(1) + len(iban), 'iban', 0.99, 'tier0:iban', validator='mod97_ok')
    phone_ranges = []
    for m in PHONE_RE.finditer(t):
        add(m.start(), m.end(), 'phone_number', 0.85, 'tier0:phone')
        phone_ranges.append((m.start(), m.end()))
    for m in DATE_RE.finditer(t):
        s1, e1 = m.start(1), m.end(1)
        # DOB CUE BACKSTOP (adversarial review 2026-07-02): the wire-level date policy passes bare dates in
        # every mode, so a birth-cued date must be recognized HERE (floor date_of_birth) or it ships verbatim
        # when the model misses it. Mirrors the JSON-key _DOB_KEY_RE guard, for prose.
        if _DOB_CUE_RE.search(t[max(0, s1 - _DOB_CUE_WINDOW):s1]):
            add(s1, e1, 'date_of_birth', 0.9, 'tier0:dob_cue')
        else:
            add(s1, e1, 'sensitive_date', 0.8, 'tier0:date')
    for m in DIGIT_RUN_RE.finditer(t):
        raw = m.group(1); digits = re.sub(r'\D', '', raw)
        n = len(digits); val = None
        if _date_shaped(raw):
            lab = 'date_of_birth' if _DOB_CUE_RE.search(t[max(0, m.start(1) - _DOB_CUE_WINDOW):m.start(1)]) else 'sensitive_date'
            add(m.start(1), m.end(1), lab, 0.9 if lab == 'date_of_birth' else 0.8,
                'tier0:dob_cue' if lab == 'date_of_birth' else 'tier0:date_shaped')
            continue
        if not raw.isdigit() and any(ps <= m.start(1) and m.end(1) <= pe for ps, pe in phone_ranges):
            continue  # separator-bearing run inside a phone match: owned by PHONE_RE (see the note above)
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
    spans += cue_digit_spans(t)   # cue-gated ID/phone/DOB backstop (miss-inventory-driven, 2026-07-07)
    # Zero-width/format-char obfuscation resistance: if the ORIGINAL carries Cf codepoints, re-scan a stripped
    # copy and map the spans back. clean has no Cf chars, so tier0_spans(clean) cannot re-enter this branch.
    if _has_format_chars(text):
        clean, idx_map = _strip_format_chars(text)
        if clean and clean != text:
            for s in tier0_spans(clean):
                a, b = idx_map[s['start']], idx_map[s['end'] - 1] + 1
                spans.append({**s, 'start': a, 'end': b, 'rule': (s.get('rule') or 'tier0') + '+cf'})
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
    (duck-typed into PrivacyGate.npu). Loads the model in its deployment form (fp16 on GPU), not INT8.
    This is the tier the dedicated GPU appliance box (spare 3090s) will run; max_len mirrors NPUTier (512)."""
    def __init__(self, model_dir, device='cuda', max_len=512):  # 512: see NPUTier note (256 truncated dense-chunk tails)
        import os as _os
        import torch
        from transformers import AutoTokenizer, AutoModelForTokenClassification
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_dir)
        # GPU_GATE_DTYPE=bfloat16 for bf16-trained bases (v12 openai/privacy-filter MoE: fp16
        # inference risks activation overflow in expert/router paths). Default float16 unchanged
        # for the xlm-r family (mirrors gate/privacy_gate.py).
        dtype = getattr(torch, _os.environ.get('GPU_GATE_DTYPE', 'float16'))
        self.model = AutoModelForTokenClassification.from_pretrained(
            model_dir, torch_dtype=dtype).to(device).eval()
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
            # cluster's primary so the downstream floor guards (policy + allowlist) see a floor label.
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


# ---------------- detect-time repeat propagation (workbench mid-doc name misses) ----------------
# 2026-07-05: mirror of gate/privacy_gate.py propagate_repeats (this appliance copy backs the local CPU gate
# unit via PYTHONPATH). Called ONLY by the gate services' detect_chunked over a full document; the egress
# wire path never calls it (live coding traffic keeps its own session sweep -- precision-first on the wire).
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
        # Person NAME TOKENS propagate too (mirrors gate copy): "Jean Tremblay" detected once must catch
        # bare "TREMBLAY" repeats; len>=4 keeps particles out.
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
