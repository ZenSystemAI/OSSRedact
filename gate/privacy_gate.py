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
import re, json
from collections import defaultdict

# ---------------- Tier 0: thin validated floor (checksum/format-exact catastrophic shapes only) ----------------
# Phase 2 (2026-06-14): the floor emits ONLY shapes that are checksum- or format-exact, so it is a
# never-leak safety net with near-zero false positives. Loose shapes (dates, amounts, bare digit runs,
# postal codes, phone numbers, IPs) are LEFT for the neural model, which owns recall AND labeling. This
# REMOVES the precision tax the old tier0 imposed (it over-fired on every number/date/postal/phone shape).
EMAIL_RE = re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b')
# UUID (8-4-4-4-12 hex) = connection/session/request IDs (e.g. Flinks login id). Never occurs by accident
# in natural text, so it is a deterministic catch at ~1.0 confidence, independent of the model threshold.
UUID_RE = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
# IBAN: 2-letter country + 2 check digits + 11-30 alphanumerics (internal single spaces allowed). Validated
# by the ISO 7064 mod-97 checksum (_iban_ok), so a match is a near-certain real IBAN with no precision risk.
IBAN_RE = re.compile(r'\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30})\b')
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
def _normseps(s: str) -> str:
    return _normspace(_normdash(s))

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
    s = re.sub(r'\s', '', s).upper()
    if not re.fullmatch(r'[A-Z]{2}\d{2}[A-Z0-9]+', s):
        return False
    s2 = s[4:] + s[:4]
    digits = ''.join(str(ord(c) - 55) if c.isalpha() else c for c in s2)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False

def validated_floor(text: str):
    """The thin never-leak floor: emit ONLY checksum/format-exact catastrophic shapes (email, UUID,
    mod-97 IBAN, Luhn card, Luhn SIN). Loose shapes (dates, amounts, bare digit runs, postal, phone, IP)
    are LEFT for the neural model, which owns recall AND labeling. Matching runs on a length-preserving
    _normseps copy, so the returned offsets index the ORIGINAL text the caller redacts."""
    spans = []
    t = _normseps(text)
    def add(s, e, lab, conf, rule, **extra):
        spans.append({'start': s, 'end': e, 'label': lab, 'tier': 0, 'conf': conf, 'rule': rule, **extra})
    for m in EMAIL_RE.finditer(t):
        add(m.start(), m.end(), 'email', 0.99, 'floor:email')
    for m in UUID_RE.finditer(t):
        add(m.start(), m.end(), 'sensitive_account_id', 0.99, 'floor:uuid')
    for m in IBAN_RE.finditer(t):
        if _iban_ok(m.group(1)):
            add(m.start(1), m.end(1), 'iban', 0.99, 'floor:iban', validator='mod97_ok')
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
        import torch
        from transformers import AutoTokenizer, AutoModelForTokenClassification
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(model_dir, trust_remote_code=trust_remote_code)
        self.model = AutoModelForTokenClassification.from_pretrained(
            model_dir, torch_dtype=torch.float16, trust_remote_code=trust_remote_code).to(device).eval()
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
def merge_spans(spans):
    # CONNECTED-COMPONENT UNION. A privacy gate must never leave a PII fragment exposed between two
    # overlapping detections. Greedy drop-the-loser does exactly that: model emits "21" inside a date, or a
    # spurious "password" on a UUID partially overlaps "21 mai 2026" -> whichever is dropped, half the date
    # leaks. So instead: any cluster of overlapping spans is redacted as ONE span covering their union. The
    # cluster's PRIMARY label is the highest-confidence (then longest) member's (used for the placeholder),
    # but ALL distinct member labels are recorded in 'labels' so a category filter / audit is not lied to.
    # The union text is what gets masked and stored for rehydration. Over-redaction is the safe error.
    if not spans:
        return []
    spans = sorted(spans, key=lambda s: (s['start'], -(s['end'] - s['start'])))
    out = []
    for s in spans:
        if out and s['start'] < out[-1]['end']:  # overlaps the current cluster
            cur = out[-1]
            cur['members'] = cur.get('members', 1) + 1
            cur['_labels'].add(s['label'])
            cand = (s['conf'], s['end'] - s['start'])
            if cand > (cur['_bc'], cur['_bl']):  # better label-bearer -> its provenance wins the cluster
                cur['label'] = s['label']; cur['tier'] = s['tier']; cur['_bc'], cur['_bl'] = cand
                cur['rule'] = s.get('rule'); cur['validator'] = s.get('validator')
                cur['cue'] = s.get('cue'); cur['subtype'] = s.get('subtype')
            cur['end'] = max(cur['end'], s['end'])
            cur['conf'] = max(cur['conf'], s['conf'])
        else:
            out.append({**s, '_bc': s['conf'], '_bl': s['end'] - s['start'], 'members': 1,
                        '_labels': {s['label']}})
    for m in out:
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
_CASE_SENSITIVE_LABELS = {'password', 'secret', 'username', 'access_token', 'api_key', 'file_path'}


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
    companion regex so credentials and paths that differ only by case stay lossless."""
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
    # Ordinary PII resolves case-insensitively. Case-significant labels resolve by exact text so two credentials
    # that differ only by case never collapse to one placeholder during the repeated-value sweep.
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
        spans = validated_floor(text)
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
        # Dedup placeholders by label + value. Ordinary PII keeps casefold dedup so "Jane"/"JANE" and
        # case-variant emails share a stable placeholder. Case-significant labels (credentials and paths) keep
        # exact-case values distinct so rehydrate is lossless for "AbC123" vs "abc123".
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
        # Ordinary PII sweeps case-insensitively. Credentials/paths sweep exact-case only to preserve lossless
        # rehydration when two distinct known values differ only by case.
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
    ap.add_argument('--model', default='models/pii-xlmr-quebec')
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
