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

# ---------------- Tier 0: deterministic ----------------
EMAIL_RE = re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b')
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
POSTAL_RE = re.compile(r'\b[A-Za-z]\d[A-Za-z]\s?\d[A-Za-z]\d\b')
# UUID (8-4-4-4-12 hex) = connection/session/request IDs (e.g. Flinks login id). Never occurs by accident
# in natural text, so it is a deterministic catch at ~1.0 confidence, independent of the model threshold.
UUID_RE = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
# digit runs with optional separators (space/dot/dash). Floor = 7 chars so a bare 7-digit bank account
# (common Canadian format) is caught deterministically, not left to the model. The digit-count gate below
# decides the label and rejects too-short noise.
DIGIT_RUN_RE = re.compile(r'(?<![\w])(\d[\d .\-]{5,}\d)(?![\w])')
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

# IBAN mod-97 deterministic backstop. BACKPORTED from gate/privacy_gate.py to close F14: the deployed floor
# had NO IBAN catch, so an IBAN the NER model missed had no deterministic guarantee (a catastrophic-tier
# financial ID with no backstop). A mod-97 pass is a near-certain real IBAN, so there is no precision risk.
IBAN_RE = re.compile(r'\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30})\b')
def _iban_ok(s: str) -> bool:
    s = re.sub(r'\s', '', s).upper()
    if not re.fullmatch(r'[A-Z]{2}\d{2}[A-Z0-9]+', s):
        return False
    s2 = s[4:] + s[:4]
    digits = ''.join(str(ord(c) - 55) if c.isalpha() else c for c in s2)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False

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
# 11-19 digit run; letter-adjacency ALLOWED (that is the gap DIGIT_RUN_RE leaves). Not digit-bounded.
_LONG_ID_RE = re.compile(r'(?<!\d)(\d(?:[ \-]?\d){10,18})(?!\d)')
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
    for m in POSTAL_RE.finditer(t): add(m.start(), m.end(), 'postal_code', 0.9, 'tier0:postal')
    for m in UUID_RE.finditer(t): add(m.start(), m.end(), 'sensitive_account_id', 0.99, 'tier0:uuid')
    for m in IBAN_RE.finditer(t):
        if _iban_ok(m.group(1)): add(m.start(1), m.end(1), 'iban', 0.99, 'tier0:iban', validator='mod97_ok')
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
def merge_spans(spans):
    # CONNECTED-COMPONENT UNION. A privacy gate must never leave a PII fragment exposed between two
    # overlapping detections. Greedy drop-the-loser does exactly that: model emits "21" inside a date, or a
    # spurious "password" on a UUID partially overlaps "21 mai 2026" -> whichever is dropped, half the date
    # leaks. So instead: any cluster of overlapping spans is redacted as ONE span covering their union. The
    # cluster's label is the highest-confidence (then longest) member's; the union text is what gets masked
    # and stored for rehydration. Over-redaction (a UUID swallowed with an adjacent date) is the safe error.
    if not spans:
        return []
    spans = sorted(spans, key=lambda s: (s['start'], -(s['end'] - s['start'])))
    out = []
    for s in spans:
        if out and s['start'] < out[-1]['end']:  # overlaps the current cluster
            cur = out[-1]
            cur['members'] = cur.get('members', 1) + 1
            cand = (s['conf'], s['end'] - s['start'])
            if cand > (cur['_bc'], cur['_bl']):  # better label-bearer -> its provenance wins the cluster
                cur['label'] = s['label']; cur['tier'] = s['tier']; cur['_bc'], cur['_bl'] = cand
                cur['rule'] = s.get('rule'); cur['validator'] = s.get('validator')
                cur['cue'] = s.get('cue'); cur['subtype'] = s.get('subtype')
            cur['end'] = max(cur['end'], s['end'])
            cur['conf'] = max(cur['conf'], s['conf'])
        else:
            out.append({**s, '_bc': s['conf'], '_bl': s['end'] - s['start'], 'members': 1})
    for m in out:
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

def _build_known_re(values):
    """Regex over already-known session entity VALUES (len>=4, word-boundary-guarded, longest-first).
    The known-entity backstop (Finding C): positional redaction masks only DETECTED span positions, so a value
    that repeats across a long/multi-page document (footers, repeated headers, line items) leaks at the
    occurrences the detector skipped. Pure deterministic, no model. Longest-first alternation makes the engine
    prefer the longer value at any position (so a 7-digit value can not be matched as a prefix of an 8-digit one).
    NOTE: Python stdlib re has no \\p{M}; we use \\w boundaries (letter/digit/underscore, ASCII-by-default), so a
    DECOMPOSED combining accent immediately adjacent to a value is not part of the guard. The egress proxy twin
    has the same limitation; the JS twin uses \\p{M}. Acceptable: over-masking is the safe error here anyway.
    Compiled IGNORECASE (Codex HIGH-1): a known value must be masked regardless of case, else "John" detected
    once leaks as "JOHN"/"john" elsewhere. _sweep_known resolves the placeholder via a casefolded lookup."""
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
    return re.compile('|'.join(parts), re.IGNORECASE)

def _sweep_known(text, known_re, value_to_placeholder):
    """Replace every literal occurrence of a known value with its EXISTING placeholder (never mint a new one),
    running ONLY on the literal segments BETWEEN already-inserted placeholders so it can never rewrite a
    placeholder the positional pass produced. Returns (text, n_swept). Over-masking an already-detected value
    is the safe error; rehydrate() restores every occurrence regardless of which pass inserted it."""
    if known_re is None:
        return text, 0
    # Case-insensitive resolution (Codex HIGH-1): known_re matches any case, so look up the placeholder by the
    # casefolded match. If two differently-cased values collide on casefold, first-wins is fine -- it still
    # masks, and rehydrate restores a same-PII value.
    cf_lookup = {}
    for v, ph in value_to_placeholder.items():
        cf_lookup.setdefault(v.casefold(), ph)
    n = 0
    def repl(m):
        nonlocal n
        ph = cf_lookup.get(m.group().casefold())
        if ph is None:
            return m.group()
        n += 1
        return ph
    # Split into literal gaps (swept) and placeholder tokens (preserved verbatim). A capture-free split drops
    # the delimiters, so parts.length == tokens.length + 1; reassemble interleaved so a value equal to a
    # placeholder token can never corrupt the token itself.
    parts = _PLACEHOLDER_TOKEN_RE.split(text)
    tokens = _PLACEHOLDER_TOKEN_RE.findall(text)
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
        # Dedup placeholders by CASEFOLDED value (Codex 2026-06-17): case variants of the same string are the
        # same sensitive token, so they share ONE placeholder. This keeps the case-insensitive Finding-C sweep
        # coherent -- the value->placeholder map can never hold two case-only-different values pointing at
        # DIFFERENT placeholders (which would restore the wrong original on rehydrate). Mirrors the TS twin
        # (buildEntityMap dedupKey lowercases) and the EntityMap session dedup.
        cf_to_ph = {}
        for s in spans:
            value = text[s['start']:s['end']]
            ph = cf_to_ph.get(value.casefold())
            if ph is None:
                counters[s['label']] += 1
                # Canonical angle-bracket placeholder (entity_map.py:116 / gate_service.py:94 / redaction-core):
                # UPPERCASE label, underscores preserved, 3-digit zero-padded counter. round-trips via rehydrate().
                ph = f"<{s['label'].upper()}_{counters[s['label']]:03d}>"
                cf_to_ph[value.casefold()] = ph
                mapping[ph] = value
            out.append(text[last:s['start']]); out.append(ph); last = s['end']
        out.append(text[last:])
        redacted = ''.join(out)
        # Finding C backstop: after the positional pass, sweep the redacted text for any repeated occurrence of
        # an already-known value the detector missed at OTHER positions, masking it with its EXISTING placeholder.
        # The map is now collision-free by casefold, so the sweep's case-insensitive lookup resolves uniquely.
        value_to_placeholder = {v: ph for ph, v in mapping.items()}
        known_re = _build_known_re(value_to_placeholder.keys())
        redacted, _ = _sweep_known(redacted, known_re, value_to_placeholder)
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
    print('IN  :', s)
    print('OUT :', red)
    print('MAP :', {k: v for k, v in mp.items()})
    print('TIERS:', [(sp['label'], 't%d' % sp['tier']) for sp in spans])
    print('ROUNDTRIP OK:', PrivacyGate.rehydrate(red, mp) == s)
    print()

if __name__ == '__main__':
    import argparse, sys
    ap = argparse.ArgumentParser()
    ap.add_argument('--model', default='/home/steven/Sparx/models/privacy-filters/pii-npu-xlmr-quebec-v1')
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
        red, mp, spans = gate.redact(s)
        print('IN  :', s)
        print('OUT :', red)
        print('MAP :', {k: v for k, v in mp.items()})
        print('TIERS:', [(text_lab['label'], 't%d' % text_lab['tier']) for text_lab in spans])
        rehyd = PrivacyGate.rehydrate(red, mp)
        print('ROUNDTRIP OK:', rehyd == s)
        print()
