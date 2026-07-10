// Client-side Tier-0 deterministic detector -- a faithful TypeScript port of the appliance's
// privacy_gate.py tier0_spans() (regex + Luhn + Presidio-style context-cue promotion).
//
// Runs ENTIRELY in the browser: the document never leaves the machine for auto-detect. This is the
// highest-precision tier (structured / number-shaped PII) and needs no model. The neural NPU tier
// (names, addresses, free-text PII) stays an OPTIONAL call to the local appliance (see gate.ts).
//
// Parity note: JS `\w` in lookbehind/ahead is ASCII (Python's is Unicode), so a digit run glued to an
// accented letter is treated marginally differently. Immaterial here -- this is a SUGGESTION layer the
// user reviews; the appliance remains authoritative for egress.
//
// MAINTENANCE: This file is a hand-maintained port of gate/privacy_gate.py validated_floor / tier0_spans.
// Any change to gate/privacy_gate.py detectors (IBAN, Luhn, etc.) must be mirrored here by hand until
// direction D1 (unified detector source) lands.

import type { RawSpan } from './types'

// Unicode dash variants -> ASCII hyphen. PDF extraction emits en-dash/em-dash as separators, which
// otherwise split structured IDs ("006–02761–1234567" seen as 3 short groups). Single-char -> single-char,
// so it is LENGTH-PRESERVING and offsets map 1:1 back onto the original text.
const DASH_RE = /[‐‑‒–\u2014―−⁃﹘﹣－]/g
export function normDash(s: string): string {
  return s.replace(DASH_RE, '-')
}

// Length-preserving unicode-space -> ASCII space (offsets still map 1:1). pdf.js NFKC-normalizes these on the
// PDF path, but the .docx text path does not, and French/OQLF digit grouping commonly uses NBSP / narrow-NBSP
// between digit groups ("123 456 789"), which would otherwise defeat the digit-run / long-id separators.
const SPACE_RE = /[  -   　	]/g
export function normSpace(s: string): string {
  return s.replace(SPACE_RE, ' ')
}

// Unicode DIGIT homoglyphs that aren't ASCII 0-9 (SUPERSCRIPT/SUBSCRIPT/circled = category No, which \d never
// matches): map every single-codepoint digit-valued char to its ASCII digit so "card ⁴¹¹¹..." engages the
// digit floor (NFKC-reconstructable card must not leave verbatim). Per-char NFKC yields a single ASCII digit
// for these (length-preserving, offsets map 1:1); also folds non-ASCII Nd (fullwidth, Arabic-Indic) to ASCII.
// Mirrors privacy_gate.py _normdigits.
export function normDigits(s: string): string {
  // fast path: plain ASCII has no homoglyph digits
  // eslint-disable-next-line no-control-regex
  if (!/[^\x00-\x7f]/.test(s)) return s
  let out = ''
  for (const ch of s) {
    // Only fold a BMP single-UTF-16-unit char (super/subscript/fullwidth digits are all BMP) so the
    // replacement stays length-preserving and offsets map 1:1. Astral math digits (2 units) are left as-is.
    if (ch.length === 1 && !(ch >= '0' && ch <= '9')) {
      const nf = ch.normalize('NFKC')
      if (nf.length === 1 && nf >= '0' && nf <= '9') { out += nf; continue }
    }
    out += ch
  }
  return out
}

// Mirrors privacy_gate.py _normseps: dash + space + digit-homoglyph normalization, all length-preserving.
export function normSeps(s: string): string {
  return normDigits(normSpace(normDash(s)))
}

// Case-normalize runs of >=2 uppercase letters to Title case for a second neural pass (length-preserving,
// offsets map 1:1). Recovers ALL-CAPS names the case-sensitive model misses. Used by gate.ts only.
const CAPS_RUN = /[A-ZÀ-ÖØ-Þ]{2,}/g
export function normCase(s: string): string {
  return s.replace(CAPS_RUN, (m) => m.charAt(0) + m.slice(1).toLowerCase())
}

// Zero-width / format (Unicode category Cf) + CONTROL (category Cc: TAB U+0009, LF, VT, FF, CR, and the C0/C1
// separators FS/GS/RS/US U+001C-001F) + soft-hyphen interleaving INVISIBLY breaks every Tier-0
// number/identifier regex: "4<U+200B>1<TAB>1<U+200B>1..." has digit-run separators a human and the upstream
// LLM never see, so the deterministic floor returns 0 spans and the real card/IBAN/SIN ships raw.
// normSpace/normDash only map spaces/dashes, never these. Fix: strip Cf AND Cc codepoints to a clean copy,
// re-run the Tier-0 scan there, and map each span back onto the ORIGINAL offsets so the mask covers the value
// AND the interleaved invisibles. (Soft hyphen U+00AD is Cf; ZWSP/ZWNJ/ZWJ/WORD-JOINER/BOM are Cf too; TAB and
// the C0 control separators are Cc -- two Unicode category tests cover them all.) Mirrors privacy_gate.py
// _has_format_chars / _strip_format_chars (_INVISIBLE_CATS = ('Cf','Cc')). Parity: Python uses
// unicodedata.category(ch) in ('Cf','Cc'); JS `\p{Cf}|\p{Cc}` (i.e. `[\p{Cf}\p{Cc}]`) under `u` is the same.
const FORMAT_CHAR_RE = /[\p{Cf}\p{Cc}]/u
export function hasFormatChars(s: string): boolean {
  return FORMAT_CHAR_RE.test(s)
}

// Return [clean, idxMap]: clean has every Cf/Cc codepoint removed; idxMap[j] = ORIGINAL (UTF-16) index of the
// clean character occupying UTF-16 unit j, with a trailing sentinel idxMap[clean.length] = text.length so an
// end offset always maps. tier0Spans operates on UTF-16 string indices (m.index / slice), so idxMap is keyed
// per-UTF-16-unit of clean (each retained code point contributes ch.length entries, all pointing at its
// original start). Mirrors privacy_gate.py _strip_format_chars (Python indexes by code point; for BMP PII the
// two coincide, and this UTF-16 form stays correct even if a non-Cf/Cc astral char sits beside the value).
const FORMAT_CHAR_TEST = /[\p{Cf}\p{Cc}]/u
export function stripFormatChars(text: string): [string, number[]] {
  const chars: string[] = []
  const idxMap: number[] = []
  let i = 0
  for (const ch of text) {
    if (!FORMAT_CHAR_TEST.test(ch)) {
      chars.push(ch)
      for (let k = 0; k < ch.length; k++) idxMap.push(i) // one entry per UTF-16 unit -> original start
    }
    i += ch.length // advance by UTF-16 code units so offsets stay in string-index space
  }
  const clean = chars.join('')
  idxMap.push(text.length)
  return [clean, idxMap]
}

export function luhnOk(digits: string): boolean {
  let sum = 0
  const rev = digits.split('').reverse()
  for (let i = 0; i < rev.length; i++) {
    let d = rev[i].charCodeAt(0) - 48
    if (d < 0 || d > 9) return false
    if (i % 2 === 1) {
      d *= 2
      if (d > 9) d -= 9
    }
    sum += d
  }
  return sum % 10 === 0
}

// Unicode-aware: JS `\w`/`\b` are ASCII-only, so the old /\b[\w.+-]+@.../ leaked accented local-parts
// (francois@, claude@ with accents) -- the French/Quebec market this targets. Python's `re` `\w` is Unicode
// by default, so this mirrors the appliance EMAIL_RE. \p{L}\p{N} (with the `u` flag) cover accented letters;
// the domain is matched as dotted alnum labels so a trailing sentence period is not swallowed into the span.
// The leading lookbehind is a Unicode-aware boundary (JS `\b` could not be) AND prunes start positions: it
// stops the regex from re-attempting at every char of a long '.'/'-' run, which is in the local-part class --
// without it a pathological dotted line (PDF leader, markdown rule) is O(n^2) and blocks the main thread.
// Alphabetic-TLD tail (mirrors the 2026-07-02 appliance/gate EMAIL_RE contract): npm/version pins like
// "unpkg@1.1.0" matched the old any-label tail and minted EMAIL spans on every package pin. A real
// deliverable address ends in a letters-only label; user@192.168.1.1 loses its email span but IP_RE
// still owns the IP part.
const EMAIL_RE = /(?<![\p{L}\p{N}_.+-])[\p{L}\p{N}_.+-]+@[\p{L}\p{N}_-]+(?:\.[\p{L}\p{N}_-]+)*\.[A-Za-z]{2,}(?![\p{L}\p{N}])/gu
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const POSTAL_RE = /\b[A-Za-z]\d[A-Za-z]\s?\d[A-Za-z]\d\b/g
const UUID_RE = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g
const NAM_RE = /\b([A-Z]{4} \d{4} ?\d{4})\b/g

// IBAN: 2-letter country + 2 check digits + 11-30 alphanumerics (single internal spaces/hyphens allowed).
// Validated by ISO 7064 mod-97 (ibanOk) -> a match is a near-certain real IBAN.
// Port of privacy_gate.py IBAN_RE + _iban_ok. BigInt used because the digit string overflows Number.
const IBAN_RE = /\b([A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?:[ -][A-Z0-9]{2,4}){3,8}))\b/gi
export function ibanOk(s: string): boolean {
  const c = s.replace(/[\s-]/g, '').toUpperCase()
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(c)) return false
  const r = c.slice(4) + c.slice(0, 4)
  let digits = ''
  for (const ch of r) digits += ch >= 'A' && ch <= 'Z' ? String(ch.charCodeAt(0) - 55) : ch
  try {
    return BigInt(digits) % 97n === 1n
  } catch {
    return false
  }
}

function validIbanCandidate(raw: string): string | null {
  let candidate = raw
  while (candidate) {
    if (ibanOk(candidate)) return candidate
    const cut = Math.max(candidate.lastIndexOf(' '), candidate.lastIndexOf('-'))
    if (cut <= 4) break
    candidate = candidate.slice(0, cut)
  }
  return null
}

// A bank/identity digit run: digit groups joined by a SINGLE space or hyphen (Quebec/OQLF grouping like
// "123 456 789" or "006-02761-1234567"). v11 fix: dropped '.' from the separator class and forbade ending
// right before a decimal ((?![\w.])) + leading (?<![\w.]) -- so the run no longer swallows the transaction
// AMOUNT that follows a bank-statement account/target on the same line ("...55566677788 1.50 $ 507.40 $"):
// the amount sits after a WIDER gap (>=2 spaces breaks the single-separator run) and carries a ".dd" decimal
// (the leading/trailing dot-boundaries exclude it). General across bank statements, not just flinks.
const DIGIT_RUN_RE = /(?<![\w.])(\d+(?:[ \-]\d+)*)(?![\w.])/g

// Date-shaped digit runs: a DIGIT_RUN_RE run that is really a DATE, not an account id -- a coding agent
// passes '2026-07-01' / '20260701' / 'context-1m-2025-08-07' constantly, and masking those as account ids
// balloons the entity map and breaks the agent's own diffs. Three shapes, HYPHEN-only separators (space-
// grouped runs stay account-shaped: real account/transit groupings use spaces): ISO Y-M-D with an optional
// trailing " HH" log hour, hyphenated D-M-Y / M-D-Y, and compact YYYYMMDD (build/date stamps). Anchored
// (^...$) against the whole run + month/day range-validated so a 16-digit card or a "2026-99-99" account
// never masquerades as a date. Mirrors privacy_gate.py _DATE_SHAPED_RES / _date_shaped.
const DATE_SHAPED_RES: RegExp[] = [
  /^(19|20)\d{2}-(\d{1,2})-(\d{1,2})( \d{1,2})?$/, // Y-M-D (+ optional glued log hour)
  /^(\d{1,2})-(\d{1,2})-((?:19|20)\d{2})$/, // D-M-Y / M-D-Y
  /^(19|20)(\d{2})(\d{2})(\d{2})$/, // compact YYYYMMDD
]
export function dateShaped(raw: string): boolean {
  let m = DATE_SHAPED_RES[0].exec(raw)
  if (m) return +m[2] >= 1 && +m[2] <= 12 && +m[3] >= 1 && +m[3] <= 31
  m = DATE_SHAPED_RES[1].exec(raw)
  if (m) {
    const a = +m[1]
    const b = +m[2]
    return (a >= 1 && a <= 31 && b >= 1 && b <= 12) || (a >= 1 && a <= 12 && b >= 1 && b <= 31)
  }
  m = DATE_SHAPED_RES[2].exec(raw)
  if (m) return +m[3] >= 1 && +m[3] <= 12 && +m[4] >= 1 && +m[4] <= 31
  return false
}
const PHONE_RE = /(?<![\w])(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}(?![\w])/g
const BARE_TEN_DIGITS_RE = /^\d{10}$/

// Canadian Business Number program-account suffix (RT=GST/HST, RP=payroll, RC=corp tax, RZ/RM/RR/RG=other).
// A 9-digit Luhn number IMMEDIATELY followed by this is a Business Number (the GST/QST registration printed
// on every invoice), NOT a SIN. Suppress it so the client floor stops mislabeling + over-redacting public
// merchant tax ids -- UNLESS a SIN cue precedes the number (then a real SIN must win the never-leak
// guarantee). Mirrors gate/privacy_gate.py exactly: single space/hyphen separator (no newline), (?!\d) not
// \b for engine parity. See validation/RESULT-realworld-expenses.md (Finding A) + the Codex review.
const BN_PROGRAM_SUFFIX_RE = /^[ \-]?(?:RT|RP|RC|RZ|RM|RR|RG)[ \-]?\d{4}(?!\d)/i
// nas/sin are ASCII-word-boundary-gated (else "Business"/"casino"/"using" would falsely fire the override and
// un-suppress a real BN -- Codex round 2) and tolerate dotted forms (N.A.S., S.I.N.). Mirrors privacy_gate.py.
const SIN_CUE_RE = /(?:(?<![a-z])(?:n\.?a\.?s|s\.?i\.?n)(?![a-z])|social\s*insurance|assurance\s*sociale|num[ée]ro\s*d.?assurance)/i

const MONTHS =
  'jan(?:vier|uary)?|f[eé]v(?:rier)?|feb(?:ruary)?|mar(?:s|ch)?|avr(?:il)?|apr(?:il)?|mai|may|' +
  'juin|june|juil(?:let)?|jul(?:y)?|ao[uû]t|aug(?:ust)?|sep(?:t(?:embre|ember)?)?|' +
  'oct(?:obre|ober)?|nov(?:embre|ember)?|d[eé]c(?:embre|ember)?'
const DATE_RE = new RegExp(
  '\\b(\\d{1,2}\\s+(?:' +
    MONTHS +
    ')\\s+\\d{4}|(?:' +
    MONTHS +
    ')\\.?\\s+\\d{1,2},?\\s+\\d{4}' +
    '|\\d{4}-\\d{2}-\\d{2}|\\d{1,2}[/.]\\d{1,2}[/.]\\d{2,4})\\b',
  'gi',
)

// Context-cued structured IDs (Presidio LemmaContextAwareEnhancer pattern). A long digit run GLUED to
// letters is rejected by DIGIT_RUN_RE's word boundary (else every digit-bearing code token would redact).
// When a financial/identity CUE sits adjacent, PROMOTE it: recall win on real prose, ~0 code false-positives.
const ID_CUE_RE =
  /(?<![a-z0-9é])(?:r[ée]f(?:[ée]rence)?|confirmation|transaction|virement|transfert|transfer|interac|paiement|payment|ch[èe]que|cheque|facture|invoice|dossier|folio|compte|account|acct|transit|autorisation|authorization|mandat|num[ée]ro|n°|nas|sin|sdi|imp[oô]t|ramq|iban)(?![a-z])/i
// 9-19 digit run; letter-adjacency ALLOWED (the gap DIGIT_RUN_RE leaves). The 9-10 digit low end is cue-gated
// here (a financial/identity cue must be adjacent) so it does NOT over-redact code identifiers -- a non-Luhn
// SSN/account glued to a CUE word ("account 0781234567") is caught; glued to a non-cue word it is not (that
// residual is accepted to keep coding traffic clean -- see gluedDigitSpans). Mirrors privacy_gate.py _LONG_ID_RE.
const LONG_ID_RE = /(?<!\d)(\d(?:[ \-]?\d){8,18})(?!\d)/g
const CUE_BEFORE = 24
const CUE_AFTER = 12

const EMAIL_ANCHOR_RE = /<[ \t]*[\p{L}\p{N}_.+-]+@[\p{L}\p{N}_-]+(?:\.[\p{L}\p{N}_-]+)+[ \t]*>/gu
// statement-header cues (2026-07-08, plan 049) added to the mail/header set: the account holder / member
// name printed at the top of a bank statement, colon-anchored and line-anchored like the mail headers.
const HDR_CUE_RE =
  /^[ \t]*(?:from|to|cc|bcc|reply-to|sender|author|co-authored-by|signed-off-by|owner|titulaire|propri[ée]taire|attn|attention|nom|client(?:e)?|membre|member|account\s+holder|prepared\s+for|pr[ée]par[ée]\s+pour)[ \t]*:[ \t]*/gim
const NAME_TOKEN_RE = /\p{L}+(?:['’.\-]\p{L}+)*/gu
export const NAME_PARTICLES = new Set(['van', 'von', 'de', 'der', 'den', 'del', 'della', 'di', 'da', 'du', 'la', 'le', 'el', 'bin', 'ibn', 'al', 'dos', 'das', 'do', 'of', 'and'])
export const NAME_ROLE_DENY = new Set([
  'support',
  'sales',
  'billing',
  'info',
  'admin',
  'noreply',
  'no-reply',
  'notifications',
  'notification',
  'team',
  'contact',
  'hello',
  'help',
  'marketing',
  'security',
  'abuse',
  'postmaster',
  'mailer-daemon',
  'do-not-reply',
  'donotreply',
  'newsletter',
  'accounts',
  'service',
  'services',
  'sender',
  'recipient',
  'no_reply',
])

// Quebec cue-gated IDs are TS-only client over-detection; the Python floor has no cue path.
const SAAQ_LICENCE_RE = /(?<![A-Za-z0-9])([A-Za-z]\d{12})(?![A-Za-z0-9])/g
const SAAQ_CUE_RE = /(?<![a-z0-9é])(?:permis|licen[cs]e|saaq)(?![a-z])/i
const NEQ_RE = /(?<![A-Za-z0-9])(\d{10})(?![A-Za-z0-9])/g
const NEQ_CUE_RE = /(?<![a-z0-9é])(?:neq|entreprise|registraire)(?![a-z])/i

function nearbyCue(t: string, start: number, end: number, cueRe: RegExp): RegExpMatchArray | null {
  const before = t.slice(Math.max(0, start - CUE_BEFORE), start)
  const after = t.slice(end, end + CUE_AFTER)
  return before.match(cueRe) || after.match(cueRe)
}

function quebecCuedIdSpans(text: string): RawSpan[] {
  const out: RawSpan[] = []
  const t = normSeps(text)

  for (const m of t.matchAll(SAAQ_LICENCE_RE)) {
    const start = m.index!
    const end = start + m[1].length
    const cm = nearbyCue(t, start, end, SAAQ_CUE_RE)
    if (cm) {
      out.push({
        start,
        end,
        label: 'sensitive_account_id',
        tier: 0,
        conf: 0.65,
        rule: 'tier0:saaq_licence',
        cue: cm[0].toLowerCase(),
        subtype: 'saaq_licence',
      })
    }
  }

  for (const m of t.matchAll(NEQ_RE)) {
    const start = m.index!
    const end = start + m[1].length
    const cm = nearbyCue(t, start, end, NEQ_CUE_RE)
    if (cm) {
      out.push({
        start,
        end,
        label: 'sensitive_account_id',
        tier: 0,
        conf: 0.9,
        rule: 'tier0:neq',
        cue: cm[0].toLowerCase(),
        subtype: 'neq',
      })
    }
  }

  return out
}

export function contextCuedIdSpans(text: string): RawSpan[] {
  const out: RawSpan[] = []
  const t = normSeps(text)
  for (const m of t.matchAll(LONG_ID_RE)) {
    let s = m.index!
    let e = s + m[1].length
    const left = s > 0 ? t[s - 1] : ' '
    const right = e < t.length ? t[e] : ' '
    if (!(isAlpha(left) || isAlpha(right))) continue // clean boundary -> already owned by DIGIT_RUN_RE
    const before = t.slice(Math.max(0, s - CUE_BEFORE), s)
    const after = t.slice(e, e + CUE_AFTER)
    const cm = before.match(ID_CUE_RE) || after.match(ID_CUE_RE)
    if (cm) {
      // expand over the GLUED alphanumeric run so the whole identifier (e.g. X1234567890123A) is covered,
      // not just the digit core -- the glued letter is what promoted it and must not be left exposed.
      while (s > 0 && isAlnum(t[s - 1])) s--
      while (e < t.length && isAlnum(t[e])) e++
      out.push({
        start: s,
        end: e,
        label: 'sensitive_account_id',
        tier: 0,
        conf: 0.55,
        rule: 'tier0:context_cue',
        cue: cm[0].toLowerCase(),
      })
    }
  }
  return out
}

function gapOnly(gap: string): boolean {
  return gap.replace(/[ \t"'’]/g, '') === ''
}

export function nameShaped(value: string): boolean {
  const s = value.trim().replace(/^"+|"+$/g, '').trim()
  const words = s.split(/\s+/).filter(Boolean)
  if (s.length < 2 || s.length > 60 || words.length < 1 || words.length > 5 || /\d/.test(s)) return false
  if (NAME_ROLE_DENY.has(s.toLowerCase()) || words.every((w) => NAME_ROLE_DENY.has(w.toLowerCase()))) return false

  let hasCap = false
  for (const w of words) {
    const core = w.replace(/[-'’.]/g, '')
    if (!core || ![...core].every((ch) => /\p{L}/u.test(ch))) return false
    if (w[0] === w[0].toUpperCase() && w[0] !== w[0].toLowerCase()) hasCap = true
    else if (!NAME_PARTICLES.has(w.toLowerCase())) return false
  }
  return hasCap
}

function isNameToken(tok: string): boolean {
  const first = tok[0] ?? ''
  return ((first === first.toUpperCase() && first !== first.toLowerCase()) || NAME_PARTICLES.has(tok.toLowerCase())) && !NAME_ROLE_DENY.has(tok.toLowerCase())
}

function nameTokens(t: string, start = 0, stop = t.length): Array<{ tok: string; start: number; end: number }> {
  return [...t.slice(start, stop).matchAll(NAME_TOKEN_RE)].map((m) => ({
    tok: m[0],
    start: start + m.index!,
    end: start + m.index! + m[0].length,
  }))
}

function nameRunBefore(t: string, end: number): [number, number] | null {
  const toks = nameTokens(t, 0, end)
  if (toks.length === 0 || !gapOnly(t.slice(toks[toks.length - 1].end, end))) return null
  const chosen: Array<{ start: number; end: number }> = []
  let next = end
  for (let i = toks.length - 1; i >= 0; i--) {
    const { tok, start, end: tokEnd } = toks[i]
    if (!gapOnly(t.slice(tokEnd, next)) || !isNameToken(tok)) break
    chosen.push({ start, end: tokEnd })
    next = start
    if (chosen.length >= 5) break
  }
  while (chosen.length && NAME_PARTICLES.has(t.slice(chosen[chosen.length - 1].start, chosen[chosen.length - 1].end).toLowerCase())) chosen.pop()
  return chosen.length ? [chosen[chosen.length - 1].start, chosen[0].end] : null
}

function nameRunAfter(t: string, start: number, stop: number): [number, number] | null {
  const chosen: Array<{ start: number; end: number }> = []
  let prev = start
  for (const { tok, start: tokStart, end } of nameTokens(t, start, stop)) {
    if (!gapOnly(t.slice(prev, tokStart)) || !isNameToken(tok)) break
    chosen.push({ start: tokStart, end })
    prev = end
    if (chosen.length >= 5) break
  }
  while (chosen.length && NAME_PARTICLES.has(t.slice(chosen[0].start, chosen[0].end).toLowerCase())) chosen.shift()
  return chosen.length ? [chosen[0].start, chosen[chosen.length - 1].end] : null
}

// Cue-gated ID/phone/DOB backstop (2026-07-07) -- TS twin of privacy_gate.cue_digit_spans, driven by
// the v12 miss inventory. Every emission is cue-GATED (never a bare shape); minDigits blocks a
// letters-only word after a cue; BN program accounts stay suppressed (public GST/QST registrations);
// NEQ/TVQ deliberately absent (public registry). Parity cases live in validation/parity_vectors.json.
const CUE_SEP = String.raw`[ \t]*[:#=|]?[ \t]*`
const MONTHS_ALT =
  String.raw`janv(?:ier)?|f[ée]vr(?:ier)?|mars|avril|mai|juin|juil(?:let)?|ao[ûu]t|sept(?:embre)?|` +
  String.raw`oct(?:obre)?|nov(?:embre)?|d[ée]c(?:embre)?|january|february|march|april|may|june|july|` +
  String.raw`august|september|october|november|december`
const DATE_SHAPE =
  String.raw`(?:\d{4}-\d{2}-\d{2}|\d{1,2}[/.]\d{1,2}[/.]\d{2,4}|` +
  String.raw`(?:${MONTHS_ALT})\.?\s+\d{1,2},?\s+\d{4}|\d{1,2}(?:er)?\s+(?:${MONTHS_ALT})\.?\s+\d{4})`
const CUE_DIGIT_RULES: Array<{ label: string; re: RegExp; minDigits: number }> = [
  {
    label: 'sensitive_account_id',
    re: new RegExp(String.raw`(?<![\w])(?:code\s+d[' ]acc[eè]s\s+netfile|netfile\s+access\s+code)${CUE_SEP}([A-Z0-9]{6,12})`, 'gi'),
    minDigits: 1,
  },
  {
    label: 'sensitive_account_id',
    re: new RegExp(
      String.raw`(?<![\w])(?:num[ée]ro\s+de\s+police|no\.?\s+de\s+police|policy\s+(?:number|no\.?)|` +
        String.raw`num[ée]ro\s+du\s+document(?:\s+d[ée]livr[ée])?|issued\s+document\s+number|` +
        String.raw`num[ée]ro\s+de\s+dossier|no\.?\s+de\s+dossier|(?:credit\s+)?file\s+(?:number|no\.?))` +
        String.raw`${CUE_SEP}([A-Z0-9][\dA-Z -]{3,20}[\dA-Z])`,
      'gi',
    ),
    minDigits: 2,
  },
  {
    label: 'account_number',
    re: new RegExp(
      String.raw`(?<![\w])(?:num[ée]ro\s+de\s+compte|no\.?\s+de\s+compte|compte(?:\s+ch[eè]que)?|account\s+(?:number|no\.?)|acct\.?|folio)` +
        String.raw`${CUE_SEP}(\d(?:[ -]?\d){4,16})`,
      'gi',
    ),
    minDigits: 5,
  },
  {
    label: 'phone_number',
    re: new RegExp(
      String.raw`(?<![\w])(?:t[ée]l[ée]phone|t[ée]l\.?|telephone|cellular|cellulaire|mobile|` +
        String.raw`num[ée]ro\s+de\s+service|(?:subscriber\s+)?service\s+number)[,]?` +
        String.raw`${CUE_SEP}((?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]\d{4})`,
      'gi',
    ),
    minDigits: 10,
  },
  {
    label: 'date_of_birth',
    re: new RegExp(
      String.raw`(?<![\w])(?:n[ée]\(?e?\)?\s+le|born(?:\s+on)?|date\s+de\s+naissance|date\s+of\s+birth|dob|naissance)` +
        String.raw`${CUE_SEP}(${DATE_SHAPE})`,
      'gi',
    ),
    minDigits: 4,
  },
]
// (BN_PROGRAM_SUFFIX_RE is declared once earlier in this file -- reused below.)

export function cueDigitSpans(text: string): RawSpan[] {
  const spans: RawSpan[] = []
  const seen = new Set<string>()
  for (const { label, re, minDigits } of CUE_DIGIT_RULES) {
    for (const m of text.matchAll(re)) {
      const val = m[1]
      const start = m.index! + m[0].length - val.length
      const end = start + val.length
      if (text.slice(m.index!, start).includes('\n')) continue // cue and value must share a line
      if ((val.match(/\d/g) ?? []).length < minDigits) continue
      if (label === 'account_number') {
        const digits = val.replace(/\D/g, '')
        if (digits.length === 9 && BN_PROGRAM_SUFFIX_RE.test(text.slice(end, end + 9))) continue
      }
      const key = `${start}:${end}`
      if (seen.has(key)) continue
      seen.add(key)
      spans.push({ start, end, label, tier: 0, conf: 0.92, rule: 'tier0:cue_digit' })
    }
  }
  return spans
}

// ---- e-transfer / bank-ledger counterparty-name floor (2026-07-08, plan 049) -- TS twin of
// privacy_gate.cue_name_spans e-transfer path. A class of counterparty NAMES leaks from bank statements:
// they sit after a bank-specific ledger cue ("VIR INTERAC RECU <name>", "E-TRANSFER <ref> <name>", RBC
// "Depot auto - virements par courriel <name> <ref>", Desjardins slash "Interac e-Transfer from /<name> /").
// The cue grammar is deterministic; the neural tier misses these (no prose, often lowercase/ALL-CAPS/ref-
// truncated). Cues are SPECIFIC multi-word financial phrases; a cue-anchored over-mask is the safe error.
export const LEDGER_STOPWORDS = new Set([
  'fonds', 'admis', 'ca', 'no', 'ref', 'reference', 'cad', 'usd', 'id', 'conf', 'confirmation',
  'interac', 'etrnsr', 'etransfer', 'transfer', 'transfert', 'virement', 'virements', 'vir', 'dep', 'auto',
  'rec', 'recu', 'reçu', 'recvd', 'received', 'sent', 'envoye', 'envoyé', 'envoi', 'annule', 'annulé',
  'autodeposit', 'deposit', 'depot', 'dépôt', 'courriel', 'par', 'en', 'ligne', 'from', 'to', 'cancellation',
  'rent', 'lease', 'prepared', 'préparé', 'pour', 'nom', 'client', 'cliente', 'membre', 'member',
  // entity suffixes -- never part of a personal-name span ('me' = Maître stays here: too common a word)
  'me', 'ing', 'inc', 'ltd', 'ltee', 'ltée', 'corp',
  // amount/currency words (an "E-TRANSFER 123456 dollars" prose form must not mint a person)
  'dollars', 'dollar', 'euros', 'euro', 'cents', 'cts',
  // function words / generic nouns after a prose colon-cue -- never part of a name
  'the', 'a', 'an', 'my', 'your', 'this', 'that', 'account', 'compte', 'amount', 'montant',
  'solde', 'achat', 'paiement', 'retrait', 'frais', 'cheque', 'chèque', 'facture', 'remboursement',
  'retour', 'total', 'balance', 'depot',
])
// Honorifics are NOT stopwords: "VIR INTERAC RECU MME MARIE DUPUIS" must still floor the name (Codex review
// 2026-07-08 HIGH: a leading honorific used to terminate the run and drop the whole name). The ledger scanner
// SKIPS leading honorifics (kept out of the span); mid-run they ride along as ordinary tokens (safe over-mask).
const LEDGER_HONORIFICS = new Set(['mme', 'mlle', 'mr', 'mrs', 'ms', 'dr', 'madame', 'monsieur'])
// Log/code status words a person span must never GROW over (and never propagate as name tokens): the model
// tags "John" in "INFO user=John Error Retrying" and unguarded absorption would mask "Error" document-wide
// (Codex review 2026-07-08 MEDIUM -- the fat-floor lesson applied to growth).
export const GROW_STATUS_DENY = new Set([
  'error', 'errors', 'warning', 'warn', 'info', 'debug', 'trace', 'fatal', 'panic', 'exception',
  'traceback', 'failed', 'failure', 'fail', 'retry', 'retrying', 'timeout', 'denied', 'invalid',
  'unknown', 'null', 'none', 'true', 'false', 'undefined', 'nan', 'success', 'started', 'stopped',
  'killed', 'deprecated', 'todo', 'fixme', 'notice', 'pending', 'alert', 'critical', 'severe',
  // French log/status vocabulary (Codex re-verify: 'John Erreur Reessayer' absorbed+propagated)
  'erreur', 'erreurs', 'avertissement', 'attention', 'reessayer', 'réessayer',
  'succes', 'succès', 'echec', 'échec', 'demarre', 'démarré', 'arrete', 'arrêté', 'termine', 'terminé',
  'annulation', 'refuse', 'refusé', 'valide', 'validé', 'expire', 'expiré',
])
// NON-slash cues: each alternative consumes up to the whitespace before the name (incl. the leading numeric
// reference for the CIBC E-TRANSFER form). Keyword forms are ordered BEFORE the generic E-TRANSFER catch.
const ETRANSFER_CUE_RE = new RegExp(
  '(?:' +
    String.raw`vir\s+interac\s+(?:dep\s+auto\s+rec|recu|re[çc]u|envoy[eé]|annul[eé])` +
    String.raw`|interac\s+(?:etrnsfr|etrnsr)\s+(?:ad\s+recvd|recvd|sent)` +
    String.raw`|d[eé]p[oô]t\s+auto\s*-\s*virements?\s+par\s+courriel` +
    String.raw`|virement\s+(?:en\s+ligne\s+)?(?:envoy[eé]|recu|re[çc]u)` +
    String.raw`|e-?transfer\s*-\s*autodeposit` +
    String.raw`|e-?transfer\s+sent` +
    String.raw`|e-?transfer\s+(?:to|from)\s*:` +
    String.raw`|e-?transfer\s+\d{6,}(?:\s*[;:,]\s*|\s+)` +
    String.raw`)[ \t]*`,
  'gi',
)
// Desjardins slash fields: name between/after slashes. Cue ends right after the OPENING slash.
const ETRANSFER_SLASH_RE = /(?:(?:cancellation[ \-]*)?interac\s+e-?transfer\s+(?:from|to)|rent\s*\/\s*lease)\s*\/\s*/gi
const LEDGER_COLGAP_RE = /  +|\t/
// NARROW initial: a single letter or a dotted run (A, A., M.C.) -- NOT an all-caps word (FONDS).
// Used where the check runs BEFORE the stopword test, so 'A' beats the article but 'FONDS' cannot.
const LEDGER_INITIAL_NARROW_RE = /^[A-Z](?:\.[A-Z])*\.?$/
const LEDGER_TRIM_RE = /^[.,;:()'"’-]+|[.,;:()'"’-]+$/g

// Like nameShaped but WITHOUT the leading-capital requirement -- for cue-anchored ledger fields where
// lowercase counterparty names are common (CIBC 'delyna morvan', RBC 'barb'). Cue-anchored, so a lowercase
// over-mask is the safe error; nameShaped itself is unchanged for the header/email paths.
export function nameShapedRelaxed(value: string): boolean {
  const s = value.trim().replace(/^"+|"+$/g, '').trim()
  const words = s.split(/\s+/).filter((w) => w && w !== '-') // a lone hyphen is a run CONNECTOR (DBA form), not a word
  if (s.length < 2 || s.length > 60 || words.length < 1 || words.length > 5 || /\d/.test(s)) return false
  if (NAME_ROLE_DENY.has(s.toLowerCase()) || words.every((w) => NAME_ROLE_DENY.has(w.toLowerCase()))) return false
  for (const w of words) {
    const core = w.replace(/[-'’.]/g, '')
    if (!core || !/^\p{L}+$/u.test(core)) return false
  }
  return true
}

function ledgerTokStop(tok: string): boolean {
  if (/\d/.test(tok) || tok.includes('/')) return true
  const low = tok.replace(LEDGER_TRIM_RE, '').toLowerCase()
  if (!low || LEDGER_STOPWORDS.has(low)) return true
  const core = tok.replace(/['’.\-]/g, '')
  return !core || !/^\p{L}+$/u.test(core)
}

function ledgerNameRun(t: string, start: number, stop: number): [number, number] | null {
  // '\r' ends the line like '\n' (CRLF ledgers: 'DUPUIS\r' must not fail the alpha check); leading
  // honorifics (MME/MR/...) are skipped, not included in the span.
  const cr = t.indexOf('\r', start)
  if (cr !== -1 && cr < stop) stop = cr
  const gm = LEDGER_COLGAP_RE.exec(t.slice(start, stop))
  if (gm) stop = start + gm.index
  const chosen: Array<[number, number]> = []
  let i = start
  while (i < stop && chosen.length < 5) {
    while (i < stop && (t[i] === ' ' || t[i] === '\t')) i++
    if (i >= stop) break
    let j = i
    while (j < stop && t[j] !== ' ' && t[j] !== '\t') j++
    if (!chosen.length && LEDGER_HONORIFICS.has(t.slice(i, j).replace(LEDGER_TRIM_RE, '').toLowerCase())) {
      i = j
      continue // skip a leading honorific; the span starts at the name itself
    }
    if (t.slice(i, j) === '-' && chosen.length) {
      i = j
      continue // lone hyphen CONNECTOR inside a run ("Traduction - Lise Charbonnel" DBA form)
    }
    const nxt = t.slice(j, stop).replace(/^[ \t]+/, '').charAt(0)
    if (LEDGER_INITIAL_NARROW_RE.test(t.slice(i, j)) && (chosen.length || t.slice(i, j).includes('.') || /[A-ZÀ-ÖØ-Þ]/.test(nxt))) {
      // an uppercase initial is a name token -- mid-run always ("DEREK A MARTEL"), leading when dotted
      // ("A. MARTEL") or followed by a capitalized token ("A MARTEL"). It must win over the 'a'/'an'
      // article stopwords added for the prose colon-cue; "e-transfer to: A friend" still stops.
      chosen.push([i, j])
      i = j
      continue
    }
    if (ledgerTokStop(t.slice(i, j))) break
    chosen.push([i, j])
    i = j
    if (chosen[chosen.length - 1][1] - chosen[0][0] >= 60) break
  }
  while (chosen.length && NAME_PARTICLES.has(t.slice(chosen[chosen.length - 1][0], chosen[chosen.length - 1][1]).toLowerCase())) chosen.pop()
  while (chosen.length && NAME_PARTICLES.has(t.slice(chosen[0][0], chosen[0][1]).toLowerCase())) chosen.shift()
  return chosen.length ? [chosen[0][0], chosen[chosen.length - 1][1]] : null
}

function ledgerSlashName(t: string, start: number, stop: number): [number, number] | null {
  const cr = t.indexOf('\r', start) // '\r' ends the line like '\n' (CRLF ledgers)
  if (cr !== -1 && cr < stop) stop = cr
  const slash = t.indexOf('/', start)
  if (slash !== -1 && slash < stop) stop = slash
  const gm = LEDGER_COLGAP_RE.exec(t.slice(start, stop))
  if (gm) stop = start + gm.index
  let ls = start
  while (ls < stop && (t[ls] === ' ' || t[ls] === '\t')) ls++
  let rs = stop
  while (rs > ls && (t[rs - 1] === ' ' || t[rs - 1] === '\t')) rs--
  return rs > ls ? [ls, rs] : null
}

export function cueNameSpans(text: string): RawSpan[] {
  const spans: RawSpan[] = []
  const t = normSeps(text)
  const seen = new Set<string>()
  const emit = (range: [number, number] | null, shaped: (v: string) => boolean = nameShaped) => {
    if (!range) return
    const key = `${range[0]}:${range[1]}`
    if (seen.has(key) || !shaped(t.slice(range[0], range[1]))) return
    seen.add(key)
    spans.push({ start: range[0], end: range[1], label: 'person', tier: 0, conf: 0.95, rule: 'tier0:cue_name' })
  }

  for (const m of t.matchAll(EMAIL_ANCHOR_RE)) emit(nameRunBefore(t, m.index!))
  for (const m of t.matchAll(HDR_CUE_RE)) {
    const lineEnd = t.indexOf('\n', m.index! + m[0].length)
    emit(nameRunAfter(t, m.index! + m[0].length, lineEnd === -1 ? t.length : lineEnd))
  }
  for (const m of t.matchAll(ETRANSFER_CUE_RE)) {
    const start = m.index! + m[0].length
    const lineEnd = t.indexOf('\n', start)
    emit(ledgerNameRun(t, start, lineEnd === -1 ? t.length : lineEnd), nameShapedRelaxed)
  }
  for (const m of t.matchAll(ETRANSFER_SLASH_RE)) {
    const start = m.index! + m[0].length
    const lineEnd = t.indexOf('\n', start)
    emit(ledgerSlashName(t, start, lineEnd === -1 ? t.length : lineEnd), nameShapedRelaxed)
  }
  return spans
}

function isAlpha(ch: string): boolean {
  return /[A-Za-zÀ-ÖØ-öø-ÿ]/.test(ch)
}
function isAlnum(ch: string): boolean {
  return /[0-9A-Za-zÀ-ÖØ-öø-ÿ]/.test(ch)
}

// Glued NON-checksum digit-run floor. DIGIT_RUN_RE rejects digit runs glued to letters (precision for code).
// A confirmed leak was a 9-digit SIN glued to a word ("JaneDoe046454286"). The naive fix (promote ANY 9-19
// digit run glued to a letter) over-redacts real coding traffic badly -- translateY(123456789px),
// seed1234567890, unix timestamps createdAt1700000000 (FP audit). So glued promotion is PRECISION-GATED:
//   - 9 digits + LUHN-valid -> government_id. Canadian SINs carry a Luhn check digit, so this catches the real
//     SIN ("046454286" passes Luhn) while rejecting code numbers ("123456789" fails Luhn). No cue needed.
//   - everything else glued (incl. non-Luhn SSN, 10-19 account runs) is left to contextCuedIdSpans, which
//     fires ONLY when a financial/identity cue is adjacent (its LONG_ID_RE now covers 9-19 digits). A bank
//     account glued to a NON-cue word relies on the neural tier -- accepted residual vs. nuking every code id.
// Luhn cards stay with the checksum/DIGIT_RUN rules. Letter-adjacency REQUIRED.
// Mirrors privacy_gate.py _GLUED_DIGIT_RE / glued_digit_spans.
const GLUED_DIGIT_RE = /(?<!\d)(\d{9})(?!\d)/g

export function gluedDigitSpans(text: string): RawSpan[] {
  const out: RawSpan[] = []
  const t = normSeps(text)
  for (const m of t.matchAll(GLUED_DIGIT_RE)) {
    const digits = m[1]
    const s = m.index!
    const e = s + digits.length
    const left = s > 0 ? t[s - 1] : ' '
    const right = e < t.length ? t[e] : ' '
    if (!(isAlpha(left) || isAlpha(right))) continue // clean boundary -> already owned by DIGIT_RUN_RE
    if (luhnOk(digits)) {
      // Luhn-valid 9-digit glued to a word = a SIN, not a code id.
      // Business Number suppression (mirrors validated_floor's SIN path): a glued RT/RP/RC...
      // program-account suffix ("046454286RT0001") is a public GST/QST registration, not a personal SIN.
      // Suppress UNLESS a SIN cue forces emission (never-leak override). A clean SIN glued to a non-suffix
      // word ("JaneDoe046454286") is unaffected and still emits.
      if (BN_PROGRAM_SUFFIX_RE.test(t.slice(e, e + 12)) && !SIN_CUE_RE.test(t.slice(Math.max(0, s - 40), s))) {
        continue
      }
      out.push({ start: s, end: e, label: 'government_id', tier: 0, conf: 0.8, rule: 'tier0:digit_glued', validator: 'luhn_ok' })
    }
  }
  return out
}

// Separator-tolerant payment card: DIGIT_RUN_RE / glued-checksum reject '.'-separated groups (a confirmed leak:
// "4111.1111.1111.1111") and percent-encoded spaces ("4111%201111%201111%201111"). A 4-4-4-4 (or amex 4-6-5)
// grouping joined by '.', '-', space, or the literal "%20" whose digits are a Luhn-valid 15/16-run is a card
// with near-zero FP (Luhn-gated). Space/dash forms re-emit harmlessly (merged). Mirrors privacy_gate.py.
const CARD_SEP = '(?:[ .\\-]|%20)'
const SEP_CARD_RE = new RegExp('(?<![\\d.])(\\d{4}(?:' + CARD_SEP + '\\d{4}){3}|\\d{4}' + CARD_SEP + '\\d{6}' + CARD_SEP + '\\d{5})(?![\\d.])', 'g')
// US SSN written with dot separators ("123.45.6789"): a 3-2-4 digit grouping joined by dots. The boundary
// rejects longer dotted sequences (IPs/versions never group 3-2-4). government_id floor. Mirrors _DOT_SSN_RE.
const DOT_SSN_RE = /(?<![\d.])(\d{3}\.\d{2}\.\d{4})(?![\d.])/g

export function separatedCardSpans(text: string): RawSpan[] {
  const out: RawSpan[] = []
  const t = normSeps(text)
  for (const m of t.matchAll(SEP_CARD_RE)) {
    const digits = m[1].replace(/%20/g, ' ').replace(/\D/g, '') // decode %20 before digit extraction (its 2,0 are not card digits)
    if ((digits.length === 15 || digits.length === 16) && luhnOk(digits)) {
      out.push({ start: m.index!, end: m.index! + m[1].length, label: 'payment_card', tier: 0, conf: 0.95, rule: 'tier0:card_sep', validator: 'luhn_ok' })
    }
  }
  for (const m of t.matchAll(DOT_SSN_RE)) {
    out.push({ start: m.index!, end: m.index! + m[1].length, label: 'government_id', tier: 0, conf: 0.8, rule: 'tier0:ssn_dotted' })
  }
  return out
}

// card_cvv + card_expiry are FLOOR_LABELS but had NO deterministic Tier-0 regex -- they fired only when the
// neural tier happened to tag them, so a bare CVV ("security code 123", "cvc: 123") or a short expiry
// ("expiry 08/27", "exp 12/2026") leaked verbatim. Both are CUE-ANCHORED so a stray 3-digit number or a
// generic date never blanket-redacts: a card-verification / expiry keyword (EN+FR) must sit immediately
// before. Cue words are CVV-SPECIFIC: cvv/cvc(+2), 'security code', card-verification, FR
// code-de-securite / cryptogramme. DROPPED 'cid' (correlation/customer/container id -- a ubiquitous dev
// abbreviation that mis-fired) and bare 'sec code'. The cue->value separator tolerates a JSON closing-quote
// on the key and an optional quote on the value, so a CVV/expiry pasted as JSON TEXT ("cvv": 834) is caught.
// CVV cue whitespace also accepts underscores (security_code). Mirrors privacy_gate.py _CVV_RE / _EXPIRY_RE /
// _NUM_SECRET_RE / card_aux_spans. JS regex differences: no inline (?i) -- use the `i` flag; `g` to walk.
const QSEP = String.raw`\s*(?:no\.?|num(?:[ée]ro)?|#)?\s*["']?\s*[:=#-]?\s*["']?\s*`
const CVV_RE = new RegExp(
  String.raw`(?:cvv2?|cvc2?|security[\s_]*code|card[\s_]*verification(?:[\s_]*(?:code|value))?|` +
    String.raw`code\s*de\s*s[eé]curit[eé]|cryptogramme(?:\s*visuel)?)` +
    QSEP +
    String.raw`(\d{3,4})(?!\d)`,
  'gi',
)
const EXPIRY_RE = new RegExp(
  String.raw`(?:exp(?:iry|ires?|iration)?|exp\.?\s*date|valid\s*thru|valid\s*through|good\s*thru|` +
    String.raw`valable\s*jusqu.?(?:au)?|[ée]ch[ée]ance|date\s*d.?expiration)\s*["']?\s*[:=#-]?\s*["']?\s*` +
    String.raw`((?:0[1-9]|1[0-2])\s*[/\-]\s*(?:\d{4}|\d{2}))(?!\d)`,
  'gi',
)
// PIN / passcode / OTP numeric secrets (EN + FR 'NIP'). Cue-anchored with WORD boundaries so 'pinned'/'spinning'
// never fire, and the same JSON-quote-tolerant separator so "pin": 5571 is caught. 3-8 digits. Emits FLOOR
// 'password'. A bare cue-less number stays the NER's job.
const NUM_SECRET_RE = new RegExp(
  String.raw`(?:(?:\b\w+_)?pin\b|\bnip\b|\bpasscode\b|\bpass[\s_]*code\b|\botp\b|` +
    String.raw`\bone[\s_-]?time[\s_]*(?:code|password|passcode|pin)\b|\baccess[\s_]*code\b)` +
    QSEP +
    String.raw`(\d{3,8})(?!\d)`,
  'gi',
)

export function cardAuxSpans(text: string): RawSpan[] {
  const out: RawSpan[] = []
  const t = normSeps(text)
  // matchAll gives no per-group offset (Python's m.start(1)); but in these regexes group 1 is the FINAL token
  // of the match (followed only by a zero-width (?!\d) lookahead), so its offset within the match is
  // m[0].length - m[1].length. That is exact regardless of what the cue prefix contains.
  for (const m of t.matchAll(CVV_RE)) {
    const s = m.index! + (m[0].length - m[1].length)
    out.push({ start: s, end: s + m[1].length, label: 'card_cvv', tier: 0, conf: 0.9, rule: 'tier0:cvv' })
  }
  for (const m of t.matchAll(EXPIRY_RE)) {
    const s = m.index! + (m[0].length - m[1].length)
    out.push({ start: s, end: s + m[1].length, label: 'card_expiry', tier: 0, conf: 0.9, rule: 'tier0:expiry' })
  }
  for (const m of t.matchAll(NUM_SECRET_RE)) {
    const s = m.index! + (m[0].length - m[1].length)
    out.push({ start: s, end: s + m[1].length, label: 'password', tier: 0, conf: 0.9, rule: 'tier0:num_secret' })
  }
  return out
}

export function tier0Spans(text: string): RawSpan[] {
  const spans: RawSpan[] = []
  const t = normSeps(text)
  const add = (start: number, end: number, label: string, conf: number, rule: string, extra?: Partial<RawSpan>) =>
    spans.push({ start, end, label, tier: 0, conf, rule, ...extra })

  for (const m of t.matchAll(EMAIL_RE)) add(m.index!, m.index! + m[0].length, 'email', 0.99, 'tier0:email')
  for (const m of t.matchAll(IP_RE)) {
    if (m[0].split('.').every((o) => +o >= 0 && +o <= 255))
      add(m.index!, m.index! + m[0].length, 'ip_address', 0.95, 'tier0:ip')
  }
  for (const m of t.matchAll(POSTAL_RE)) add(m.index!, m.index! + m[0].length, 'postal_code', 0.9, 'tier0:postal')
  // 'uuid' is a SOFT label (DEMOTED 2026-07-02 from floor 'sensitive_account_id', mirroring both Python
  // twins): session/request ids are load-bearing in coding traffic; the old floor label was merge-sticky,
  // un-allowlistable and withheld from tool arguments. Detection stays deterministic; only the label's
  // privileges changed. In the Workbench display tier, 'uuid' remains catastrophic (redact-by-default).
  for (const m of t.matchAll(UUID_RE)) add(m.index!, m.index! + m[0].length, 'uuid', 0.99, 'tier0:uuid')
  for (const m of t.matchAll(NAM_RE)) {
    const digits = m[1].replace(/\D/g, '')
    if (digits.length === 8) add(m.index!, m.index! + m[1].length, 'government_id', 0.85, 'tier0:nam', { subtype: 'ramq_nam' })
  }
  for (const m of t.matchAll(IBAN_RE)) {
    const iban = validIbanCandidate(m[1])
    if (iban) add(m.index!, m.index! + iban.length, 'iban', 0.99, 'tier0:iban', { validator: 'mod97_ok' })
  }
  const phoneRanges: Array<[number, number]> = []
  for (const m of t.matchAll(PHONE_RE)) {
    if (!BARE_TEN_DIGITS_RE.test(m[0])) {
      add(m.index!, m.index! + m[0].length, 'phone_number', 0.85, 'tier0:phone')
      phoneRanges.push([m.index!, m.index! + m[0].length])
    }
  }
  for (const m of t.matchAll(DATE_RE)) add(m.index!, m.index! + m[0].length, 'sensitive_date', 0.8, 'tier0:date')

  for (const m of t.matchAll(DIGIT_RUN_RE)) {
    const raw = m[1]
    const start = m.index!
    const end = start + raw.length
    const digits = raw.replace(/\D/g, '')
    const n = digits.length
    // A date-shaped run is a DATE, not an account id: tag it sensitive_date and skip the account-id
    // fallthrough (mirrors privacy_gate.py DIGIT_RUN date branch). Space-grouped runs are NOT date-shaped.
    if (dateShaped(raw)) {
      add(start, end, 'sensitive_date', 0.8, 'tier0:date_shaped')
      continue
    }
    if (n === 16 || n === 15) {
      const ok = luhnOk(digits)
      add(start, end, 'payment_card', ok ? 0.97 : 0.7, 'tier0:digit_run', { validator: ok ? 'luhn_ok' : 'luhn_fail' })
    } else if (n === 9) {
      // A 9-digit number followed by an "...RT0001" program account is a Business Number, not a SIN, so
      // suppress it (Finding A: ~78% of real-doc government_id hits were merchant BNs) -- UNLESS a SIN cue
      // precedes it, in which case a real SIN must always win the never-leak guarantee (Codex review).
      const bn = BN_PROGRAM_SUFFIX_RE.test(t.slice(end, end + 12))
      const sinCue = SIN_CUE_RE.test(t.slice(Math.max(0, start - 40), start))
      if (bn && !sinCue) continue
      const ok = luhnOk(digits)
      add(start, end, 'government_id', ok ? 0.9 : 0.75, 'tier0:digit_run', { validator: ok ? 'luhn_ok' : 'luhn_fail' })
    } else if (n >= 7 && n <= 19) {
      // A separator-bearing run lying entirely INSIDE a phone match is the phone's own digits (mirrors the
      // appliance's 2026-07-02 containment fix): minting the generic account id too made the FLOOR-sticky
      // merge relabel the phone as an un-allowlistable account id. Separator-LESS runs stay account-shaped
      // (compact bank accounts are 7-12 digits).
      if (!/^\d+$/.test(raw) && phoneRanges.some(([ps, pe]) => ps <= start && end <= pe)) continue
      // A bare 10-digit run still falls through to the generic account-id catch-all (recall: it gets
      // the reviewer's attention). When an NEQ cue is adjacent, quebecCuedIdSpans adds a higher-conf
      // `neq` span and mergeSpans upgrades to it. Do NOT suppress the bare run here (that was a
      // detection regression -- a cue-less 10-digit account/reference number would leak silently).
      add(start, end, 'sensitive_account_id', 0.6, 'tier0:digit_run')
    }
  }

  spans.push(...contextCuedIdSpans(t)) // Presidio-style cue-promoted letter-glued long IDs
  spans.push(...gluedDigitSpans(t)) // Luhn-valid 9-digit SIN glued to letters (no cue; Luhn-precise)
  spans.push(...separatedCardSpans(t)) // dot/space/dash-grouped Luhn card + dotted SSN (sep DIGIT_RUN rejects)
  spans.push(...cardAuxSpans(t)) // cue-anchored card_cvv + card_expiry (no standalone Tier-0 before)
  spans.push(...quebecCuedIdSpans(t))
  spans.push(...cueNameSpans(t))
  spans.push(...cueDigitSpans(t)) // cue-gated ID/phone/DOB backstop (miss-inventory-driven, 2026-07-07)

  // Zero-width / format-char obfuscation resistance: if the ORIGINAL carries Cf codepoints, re-scan a
  // stripped copy and map every span back onto the original offsets (end = idxMap[span.end]). clean has no Cf
  // chars, so tier0Spans(clean) cannot re-enter this branch. Mirrors privacy_gate.py tier0_spans `+cf` block.
  if (hasFormatChars(text)) {
    const [clean, idxMap] = stripFormatChars(text)
    if (clean && clean !== text) {
      for (const s of tier0Spans(clean)) {
        spans.push({ ...s, start: idxMap[s.start], end: idxMap[s.end], rule: (s.rule || 'tier0') + '+cf' })
      }
    }
  }
  return spans
}
