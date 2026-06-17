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
// direction D1 (unified detector source) lands. See plans/014 for context.

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

// Case-normalize runs of >=2 uppercase letters to Title case for a second neural pass (length-preserving,
// offsets map 1:1). Recovers ALL-CAPS names the case-sensitive model misses. Used by gate.ts only.
const CAPS_RUN = /[A-ZÀ-ÖØ-Þ]{2,}/g
export function normCase(s: string): string {
  return s.replace(CAPS_RUN, (m) => m.charAt(0) + m.slice(1).toLowerCase())
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

const EMAIL_RE = /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const POSTAL_RE = /\b[A-Za-z]\d[A-Za-z]\s?\d[A-Za-z]\d\b/g
const UUID_RE = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g
const NAM_RE = /\b([A-Z]{4} \d{4} ?\d{4})\b/g

// IBAN: 2-letter country + 2 check digits + 11-30 alphanumerics (single internal spaces allowed).
// Validated by ISO 7064 mod-97 (ibanOk) -> a match is a near-certain real IBAN.
// Port of privacy_gate.py IBAN_RE + _iban_ok. BigInt used because the digit string overflows Number.
const IBAN_RE = /\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30})\b/g
export function ibanOk(s: string): boolean {
  const c = s.replace(/\s/g, '').toUpperCase()
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

// A bank/identity digit run: digit groups joined by a SINGLE space or hyphen (Quebec/OQLF grouping like
// "123 456 789" or "006-02761-1234567"). v11 fix: dropped '.' from the separator class and forbade ending
// right before a decimal ((?![\w.])) + leading (?<![\w.]) -- so the run no longer swallows the transaction
// AMOUNT that follows a bank-statement account/target on the same line ("...49206280932 1.50 $ 507.40 $"):
// the amount sits after a WIDER gap (>=2 spaces breaks the single-separator run) and carries a ".dd" decimal
// (the leading/trailing dot-boundaries exclude it). General across bank statements, not just flinks.
const DIGIT_RUN_RE = /(?<![\w.])(\d+(?:[ \-]\d+)*)(?![\w.])/g
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
const LONG_ID_RE = /(?<!\d)(\d(?:[ \-]?\d){10,18})(?!\d)/g
const CUE_BEFORE = 24
const CUE_AFTER = 12

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
  const t = normSpace(normDash(text))

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
  const t = normSpace(normDash(text))
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

function isAlpha(ch: string): boolean {
  return /[A-Za-zÀ-ÖØ-öø-ÿ]/.test(ch)
}
function isAlnum(ch: string): boolean {
  return /[0-9A-Za-zÀ-ÖØ-öø-ÿ]/.test(ch)
}

export function tier0Spans(text: string): RawSpan[] {
  const spans: RawSpan[] = []
  const t = normSpace(normDash(text))
  const add = (start: number, end: number, label: string, conf: number, rule: string, extra?: Partial<RawSpan>) =>
    spans.push({ start, end, label, tier: 0, conf, rule, ...extra })

  for (const m of t.matchAll(EMAIL_RE)) add(m.index!, m.index! + m[0].length, 'email', 0.99, 'tier0:email')
  for (const m of t.matchAll(IP_RE)) {
    if (m[0].split('.').every((o) => +o >= 0 && +o <= 255))
      add(m.index!, m.index! + m[0].length, 'ip_address', 0.95, 'tier0:ip')
  }
  for (const m of t.matchAll(POSTAL_RE)) add(m.index!, m.index! + m[0].length, 'postal_code', 0.9, 'tier0:postal')
  for (const m of t.matchAll(UUID_RE)) add(m.index!, m.index! + m[0].length, 'sensitive_account_id', 0.99, 'tier0:uuid')
  for (const m of t.matchAll(NAM_RE)) {
    const digits = m[1].replace(/\D/g, '')
    if (digits.length === 8) add(m.index!, m.index! + m[1].length, 'government_id', 0.85, 'tier0:nam', { subtype: 'ramq_nam' })
  }
  for (const m of t.matchAll(IBAN_RE)) {
    if (ibanOk(m[1])) add(m.index!, m.index! + m[1].length, 'iban', 0.99, 'tier0:iban', { validator: 'mod97_ok' })
  }
  for (const m of t.matchAll(PHONE_RE)) {
    if (!BARE_TEN_DIGITS_RE.test(m[0])) add(m.index!, m.index! + m[0].length, 'phone_number', 0.85, 'tier0:phone')
  }
  for (const m of t.matchAll(DATE_RE)) add(m.index!, m.index! + m[0].length, 'sensitive_date', 0.8, 'tier0:date')

  for (const m of t.matchAll(DIGIT_RUN_RE)) {
    const raw = m[1]
    const start = m.index!
    const end = start + raw.length
    const digits = raw.replace(/\D/g, '')
    const n = digits.length
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
      // A bare 10-digit run still falls through to the generic account-id catch-all (recall: it gets
      // the reviewer's attention). When an NEQ cue is adjacent, quebecCuedIdSpans adds a higher-conf
      // `neq` span and mergeSpans upgrades to it. Do NOT suppress the bare run here (that was a
      // detection regression -- a cue-less 10-digit account/reference number would leak silently).
      add(start, end, 'sensitive_account_id', 0.6, 'tier0:digit_run')
    }
  }

  spans.push(...contextCuedIdSpans(t)) // Presidio-style cue-promoted letter-glued long IDs
  spans.push(...quebecCuedIdSpans(t))
  return spans
}
