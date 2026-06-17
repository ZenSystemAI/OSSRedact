// Tests for tier0Spans and helpers -- run against the @ossredact/core public API.
// All inputs are synthetic -- no real PII.
// Luhn and mod-97 values are standard public test vectors.

import { describe, it, expect } from 'vitest'
import { tier0Spans, luhnOk, ibanOk, normSpace, normDash } from './tier0'
import { mergeSpans } from './redaction'

// Helper: extract (label, substring) pairs from tier0Spans
function lset(text: string): Set<string> {
  const spans = tier0Spans(text)
  return new Set(spans.map((s) => `${s.label}:${text.slice(s.start, s.end)}`))
}

// Helper: get all spans as an array of {label, sub, ...} for easier inspection
function labeledSpans(text: string) {
  return tier0Spans(text).map((s) => ({ ...s, sub: text.slice(s.start, s.end) }))
}

// -------------------------
// luhnOk
// -------------------------
describe('luhnOk', () => {
  it('returns true for a standard Luhn-valid 16-digit test card', () => {
    // Public Luhn test vector (Visa test card)
    expect(luhnOk('4539148803436467')).toBe(true)
  })

  it('returns false when the last digit is wrong', () => {
    expect(luhnOk('4539148803436460')).toBe(false)
  })

  it('returns true for a Luhn-valid 9-digit value (SIN test vector)', () => {
    // Public SIN test vector: 046454286 (passes Luhn)
    expect(luhnOk('046454286')).toBe(true)
  })

  it('returns false for an obviously invalid number', () => {
    expect(luhnOk('123456789')).toBe(false)
  })
})

// -------------------------
// normSpace + normDash
// -------------------------
describe('normSpace', () => {
  it('replaces NBSP with regular space', () => {
    const withNbsp = '653 956 771'
    expect(normSpace(withNbsp)).toBe('653 956 771')
  })

  it('replaces narrow-NBSP (U+202F) with regular space', () => {
    const withNarrow = '653 956 771'
    expect(normSpace(withNarrow)).toBe('653 956 771')
  })
})

describe('normDash', () => {
  it('replaces en-dash with ASCII hyphen', () => {
    expect(normDash('006–02761')).toBe('006-02761')
  })

  it('replaces em-dash with ASCII hyphen', () => {
    // U+2014 EM DASH expressed as unicode escape to keep the file free of literal em-dash chars
    expect(normDash('006\u201402761')).toBe('006-02761')
  })
})

// -------------------------
// tier0Spans -- basic label detection
// -------------------------
describe('tier0Spans', () => {
  it('detects a Luhn-valid 16-digit payment card', () => {
    const text = 'Card: 4539148803436467 expires 12/28'
    const spans = labeledSpans(text)
    const card = spans.find((s) => s.label === 'payment_card')
    expect(card).toBeDefined()
    expect(card!.sub).toBe('4539148803436467')
    expect(card!.validator).toBe('luhn_ok')
  })

  it('still detects a Luhn-fail 16-digit run as payment_card with luhn_fail', () => {
    const text = '4539148803436460 was the wrong number'
    const spans = labeledSpans(text)
    const card = spans.find((s) => s.label === 'payment_card')
    expect(card).toBeDefined()
    expect(card!.validator).toBe('luhn_fail')
  })

  it('detects a Luhn-valid 9-digit SIN as government_id', () => {
    // Public SIN test vector: 046 454 286
    const text = 'NAS du client: 046 454 286'
    const spans = labeledSpans(text)
    const gov = spans.find((s) => s.label === 'government_id')
    expect(gov).toBeDefined()
    expect(gov!.sub.replace(/\D/g, '')).toBe('046454286')
  })

  it('detects email address', () => {
    const text = 'Envoyer a test.user+tag@example.org svp'
    const found = lset(text)
    expect([...found].some((e) => e.startsWith('email:') && e.includes('test.user+tag@example.org'))).toBe(true)
  })

  it('detects phone number in North American format', () => {
    const text = 'Appelez au (514) 555-0199 pour de laide.'
    const found = lset(text)
    expect([...found].some((e) => e.startsWith('phone_number:'))).toBe(true)
  })

  it('detects Canadian postal code', () => {
    const text = 'Adresse: 123 rue Principale, H2X 1Y3'
    const found = lset(text)
    expect([...found].some((e) => e.startsWith('postal_code:') && e.includes('H2X 1Y3'))).toBe(true)
  })

  it('detects UUID', () => {
    const text = 'Session ID: 446062b5-366a-4a17-d308-8a7cb0524be4'
    const found = lset(text)
    expect([...found].some((e) => e.startsWith('sensitive_account_id:') && e.includes('446062b5'))).toBe(true)
  })

  it('detects ISO date', () => {
    const text = 'Date de naissance: 1985-03-22'
    const found = lset(text)
    expect([...found].some((e) => e.startsWith('sensitive_date:') && e.includes('1985-03-22'))).toBe(true)
  })

  // -------------------------
  // Amount-bleed regression (plans 022 / 014)
  // -------------------------
  it('amount-bleed regression: detects account number but NOT transaction amounts', () => {
    const text = 'compte 49206280932 1.50 $ 507.40 $'
    const spans = labeledSpans(text)

    const acctSpan = spans.find((s) => s.sub.replace(/\D/g, '') === '49206280932')
    expect(acctSpan).toBeDefined()

    const allSubstrings = spans.map((s) => s.sub)
    expect(allSubstrings.some((sub) => sub.includes('1.50'))).toBe(false)
    expect(allSubstrings.some((sub) => sub.includes('507.40'))).toBe(false)

    const digits = acctSpan!.sub.replace(/\D/g, '')
    expect(digits).toBe('49206280932')
  })

  // -------------------------
  // NBSP-separated digit run detection
  // -------------------------
  it('detects a 9-digit run with NBSP separators (French grouping)', () => {
    const text = '653 956 771'
    const spans = labeledSpans(text)
    const govSpan = spans.find((s) => s.label === 'government_id')
    expect(govSpan).toBeDefined()
    const digits = govSpan!.sub.replace(/\D/g, '')
    expect(digits.length).toBe(9)
  })

  // -------------------------
  // Bare-10-digit account catch-all (plan 022 regression)
  // -------------------------
  it('bare-10-digit run still flags as generic account id without a cue (recall preserved)', () => {
    const spans = labeledSpans('1234567890')
    expect(spans.some((s) => s.label === 'sensitive_account_id')).toBe(true)
    expect(spans.some((s) => s.subtype === 'neq')).toBe(false)
  })
})

// -------------------------
// ibanOk -- mod-97 checksum validator
// -------------------------
describe('ibanOk', () => {
  it('returns true for the canonical ISO 13616 GB82 test IBAN', () => {
    expect(ibanOk('GB82WEST12345698765432')).toBe(true)
  })

  it('returns false when the last digit is wrong (mod-97-invalid lookalike)', () => {
    expect(ibanOk('GB82WEST12345698765433')).toBe(false)
  })

  it('returns true for a valid IBAN with internal spaces (spaced form)', () => {
    expect(ibanOk('GB82 WEST 1234 5698 7654 32')).toBe(true)
  })

  it('returns false for a short string that cannot be an IBAN', () => {
    expect(ibanOk('GB82')).toBe(false)
  })
})

// -------------------------
// IBAN detection + mergeSpans confidence resolution
// -------------------------
describe('tier0Spans IBAN', () => {
  it('emits an iban span for a valid IBAN embedded in text', () => {
    const text = 'solde IBAN GB82WEST12345698765432 fin'
    const spans = labeledSpans(text)
    const ibanSpan = spans.find((s) => s.label === 'iban')
    expect(ibanSpan).toBeDefined()
    expect(ibanSpan!.sub).toBe('GB82WEST12345698765432')
    expect(ibanSpan!.validator).toBe('mod97_ok')
  })

  it('does NOT emit an iban span for a mod-97-invalid lookalike', () => {
    const text = 'IBAN invalide GB82WEST12345698765433 fin'
    const spans = labeledSpans(text)
    const ibanSpan = spans.find((s) => s.label === 'iban')
    expect(ibanSpan).toBeUndefined()
  })

  it('keeps the iban label after mergeSpans (IBAN conf 0.99 wins over digit-run conf 0.6)', () => {
    const text = 'virement GB82WEST12345698765432 ref'
    const merged = mergeSpans(tier0Spans(text))
    const ibanSpan = merged.find((s) => s.label === 'iban')
    expect(ibanSpan).toBeDefined()
    expect(merged.filter((s) => s.label === 'sensitive_account_id' && text.slice(s.start, s.end).includes('GB82'))).toHaveLength(0)
  })

  it('offset test: span start/end index back to the exact IBAN substring in original text', () => {
    const iban = 'GB82WEST12345698765432'
    const prefix = 'compte: '
    const text = prefix + iban + ' solde'
    const spans = tier0Spans(text)
    const ibanSpan = spans.find((s) => s.label === 'iban')
    expect(ibanSpan).toBeDefined()
    expect(ibanSpan!.start).toBe(prefix.length)
    expect(ibanSpan!.end).toBe(prefix.length + iban.length)
    expect(text.slice(ibanSpan!.start, ibanSpan!.end)).toBe(iban)
  })
})

// -------------------------
// Quebec structured IDs (SAAQ, NEQ, RAMQ/NAM)
// -------------------------
describe('tier0Spans Quebec IDs', () => {
  it('emits a RAMQ/NAM government_id span without requiring a cue', () => {
    const text = 'TEST 86120319'
    const spans = labeledSpans(text)
    const nam = spans.find((s) => s.subtype === 'ramq_nam')
    expect(nam).toBeDefined()
    expect(nam!.label).toBe('government_id')
    expect(nam!.sub).toBe('TEST 86120319')
  })

  it('emits a RAMQ/NAM government_id span with an internal digit-group space', () => {
    const text = 'ABCD 8612 0319'
    const spans = labeledSpans(text)
    const nam = spans.find((s) => s.subtype === 'ramq_nam')
    expect(nam).toBeDefined()
    expect(nam!.label).toBe('government_id')
    expect(nam!.sub).toBe('ABCD 8612 0319')
  })

  it('does not emit RAMQ/NAM for a 3-letter near miss', () => {
    const spans = labeledSpans('ABC 86120319')
    expect(spans.some((s) => s.subtype === 'ramq_nam')).toBe(false)
  })

  it('emits a cue-gated SAAQ licence span when a permis cue is present', () => {
    const text = 'permis A123456789012'
    const spans = labeledSpans(text)
    const saaq = spans.find((s) => s.subtype === 'saaq_licence')
    expect(saaq).toBeDefined()
    expect(saaq!.label).toBe('sensitive_account_id')
    expect(saaq!.sub).toBe('A123456789012')
  })

  it('does not emit SAAQ licence without a cue', () => {
    const spans = labeledSpans('A123456789012')
    expect(spans).toHaveLength(0)
    expect(spans.some((s) => s.subtype === 'saaq_licence')).toBe(false)
  })

  it('emits a cue-gated NEQ span when a NEQ cue is present', () => {
    const text = 'NEQ 1234567890'
    const spans = labeledSpans(text)
    const neq = spans.find((s) => s.subtype === 'neq')
    const merged = mergeSpans(tier0Spans(text))
    expect(neq).toBeDefined()
    expect(neq!.label).toBe('sensitive_account_id')
    expect(neq!.sub).toBe('1234567890')
    expect(merged.some((s) => s.subtype === 'neq')).toBe(true)
  })
})
