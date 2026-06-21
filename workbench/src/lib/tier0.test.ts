// Tests for tier0Spans and helpers in tier0.ts.
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
    // all-zeros passes structural check but fails Luhn
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
  // Amount-bleed regression
  // -------------------------
  it('amount-bleed regression: detects account number but NOT transaction amounts', () => {
    // This is the key regression from tier0.ts:56-62 comments.
    // Bank statement line: long account number followed by decimal amounts on the same line.
    // The DIGIT_RUN_RE must NOT swallow the amounts into the account number span.
    const text = 'compte 49206280932 1.50 $ 507.40 $'
    const spans = labeledSpans(text)

    // There must be a span for the account number
    const acctSpan = spans.find((s) => s.sub.replace(/\D/g, '') === '49206280932')
    expect(acctSpan).toBeDefined()

    // Verify neither amount appears inside any span
    const allSubstrings = spans.map((s) => s.sub)
    expect(allSubstrings.some((sub) => sub.includes('1.50'))).toBe(false)
    expect(allSubstrings.some((sub) => sub.includes('507.40'))).toBe(false)

    // The account number span must be exactly the run (no trailing digits from the amounts)
    const digits = acctSpan!.sub.replace(/\D/g, '')
    expect(digits).toBe('49206280932')
  })

  // -------------------------
  // NBSP-separated digit run detection
  // -------------------------
  it('detects a 9-digit run with NBSP separators (French grouping)', () => {
    // "653 956 771" with narrow NBSP between groups
    const text = '653 956 771'
    const spans = labeledSpans(text)
    // After normSpace, it becomes "653 956 771" -- 9 digits -> government_id
    const govSpan = spans.find((s) => s.label === 'government_id')
    expect(govSpan).toBeDefined()
    // The matched substring (in original text) should cover all 3 groups
    const digits = govSpan!.sub.replace(/\D/g, '')
    expect(digits.length).toBe(9)
  })
})

// -------------------------
// ibanOk -- mod-97 checksum validator
// Public test vector: GB82WEST12345698765432 is the canonical IBAN example from
// ISO 13616 / Wikipedia; mirrors test_validated_floor.py:31-34 in gate/tests/.
// -------------------------
describe('ibanOk', () => {
  it('returns true for the canonical ISO 13616 GB82 test IBAN', () => {
    // GB82WEST12345698765432 -- public test vector (Wikipedia / ISO 13616)
    expect(ibanOk('GB82WEST12345698765432')).toBe(true)
  })

  it('returns false when the last digit is wrong (mod-97-invalid lookalike)', () => {
    // GB82WEST12345698765433 -- last digit changed: same structure, invalid checksum
    expect(ibanOk('GB82WEST12345698765433')).toBe(false)
  })

  it('returns true for a valid IBAN with internal spaces (spaced form)', () => {
    // Spaced form of the same canonical IBAN
    expect(ibanOk('GB82 WEST 1234 5698 7654 32')).toBe(true)
  })

  it('returns true for lowercase and hyphen-separated valid IBANs', () => {
    expect(ibanOk('gb82west12345698765432')).toBe(true)
    expect(ibanOk('GB82-WEST-1234-5698-7654-32')).toBe(true)
  })

  it('returns false for a short string that cannot be an IBAN', () => {
    expect(ibanOk('GB82')).toBe(false)
  })
})

// -------------------------
// tier0Spans -- IBAN detection and offset accuracy
// -------------------------
describe('tier0Spans IBAN', () => {
  it('emits an iban span for a valid IBAN embedded in text', () => {
    const text = 'solde IBAN GB82WEST12345698765432 fin'
    const spans = labeledSpans(text)
    const ibanSpan = spans.find((s) => s.label === 'iban')
    expect(ibanSpan).toBeDefined()
    // The span substring must be exactly the IBAN string -- no offset error
    expect(ibanSpan!.sub).toBe('GB82WEST12345698765432')
    expect(ibanSpan!.validator).toBe('mod97_ok')
  })

  it('emits iban spans for lowercase and hyphen-separated valid IBANs', () => {
    for (const iban of ['gb82west12345698765432', 'GB82-WEST-1234-5698-7654-32']) {
      const text = `solde IBAN ${iban} fin`
      const spans = labeledSpans(text)
      const ibanSpan = spans.find((s) => s.label === 'iban')
      expect(ibanSpan).toBeDefined()
      expect(ibanSpan!.sub).toBe(iban)
      expect(ibanSpan!.validator).toBe('mod97_ok')
    }
  })

  it('does NOT emit an iban span for a mod-97-invalid lookalike', () => {
    // GB82WEST12345698765433 -- same structure, invalid checksum
    const text = 'IBAN invalide GB82WEST12345698765433 fin'
    const spans = labeledSpans(text)
    const ibanSpan = spans.find((s) => s.label === 'iban')
    expect(ibanSpan).toBeUndefined()
  })

  it('keeps the iban label after mergeSpans (IBAN conf 0.99 wins over digit-run conf 0.6)', () => {
    // The IBAN digits also match DIGIT_RUN_RE as sensitive_account_id at conf 0.6.
    // mergeSpans must pick the highest-confidence member -> iban at 0.99.
    const text = 'virement GB82WEST12345698765432 ref'
    const merged = mergeSpans(tier0Spans(text))
    const ibanSpan = merged.find((s) => s.label === 'iban')
    expect(ibanSpan).toBeDefined()
    // The merged span must not have been relabeled by the lower-confidence digit-run detector
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
// tier0Spans -- Quebec structured IDs
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

    // No SAAQ-specific span without a cue. The round-2 glued-digit floor is precision-gated to a Luhn-valid
    // 9-digit run only (mirrors privacy_gate.py glued_digit_spans), so a 12-digit code run glued to a leading
    // 'A' is no longer over-redacted -- and it must NOT be labeled a SAAQ licence.
    expect(spans.some((s) => s.subtype === 'saaq_licence')).toBe(false)
    expect(spans.some((s) => s.rule === 'tier0:digit_glued')).toBe(false)
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

  it('does not label a bare 10-digit run as NEQ without a cue, but still flags it generically', () => {
    const spans = labeledSpans('1234567890')

    // no NEQ label without a cue ...
    expect(spans.some((s) => s.subtype === 'neq')).toBe(false)
    // ... but recall is preserved: a bare 10-digit run is still caught as a generic account id for review
    expect(spans.some((s) => s.label === 'sensitive_account_id')).toBe(true)
  })
})

// -------------------------
// Canadian Business Number suppression (real-doc Finding A)
// -------------------------
describe('tier0Spans Business Number suppression', () => {
  it('does NOT emit government_id for a 9-digit number with a BN program-account suffix (RT0001)', () => {
    // 046454286 is a Luhn-valid public SIN test vector, but "046454286 RT0001" is a Canadian Business
    // Number (GST/HST registration printed on invoices), not a SIN.
    const spans = labeledSpans('TPS 046454286 RT0001')
    expect(spans.some((s) => s.label === 'government_id')).toBe(false)
  })

  it('does NOT emit government_id for an RP (payroll) program account', () => {
    expect(labeledSpans('046454286 RP0001').some((s) => s.label === 'government_id')).toBe(false)
  })

  it('does NOT emit government_id for a hyphen-separated BN program account', () => {
    expect(labeledSpans('046454286-RT0001').some((s) => s.label === 'government_id')).toBe(false)
  })

  it('emits government_id when a SIN cue precedes the number, even with a BN-looking suffix (never-leak)', () => {
    // A real SIN must always win: a SIN cue before the number overrides the BN suppression (Codex review).
    expect(labeledSpans('NAS 046454286 RT0001').some((s) => s.label === 'government_id')).toBe(true)
    expect(labeledSpans('N.A.S. 046454286 RT0001').some((s) => s.label === 'government_id')).toBe(true)
  })

  it('SIN cue is word-bounded, not a substring (Business/casino must NOT un-suppress a BN)', () => {
    // "Business" contains "sin"; without ASCII word boundaries it would falsely fire the SIN override and
    // re-emit a real BN as a SIN (Codex round 2). It must stay suppressed.
    expect(labeledSpans('Business number 046454286 RT0001').some((s) => s.label === 'government_id')).toBe(false)
  })

  it('does NOT treat a newline as the BN separator (no suppression across a line break)', () => {
    expect(labeledSpans('compte 046454286\nRT0001').some((s) => s.label === 'government_id')).toBe(true)
  })

  it('still emits government_id for a bare 9-digit Luhn number (SIN recall preserved)', () => {
    const gov = labeledSpans('NAS 046454286').find((s) => s.label === 'government_id')
    expect(gov).toBeDefined()
    expect(gov!.sub.replace(/\D/g, '')).toBe('046454286')
  })

  it('does NOT suppress when the trailing token is a letter code that is not a BN program code', () => {
    // "ST0001" is not an RT/RP/RC/RZ/RM/RR/RG program account, so the 9-digit run still flags as a SIN.
    // (A trailing plain digit group like "046454286 1234" instead merges into one 13-digit account-id run.)
    expect(labeledSpans('046454286 ST0001').some((s) => s.label === 'government_id')).toBe(true)
  })
})
