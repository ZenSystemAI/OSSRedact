// Tests for tier0Spans and helpers -- run against the @ossredact/core public API.
// All inputs are synthetic -- no real PII.
// Luhn and mod-97 values are standard public test vectors.

import { describe, it, expect } from 'vitest'
import { tier0Spans, cueNameSpans, luhnOk, ibanOk, nameShaped, normSpace, normDash, hasFormatChars } from './tier0'
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

  it('detects accented (non-ASCII) email local-parts -- the offline leak the ASCII \\w regex missed', () => {
    // françoise.bélisle (cedilla + accent mid-run) and a LEADING accented char (élise) on a
    // multi-level .qc.ca domain. The old /\\b[\\w.+-]+@/ matched only the ASCII tail, leaving the accented
    // prefix literal in the outbound text -- a real PII leak on exactly the French/Quebec market.
    const text = 'Ecrire a françoise.bélisle@example.org et élise@courriel.qc.ca'
    const found = lset(text)
    expect([...found].some((e) => e.startsWith('email:') && e.includes('françoise.bélisle@example.org'))).toBe(true)
    expect([...found].some((e) => e.startsWith('email:') && e.includes('élise@courriel.qc.ca'))).toBe(true)
  })

  it('email scan stays linear on a long punctuation run (no O(n^2) main-thread block)', () => {
    // The Unicode email local-part class includes '.' and '-', so without a left boundary the global scan
    // re-attempts at every char of a long dotted/dashed line (PDF leader, markdown rule) -- O(n^2), seconds
    // on the unchunked in-browser floor. The leading lookbehind prunes those starts. 100k chars must be fast.
    const t0 = performance.now()
    tier0Spans('.'.repeat(100000))
    tier0Spans('-'.repeat(100000))
    tier0Spans('a'.repeat(100000) + '@')
    expect(performance.now() - t0).toBeLessThan(250)
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
  // Date-shaped digit runs (tier0:date_shaped) -- a hyphenated / compact digit run that is really a DATE,
  // not an account id (a coding agent passes '2026-07-01' / '20260701' constantly). Port of privacy_gate.py
  // _date_shaped + the DIGIT_RUN date branch. Space-grouped runs stay account-shaped.
  // -------------------------
  describe('date-shaped digit runs', () => {
    // the value is tagged sensitive_date somewhere, and NOTHING in the doc is tagged sensitive_account_id
    const dateNotAccount = (text: string, value: string) => {
      const spans = labeledSpans(text)
      expect(spans.some((s) => s.label === 'sensitive_date' && s.sub.includes(value))).toBe(true)
      expect(spans.some((s) => s.label === 'sensitive_account_id')).toBe(false)
    }

    it('hyphenated ISO Y-M-D -> sensitive_date, not sensitive_account_id', () => {
      dateNotAccount('2026-07-01', '2026-07-01')
    })
    it('compact YYYYMMDD -> sensitive_date, not sensitive_account_id', () => {
      dateNotAccount('20260701', '20260701')
    })
    it('ISO date glued to a prefix token (context-1m-2025-08-07) -> sensitive_date', () => {
      dateNotAccount('context-1m-2025-08-07', '2025-08-07')
    })
    it('hyphenated D-M-Y -> sensitive_date, not sensitive_account_id', () => {
      dateNotAccount('01-07-2026', '01-07-2026')
    })
    it('ISO date with a trailing log hour -> sensitive_date', () => {
      dateNotAccount('at 2026-07-01 23 UTC', '2026-07-01 23')
    })

    it('space-grouped run stays sensitive_account_id (not date-shaped)', () => {
      const spans = labeledSpans('ref 2026 07 01 99')
      expect(spans.some((s) => s.label === 'sensitive_account_id' && s.sub.replace(/\D/g, '') === '2026070199')).toBe(true)
      expect(spans.some((s) => s.label === 'sensitive_date')).toBe(false)
    })

    it('a real (Luhn-valid) SIN stays government_id, never a date', () => {
      const spans = labeledSpans('046-454-286')
      expect(spans.some((s) => s.label === 'government_id')).toBe(true)
      expect(spans.some((s) => s.label === 'sensitive_date')).toBe(false)
    })

    it('an 8-digit account with an out-of-range month stays sensitive_account_id (acct 20269999)', () => {
      const spans = labeledSpans('acct 20269999')
      expect(spans.some((s) => s.label === 'sensitive_account_id' && s.sub === '20269999')).toBe(true)
      expect(spans.some((s) => s.label === 'sensitive_date')).toBe(false)
    })

    it('card and IBAN vectors are unaffected by date-shaping', () => {
      const card = labeledSpans('Card: 4539148803436467')
      expect(card.some((s) => s.label === 'payment_card')).toBe(true)
      expect(card.some((s) => s.label === 'sensitive_date')).toBe(false)
      const iban = labeledSpans('IBAN GB82WEST12345698765432')
      expect(iban.some((s) => s.label === 'iban')).toBe(true)
      expect(iban.some((s) => s.label === 'sensitive_date')).toBe(false)
    })
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

describe('cueNameSpans', () => {
  it('detects cue-anchored personal names beside mailbox/header forms', () => {
    const cases = [
      ['From: Olivier Tremblay <o.tremblay@example.org>', 'Olivier Tremblay'],
      ['Co-authored-by: Hassan El-Amrani <hassan@example.org>', 'Hassan El-Amrani'],
      ['Reply-To: Bjørn Halvorsen <bjorn@example.org>', 'Bjørn Halvorsen'],
      ['Attn: Jean-Philippe Gagnon-Roy', 'Jean-Philippe Gagnon-Roy'],
    ] as const

    for (const [text, expected] of cases) {
      const names = cueNameSpans(text).map((s) => text.slice(s.start, s.end))
      expect(names).toContain(expected)
    }
  })

  it('rejects role mailboxes and lowercase non-name fragments', () => {
    const cases = [
      'Support <support@example.org>',
      'To: Marketing Team <mkt@example.org>',
      'no-reply <noreply@example.org>',
      'Email bob@example.org please',
      'the value is foo <bar@example.org>',
    ]

    for (const text of cases) expect(cueNameSpans(text)).toEqual([])
  })

  it('exposes the same cue-name spans through tier0Spans', () => {
    const text = 'From: Olivier Tremblay <o.tremblay@example.org>'
    const spans = labeledSpans(text)
    expect(spans.some((s) => s.label === 'person' && s.sub === 'Olivier Tremblay')).toBe(true)
  })

  it('keeps nameShaped conservative for role names', () => {
    expect(nameShaped('Olivier Tremblay')).toBe(true)
    expect(nameShaped('Support')).toBe(false)
    expect(nameShaped('Marketing Team')).toBe(false)
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

  it('returns true for lowercase and hyphen-separated valid IBANs', () => {
    expect(ibanOk('gb82west12345698765432')).toBe(true)
    expect(ibanOk('GB82-WEST-1234-5698-7654-32')).toBe(true)
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
    // No SAAQ-specific span without a cue. The round-2 glued-digit floor is precision-gated to a Luhn-valid
    // 9-digit run only (mirrors privacy_gate.py glued_digit_spans), so a 12-digit code run glued to a leading
    // 'A' is no longer over-redacted as a generic account id -- it must NOT be labeled a SAAQ licence either.
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
})

// -------------------------
// Canadian Business Number suppression (real-doc Finding A; never-leak SIN-cue override)
// -------------------------
describe('tier0Spans Business Number suppression', () => {
  it('does NOT emit government_id for a 9-digit number with a BN program-account suffix (RT0001)', () => {
    expect(labeledSpans('TPS 046454286 RT0001').some((s) => s.label === 'government_id')).toBe(false)
  })

  it('does NOT emit government_id for an RP (payroll) or hyphen-separated BN program account', () => {
    expect(labeledSpans('046454286 RP0001').some((s) => s.label === 'government_id')).toBe(false)
    expect(labeledSpans('046454286-RT0001').some((s) => s.label === 'government_id')).toBe(false)
  })

  it('emits government_id when a SIN cue precedes the number, even with a BN-looking suffix (never-leak)', () => {
    expect(labeledSpans('NAS 046454286 RT0001').some((s) => s.label === 'government_id')).toBe(true)
    expect(labeledSpans('N.A.S. 046454286 RT0001').some((s) => s.label === 'government_id')).toBe(true)
  })

  it('SIN cue is word-bounded, not a substring ("Business" must NOT un-suppress a BN)', () => {
    expect(labeledSpans('Business number 046454286 RT0001').some((s) => s.label === 'government_id')).toBe(false)
  })

  it('still emits government_id for a bare 9-digit Luhn number (SIN recall preserved)', () => {
    const gov = labeledSpans('NAS 046454286').find((s) => s.label === 'government_id')
    expect(gov).toBeDefined()
    expect(gov!.sub.replace(/\D/g, '')).toBe('046454286')
  })
})

// -------------------------
// Glued NON-checksum digit-run floor (port of privacy_gate.py glued_digit_spans)
// All values are synthetic; 046454286 is the public SIN Luhn test vector.
// -------------------------
describe('tier0Spans glued digit-run floor', () => {
  it('catches a Luhn-valid 9-digit SIN glued to a name as government_id (no cue needed)', () => {
    const spans = labeledSpans('JaneDoe046454286')
    const hit = spans.find((s) => s.rule === 'tier0:digit_glued')
    expect(hit).toBeDefined()
    expect(hit!.label).toBe('government_id')
    expect(hit!.conf).toBe(0.8)
    expect(hit!.validator).toBe('luhn_ok')
    expect(hit!.sub).toBe('046454286')
  })

  it('does NOT over-redact a long non-cue account run glued to letters (round-2 precision gate)', () => {
    // Round-2 dropped the old 10-19 no-cue glued path: a 12-digit run glued to a word is left to the neural
    // tier / cue-gated path, so coding traffic is not nuked. Mirrors privacy_gate.py glued_digit_spans.
    const spans = labeledSpans('foo000123456789')
    expect(spans.some((s) => s.rule === 'tier0:digit_glued')).toBe(false)
  })

  it('does NOT fire on a non-Luhn 9-digit code id glued to letters (translateY(123456789px))', () => {
    // 123456789 fails Luhn -> a code identifier, not a SIN. Must stay clean so CSS/transform code survives.
    expect(labeledSpans('translateY(123456789px)').some((s) => s.rule === 'tier0:digit_glued')).toBe(false)
    expect(labeledSpans('seed1234567890').some((s) => s.rule === 'tier0:digit_glued')).toBe(false)
  })

  it('catches a Luhn-valid 9-digit run glued after a SIN cue (still government_id)', () => {
    const spans = labeledSpans('NAS:client046454286')
    const hit = spans.find((s) => s.rule === 'tier0:digit_glued')
    expect(hit).toBeDefined()
    expect(hit!.label).toBe('government_id')
    expect(hit!.conf).toBe(0.8)
  })

  it('does NOT fire on a clean-boundary run (owned by DIGIT_RUN_RE, not the glued floor)', () => {
    // A space-separated 12-digit run has clean boundaries on both sides -> no letter-adjacency.
    const spans = labeledSpans('value 000123456789 here')
    expect(spans.some((s) => s.rule === 'tier0:digit_glued')).toBe(false)
  })
})

// -------------------------
// Cue-anchored card_cvv + card_expiry (port of privacy_gate.py card_aux_spans)
// -------------------------
describe('tier0Spans card aux (CVV + expiry)', () => {
  it('catches a cue-anchored CVV (EN keyword)', () => {
    for (const text of ['security code 123', 'cvc: 123', 'CVV 4567']) {
      const hit = labeledSpans(text).find((s) => s.label === 'card_cvv')
      expect(hit, text).toBeDefined()
      expect(/^\d{3,4}$/.test(hit!.sub), `${text} -> ${hit!.sub}`).toBe(true)
    }
  })

  it('catches a French CVV cue (cryptogramme)', () => {
    const hit = labeledSpans('cryptogramme visuel 321').find((s) => s.label === 'card_cvv')
    expect(hit).toBeDefined()
    expect(hit!.sub).toBe('321')
  })

  it('catches a cue-anchored expiry (MM/YY and MM/YYYY)', () => {
    const a = labeledSpans('expiry 08/27').find((s) => s.label === 'card_expiry')
    expect(a).toBeDefined()
    expect(a!.sub).toBe('08/27')
    const b = labeledSpans('exp 12/2026').find((s) => s.label === 'card_expiry')
    expect(b).toBeDefined()
    expect(b!.sub).toBe('12/2026')
  })

  it('does NOT blanket-redact a bare 3-digit number or a generic date (cue required)', () => {
    expect(labeledSpans('the answer is 123').some((s) => s.label === 'card_cvv')).toBe(false)
    // a bare MM/YY with no expiry cue should not be a card_expiry
    expect(labeledSpans('see section 08/27 below').some((s) => s.label === 'card_expiry')).toBe(false)
  })

  it('offset test: the CVV span indexes exactly the digit group in the original text', () => {
    const text = 'card verification code 4567 ok'
    const hit = tier0Spans(text).find((s) => s.label === 'card_cvv')
    expect(hit).toBeDefined()
    expect(text.slice(hit!.start, hit!.end)).toBe('4567')
  })
})

// -------------------------
// Separator-tolerant card + dotted SSN (port of privacy_gate.py separated_card_spans)
// 4111111111111111 is the public Visa Luhn test card; 123.45.6789 a synthetic dotted SSN.
// -------------------------
describe('tier0Spans separated card + dotted SSN', () => {
  it('catches a dot-separated Luhn-valid payment card (tier0:card_sep)', () => {
    const hit = labeledSpans('pay 4111.1111.1111.1111 now').find((s) => s.rule === 'tier0:card_sep')
    expect(hit).toBeDefined()
    expect(hit!.label).toBe('payment_card')
    expect(hit!.validator).toBe('luhn_ok')
    expect(hit!.sub).toBe('4111.1111.1111.1111')
  })

  it('catches a hyphen-separated Luhn-valid payment card', () => {
    const hit = labeledSpans('card 4111-1111-1111-1111 end').find((s) => s.rule === 'tier0:card_sep')
    expect(hit).toBeDefined()
    expect(hit!.label).toBe('payment_card')
  })

  it('does NOT emit card_sep for a dot-grouped 16-run that fails Luhn', () => {
    expect(labeledSpans('4111.1111.1111.1112').some((s) => s.rule === 'tier0:card_sep')).toBe(false)
  })

  it('catches a dot-separated SSN as government_id (tier0:ssn_dotted)', () => {
    const hit = labeledSpans('ssn 123.45.6789 ok').find((s) => s.rule === 'tier0:ssn_dotted')
    expect(hit).toBeDefined()
    expect(hit!.label).toBe('government_id')
    expect(hit!.sub).toBe('123.45.6789')
  })

  it('does NOT treat a longer dotted sequence (version/IP-like) as a dotted SSN', () => {
    expect(labeledSpans('build 123.45.6789.1').some((s) => s.rule === 'tier0:ssn_dotted')).toBe(false)
  })
})

// -------------------------
// Control-char (Cc) digit-separator obfuscation resistance (round-2 Cf+Cc strip)
// TAB is already neutralized by normSpace; the C0 separators (FS/GS/RS/US U+001C-001F) are NOT, so a
// US-separated (U+001F) card exercises the new Cc branch of the +cf re-scan specifically.
// -------------------------
describe('tier0Spans control-char (Cc) resistance', () => {
  const US = '' // UNIT SEPARATOR (category Cc), not covered by normSpace

  it('catches a US-control-separated payment card via the +cf re-scan', () => {
    const text = 'card ' + '4111111111111111'.split('').join(US) + ' end'
    const card = tier0Spans(text).find((s) => s.label === 'payment_card')
    expect(card).toBeDefined()
    expect(card!.rule.endsWith('+cf')).toBe(true)
    expect(text.slice(card!.start, card!.end).replace(/[^0-9]/g, '')).toBe('4111111111111111')
  })

  it('also catches a TAB-separated payment card (normSpace path)', () => {
    const text = 'card ' + '4111111111111111'.split('').join('\t') + ' end'
    const card = tier0Spans(text).find((s) => s.label === 'payment_card')
    expect(card).toBeDefined()
    expect(text.slice(card!.start, card!.end).replace(/[^0-9]/g, '')).toBe('4111111111111111')
  })

  it('hasFormatChars is true for TAB + C0-control (Cc) and ZWSP (Cf)', () => {
    expect(hasFormatChars('a\tb')).toBe(true)
    expect(hasFormatChars('a' + US + 'b')).toBe(true)
    expect(hasFormatChars('a​b')).toBe(true)
    expect(hasFormatChars('plain text')).toBe(false)
  })
})

// -------------------------
// Zero-width / Unicode format-char (Cf) obfuscation resistance
// (port of privacy_gate.py _has_format_chars / _strip_format_chars + the tier0_spans +cf re-scan)
// All values are synthetic; 4111111111111111 is the public Visa Luhn test card, GB82WEST...32 the ISO IBAN
// test vector, 046454286 the public SIN Luhn vector. ZW is a literal zero-width space (U+200B).
// -------------------------
describe('tier0Spans zero-width / format-char resistance', () => {
  const ZW = '​'

  it('catches a zero-width-interleaved payment card', () => {
    const text = 'card ' + '4111111111111111'.split('').join(ZW) + ' end'
    const card = tier0Spans(text).find((s) => s.label === 'payment_card')
    expect(card).toBeDefined()
    expect(card!.rule.endsWith('+cf')).toBe(true)
    // the span maps back onto the ORIGINAL text and covers the digits (with the interleaved invisibles)
    expect(text.slice(card!.start, card!.end).replace(/[^0-9]/g, '')).toBe('4111111111111111')
  })

  it('catches a zero-width-interleaved IBAN', () => {
    const text = 'IBAN ' + 'GB82WEST12345698765432'.split('').join(ZW) + ' fin'
    const iban = tier0Spans(text).find((s) => s.label === 'iban')
    expect(iban).toBeDefined()
    expect(iban!.rule.endsWith('+cf')).toBe(true)
    expect(text.slice(iban!.start, iban!.end).replace(new RegExp(ZW, 'g'), '')).toBe('GB82WEST12345698765432')
  })

  it('catches a zero-width-interleaved 9-digit government id (SIN cue)', () => {
    const text = 'NAS ' + '046454286'.split('').join(ZW)
    const gov = tier0Spans(text).find((s) => s.label === 'government_id')
    expect(gov).toBeDefined()
    expect(gov!.rule.endsWith('+cf')).toBe(true)
    expect(text.slice(gov!.start, gov!.end).replace(/[^0-9]/g, '')).toBe('046454286')
  })

  it('does not crash and adds no +cf spans when no format chars are present', () => {
    const spans = tier0Spans('Card: 4539148803436467')
    expect(spans.some((s) => s.rule.endsWith('+cf'))).toBe(false)
    expect(spans.some((s) => s.label === 'payment_card')).toBe(true)
  })
})

describe('Unicode No-digit + percent-encoded card homoglyphs (parity with privacy_gate _normdigits / _SEP_CARD_RE %20)', () => {
  const sup = (d: string) =>
    [...d].map((c) => ('⁰¹²³⁴⁵⁶⁷⁸⁹'[Number(c)])).join('')
  it('catches a superscript-digit Luhn card (category No, which \\d misses)', () => {
    const card = sup('4111111111111111')
    const spans = tier0Spans('card ' + card)
    expect(spans.some((s) => s.label === 'payment_card')).toBe(true)
  })
  it('catches a %20-separated Luhn card (URL-encoded spaces)', () => {
    const spans = tier0Spans('card=4111%201111%201111%201111')
    expect(spans.some((s) => s.label === 'payment_card' && s.rule === 'tier0:card_sep')).toBe(true)
  })
  it('does not over-redact a non-Luhn %20 / dotted group', () => {
    expect(tier0Spans('id 1234.5678.9012.3456').some((s) => s.rule === 'tier0:card_sep')).toBe(false)
  })
})
