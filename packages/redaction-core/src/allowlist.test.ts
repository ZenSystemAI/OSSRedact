import { describe, it, expect } from 'vitest'
import { normalizeAllowValue, buildAllowSet, isAllowlisted, applyAllowlist } from './allowlist.js'

type S = { start: number; end: number; label: string }
const span = (text: string, sub: string, label: string): S => {
  const start = text.indexOf(sub)
  return { start, end: start + sub.length, label }
}

describe('normalizeAllowValue', () => {
  it('lowercases, trims, NFC-normalizes', () => {
    expect(normalizeAllowValue('  Alex ')).toBe('alex')
    expect(normalizeAllowValue('ALEX')).toBe('alex')
    // NFC: composed vs decomposed e-acute compare equal
    expect(normalizeAllowValue('André')).toBe(normalizeAllowValue('André'))
  })
})

describe('buildAllowSet', () => {
  it('normalizes + dedups + drops empties', () => {
    const s = buildAllowSet(['Alex', 'alex', '  ', 'alex@acme-loans.example'])
    expect(s.size).toBe(2)
    expect(s.has('alex')).toBe(true)
    expect(s.has('alex@acme-loans.example')).toBe(true)
  })
})

describe('isAllowlisted', () => {
  const allow = buildAllowSet(['alex', 'alex@acme-loans.example'])
  it('matches case-insensitively', () => {
    expect(isAllowlisted('Alex', allow)).toBe(true)
    expect(isAllowlisted('ALEX', allow)).toBe(true)
    expect(isAllowlisted('alex@ACME-LOANS.example', allow)).toBe(true)
  })
  it('does not match a non-listed value', () => {
    expect(isAllowlisted('jane', allow)).toBe(false)
  })
  it('an empty allowlist matches nothing', () => {
    expect(isAllowlisted('alex', new Set())).toBe(false)
  })
})

describe('applyAllowlist', () => {
  const allow = buildAllowSet(['alex', 'alex@acme-loans.example'])

  it('returns spans unchanged when the allowlist is empty', () => {
    const text = 'I am Alex'
    const spans = [span(text, 'Alex', 'person')]
    expect(applyAllowlist(spans, text, new Set())).toBe(spans)
  })

  it('drops a span whose exact text is allowlisted (any casing)', () => {
    const text = 'open /home/alex and email Alex'
    // 'alex' (lowercase path token at idx 11) and 'Alex' (prose, capitalized) both drop
    const lower = { start: 11, end: 15, label: 'username' } // 'alex' inside /home/alex
    const upper = { start: text.indexOf('Alex'), end: text.indexOf('Alex') + 4, label: 'person' }
    expect(text.slice(lower.start, lower.end)).toBe('alex')
    expect(text.slice(upper.start, upper.end)).toBe('Alex')
    const kept = applyAllowlist([lower, upper], text, allow)
    expect(kept).toHaveLength(0)
  })

  it('drops an allowlisted email span', () => {
    const text = 'reply to alex@acme-loans.example please'
    const spans = [span(text, 'alex@acme-loans.example', 'email')]
    expect(applyAllowlist(spans, text, allow)).toHaveLength(0)
  })

  it('NEVER drops a larger span that merely CONTAINS an allowlisted substring', () => {
    // allowlisting "alex" must not un-redact a different, sensitive email that contains it.
    const text = 'leaked: alex@acme-bank.example'
    const spans = [span(text, 'alex@acme-bank.example', 'email')]
    const kept = applyAllowlist(spans, text, allow)
    expect(kept).toHaveLength(1)
    expect(kept[0].label).toBe('email')
  })

  it('NEVER drops a multi-token name when only the first token is allowlisted', () => {
    const text = 'signed Alex Martin'
    const spans = [span(text, 'Alex Martin', 'person')]
    expect(applyAllowlist(spans, text, allow)).toHaveLength(1)
  })

  it('preserves non-allowlisted spans while dropping allowlisted ones', () => {
    const text = 'Alex met Jane'
    const spans = [span(text, 'Alex', 'person'), span(text, 'Jane', 'person')]
    const kept = applyAllowlist(spans, text, allow)
    expect(kept).toHaveLength(1)
    expect(text.slice(kept[0].start, kept[0].end)).toBe('Jane')
  })

  it('NEVER exempts a hard-floor span even when its exact text is allowlisted (floor guard)', () => {
    // Parity with the Python gate's FLOOR_NEVER_EXEMPT: a user who allowlists a real card + their own name
    // gets the NAME exempted but the CARD is force-kept. Closes the twin-parity gap (the shared filter is
    // self-protecting; a future caller cannot lose the floor).
    const card = '4111111111111111'
    const text = `card ${card} and name Alex`
    const floorAllow = buildAllowSet([card, 'alex'])
    const kept = applyAllowlist(
      [span(text, card, 'payment_card'), span(text, 'Alex', 'person')],
      text,
      floorAllow,
    )
    expect(kept).toHaveLength(1)
    expect(kept[0].label).toBe('payment_card') // card stays (floor); the allowlisted name drops
  })

  it('floor-guards every FLOOR_LABELS category against allowlisting', () => {
    for (const label of ['secret', 'payment_card', 'iban', 'government_id', 'tax_id', 'date_of_birth']) {
      const text = 'value SENSITIVE here'
      const sensitiveAllow = buildAllowSet(['SENSITIVE'])
      const kept = applyAllowlist([span(text, 'SENSITIVE', label)], text, sensitiveAllow)
      expect(kept, `${label} must survive allowlisting`).toHaveLength(1)
    }
  })
})
