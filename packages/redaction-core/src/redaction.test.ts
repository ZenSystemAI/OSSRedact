// Tests for the pure redaction core -- mergeSpans, buildEntityMap, redactedText, rehydrate, explain.
// All inputs are synthetic -- no real PII.
// Batch helpers (JSZip-dependent assembleZip, extOf, etc.) live in the workbench only.

import { describe, it, expect } from 'vitest'
import {
  mergeSpans,
  combineWithManual,
  buildEntityMap,
  redactedText,
  rehydrate,
  toSpans,
  newPlaceholderIndex,
  explain,
  sweepKnownValues,
  resolveRenderSpans,
} from './redaction'
import type { RawSpan, Span } from './types'

// Helper: build a minimal RawSpan
function raw(start: number, end: number, label: string, conf = 0.9): RawSpan {
  return { start, end, label, tier: 0, conf, rule: 'test' }
}

// Helper: build a full Span from a RawSpan
function span(start: number, end: number, label: string, conf = 0.9, active = true): Span {
  return { start, end, label, tier: 0, conf, rule: 'test', id: `t_${start}_${end}`, source: 'auto', active }
}

// -------------------------
// mergeSpans
// -------------------------
describe('mergeSpans', () => {
  it('merges two overlapping spans into one with max end', () => {
    const result = mergeSpans([raw(0, 10, 'email'), raw(5, 15, 'email')])
    expect(result).toHaveLength(1)
    expect(result[0].start).toBe(0)
    expect(result[0].end).toBe(15)
  })

  it('keeps non-overlapping spans separate', () => {
    const result = mergeSpans([raw(0, 5, 'email'), raw(10, 20, 'phone')])
    expect(result).toHaveLength(2)
    expect(result[0].end).toBe(5)
    expect(result[1].start).toBe(10)
  })

  it('picks the higher-confidence member label', () => {
    const a = raw(0, 10, 'email', 0.7)
    const b = raw(5, 15, 'phone', 0.95)
    const result = mergeSpans([a, b])
    expect(result).toHaveLength(1)
    expect(result[0].label).toBe('phone')
  })

  it('picks the longer member label when confidence is equal', () => {
    const a = raw(0, 5, 'email', 0.9)
    const b = raw(3, 15, 'phone', 0.9)
    const result = mergeSpans([a, b])
    expect(result).toHaveLength(1)
    expect(result[0].label).toBe('phone')
  })

  it('merges three chained-overlapping spans into exactly one', () => {
    const result = mergeSpans([raw(0, 10, 'email'), raw(8, 18, 'phone'), raw(16, 25, 'email')])
    expect(result).toHaveLength(1)
    expect(result[0].start).toBe(0)
    expect(result[0].end).toBe(25)
  })

  it('returns empty array for empty input', () => {
    expect(mergeSpans([])).toHaveLength(0)
  })
})

// -------------------------
// combineWithManual
// -------------------------
describe('combineWithManual', () => {
  it('active manual span suppresses an overlapping fresh detection', () => {
    const manual: Span = span(0, 10, 'manual_label', 0.9, true)
    manual.source = 'manual'
    const detected: Span = span(5, 15, 'phone', 0.85, true)
    detected.source = 'auto'

    const result = combineWithManual([manual], [detected])
    expect(result.some((s) => s.source === 'auto' && s.start === 5)).toBe(false)
    expect(result.some((s) => s.source === 'manual')).toBe(true)
  })

  it('inactive manual span does NOT suppress a fresh detection', () => {
    const manual: Span = span(0, 10, 'manual_label', 0.9, false)
    manual.source = 'manual'
    const detected: Span = span(5, 15, 'phone', 0.85, true)
    detected.source = 'auto'

    const result = combineWithManual([manual], [detected])
    expect(result.some((s) => s.source === 'auto' && s.start === 5 && s.end === 15)).toBe(true)
  })

  it('discards prior auto spans and replaces with fresh detections', () => {
    const oldAuto: Span = span(20, 30, 'email', 0.9, true)
    oldAuto.source = 'auto'
    const fresh: Span = span(20, 30, 'email', 0.95, true)
    fresh.source = 'auto'
    const result = combineWithManual([oldAuto], [fresh])
    const autoSpans = result.filter((s) => s.source === 'auto')
    expect(autoSpans).toHaveLength(1)
    expect(autoSpans[0].conf).toBe(0.95)
  })
})

// -------------------------
// buildEntityMap + redactedText + rehydrate (plan 019 / plan 020 core API)
// -------------------------
describe('round-trip', () => {
  it('buildEntityMap creates zero-padded placeholders per label', () => {
    const text = 'Contact alice@example.com or bob@example.com for info.'
    const spans: Span[] = [
      span(8, 25, 'email'),
      span(29, 44, 'email'),
    ]
    spans[0].id = 'id1'
    spans[1].id = 'id2'
    const { map } = buildEntityMap(text, spans)
    expect(Object.keys(map)).toContain('<EMAIL_001>')
    expect(Object.keys(map)).toContain('<EMAIL_002>')
    expect(map['<EMAIL_001>']).toBe('alice@example.com')
    expect(map['<EMAIL_002>']).toBe('bob@example.com')
  })

  it('redactedText replaces active spans with placeholders', () => {
    const t = 'Contact alice@test.com or bob@test.com done.'
    const spans: Span[] = [
      span(8, 22, 'email'),
      span(26, 38, 'email'),
    ]
    const redacted = redactedText(t, spans)
    expect(redacted).toContain('<EMAIL_001>')
    expect(redacted).toContain('<EMAIL_002>')
    expect(redacted).not.toContain('alice')
    expect(redacted).not.toContain('bob')
  })

  it('rehydrate restores original text from entity map', () => {
    const t = 'Contact alice@test.com or bob@test.com done.'
    const spans: Span[] = [
      span(8, 22, 'email'),
      span(26, 38, 'email'),
    ]
    const { map } = buildEntityMap(t, spans)
    const redacted = redactedText(t, spans)
    const restored = rehydrate(redacted, map)
    expect(restored).toBe(t)
  })

  it('inactive spans are skipped by redactedText and do not appear in buildEntityMap', () => {
    const t = 'Call 514-555-0100 or 514-555-0101 for help.'
    const spans: Span[] = [
      span(5, 17, 'phone', 0.85, true),
      span(21, 33, 'phone', 0.85, false),
    ]
    const { map } = buildEntityMap(t, spans)
    expect(Object.keys(map)).toHaveLength(1)
    const redacted = redactedText(t, spans)
    expect(redacted).toContain('514-555-0101')
    expect(redacted).not.toContain('514-555-0100')
  })
})

// -------------------------
// buildEntityMap carry-in / shared batch index (finding 020)
// -------------------------
describe('buildEntityMap carry-in (shared index)', () => {
  it('same label+value across two files yields the SAME placeholder', () => {
    const t1 = 'Marie Tremblay sent a wire.'
    const t2 = 'Hello Marie Tremblay, your file is ready.'
    const s1: Span[] = [span(0, 14, 'person')]
    const s2: Span[] = [span(6, 20, 'person')]
    s1[0].id = 'a1'
    s2[0].id = 'b1'
    const idx = newPlaceholderIndex()
    const r1 = buildEntityMap(t1, s1, idx)
    const r2 = buildEntityMap(t2, s2, idx)
    expect(r1.placeholderOf.get('a1')).toBe('<PERSON_001>')
    expect(r2.placeholderOf.get('b1')).toBe('<PERSON_001>')
    expect(r2.map['<PERSON_001>']).toBe('Marie Tremblay')
    expect(Object.keys(r2.map)).toHaveLength(1)
  })

  it('distinct values increment monotonically across files (continuous numbering)', () => {
    const t1 = 'Alice Martin'
    const t2 = 'Bob Gagnon'
    const t3 = 'Carl Roy'
    const s1: Span[] = [span(0, 12, 'person')]
    const s2: Span[] = [span(0, 10, 'person')]
    const s3: Span[] = [span(0, 8, 'person')]
    s1[0].id = 'x'; s2[0].id = 'y'; s3[0].id = 'z'
    const idx = newPlaceholderIndex()
    expect(buildEntityMap(t1, s1, idx).placeholderOf.get('x')).toBe('<PERSON_001>')
    expect(buildEntityMap(t2, s2, idx).placeholderOf.get('y')).toBe('<PERSON_002>')
    expect(buildEntityMap(t3, s3, idx).placeholderOf.get('z')).toBe('<PERSON_003>')
    expect(Object.keys(idx.map).sort()).toEqual(['<PERSON_001>', '<PERSON_002>', '<PERSON_003>'])
  })

  it('per-label counters are independent in the shared index', () => {
    const t = 'Marie at marie@x.ca'
    const spans: Span[] = [span(0, 5, 'person'), span(9, 19, 'email')]
    spans[0].id = 'p'; spans[1].id = 'e'
    const idx = newPlaceholderIndex()
    const r = buildEntityMap(t, spans, idx)
    expect(r.placeholderOf.get('p')).toBe('<PERSON_001>')
    expect(r.placeholderOf.get('e')).toBe('<EMAIL_001>')
  })

  it('dedup is case/whitespace-normalized but never merges distinct values', () => {
    const t1 = '  marie   tremblay '
    const t2 = 'Marie Tremblay'
    const t3 = 'Marie Gagnon'
    const s1: Span[] = [span(0, t1.length, 'person')]
    const s2: Span[] = [span(0, t2.length, 'person')]
    const s3: Span[] = [span(0, t3.length, 'person')]
    s1[0].id = '1'; s2[0].id = '2'; s3[0].id = '3'
    const idx = newPlaceholderIndex()
    const a = buildEntityMap(t1, s1, idx).placeholderOf.get('1')
    const b = buildEntityMap(t2, s2, idx).placeholderOf.get('2')
    const c = buildEntityMap(t3, s3, idx).placeholderOf.get('3')
    expect(a).toBe(b)
    expect(c).not.toBe(a)
  })

  it('no index = legacy per-document behaviour (fresh counters, byte-for-byte unchanged)', () => {
    const t = 'Contact alice@example.com or bob@example.com'
    const spans: Span[] = [span(8, 25, 'email'), span(29, 44, 'email')]
    spans[0].id = 'i1'; spans[1].id = 'i2'
    const r = buildEntityMap(t, spans)
    expect(r.placeholderOf.get('i1')).toBe('<EMAIL_001>')
    expect(r.placeholderOf.get('i2')).toBe('<EMAIL_002>')
  })

  it('redactedText threads the shared index for consistent placeholders across files', () => {
    const t1 = 'From Marie Tremblay'
    const t2 = 'To Marie Tremblay'
    const s1: Span[] = [span(5, 19, 'person')]
    const s2: Span[] = [span(3, 17, 'person')]
    s1[0].id = 'r1'; s2[0].id = 'r2'
    const idx = newPlaceholderIndex()
    const out1 = redactedText(t1, s1, idx)
    const out2 = redactedText(t2, s2, idx)
    expect(out1).toContain('<PERSON_001>')
    expect(out2).toContain('<PERSON_001>')
    expect(out1).not.toContain('Marie')
    expect(out2).not.toContain('Marie')
  })
})

// -------------------------
// toSpans (smoke)
// -------------------------
describe('toSpans', () => {
  it('converts raw spans to active workbench spans by default', () => {
    const raws = [raw(0, 5, 'email'), raw(10, 20, 'phone')]
    const spans = toSpans(raws, 'auto')
    expect(spans.every((s) => s.active)).toBe(true)
    expect(spans.every((s) => s.source === 'auto')).toBe(true)
  })

  it('marks muted-label spans as inactive', () => {
    const raws = [raw(0, 5, 'email'), raw(10, 20, 'phone')]
    const spans = toSpans(raws, 'auto', new Set(['phone']))
    const phone = spans.find((s) => s.label === 'phone')!
    expect(phone.active).toBe(false)
    const email = spans.find((s) => s.label === 'email')!
    expect(email.active).toBe(true)
  })
})

// -------------------------
// explain: provenance only -- never carries a value
// -------------------------
describe('explain', () => {
  it('returns metadata for each active span but never the original value', () => {
    const t = 'Contact alice@example.com for help.'
    const s = span(8, 25, 'email')
    const result = explain([s])
    expect(result).toHaveLength(1)
    const rec = result[0]
    expect(rec.label).toBe('email')
    expect(rec.start).toBe(8)
    expect(rec.end).toBe(25)
    // the explain record must NOT contain any field that equals the original value
    expect(JSON.stringify(rec)).not.toContain('alice@example.com')
  })

  it('omits inactive spans from the explain output', () => {
    const active = span(0, 5, 'email', 0.9, true)
    const inactive = span(10, 20, 'phone', 0.85, false)
    const result = explain([active, inactive])
    expect(result).toHaveLength(1)
    expect(result[0].label).toBe('email')
  })
})

// -------------------------
// Finding C: repeated-value sweep + active-over-inactive overlap resolution (leak-safety)
// -------------------------
describe('sweepKnownValues (repeated-value masking)', () => {
  it('masks a duplicate occurrence positional redaction would miss', () => {
    const text = 'Contact a.user@example.test then footer a.user@example.test'
    const out = redactedText(text, [span(8, 27, 'email')]) // detector found only the FIRST occurrence
    expect(out).not.toContain('a.user@example.test')
    expect((out.match(/<EMAIL_001>/g) || []).length).toBe(2)
  })

  it('does NOT mask a numeric value inside a longer number (token-boundary safe)', () => {
    const out = redactedText('acct 1234567 ref 12345678', [span(5, 12, 'account_number', 0.6)])
    expect(out).toContain('12345678')
  })

  it('does NOT rewrite inside an already-inserted placeholder, even across sweep passes', () => {
    // an org value literally "EMAIL_001" must not corrupt the "<EMAIL_001>" placeholder
    const out = sweepKnownValues('Footer a@b.example and EMAIL_001', { '<EMAIL_001>': 'a@b.example', '<ORG_001>': 'EMAIL_001' })
    expect(out).toBe('Footer <EMAIL_001> and <ORG_001>')
    expect(out).not.toMatch(/<</)
  })
})

describe('resolveRenderSpans (active PII wins over an overlapping inactive span)', () => {
  it('clips an inactive span around an active span it overlaps (active value never swallowed)', () => {
    const out = resolveRenderSpans([span(0, 26, 'manual', 1, false), span(9, 21, 'phone_number', 0.9, true)])
    expect(out.find((s) => s.start === 9 && s.end === 21)?.active).toBe(true)
    for (let off = 9; off < 21; off++) {
      expect(out.find((s) => !s.active && s.start <= off && s.end > off)).toBeUndefined()
    }
  })

  it('drops an inactive span fully contained in an active one', () => {
    const out = resolveRenderSpans([span(5, 10, 'manual', 1, false), span(0, 20, 'phone_number', 0.9, true)])
    expect(out.filter((s) => !s.active)).toHaveLength(0)
  })
})
