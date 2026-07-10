// Tests for the pure redaction core in redaction.ts.
// All inputs are synthetic -- no real PII.

import { describe, it, expect } from 'vitest'
import JSZip from 'jszip'
import { mergeSpans, combineWithManual, buildEntityMap, redactedText, rehydrate, toSpans, newPlaceholderIndex, sweepKnownValues, resolveRenderSpans } from './redaction'
import { extOf, typeBucket, sameTypeError, neutralName, assembleZip, redactedBatchText, redactTextWithPlaceholders, replacementsForText } from './batch'
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
    // span B has higher conf -> its label wins
    const a = raw(0, 10, 'email', 0.7)
    const b = raw(5, 15, 'phone', 0.95)
    const result = mergeSpans([a, b])
    expect(result).toHaveLength(1)
    expect(result[0].label).toBe('phone')
  })

  it('picks the longer member label when confidence is equal', () => {
    // a is shorter, b is longer -- both 0.9 -- b label wins
    const a = raw(0, 5, 'email', 0.9)
    const b = raw(3, 15, 'phone', 0.9)
    const result = mergeSpans([a, b])
    expect(result).toHaveLength(1)
    expect(result[0].label).toBe('phone')
  })

  it('merges three chained-overlapping spans into exactly one', () => {
    // A[0,10] overlaps B[8,18] overlaps C[16,25]
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
    // the fresh detection overlaps the active manual -> suppressed
    expect(result.some((s) => s.source === 'auto' && s.start === 5)).toBe(false)
    // the manual span survives
    expect(result.some((s) => s.source === 'manual')).toBe(true)
  })

  it('inactive manual span does NOT suppress a fresh detection', () => {
    const manual: Span = span(0, 10, 'manual_label', 0.9, false) // toggled OFF
    manual.source = 'manual'
    const detected: Span = span(5, 15, 'phone', 0.85, true)
    detected.source = 'auto'

    const result = combineWithManual([manual], [detected])
    // the fresh detection must survive because the manual span is inactive
    expect(result.some((s) => s.source === 'auto' && s.start === 5 && s.end === 15)).toBe(true)
  })

  it('discards prior auto spans and replaces with fresh detections', () => {
    const oldAuto: Span = span(20, 30, 'email', 0.9, true)
    oldAuto.source = 'auto'
    const fresh: Span = span(20, 30, 'email', 0.95, true)
    fresh.source = 'auto'
    // no manual spans -> prior auto is gone, fresh replaces
    const result = combineWithManual([oldAuto], [fresh])
    // result has exactly one auto span (the fresh one) -- the old one was replaced
    const autoSpans = result.filter((s) => s.source === 'auto')
    expect(autoSpans).toHaveLength(1)
    expect(autoSpans[0].conf).toBe(0.95)
  })
})

// -------------------------
// buildEntityMap + redactedText + rehydrate
// -------------------------
describe('round-trip', () => {
  const text = 'Contact alice@example.com or bob@example.com for info.'

  it('buildEntityMap creates zero-padded placeholders per label', () => {
    // text = 'Contact alice@example.com or bob@example.com for info.'
    //         01234567890123456789012345678901234567890123456789
    //                 8                25   29             44
    const spans: Span[] = [
      span(8, 25, 'email'),  // alice@example.com  (len 17)
      span(29, 44, 'email'), // bob@example.com   (len 15)
    ]
    spans[0].id = 'id1'
    spans[1].id = 'id2'
    const { map } = buildEntityMap(text, spans)
    const phs = Object.keys(map)
    expect(phs).toContain('<EMAIL_001>')
    expect(phs).toContain('<EMAIL_002>')
    expect(map['<EMAIL_001>']).toBe('alice@example.com')
    expect(map['<EMAIL_002>']).toBe('bob@example.com')
  })

  it('redactedText replaces active spans with placeholders', () => {
    // t = 'Contact alice@test.com or bob@test.com done.'
    //       01234567890123456789012345678901234567890123
    //               8            22  26          38
    const t = 'Contact alice@test.com or bob@test.com done.'
    const spans: Span[] = [
      span(8, 22, 'email'),  // alice@test.com
      span(26, 38, 'email'), // bob@test.com
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
      span(8, 22, 'email'),   // alice@test.com
      span(26, 38, 'email'),  // bob@test.com
    ]
    const { map } = buildEntityMap(t, spans)
    const redacted = redactedText(t, spans)
    const restored = rehydrate(redacted, map)
    expect(restored).toBe(t)
  })

  it('inactive spans are skipped by redactedText and do not appear in buildEntityMap', () => {
    const t = 'Call 514-555-0100 or 514-555-0101 for help.'
    const spans: Span[] = [
      span(5, 17, 'phone', 0.85, true),   // active
      span(21, 33, 'phone', 0.85, false),  // inactive
    ]
    const { map } = buildEntityMap(t, spans)
    // only 1 active span -> only one placeholder
    expect(Object.keys(map)).toHaveLength(1)
    // inactive span's original text stays in redactedText output
    const redacted = redactedText(t, spans)
    expect(redacted).toContain('514-555-0101')
    expect(redacted).not.toContain('514-555-0100')
  })
})

// -------------------------
// buildEntityMap carry-in (shared batch index, finding 020)
// -------------------------
describe('buildEntityMap carry-in (shared index)', () => {
  it('same label+value across two files yields the SAME placeholder', () => {
    // file 1: "Marie Tremblay" at [0,14]; file 2: same name at [6,20]
    const t1 = 'Marie Tremblay sent a wire.'
    const t2 = 'Hello Marie Tremblay, your file is ready.'
    const s1: Span[] = [span(0, 14, 'person')]
    const s2: Span[] = [span(6, 20, 'person')]
    s1[0].id = 'a1'
    s2[0].id = 'b1'
    const idx = newPlaceholderIndex()
    const r1 = buildEntityMap(t1, s1, idx)
    const r2 = buildEntityMap(t2, s2, idx)
    // identical original value -> identical placeholder across the two calls
    expect(r1.placeholderOf.get('a1')).toBe('<PERSON_001>')
    expect(r2.placeholderOf.get('b1')).toBe('<PERSON_001>')
    // the shared map has exactly ONE person entry (deduped), pointing at the value
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

  it('dedup is whitespace-normalized but never merges distinct values', () => {
    const t1 = '  Marie   Tremblay '
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
    expect(a).toBe(b) // whitespace only -> same placeholder
    expect(c).not.toBe(a) // a different person stays distinct
  })

  it('person case variants stay distinct and preserve lowercase paths and usernames', () => {
    const t = "I'm Nadia; open /home/nadia/dev/x and log in as nadia."
    const p = t.indexOf('Nadia')
    const spans: Span[] = [span(p, p + 'Nadia'.length, 'person')]
    spans[0].id = 'person'
    const { map } = buildEntityMap(t, spans)
    const out = redactedText(t, spans)
    expect(out).toContain('<PERSON_001>')
    expect(out).toContain('/home/nadia/dev/x')
    expect(out).toContain('as nadia')
    expect(rehydrate(out, map)).toBe(t)

    const idx = newPlaceholderIndex()
    const upper = [span(0, 'Nadia'.length, 'person')]
    const lower = [span(0, 'nadia'.length, 'person')]
    upper[0].id = 'upper'; lower[0].id = 'lower'
    expect(buildEntityMap('Nadia', upper, idx).placeholderOf.get('upper')).toBe('<PERSON_001>')
    expect(buildEntityMap('nadia', lower, idx).placeholderOf.get('lower')).toBe('<PERSON_002>')
  })

  it('case-sensitive password variants stay distinct and round-trip losslessly', () => {
    const t = 'primary AbC123xy backup abc123xy repeat abc123xy'
    const p1 = t.indexOf('AbC123xy')
    const p2 = t.indexOf('abc123xy')
    const spans: Span[] = [
      span(p1, p1 + 'AbC123xy'.length, 'password'),
      span(p2, p2 + 'abc123xy'.length, 'password'),
    ]
    spans[0].id = 'p1'; spans[1].id = 'p2'
    const { map } = buildEntityMap(t, spans)
    const out = redactedText(t, spans)
    expect(map['<PASSWORD_001>']).toBe('AbC123xy')
    expect(map['<PASSWORD_002>']).toBe('abc123xy')
    expect((out.match(/<PASSWORD_001>/g) || []).length).toBe(1)
    expect((out.match(/<PASSWORD_002>/g) || []).length).toBe(2)
    expect(rehydrate(out, map)).toBe(t)
  })

  it('no index = legacy per-document behaviour (fresh counters, byte-for-byte unchanged)', () => {
    const t = 'Contact alice@example.com or bob@example.com'
    const spans: Span[] = [span(8, 25, 'email'), span(29, 44, 'email')]
    spans[0].id = 'i1'; spans[1].id = 'i2'
    const r = buildEntityMap(t, spans) // no index
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
    expect(out2).toContain('<PERSON_001>') // same person -> same placeholder in both files
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
// batch helpers (finding 020): same-type enforcement, neutral names, zip assembly
// -------------------------
describe('batch helpers', () => {
  it('extOf + typeBucket bucket text-ish formats together; office/pdf stand alone', () => {
    expect(extOf('report.DOCX')).toBe('docx')
    expect(typeBucket('txt')).toBe('text')
    expect(typeBucket('md')).toBe('text')
    expect(typeBucket('csv')).toBe('text')
    expect(typeBucket('docx')).toBe('docx')
    expect(typeBucket('pdf')).toBe('pdf')
  })

  it('sameTypeError accepts a matching type and rejects a mismatch with a reason', () => {
    expect(sameTypeError('docx', 'docx')).toBeNull()
    expect(sameTypeError('text', 'md')).toBeNull() // .md is text-ish -> allowed in a text batch
    const err = sameTypeError('docx', 'xlsx')
    expect(err).toBeTruthy()
    expect(err).toContain('.xlsx')
    expect(err).toMatch(/different|own batch/i)
  })

  it('neutralName never echoes the upload filename; it is index-stamped and zero-padded', () => {
    expect(neutralName(0, 3, 'docx')).toBe('redacted-001.docx')
    expect(neutralName(2, 3, 'docx')).toBe('redacted-003.docx')
    // width grows with the batch size
    expect(neutralName(0, 1200, 'pdf')).toBe('redacted-0001.pdf')
  })

  it('assembleZip adds one entry per file with neutral names and never includes the entity map', async () => {
    const files = [
      { name: neutralName(0, 3, 'txt'), blob: new Blob(['<EMAIL_001> a'], { type: 'text/plain' }) },
      { name: neutralName(1, 3, 'txt'), blob: new Blob(['<EMAIL_001> b'], { type: 'text/plain' }) },
      { name: neutralName(2, 3, 'txt'), blob: new Blob(['<PERSON_001> c'], { type: 'text/plain' }) },
    ]
    const blob = await assembleZip(files, JSON.stringify([{ file: files[0].name, spans: [] }]))
    const zip = await JSZip.loadAsync(blob)
    const names = Object.keys(zip.files).sort()
    expect(names).toContain('redacted-001.txt')
    expect(names).toContain('redacted-002.txt')
    expect(names).toContain('redacted-003.txt')
    expect(names).toContain('audit-trail.json') // values-free audit is allowed
    // the shared entity map (originals) is NEVER inside the shareable zip
    expect(names.some((n) => /entity-map|map\.json/i.test(n))).toBe(false)
    // and no upload filename leaked in as an archive entry
    expect(names.every((n) => /^redacted-\d+\.txt$|^audit-trail\.json$/.test(n))).toBe(true)
  })

  it('redactedBatchText sweeps known values from the shared map across files', () => {
    const text = 'Second file repeats cross.file@example.test after detection missed it.'
    const shared = { '<EMAIL_001>': 'cross.file@example.test' }
    const out = redactedBatchText(text, [], new Map(), shared)
    expect(out).toBe('Second file repeats <EMAIL_001> after detection missed it.')
    expect(out).not.toContain('cross.file@example.test')
  })

  it('replacementsForText emits shared-map replacements outside active spans', () => {
    const text = 'First cross.file@example.test then cross.file@example.test again.'
    const s = span(6, 29, 'email')
    s.id = 'first'
    const repls = replacementsForText(text, [s], new Map([['first', '<EMAIL_001>']]), {
      '<EMAIL_001>': 'cross.file@example.test',
    })
    expect(repls).toEqual([
      { start: 6, end: 29, text: '<EMAIL_001>' },
      { start: 35, end: 58, text: '<EMAIL_001>' },
    ])
  })

  it('redactTextWithPlaceholders preserves inactive spans for review-controlled exports', () => {
    const text = 'Keep keep@example.test, redact mask@example.test.'
    const active = span(31, 48, 'email')
    active.id = 'active'
    const inactive = span(5, 22, 'email', 0.9, false)
    inactive.id = 'inactive'
    const out = redactTextWithPlaceholders(text, [inactive, active], new Map([['active', '<EMAIL_001>']]))
    expect(out).toBe('Keep keep@example.test, redact <EMAIL_001>.')
  })
})

// -------------------------
// Drift guard: the TEXT export path (redactedBatchText -> redaction-core sweepKnownValues) and the
// OFFICE export path (replacementsForText -> batch.ts sweepReplacements) are two SEPARATE sweep
// implementations that must stay leak-equivalent. They share MIN_SWEEP_LEN and the case-sensitive
// label set by hand; if one drifts (e.g. a changed min length or a removed cred label), these cases
// diverge and fail. Both paths self-redact here -- App.tsx's survivor gate is intentionally NOT
// involved, so this pins the library behaviour itself.
// -------------------------
describe('batch text vs office sweep stay leak-equivalent', () => {
  // Apply replacementsForText() ranges to the original text the way the office rebuild() does.
  function applyRepls(text: string, repls: { start: number; end: number; text: string }[]): string {
    const sorted = [...repls].sort((a, b) => a.start - b.start)
    let out = ''
    let last = 0
    for (const r of sorted) {
      out += text.slice(last, r.start) + r.text
      last = r.end
    }
    return out + text.slice(last)
  }

  type Case = {
    name: string
    text: string
    spans: Span[]
    placeholderOf: Map<string, string>
    sharedMap: Record<string, string>
    gone: string[] // values that MUST NOT survive in either output
    kept: string[] // values that MUST survive in both (sub-min-length / wrong-case)
  }

  const sp = (start: number, end: number, label: string): Span => span(start, end, label)

  const cases: Case[] = [
    {
      name: 'repeated regular value: span on first occurrence, sweep on the second',
      text: 'Email a.user@example.test now; footer a.user@example.test end.',
      spans: [sp(6, 25, 'email')],
      placeholderOf: new Map([['t_6_25', '<EMAIL_001>']]),
      sharedMap: { '<EMAIL_001>': 'a.user@example.test' },
      gone: ['a.user@example.test'],
      kept: [],
    },
    {
      name: 'cross-file value present only via the shared map (no local span)',
      text: 'Second file repeats cross.file@example.test after detection missed it.',
      spans: [],
      placeholderOf: new Map(),
      sharedMap: { '<EMAIL_001>': 'cross.file@example.test' },
      gone: ['cross.file@example.test'],
      kept: [],
    },
    {
      name: 'email label is case-insensitive: a lower-case repeat is also swept',
      text: 'Owner Marie@Example.test; cc marie@example.test on file.',
      spans: [],
      placeholderOf: new Map(),
      sharedMap: { '<EMAIL_001>': 'Marie@Example.test' },
      gone: ['Marie@Example.test', 'marie@example.test'],
      kept: [],
    },
    {
      name: 'person label is exact-case: lowercase path and username tokens are preserved',
      text: 'Owner Nadia; path /home/nadia/dev/x and user nadia.',
      spans: [],
      placeholderOf: new Map(),
      sharedMap: { '<PERSON_001>': 'Nadia' },
      gone: ['Owner Nadia'],
      kept: ['/home/nadia/dev/x', 'user nadia'],
    },
    {
      name: 'credential label is case-sensitive: a different-case token is left intact',
      text: 'pw Hunter2Token set; old value hunter2token differs.',
      spans: [],
      placeholderOf: new Map(),
      sharedMap: { '<PASSWORD_001>': 'Hunter2Token' },
      gone: ['Hunter2Token'],
      kept: ['hunter2token'], // proves the case-sensitive cred path, in BOTH implementations
    },
    {
      name: 'sub-min-length value is not swept (MIN_SWEEP_LEN floor, both paths)',
      text: 'code abc appears, then abc again.',
      spans: [],
      placeholderOf: new Map(),
      sharedMap: { '<CODE_001>': 'abc' },
      gone: [],
      kept: ['abc'],
    },
  ]

  for (const c of cases) {
    it(c.name, () => {
      const fromText = redactedBatchText(c.text, c.spans, c.placeholderOf, c.sharedMap)
      const fromOffice = applyRepls(c.text, replacementsForText(c.text, c.spans, c.placeholderOf, c.sharedMap))
      // 1) byte-for-byte parity: the two implementations must produce the identical redaction
      expect(fromOffice).toBe(fromText)
      // 2) every value that must be removed is gone from both
      for (const v of c.gone) {
        expect(fromText).not.toContain(v)
        expect(fromOffice).not.toContain(v)
      }
      // 3) every value that must remain is preserved in both
      for (const v of c.kept) {
        expect(fromText).toContain(v)
        expect(fromOffice).toContain(v)
      }
    })
  }
})

// -------------------------
// Finding C: repeated-value sweep (positional redaction misses duplicate occurrences)
// -------------------------
describe('sweepKnownValues + redactedText repeated-value hardening', () => {
  it('redactedText masks a duplicate occurrence the detector missed', () => {
    // detector found ONLY the first email occurrence (recall gap on the repeated footer copy)
    const text = 'Contact a.user@example.test for details. Footer: a.user@example.test'
    const spans: Span[] = [
      { id: 's1', start: 8, end: 27, label: 'email', tier: 0, conf: 0.99, rule: 'tier0:email', source: 'auto', active: true },
    ]
    expect(text.slice(8, 27)).toBe('a.user@example.test') // sanity: span covers the first occurrence
    const out = redactedText(text, spans)
    expect(out).not.toContain('a.user@example.test') // BOTH occurrences masked
    expect((out.match(/<EMAIL_001>/g) || []).length).toBe(2)
  })

  it('does NOT mask a numeric value inside a longer number (token-boundary safe)', () => {
    // "1234567" is detected; "12345678" elsewhere must NOT be corrupted by the sweep
    const text = 'acct 1234567 then ref 12345678 end'
    const spans: Span[] = [
      { id: 's1', start: 5, end: 12, label: 'account_number', tier: 0, conf: 0.6, rule: 'x', source: 'auto', active: true },
    ]
    expect(text.slice(5, 12)).toBe('1234567')
    const out = redactedText(text, spans)
    expect(out).toContain('12345678') // longer number intact
    expect(out).not.toMatch(/(?<![\d])1234567(?![\d])/) // the standalone value is gone
  })

  it('does NOT mask a short value inside a longer word', () => {
    const out = sweepKnownValues('Live wire', { '<X_001>': 'Live' })
    // "Live" (4 chars) is a whole word here -> masked; but it must not match inside "Lives"
    expect(out).toBe('<X_001> wire')
    expect(sweepKnownValues('He Lives here', { '<X_001>': 'Live' })).toBe('He Lives here')
  })

  it('does NOT rewrite inside an already-inserted placeholder (Codex DO-NOT-SHIP fix)', () => {
    // an org literally named "EMAIL" must not corrupt the "<EMAIL_001>" placeholder the positional pass made
    const map = { '<EMAIL_001>': 'a@b.example', '<ORG_001>': 'EMAIL' }
    const positional = '<EMAIL_001> ref a@b.example for EMAIL'
    const out = sweepKnownValues(positional, map)
    expect(out).not.toMatch(/<<|_001>_\d/) // no nested / corrupted placeholder
    expect(out.startsWith('<EMAIL_001> ')).toBe(true) // the inserted placeholder survived verbatim
    expect(out).not.toContain('a@b.example') // the duplicate value still got masked
    expect(rehydrate(out, map)).toContain('a@b.example') // and round-trips cleanly
  })

  it('does NOT let a later sweep entry corrupt a placeholder an earlier entry inserted (Codex round 2)', () => {
    // an org value literally "EMAIL_001" must not rewrite the "<EMAIL_001>" the email sweep just inserted
    const map = { '<EMAIL_001>': 'a@b.example', '<ORG_001>': 'EMAIL_001' }
    const out = sweepKnownValues('Footer a@b.example and EMAIL_001', map)
    expect(out).toBe('Footer <EMAIL_001> and <ORG_001>')
    expect(out).not.toMatch(/<</) // no nested/corrupted placeholder
    expect(rehydrate(out, map)).toBe('Footer a@b.example and EMAIL_001') // round-trips exactly
  })

  it('does NOT mask a value immediately before a combining accent mark', () => {
    // decomposed "Jose" + U+0301 is one visual token; masking "Jose" would orphan the accent
    const out = sweepKnownValues('José paid', { '<PERSON_001>': 'Jose' })
    expect(out).toBe('José paid')
  })

  it('does NOT mask a value inside an underscore-compound token', () => {
    expect(sweepKnownValues('Live_Wire on', { '<X_001>': 'Live' })).toBe('Live_Wire on')
  })

  it('round-trips: rehydrate restores all swept occurrences', () => {
    const text = 'a.user@example.test x a.user@example.test'
    const spans: Span[] = [
      { id: 's1', start: 0, end: 19, label: 'email', tier: 0, conf: 0.99, rule: 'x', source: 'auto', active: true },
    ]
    const { map } = buildEntityMap(text, spans)
    const out = redactedText(text, spans)
    expect(rehydrate(out, map)).toBe(text)
  })

  it('uses exact-case sweep for credentials and person values', () => {
    const out = sweepKnownValues('again abc123xy and Jane Roy and JANE ROY', {
      '<PASSWORD_001>': 'AbC123xy',
      '<PASSWORD_002>': 'abc123xy',
      '<PERSON_001>': 'Jane Roy',
    })
    expect(out).toBe('again <PASSWORD_002> and <PERSON_001> and JANE ROY')
  })
})

// -------------------------
// resolveRenderSpans: active PII must win over an overlapping inactive span (display-leak fix, pre-merge review)
// -------------------------
describe('resolveRenderSpans', () => {
  const span = (id: string, start: number, end: number, active: boolean, label = 'x'): Span => ({
    id, start, end, label, tier: 0, conf: 1, rule: 'r', source: id.startsWith('m') ? 'manual' : 'auto', active,
  })

  it('clips an inactive span around an active span it overlaps (active value never swallowed)', () => {
    // the EXACT pre-merge-review leak: inactive manual [0,26) overlapping active phone [9,21)
    const out = resolveRenderSpans([span('m1', 0, 26, false), span('p1', 9, 21, true, 'phone_number')])
    const act = out.find((s) => s.id === 'p1')!
    expect([act.start, act.end]).toEqual([9, 21]) // active span survives whole
    // NO inactive span may cover ANY offset inside the active range -> renders as a chip, not kept plaintext
    for (let off = 9; off < 21; off++) {
      expect(out.find((s) => !s.active && s.start <= off && s.end > off)).toBeUndefined()
    }
    // the inactive span is preserved only in the gaps around the active one
    expect(out.some((s) => !s.active && s.start === 0 && s.end === 9)).toBe(true)
    expect(out.some((s) => !s.active && s.start === 21 && s.end === 26)).toBe(true)
  })

  it('drops an inactive span fully contained in an active one', () => {
    const out = resolveRenderSpans([span('m', 5, 10, false), span('a', 0, 20, true)])
    expect(out.filter((s) => !s.active)).toHaveLength(0)
  })

  it('is a no-op (sort only) when nothing overlaps', () => {
    const out = resolveRenderSpans([span('a', 10, 15, true), span('b', 0, 5, false)])
    expect(out.map((s) => s.id)).toEqual(['b', 'a'])
    expect(out).toHaveLength(2)
  })
})
