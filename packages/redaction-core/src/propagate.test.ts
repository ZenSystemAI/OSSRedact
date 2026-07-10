// Detect-time repeat propagation -- TS twin of gate/tests/test_propagate_repeats.py (2026-07-05).
// Same contract: high-conf name-ish spans propagate to every literal repeat (case-insensitive,
// token-boundary-guarded), rule 'repeat'; low-conf / short / floor-shaped sources do not; mergeSpans
// unions overlaps so occurrences never duplicate.
import { describe, expect, it } from 'vitest'
import { mergeSpans, propagateRepeats } from './redaction.js'
import type { RawSpan } from './types.js'

const span = (start: number, end: number, label: string, conf = 0.99): RawSpan => ({
  start,
  end,
  label,
  tier: 2,
  conf,
  rule: 'gpu',
})

describe('propagateRepeats', () => {
  it('a single full-name span propagates bare surname repeats (the reported scenario)', () => {
    const text = 'Client: Jean Tremblay\nsolde...\nTREMBLAY dossier\ntremblay'
    const out = propagateRepeats(text, [span(8, 21, 'person')])
    const repeats = out.filter((s) => s.rule === 'repeat').map((s) => text.slice(s.start, s.end))
    expect(repeats).toContain('TREMBLAY')
    expect(repeats).toContain('tremblay')
  })

  it('does not propagate low-conf, short, or floor-shaped sources', () => {
    const text = 'Jo saw Jo; Dupont met Dupont; a@b.ca then a@b.ca'
    const out = propagateRepeats(text, [
      span(0, 2, 'person'), // too short
      span(11, 17, 'person', 0.4), // below conf floor
      span(30, 36, 'email'), // floor shape: already deterministic everywhere
    ])
    expect(out.filter((s) => s.rule === 'repeat')).toEqual([])
  })

  it('boundary guard blocks matches inside longer words (accents included)', () => {
    const text = 'Mme BÉLANGER note; bélanger encore; laBÉLANGERnon'
    const out = propagateRepeats(text, [span(4, 12, 'person')])
    const repeats = out.filter((s) => s.rule === 'repeat').map((s) => text.slice(s.start, s.end))
    expect(repeats).toEqual(['bélanger'])
  })

  it('mergeSpans unions propagated overlaps: one span per occurrence', () => {
    const text = 'Fournisseur: Laurentide inc. paiement a Laurentide inc. recu de LAURENTIDE INC.'
    const merged = mergeSpans(
      propagateRepeats(text, [span(13, 28, 'organization'), span(40, 56, 'organization', 0.8)]),
    )
    const orgs = merged.filter((s) => s.label === 'organization' || s.labels?.includes('organization'))
    expect(orgs).toHaveLength(3)
    expect(orgs.some((s) => text.slice(s.start, s.end).includes('LAURENTIDE INC'))).toBe(true)
  })
})
