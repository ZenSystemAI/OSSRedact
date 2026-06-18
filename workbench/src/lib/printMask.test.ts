import { describe, expect, it } from 'vitest'
import { buildEntityMap, redactedText } from './redaction'
import type { Span } from './types'
import { maskPlaceholdersForPrint } from './printMask'

const span = (id: string, start: number, end: number, label = 'email'): Span => ({
  id,
  start,
  end,
  label,
  tier: 0,
  conf: 0.99,
  rule: 'test',
  source: 'auto',
  active: true,
})

describe('maskPlaceholdersForPrint', () => {
  it('uses fixed-width blocks instead of placeholder or value length', () => {
    const printed = maskPlaceholdersForPrint('A <EMAIL_001> B <PERSON_001>', {
      '<EMAIL_001>': 'a@b.test',
      '<PERSON_001>': 'A Very Long Synthetic Name',
    })

    expect(printed).toBe('A ████████ B ████████')
  })

  it('leaves placeholder-shaped text alone when it is not in the entity map', () => {
    const printed = maskPlaceholdersForPrint('Literal <EMAIL_999>, real <EMAIL_001>.', {
      '<EMAIL_001>': 'a@b.test',
    })

    expect(printed).toBe('Literal <EMAIL_999>, real ████████.')
  })

  it('masks swept duplicate values in the print-safe text', () => {
    const text = 'Contact a.user@example.test for details. Footer: a.user@example.test'
    const spans = [span('s1', 8, 27)]
    const { map } = buildEntityMap(text, spans)
    const redacted = redactedText(text, spans)
    const printed = maskPlaceholdersForPrint(redacted, map)

    expect(printed).not.toContain('a.user@example.test')
    expect(printed.match(/████████/g)).toHaveLength(2)
  })
})
