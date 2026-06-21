// Tests for pure in-browser neural decode helpers.
// All inputs are synthetic -- no real PII and no model load.

import { describe, expect, it } from 'vitest'
import { decodeChunk, lineChunks, reconstructOffsets, windows } from './neural-decode'

function row(winner: number, width = 3): number[] {
  const logits = Array(width).fill(-8)
  logits[winner] = 8
  return logits
}

describe('neural decode chunking', () => {
  it('windows long lines on a word boundary and preserves absolute offsets', () => {
    const chunks = [...windows('aaaa bbbb cccc dddd', 100, 12, 4)]

    expect(chunks[0]).toEqual(['aaaa bbbb', 100])
    expect(chunks[1][1]).toBe(105)
    expect(chunks.map(([chunk]) => chunk).join('')).toContain('cccc')
  })

  it('prefers line boundaries without shifting offsets', () => {
    const chunks = [...lineChunks('abcd\nefgh\nijk\n', 10)]

    expect(chunks).toEqual([
      ['abcd\nefgh\n', 0],
      ['ijk\n', 10],
    ])
  })
})

describe('reconstructOffsets', () => {
  it('maps SentencePiece word markers across NBSP and narrow NBSP separators', () => {
    const text = 'Name:\u00a0Jean\u202fLuc'
    const offsets = reconstructOffsets(text, ['▁Name', ':', '▁Jean', '▁Luc'])

    expect(offsets).toEqual([
      [0, 4],
      [4, 5],
      [6, 10],
      [11, 14],
    ])
    expect(text.slice(offsets[2][0], offsets[2][1])).toBe('Jean')
    expect(text.slice(offsets[3][0], offsets[3][1])).toBe('Luc')
  })
})

describe('decodeChunk', () => {
  const id2label = {
    0: 'O',
    1: 'B-person',
    2: 'I-person',
  }

  it('merges BIO pieces into one offset-true span', () => {
    const text = 'Alice Zephyr wrote a note.'
    const spans = decodeChunk(text, ['▁Alice', '▁Zephyr', '▁wrote'], [
      row(0),
      row(1),
      row(2),
      row(0),
      row(0),
    ], id2label)

    expect(spans).toHaveLength(1)
    expect(spans[0]).toMatchObject({ start: 0, end: 12, label: 'person', tier: 1, rule: 'neural' })
    expect(text.slice(spans[0].start, spans[0].end)).toBe('Alice Zephyr')
    expect(spans[0].conf).toBeGreaterThan(0.99)
  })

  it('clamps decode to available logits so truncated chunks do not over-read', () => {
    const text = 'Alice Zephyr Extra'
    const spans = decodeChunk(text, ['▁Alice', '▁Zephyr', '▁Extra'], [
      row(0),
      row(1),
      row(2),
      row(0),
    ], id2label)

    expect(spans).toHaveLength(1)
    expect(text.slice(spans[0].start, spans[0].end)).toBe('Alice Zephyr')
  })
})
