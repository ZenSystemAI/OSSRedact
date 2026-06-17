// Tests for the layout-preserving view reconstruction. The SAFETY-CRITICAL invariant: every reconstructed
// display char that belongs to the original document maps to its TRUE original offset, and synthetic padding
// is offset -1 (a space). If this holds, redaction chips (rendered by slicing `text` at span offsets) can
// never disagree with the flat view about WHAT gets redacted -- only about where it sits on screen.

import { describe, it, expect } from 'vitest'
import { buildPdfLines, buildGridLines, layoutKind } from './LayoutCanvas'
import type { PageGeom } from '../lib/pdf'

type Line = { text: string; origAt: number[]; blankBefore: number; pageBreakBefore: boolean }

// the one invariant that guarantees chip correctness
function assertOffsetIntegrity(lines: Line[], text: string) {
  for (const line of lines) {
    expect(line.origAt.length).toBe(line.text.length)
    for (let i = 0; i < line.text.length; i++) {
      const o = line.origAt[i]
      if (o < 0) {
        expect(line.text[i]).toBe(' ') // padding is always a space
      } else {
        expect(line.text[i]).toBe(text[o]) // original char maps to its true offset
      }
    }
  }
}

describe('buildGridLines (xlsx/csv/tsv)', () => {
  it('reconstructs a tab grid with column alignment and exact offsets', () => {
    const text = 'A\tBB\nccc\td' // 2 rows x 2 cols
    const lines = buildGridLines(text, '\t')
    expect(lines.length).toBe(2)
    assertOffsetIntegrity(lines, text)
    // col 0 padded to the widest cell ("ccc" = 3) + 2-space gutter -> the second column starts aligned
    const col1Start = (l: Line) => l.text.search(/\S(?=[^]*$)/) // not used; alignment checked structurally below
    void col1Start
    // row 1 col-1 ("BB") and row 2 col-1 ("d") must start at the SAME display column
    const startOfSecondCell = (l: Line) => {
      // first index whose origAt corresponds to the second cell's first char
      const firstPad = l.origAt.indexOf(-1)
      let i = firstPad
      while (i < l.origAt.length && l.origAt[i] < 0) i++
      return i
    }
    expect(startOfSecondCell(lines[0])).toBe(startOfSecondCell(lines[1]))
  })

  it('handles a CSV grid', () => {
    const text = 'name,amount\nAcme,9.99'
    const lines = buildGridLines(text, ',')
    expect(lines.length).toBe(2)
    assertOffsetIntegrity(lines, text)
  })
})

describe('buildPdfLines (geometry)', () => {
  // Two visual rows (y=100 top, y=80 bottom), two columns (x=0, x=100). Offsets index `text` exactly.
  const text = 'NameTotalAcme9.99'
  const mk = (str: string, charStart: number, x: number, y: number): PageGeom['items'][number] => ({
    str,
    charStart,
    charEnd: charStart + str.length,
    transform: [1, 0, 0, 10, x, y],
    width: str.length * 6,
    height: 10,
    dir: 'ltr',
  })
  const pages: PageGeom[] = [
    {
      pageIndex: 0,
      rotation: 0,
      viewBoxWidth: 600,
      viewBoxHeight: 800,
      items: [mk('Name', 0, 0, 100), mk('Total', 4, 100, 100), mk('Acme', 9, 0, 80), mk('9.99', 13, 100, 80)],
    },
  ]

  it('groups items into 2 visual lines and preserves exact offsets', () => {
    const lines = buildPdfLines(text, pages)
    expect(lines.length).toBe(2)
    assertOffsetIntegrity(lines, text)
    // line 1 holds both first-row cells, separated by padding (the column gap)
    expect(lines[0].text.replace(/\s+/g, '')).toBe('NameTotal')
    expect(lines[1].text.replace(/\s+/g, '')).toBe('Acme9.99')
    // a column gap was inserted (the two cells are not glued)
    expect(lines[0].text).toMatch(/Name\s+Total/)
  })

  it('reports the document as pdf-layout-capable', () => {
    expect(layoutKind('pdf', pages)).toBe('pdf')
    expect(layoutKind('xlsx', undefined)).toBe('grid')
    expect(layoutKind('txt', undefined)).toBe(null)
  })

  it('treats a scanned / image-only PDF (page geometry but no text items) as NOT layout-capable', () => {
    // such a PDF must fall through to the flat/Pages flow, not a dead-end layout screen (pre-merge review)
    const scanned: PageGeom[] = [{ pageIndex: 0, rotation: 0, viewBoxWidth: 600, viewBoxHeight: 800, items: [] }]
    expect(layoutKind('pdf', scanned)).toBe(null)
  })
})
