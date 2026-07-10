// Tests for the layout-preserving view reconstruction. The SAFETY-CRITICAL invariant: every reconstructed
// display char that belongs to the original document maps to its TRUE original offset, and synthetic padding
// is offset -1 (a space). If this holds, redaction chips (rendered by slicing `text` at span offsets) can
// never disagree with the flat view about WHAT gets redacted -- only about where it sits on screen.

import React, { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { describe, it, expect, vi } from 'vitest'
import LayoutCanvas, { buildPdfLines, buildGridLines, layoutKind } from './LayoutCanvas'
import type { PageGeom } from '../lib/pdf'

type Line = { text: string; origAt: number[]; blankBefore: number; pageBreakBefore: boolean }

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

function span(id: string, start: number, end: number, active: boolean) {
  return { id, start, end, label: 'email', tier: 0, conf: 0.99, rule: 'test', source: 'manual' as const, active }
}

async function renderLayoutCanvas(props: React.ComponentProps<typeof LayoutCanvas>): Promise<{ host: HTMLDivElement; root: Root }> {
  const host = document.createElement('div')
  document.body.appendChild(host)
  const root = createRoot(host)
  await act(async () => {
    root.render(React.createElement(LayoutCanvas, props))
  })
  return { host, root }
}

async function cleanupRender(root: Root, host: HTMLDivElement): Promise<void> {
  await act(async () => {
    root.unmount()
  })
  host.remove()
}

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

describe('LayoutCanvas redaction pinning', () => {
  it('renders active spans as same-length masks, not placeholders, while inactive spans stay literal', async () => {
    const text = 'Name\tEmail\nAlice\talice@example.test\nBob\tkept@example.test'
    const activeValue = 'alice@example.test'
    const inactiveValue = 'kept@example.test'
    const activeStart = text.indexOf(activeValue)
    const inactiveStart = text.indexOf(inactiveValue)
    const placeholderOf = new Map([
      ['active-email', '<EMAIL_001>'],
      ['kept-email', '<EMAIL_002>'],
    ])
    const { host, root } = await renderLayoutCanvas({
      text,
      spans: [
        span('active-email', activeStart, activeStart + activeValue.length, true),
        span('kept-email', inactiveStart, inactiveStart + inactiveValue.length, false),
      ],
      placeholderOf,
      selectedId: null,
      onSelect: vi.fn(),
      onAddManual: vi.fn(),
      kind: 'tsv',
    })

    try {
      const activeChip = host.querySelector('.tok-active') as HTMLElement | null
      const inactiveChip = host.querySelector('.tok-inactive') as HTMLElement | null

      expect(activeChip?.textContent).toBe('██████████████████')
      expect(activeChip?.textContent).toHaveLength(activeValue.length)
      expect(activeChip?.textContent).not.toBe(placeholderOf.get('active-email'))
      expect(activeChip?.textContent).not.toContain(activeValue)
      expect(activeChip?.style.padding).toBe('0px')
      expect(activeChip?.style.fontSize).toBe('1em')
      expect(activeChip?.style.fontFamily).toBe('inherit')
      expect(activeChip?.style.fontWeight).toBe('inherit')

      expect(inactiveChip?.textContent).toBe(inactiveValue)
      expect(inactiveChip?.style.fontFamily).toBe('inherit')
      expect(inactiveChip?.style.fontWeight).toBe('inherit')
      expect(host.textContent).toContain(inactiveValue)
      expect(host.textContent).not.toContain('<EMAIL_001>')
    } finally {
      await cleanupRender(root, host)
    }
  })

  it('preserves spaces inside an active layout span so the rendered mask pins each original column', async () => {
    const text = 'Label\tA B C'
    const activeValue = 'A B C'
    const activeStart = text.indexOf(activeValue)
    const { host, root } = await renderLayoutCanvas({
      text,
      spans: [span('manual-name', activeStart, activeStart + activeValue.length, true)],
      placeholderOf: new Map([['manual-name', '<PERSON_001>']]),
      selectedId: null,
      onSelect: vi.fn(),
      onAddManual: vi.fn(),
      kind: 'tsv',
    })

    try {
      const activeChip = host.querySelector('.tok-active') as HTMLElement | null

      expect(activeChip?.textContent).toBe('█ █ █')
      expect(activeChip?.textContent).toHaveLength(activeValue.length)
      expect(activeChip?.textContent?.[1]).toBe(' ')
      expect(activeChip?.textContent?.[3]).toBe(' ')
    } finally {
      await cleanupRender(root, host)
    }
  })
})
