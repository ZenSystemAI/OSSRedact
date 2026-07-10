// Layout-preserving text view. The flat DocCanvas linearizes a document into one reading-order string, so
// tables, columns, and page structure collapse. This view reconstructs that structure:
//   - PDF: from the per-text-item geometry (PageGeom.items: x/y transform + width) already extracted by
//     lib/pdf.ts -- group items into visual lines by y, place them in columns by x (pdftotext -layout style).
//   - xlsx / csv / tsv: from the delimiter structure of the flat text (\t between cells, \n between rows),
//     padding each column to a fixed width so the grid lines up.
//
// CRITICAL INVARIANT: this view changes ONLY visual spacing. Every rendered glyph that belongs to the
// original document carries its ORIGINAL char offset (origAt), and redaction chips are produced by slicing
// the SAME `text` at the SAME span offsets the detector/redactor use. Synthetic padding has offset -1 and is
// never part of a span. So the layout view can never disagree with the flat view about WHAT is redacted --
// only about where it sits on screen. Monospace + `white-space: pre` keeps the columns aligned.

import { useMemo, useRef } from 'react'
import type * as React from 'react'
import type { Span } from '../lib/types'
import type { PageGeom } from '../lib/pdf'
import { labelMeta } from '../lib/labels'
import { resolveRenderSpans } from '../lib/redaction'
import { pinnedRedactionText } from '../lib/redactionDisplay'

type Props = {
  text: string
  spans: Span[]
  placeholderOf: Map<string, string>
  selectedId: string | null
  onSelect: (id: string | null) => void
  onAddManual: (start: number, end: number) => void
  pages?: PageGeom[]
  kind: string
}

type Line = { text: string; origAt: number[]; blankBefore: number; pageBreakBefore: boolean }

const median = (xs: number[]): number => {
  if (!xs.length) return 0
  const s = [...xs].sort((a, b) => a - b)
  return s[Math.floor(s.length / 2)]
}

// kinds whose flat text is a delimited grid we can re-align
const GRID_COL_SEP: Record<string, string> = { xlsx: '\t', csv: ',', tsv: '\t' }

export function layoutKind(kind: string, pages?: PageGeom[]): 'pdf' | 'grid' | null {
  // require at least one real text item -- a scanned / image-only PDF has page geometry but no text, so it
  // must fall through to the flat/Pages flow (NOT a dead-end layout screen). See pre-merge review.
  if (pages && pages.some((p) => p.items.some((it) => it.charEnd > it.charStart))) return 'pdf'
  if (kind in GRID_COL_SEP) return 'grid'
  return null
}

// ---- PDF: reconstruct lines/columns from item geometry ----
export function buildPdfLines(text: string, pages: PageGeom[]): Line[] {
  const lines: Line[] = []
  pages.forEach((pg, pi) => {
    const items = pg.items.filter((it) => it.charEnd > it.charStart)
    if (!items.length) return
    const widths: number[] = []
    const heights: number[] = []
    for (const it of items) {
      const len = it.charEnd - it.charStart
      if (len > 0 && it.width > 0) widths.push(it.width / len)
      if (it.height > 0) heights.push(it.height)
    }
    const cw = median(widths) || median(heights) * 0.5 || 6
    const lh = median(heights) || cw * 1.6 || 10
    const lineTol = (median(heights) || lh) * 0.5

    const withXY = items.map((it) => ({ it, x: it.transform[4], y: it.transform[5] }))
    withXY.sort((a, b) => b.y - a.y || a.x - b.x) // top-to-bottom, then left-to-right
    const x0 = Math.min(...withXY.map((o) => o.x))

    // group into visual lines by y proximity
    const groups: { items: typeof withXY; y: number }[] = []
    let group: typeof withXY = []
    let groupY: number | null = null
    for (const o of withXY) {
      if (groupY === null || Math.abs(o.y - groupY) <= lineTol) {
        group.push(o)
        if (groupY === null) groupY = o.y
      } else {
        groups.push({ items: group, y: groupY })
        group = [o]
        groupY = o.y
      }
    }
    if (group.length) groups.push({ items: group, y: groupY ?? 0 })

    let prevY: number | null = null
    groups.forEach((g, gi) => {
      g.items.sort((a, b) => a.x - b.x)
      let lineText = ''
      const origAt: number[] = []
      let cursorCol = 0
      for (const o of g.items) {
        const it = o.it
        const seg = text.slice(it.charStart, it.charEnd)
        let targetCol = Math.round((o.x - x0) / cw)
        if (targetCol < cursorCol) targetCol = cursorCol + (cursorCol > 0 ? 1 : 0) // never collide
        for (let k = cursorCol; k < targetCol; k++) {
          lineText += ' '
          origAt.push(-1)
        }
        for (let k = 0; k < seg.length; k++) {
          lineText += seg[k]
          origAt.push(it.charStart + k)
        }
        cursorCol = targetCol + seg.length
      }
      let blankBefore = 0
      if (prevY !== null) blankBefore = Math.max(0, Math.min(Math.round((prevY - g.y) / lh) - 1, 2))
      prevY = g.y
      lines.push({ text: lineText, origAt, blankBefore, pageBreakBefore: gi === 0 && pi > 0 })
    })
  })
  return lines
}

// ---- delimited grid (xlsx/csv/tsv): re-align columns from the flat text's own \t/\n structure ----
export function buildGridLines(text: string, colSep: string): Line[] {
  const rows: { cells: { start: number; end: number }[] }[] = []
  let cells: { start: number; end: number }[] = []
  let cellStart = 0
  for (let i = 0; i <= text.length; i++) {
    const ch = i < text.length ? text[i] : '\n' // virtual row terminator at EOF
    if (ch === '\n' || ch === colSep) {
      cells.push({ start: cellStart, end: i })
      if (ch === '\n') {
        rows.push({ cells })
        cells = []
      }
      cellStart = i + 1
    }
  }
  const colW: number[] = []
  for (const r of rows) r.cells.forEach((c, ci) => (colW[ci] = Math.max(colW[ci] ?? 0, c.end - c.start)))
  const lines: Line[] = []
  for (const r of rows) {
    let lineText = ''
    const origAt: number[] = []
    r.cells.forEach((c, ci) => {
      const seg = text.slice(c.start, c.end)
      for (let k = 0; k < seg.length; k++) {
        lineText += seg[k]
        origAt.push(c.start + k)
      }
      if (ci < r.cells.length - 1) {
        const pad = (colW[ci] ?? 0) - seg.length + 2 // align to widest cell in the column + a 2-space gutter
        for (let k = 0; k < pad; k++) {
          lineText += ' '
          origAt.push(-1)
        }
      }
    })
    lines.push({ text: lineText, origAt, blankBefore: 0, pageBreakBefore: false })
  }
  return lines
}

// largest span whose [start,end) covers `off`, by binary search. Input is resolveRenderSpans() output: a
// non-overlapping set where ACTIVE spans always win over inactive overlappers, so an inactive "kept" span
// can never swallow an active PII span and expose its value (the display leak the pre-merge review caught).
// Within that contract this lookup is exact.
function coveringSpan(sorted: Span[], off: number): Span | null {
  let lo = 0
  let hi = sorted.length - 1
  let best = -1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (sorted[mid].start <= off) {
      best = mid
      lo = mid + 1
    } else hi = mid - 1
  }
  if (best >= 0 && sorted[best].end > off) return sorted[best]
  return null
}

// resolve a DOM selection endpoint back to an original-text offset (same contract as DocCanvas)
function resolveOffset(node: Node | null, offset: number): number {
  let el: HTMLElement | null = node?.nodeType === 3 ? node.parentElement : (node as HTMLElement | null)
  while (el && el.dataset?.start === undefined) el = el.parentElement
  if (!el) return -1
  const base = Number(el.dataset.start)
  if (el.dataset.literal === '1') return base + offset
  return offset <= 0 ? base : Number(el.dataset.end)
}

export default function LayoutCanvas({ text, spans, placeholderOf, selectedId, onSelect, onAddManual, pages, kind }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const lines = useMemo<Line[]>(() => {
    const lk = layoutKind(kind, pages)
    if (lk === 'pdf') return buildPdfLines(text, pages!)
    if (lk === 'grid') return buildGridLines(text, GRID_COL_SEP[kind])
    return []
  }, [text, pages, kind])
  // resolveRenderSpans makes active PII win any overlap with an inactive "kept" span (display-leak fix)
  const sortedSpans = useMemo(() => resolveRenderSpans(spans), [spans])

  function onMouseUp() {
    const sel = window.getSelection()
    if (!sel || sel.isCollapsed || sel.rangeCount === 0) return
    if (!ref.current?.contains(sel.anchorNode) || !ref.current?.contains(sel.focusNode)) return
    const a = resolveOffset(sel.anchorNode, sel.anchorOffset)
    const b = resolveOffset(sel.focusNode, sel.focusOffset)
    if (a < 0 || b < 0) return
    const start = Math.min(a, b)
    const end = Math.max(a, b)
    if (end > start) {
      onAddManual(start, end)
      sel.removeAllRanges()
    }
  }

  function renderLine(line: Line, li: number): React.ReactNode {
    const { text: lt, origAt } = line
    const nodes: React.ReactNode[] = []
    let i = 0
    let nk = 0
    while (i < lt.length) {
      const o = origAt[i]
      const span = o >= 0 ? coveringSpan(sortedSpans, o) : null
      if (span && span.active) {
        let j = i + 1
        while (j < lt.length && origAt[j] >= span.start && origAt[j] < span.end) j++
        const meta = labelMeta(span.label)
        const sel = span.id === selectedId
        nodes.push(
          <span
            key={`a${li}_${nk++}`}
            data-start={span.start}
            data-end={span.end}
            onClick={(e) => {
              e.stopPropagation()
              onSelect(span.id)
            }}
            title={`${meta.en} · ${span.source} · ${span.rule} · ${placeholderOf.get(span.id) ?? `<${span.label.toUpperCase()}>`}`}
            className={`tok tok-active${sel ? ' tok-selected' : ''}`}
            style={{ background: meta.color, ['--tok-color' as string]: meta.color, padding: 0, fontSize: '1em', fontFamily: 'inherit', fontWeight: 'inherit' } as React.CSSProperties}
          >
            {pinnedRedactionText(lt.slice(i, j))}
          </span>,
        )
        i = j
      } else if (span && !span.active) {
        let j = i + 1
        while (j < lt.length && origAt[j] >= span.start && origAt[j] < span.end) j++
        const meta = labelMeta(span.label)
        const sel = span.id === selectedId
        nodes.push(
          <span
            key={`k${li}_${nk++}`}
            data-start={span.start}
            data-end={span.end}
            data-literal="1"
            onClick={(e) => {
              e.stopPropagation()
              onSelect(span.id)
            }}
            title={`${meta.en} · kept`}
            className={`tok tok-inactive${sel ? ' tok-selected' : ''}`}
            style={{ ['--tok-color' as string]: meta.color, padding: 0, fontSize: '1em', fontFamily: 'inherit', fontWeight: 'inherit' } as React.CSSProperties}
          >
            {lt.slice(i, j)}
          </span>,
        )
        i = j
      } else if (o >= 0) {
        // contiguous original chars not in any span -> one literal node (offsets map 1:1 for selection)
        let j = i + 1
        while (j < lt.length && origAt[j] === o + (j - i) && !coveringSpan(sortedSpans, origAt[j])) j++
        nodes.push(
          <span key={`l${li}_${nk++}`} data-start={o} data-literal="1">
            {lt.slice(i, j)}
          </span>,
        )
        i = j
      } else {
        // synthetic padding -> plain, offset-less (not selectable as an endpoint)
        let j = i + 1
        while (j < lt.length && origAt[j] < 0) j++
        nodes.push(<span key={`p${li}_${nk++}`}>{lt.slice(i, j)}</span>)
        i = j
      }
    }
    return (
      <div key={`line${li}`} style={{ minHeight: '1.7em' }}>
        {nodes.length ? nodes : ' '}
      </div>
    )
  }

  if (!lines.length) {
    return (
      <div className="flex items-center justify-center" style={{ height: '100%', color: 'var(--color-light)', fontSize: 13 }}>
        No layout to reconstruct for this document. Use the Text view (or Pages, for scanned / image PDFs).
      </div>
    )
  }

  return (
    <div
      ref={ref}
      onMouseUp={onMouseUp}
      onClick={(e) => {
        if (e.target === ref.current || (e.target as HTMLElement).dataset?.literal === '1') onSelect(null)
      }}
      className="mono"
      style={{
        whiteSpace: 'pre',
        fontSize: 12.5,
        lineHeight: 1.7,
        padding: 18,
        height: '100%',
        overflow: 'auto',
        color: 'var(--color-text)',
      }}
    >
      {lines.map((line, li) => (
        <div key={`blk${li}`}>
          {line.pageBreakBefore && (
            <div
              aria-hidden="true"
              style={{ borderTop: '1px dashed var(--border)', margin: '14px 0', height: 0 }}
            />
          )}
          {Array.from({ length: line.blankBefore }).map((_, b) => (
            <div key={`bb${li}_${b}`}>{' '}</div>
          ))}
          {renderLine(line, li)}
        </div>
      ))}
    </div>
  )
}
