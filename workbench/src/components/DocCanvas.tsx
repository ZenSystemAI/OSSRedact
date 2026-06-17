import { useRef } from 'react'
import type * as React from 'react'
import type { Span } from '../lib/types'
import { labelMeta } from '../lib/labels'

type Props = {
  text: string
  spans: Span[]
  placeholderOf: Map<string, string>
  selectedId: string | null
  onSelect: (id: string | null) => void
  onAddManual: (start: number, end: number) => void
}

type Seg = { type: 'text' | 'span'; start: number; end: number; span?: Span }

function buildSegments(text: string, spans: Span[]): Seg[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start)
  const segs: Seg[] = []
  let last = 0
  for (const s of sorted) {
    if (s.start > last) segs.push({ type: 'text', start: last, end: s.start })
    segs.push({ type: 'span', start: s.start, end: s.end, span: s })
    last = Math.max(last, s.end)
  }
  if (last < text.length) segs.push({ type: 'text', start: last, end: text.length })
  return segs
}

// Map a DOM selection endpoint back to an offset in the original text. Literal segments render their
// original substring 1:1, so base + in-node offset is exact. Active token chips render a placeholder
// (different length) so we snap to the chip's boundary.
function resolveOffset(node: Node | null, offset: number): number {
  let el: HTMLElement | null = node?.nodeType === 3 ? node.parentElement : (node as HTMLElement | null)
  while (el && el.dataset?.start === undefined) el = el.parentElement
  if (!el) return -1
  const base = Number(el.dataset.start)
  if (el.dataset.literal === '1') return base + offset
  return offset <= 0 ? base : Number(el.dataset.end)
}

export default function DocCanvas({ text, spans, placeholderOf, selectedId, onSelect, onAddManual }: Props) {
  const ref = useRef<HTMLDivElement>(null)

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

  const segs = buildSegments(text, spans)

  return (
    <div
      ref={ref}
      onMouseUp={onMouseUp}
      onClick={(e) => {
        if (e.target === ref.current || (e.target as HTMLElement).dataset?.literal === '1') onSelect(null)
      }}
      className="mono"
      style={{
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        fontSize: 13.5,
        lineHeight: 1.95,
        padding: 22,
        height: '100%',
        overflowY: 'auto',
        color: 'var(--color-text)',
      }}
    >
      {segs.map((seg, i) => {
        if (seg.type === 'text') {
          return (
            <span key={i} data-start={seg.start} data-literal="1">
              {text.slice(seg.start, seg.end)}
            </span>
          )
        }
        const s = seg.span!
        const meta = labelMeta(s.label)
        const selected = s.id === selectedId
        const common = {
          'data-start': seg.start,
          'data-end': seg.end,
          onClick: (e: React.MouseEvent) => {
            e.stopPropagation()
            onSelect(s.id)
          },
          title: `${meta.en} · ${s.source} · ${s.rule}`,
          style: { ['--tok-color' as string]: meta.color } as React.CSSProperties,
        }
        if (s.active) {
          return (
            <span
              key={i}
              {...common}
              className={`tok tok-active${selected ? ' tok-selected' : ''}`}
              style={{ ...common.style, background: meta.color }}
            >
              {placeholderOf.get(s.id) ?? `<${s.label.toUpperCase()}>`}
            </span>
          )
        }
        return (
          <span key={i} {...common} data-literal="1" className={`tok tok-inactive${selected ? ' tok-selected' : ''}`}>
            {text.slice(seg.start, seg.end)}
          </span>
        )
      })}
    </div>
  )
}
