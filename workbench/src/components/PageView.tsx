// Visual page view for PDFs -- closes the one gap auto-detect can't: VISUAL personal information that lives
// in pixels, not in the text layer (signatures, ID-card photos, handwriting, stamps, faces on a scanned or
// image-bearing page). The reviewer SEES each rendered page and drags black rectangles over anything to hide;
// those region boxes are normalized [0,1] and burned into the image-flatten export alongside the text-span
// boxes (see pdfExport.renderRedactedPdf). Auto-detected text spans are overlaid as read-only teal outlines so
// the reviewer can confirm coverage visually before exporting. Everything renders in-browser; no upload.
//
// The pdf.js worker is configured as a module side effect by lib/pdf.ts (already loaded by the time any PDF is
// open), so the singleton GlobalWorkerOptions is set when this component renders.

import { useEffect, useMemo, useRef, useState } from 'react'
import type * as React from 'react'
import * as pdfjsLib from 'pdfjs-dist'
import type { PDFDocumentProxy } from 'pdfjs-dist'
import type { PageGeom, PageAssessment, PageStatus } from '../lib/pdf'
import type { Span, RegionBox } from '../lib/types'
import { rectsForRange, type Rect, type Viewport } from '../lib/pdfExport'
import { labelMeta } from '../lib/labels'

type Props = {
  bytes: ArrayBuffer
  pages: PageGeom[]
  assess: PageAssessment[]
  spans: Span[]
  regions: RegionBox[]
  selectedSpanId: string | null
  onSelectSpan: (id: string | null) => void
  onAddRegion: (r: Omit<RegionBox, 'id'>) => void
  onDeleteRegion: (id: string) => void
}

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))

export default function PageView({ bytes, pages, assess, spans, regions, selectedSpanId, onSelectSpan, onAddRegion, onDeleteRegion }: Props) {
  const [pdf, setPdf] = useState<PDFDocumentProxy | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [showDetected, setShowDetected] = useState(true)

  // own render doc, separate from the headless export render; destroyed on unmount / doc swap
  useEffect(() => {
    let cancelled = false
    let doc: PDFDocumentProxy | null = null
    pdfjsLib.getDocument({ data: bytes.slice(0) }).promise.then((d) => {
      if (cancelled) { d.destroy(); return }
      doc = d
      setPdf(d)
    })
    return () => {
      cancelled = true
      if (doc) doc.destroy()
    }
  }, [bytes])

  const imagePages = assess.filter((a) => a.status !== 'text-clean').length

  return (
    <div style={{ height: '100%', overflowY: 'auto', background: 'var(--color-bg)' }} onClick={() => setSelected(null)}>
      <div
        className="flex items-center gap-3 flex-wrap px-5 py-2.5 border-b"
        style={{ borderColor: 'var(--border)', position: 'sticky', top: 0, background: 'var(--color-bg)', zIndex: 5 }}
      >
        <span className="text-xs" style={{ color: 'var(--color-muted)' }}>
          Drag on a page to draw a redaction box over anything the text scan can{'’'}t read (signatures, photos, handwriting).
        </span>
        {imagePages > 0 && (
          <span className="mono text-xs" style={{ color: 'var(--color-warning)' }}>
            {imagePages} image page{imagePages > 1 ? 's' : ''} need a manual look
          </span>
        )}
        <label className="flex items-center gap-1.5 text-xs ml-auto select-none" style={{ color: 'var(--color-light)', cursor: 'pointer' }}>
          <input type="checkbox" checked={showDetected} onChange={(e) => setShowDetected(e.target.checked)} />
          Show detected text boxes
        </label>
      </div>

      <div style={{ padding: '20px 22px 60px' }}>
        {pages.map((g) => (
          <PdfPage
            key={g.pageIndex}
            pdf={pdf}
            geom={g}
            status={assess[g.pageIndex]?.status ?? 'text-clean'}
            spans={spans}
            showDetected={showDetected}
            regions={regions.filter((r) => r.pageIndex === g.pageIndex)}
            selected={selected}
            onSelect={setSelected}
            selectedSpanId={selectedSpanId}
            onSelectSpan={onSelectSpan}
            onAddRegion={onAddRegion}
            onDeleteRegion={onDeleteRegion}
          />
        ))}
      </div>
    </div>
  )
}

type PageProps = {
  pdf: PDFDocumentProxy | null
  geom: PageGeom
  status: PageStatus
  spans: Span[]
  showDetected: boolean
  regions: RegionBox[]
  selected: string | null
  onSelect: (id: string | null) => void
  selectedSpanId: string | null
  onSelectSpan: (id: string | null) => void
  onAddRegion: (r: Omit<RegionBox, 'id'>) => void
  onDeleteRegion: (id: string) => void
}

function PdfPage({ pdf, geom, status, spans, showDetected, regions, selected, onSelect, selectedSpanId, onSelectSpan, onAddRegion, onDeleteRegion }: PageProps) {
  const wrapRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const overlayRef = useRef<HTMLDivElement>(null)
  const drawing = useRef<{ x0: number; y0: number } | null>(null)
  const [visible, setVisible] = useState(false)
  const [dims, setDims] = useState<{ cssW: number; cssH: number } | null>(null)
  const [boxVp, setBoxVp] = useState<Viewport | null>(null)
  const [draft, setDraft] = useState<Rect | null>(null)

  // rotation-aware aspect for the placeholder (before the real render gives exact dims)
  const rot = (((geom.rotation % 360) + 360) % 360)
  const vw = rot === 90 || rot === 270 ? geom.viewBoxHeight : geom.viewBoxWidth
  const vh = rot === 90 || rot === 270 ? geom.viewBoxWidth : geom.viewBoxHeight

  // defer the (heavy) raster until the page nears the viewport
  useEffect(() => {
    const el = wrapRef.current
    if (!el) return
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setVisible(true)
          io.disconnect()
        }
      },
      { rootMargin: '700px 0px' },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [])

  useEffect(() => {
    if (!visible || !pdf || !wrapRef.current || !canvasRef.current) return
    let cancelled = false
    ;(async () => {
      const page = await pdf.getPage(geom.pageIndex + 1)
      if (cancelled) return page.cleanup()
      const base = page.getViewport({ scale: 1 }) // rotation-aware visual box
      const containerW = wrapRef.current!.clientWidth || 700
      const cssScale = Math.min(containerW / base.width, 2)
      const dpr = window.devicePixelRatio || 1
      const vp = page.getViewport({ scale: cssScale * dpr })
      const canvas = canvasRef.current!
      canvas.width = Math.ceil(vp.width)
      canvas.height = Math.ceil(vp.height)
      const cssW = base.width * cssScale
      const cssH = base.height * cssScale
      canvas.style.width = cssW + 'px'
      canvas.style.height = cssH + 'px'
      const ctx = canvas.getContext('2d', { alpha: false })!
      ctx.fillStyle = '#fff'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      await page.render({ canvasContext: ctx, viewport: vp }).promise
      if (cancelled) return page.cleanup()
      const bvp = page.getViewport({ scale: cssScale }) // CSS-px space for the detection-outline math
      setBoxVp({ transform: bvp.transform, scale: bvp.scale, width: bvp.width, height: bvp.height })
      setDims({ cssW, cssH })
      page.cleanup()
    })()
    return () => {
      cancelled = true
    }
  }, [visible, pdf, geom.pageIndex])

  // read-only outlines of auto-detected text spans, in CSS px (reuses the exact export geometry), COLORED by
  // label to match the Inspector / redaction-filter legend -- so this layout-faithful page view doubles as a
  // labelled review surface: the reviewer can navigate the table and correlate each box to its category (and
  // to the flat text view's chip) by colour, without losing the table structure the text view flattens.
  const textRects = useMemo(() => {
    if (!boxVp || !showDetected) return [] as Array<Rect & { color: string; en: string; id: string }>
    const out: Array<Rect & { color: string; en: string; id: string }> = []
    for (const s of spans) {
      if (!s.active) continue
      const m = labelMeta(s.label)
      for (const r of rectsForRange(geom, boxVp, s.start, s.end)) out.push({ ...r, color: m.color, en: m.en, id: s.id })
    }
    return out
  }, [boxVp, spans, geom, showDetected])

  function localXY(e: React.PointerEvent) {
    const r = overlayRef.current!.getBoundingClientRect()
    return { x: e.clientX - r.left, y: e.clientY - r.top }
  }

  function onPointerDown(e: React.PointerEvent<HTMLDivElement>) {
    const ds = (e.target as HTMLElement).dataset
    if (ds?.regionId) {
      onSelect(ds.regionId) // clicked an existing region box -> select it, don't start a new draw
      return
    }
    if (ds?.spanId) {
      onSelectSpan(ds.spanId) // clicked a detected text box -> open it in the Inspector, don't draw
      onSelect(null)
      return
    }
    e.stopPropagation()
    onSelect(null)
    onSelectSpan(null) // clicked empty page -> clear the Inspector selection too
    const { x, y } = localXY(e)
    drawing.current = { x0: x, y0: y }
    overlayRef.current!.setPointerCapture(e.pointerId)
    setDraft({ x, y, w: 0, h: 0 })
  }
  function onPointerMove(e: React.PointerEvent<HTMLDivElement>) {
    if (!drawing.current) return
    const { x, y } = localXY(e)
    const { x0, y0 } = drawing.current
    setDraft({ x: Math.min(x0, x), y: Math.min(y0, y), w: Math.abs(x - x0), h: Math.abs(y - y0) })
  }
  function onPointerUp() {
    const d = draft
    drawing.current = null
    setDraft(null)
    if (!d || !dims || d.w < 5 || d.h < 5) return // ignore stray clicks / tiny drags
    const x = clamp(d.x, 0, dims.cssW)
    const y = clamp(d.y, 0, dims.cssH)
    const w = Math.min(d.w, dims.cssW - x)
    const h = Math.min(d.h, dims.cssH - y)
    onAddRegion({ pageIndex: geom.pageIndex, x: x / dims.cssW, y: y / dims.cssH, w: w / dims.cssW, h: h / dims.cssH, label: 'manual', active: true })
  }

  const badge = statusBadge(status, regions.length)

  return (
    <div ref={wrapRef} style={{ marginBottom: 28, maxWidth: 980 }}>
      <div className="flex items-center gap-2" style={{ marginBottom: 8 }}>
        <span className="mono text-xs" style={{ color: 'var(--color-muted)' }}>Page {geom.pageIndex + 1}</span>
        {badge && (
          <span className="mono text-xs" style={{ color: badge.color, background: 'var(--glass)', padding: '2px 8px', borderRadius: 6 }}>
            {badge.text}
          </span>
        )}
      </div>
      <div
        style={{
          position: 'relative',
          width: dims ? dims.cssW : '100%',
          maxWidth: '100%',
          aspectRatio: dims ? undefined : `${vw} / ${vh}`,
          background: 'var(--color-surface)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          overflow: 'hidden',
        }}
      >
        <canvas ref={canvasRef} style={{ display: 'block' }} />
        {!dims && (
          <div className="flex items-center justify-center" style={{ position: 'absolute', inset: 0, color: 'var(--color-light)', fontSize: 12 }}>
            {visible ? 'Rendering…' : ''}
          </div>
        )}
        {dims && (
          <div
            ref={overlayRef}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            style={{ position: 'absolute', inset: 0, cursor: 'crosshair', touchAction: 'none' }}
          >
            {textRects.map((r, i) => {
              const sel = r.id === selectedSpanId
              return (
                <div
                  key={'t' + i}
                  data-span-id={r.id}
                  title={`${r.en} -- click to inspect`}
                  style={{
                    position: 'absolute',
                    left: r.x,
                    top: r.y,
                    width: r.w,
                    height: r.h,
                    outline: `${sel ? 2.5 : 1.5}px solid ${r.color}`,
                    background: `${r.color}${sel ? '40' : '22'}`,
                    borderRadius: 2,
                    cursor: 'pointer', // clickable -> opens the detection in the Inspector (draw a region from empty space)
                  }}
                />
              )
            })}
            {regions.map((rb) => {
              const sel = rb.id === selected
              return (
                <div
                  key={rb.id}
                  data-region-id={rb.id}
                  // Keep the box SELECTED after a click: without this, the click bubbles to the page
                  // container's onClick={setSelected(null)} and instantly deselects, so the delete "x" only
                  // flashes for the duration of the click and can never be hit. stopPropagation keeps the
                  // selection (and the x) stable until the user clicks empty space.
                  onClick={(e) => e.stopPropagation()}
                  style={{
                    position: 'absolute',
                    left: rb.x * dims.cssW,
                    top: rb.y * dims.cssH,
                    width: rb.w * dims.cssW,
                    height: rb.h * dims.cssH,
                    background: 'rgba(0,0,0,0.82)',
                    border: sel ? '2px solid var(--color-teal)' : '1px solid rgba(255,255,255,0.35)',
                    boxSizing: 'border-box',
                    cursor: 'pointer',
                  }}
                >
                  {sel && (
                    <button
                      data-region-id={rb.id}
                      onClick={(e) => {
                        e.stopPropagation()
                        onDeleteRegion(rb.id)
                      }}
                      title="Remove this box"
                      style={{
                        position: 'absolute',
                        top: -10,
                        right: -10,
                        width: 22,
                        height: 22,
                        borderRadius: '50%',
                        background: 'var(--color-teal)',
                        color: '#06231f',
                        border: 'none',
                        cursor: 'pointer',
                        fontSize: 15,
                        lineHeight: '22px',
                        fontWeight: 700,
                      }}
                    >
                      {'×'}
                    </button>
                  )}
                </div>
              )
            })}
            {draft && (
              <div
                style={{
                  position: 'absolute',
                  left: draft.x,
                  top: draft.y,
                  width: draft.w,
                  height: draft.h,
                  background: 'rgba(0,0,0,0.5)',
                  border: '1.5px dashed var(--color-teal)',
                  pointerEvents: 'none',
                }}
              />
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function statusBadge(status: PageStatus, regionCount: number): { text: string; color: string } | null {
  if (status === 'image-only')
    return { text: regionCount ? `scanned image · ${regionCount} box${regionCount > 1 ? 'es' : ''}` : 'scanned image -- review + draw boxes', color: 'var(--color-warning)' }
  if (status === 'has-image')
    return { text: regionCount ? `contains image · ${regionCount} box${regionCount > 1 ? 'es' : ''}` : 'contains image -- check it', color: 'var(--color-warning)' }
  if (regionCount) return { text: `${regionCount} box${regionCount > 1 ? 'es' : ''}`, color: 'var(--color-teal)' }
  return null
}
