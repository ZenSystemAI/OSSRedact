// TRUE format-preserving PDF redaction: rasterize each page, paint opaque black boxes over the detected
// word rectangles, and reassemble an IMAGE-ONLY PDF (no text operators, no fonts) so nothing is recoverable
// under the boxes. We REJECT drawing rectangles over the original content stream (the classic fake-redaction
// trap: text stays selectable under the box) -- the output is built fresh, never from the original bytes.
//
// Box geometry is derived from pdf.js's own TextLayer math (build/pdf.mjs #appendText): for the combined
// viewport x item matrix, the baseline-left is (tx[4], tx[5]),
// fontHeight = hypot(tx[2], tx[3]), the run direction is atan2(tx[1], tx[0]), and the on-screen advance is
// item.width * viewport.scale. Over-cover is the safe error.

import { PDFDocument } from 'pdf-lib'
import * as pdfjsLib from 'pdfjs-dist'
import type { PageGeom } from './pdf'
import type { Span, RegionBox } from './types'
import { rectsForRange, type Rect, type Viewport } from './pdfGeometry'

export { rectsForRange }
export type { Rect, Viewport }

const RASTER_SCALE = 2.0 // ~144 dpi
const JPEG_QUALITY = 0.82
const MAX_CANVAS_PX = 25_000_000

export async function renderRedactedPdf(
  bytes: ArrayBuffer,
  pages: PageGeom[],
  activeSpans: Span[],
  regions: RegionBox[] = [],
  opts: { scale?: number; quality?: number } = {},
): Promise<{ blob: Blob; uncovered: Span[]; paintedRects: number }> {
  const quality = opts.quality ?? JPEG_QUALITY
  const pdf = await pdfjsLib.getDocument({ data: bytes.slice(0) }).promise
  const out = await PDFDocument.create()
  const spansByPage = spansForPages(pages, activeSpans)
  const coveredSpans = new Set<Span>()
  let paintedRects = 0
  try {
    for (let p = 1; p <= pdf.numPages; p++) {
      const page = await pdf.getPage(p)
      const base = page.getViewport({ scale: 1 }) // rotation-aware visual dimensions
      let scale = opts.scale ?? RASTER_SCALE
      while (base.width * scale * (base.height * scale) > MAX_CANVAS_PX && scale > 0.5) scale -= 0.25
      const viewport = page.getViewport({ scale })

      const canvas = document.createElement('canvas')
      canvas.width = Math.ceil(viewport.width)
      canvas.height = Math.ceil(viewport.height)
      const ctx = canvas.getContext('2d', { alpha: false })
      if (!ctx) throw new Error('canvas 2d context unavailable')
      ctx.fillStyle = '#fff'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      await page.render({ canvasContext: ctx, viewport }).promise

      ctx.fillStyle = '#000'
      ctx.globalAlpha = 1
      const geom = pages[p - 1]
      const pageSpans = spansByPage[p - 1] ?? []
      for (const span of pageSpans) {
        const rects = rectsForRange(geom, viewport as unknown as Viewport, span.start, span.end)
        if (rects.length) coveredSpans.add(span)
        for (const r of rects) {
          ctx.fillRect(r.x, r.y, r.w, r.h)
          paintedRects++
        }
      }
      // manually-drawn region boxes (normalized [0,1] -> canvas px). Cover VISUAL PII with no text layer.
      for (const rb of regions) {
        if (rb.pageIndex !== p - 1 || !rb.active) continue
        ctx.fillRect(rb.x * viewport.width, rb.y * viewport.height, rb.w * viewport.width, rb.h * viewport.height)
      }

      const blob = await new Promise<Blob>((res, rej) =>
        canvas.toBlob((b) => (b ? res(b) : rej(new Error('canvas.toBlob failed'))), 'image/jpeg', quality),
      )
      const img = await out.embedJpg(new Uint8Array(await blob.arrayBuffer()))
      const outPage = out.addPage([base.width, base.height])
      outPage.drawImage(img, { x: 0, y: 0, width: base.width, height: base.height })
      canvas.width = canvas.height = 0 // free
      page.cleanup()
    }
    const outBytes = await out.save({ objectsPerTick: 50 })
    const blob = new Blob([outBytes as BlobPart], { type: 'application/pdf' })
    const uncovered = activeSpans.filter((span) => !coveredSpans.has(span))
    return { blob, uncovered, paintedRects }
  } finally {
    await pdf.destroy()
  }
}

// Active spans that produce NO paintable rect anywhere in the document = a coverage failure: the value is
// in the flat text but no box will be drawn over it (offset drift, or the span lies entirely in a synthetic
// newline / page-join gap). Image-only output makes this invisible to verifyNoText, so it must be caught here.
export function findUncoveredSpans(pages: PageGeom[], viewports: Viewport[], activeSpans: Span[]): Span[] {
  const covered = new Set<Span>()
  const spansByPage = spansForPages(pages, activeSpans)
  pages.forEach((geom, i) => {
    const viewport = viewports[i]
    if (!viewport) return
    for (const span of spansByPage[i] ?? []) {
      if (rectsForRange(geom, viewport, span.start, span.end).length > 0) covered.add(span)
    }
  })
  return activeSpans.filter((span) => !covered.has(span))
}

function spansForPages(pages: PageGeom[], activeSpans: Span[]): Span[][] {
  return pages.map((geom) => {
    const range = pageCharRange(geom)
    if (!range) return []
    return activeSpans.filter((span) => span.end > range.start && span.start < range.end)
  })
}

function pageCharRange(geom: PageGeom): { start: number; end: number } | null {
  let start = Infinity
  let end = -Infinity
  for (const item of geom.items) {
    if (item.charEnd <= item.charStart) continue
    if (item.charStart < start) start = item.charStart
    if (item.charEnd > end) end = item.charEnd
  }
  return end > start ? { start, end } : null
}

// Fail-closed ship gate: re-open the produced PDF and confirm it has NO recoverable text (image-only) and
// that none of the original sensitive values survive. NOTE: this CANNOT catch a scanned-page leak (a scanned
// doc has no text either way) -- that case is guarded earlier by the scanned-PDF assessment, not here.
// NOTE on what this proves: for image-only output the text layer is always empty, so residualChars === 0 and
// leaked === [] will always hold regardless of box placement. Box coverage is verified separately by
// findUncoveredSpans (checked before this call). This function's value is as a defence-in-depth check for an
// accidentally-retained text layer or a residual text value; it does NOT verify that boxes landed on PII.
export async function verifyNoText(
  blob: Blob,
  entityValues: string[],
): Promise<{ ok: boolean; leaked: string[]; residualChars: number }> {
  const data = new Uint8Array(await blob.arrayBuffer())
  const pdf = await pdfjsLib.getDocument({ data }).promise
  let allText = ''
  try {
    for (let p = 1; p <= pdf.numPages; p++) {
      const page = await pdf.getPage(p)
      const c = await page.getTextContent()
      allText += c.items.map((i) => ('str' in i ? i.str : '')).join('')
      page.cleanup()
    }
  } finally {
    await pdf.destroy()
  }
  const leaked = entityValues.filter((v) => v && allText.includes(v))
  const residualChars = allText.trim().length
  return { ok: residualChars === 0 && leaked.length === 0, leaked, residualChars }
}
