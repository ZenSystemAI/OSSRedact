// TRUE format-preserving PDF redaction: rasterize each page, paint opaque black boxes over the detected
// word rectangles, and reassemble an IMAGE-ONLY PDF (no text operators, no fonts) so nothing is recoverable
// under the boxes. We REJECT drawing rectangles over the original content stream (the classic fake-redaction
// trap: text stays selectable under the box) -- the output is built fresh, never from the original bytes.
//
// Box geometry is derived from pdf.js's own TextLayer math (build/pdf.mjs #appendText): for the combined
// matrix tx = Util.transform(viewport.transform, item.transform), the baseline-left is (tx[4], tx[5]),
// fontHeight = hypot(tx[2], tx[3]), the run direction is atan2(tx[1], tx[0]), and the on-screen advance is
// item.width * viewport.scale. Over-cover is the safe error.

import { PDFDocument } from 'pdf-lib'
import * as pdfjsLib from 'pdfjs-dist'
import { Util } from 'pdfjs-dist'
import type { PageGeom } from './pdf'
import type { Span, RegionBox } from './types'

export type Rect = { x: number; y: number; w: number; h: number }
export type Viewport = { transform: number[]; scale: number; width: number; height: number }

const RASTER_SCALE = 2.0 // ~144 dpi
const JPEG_QUALITY = 0.82
const MAX_CANVAS_PX = 25_000_000
const PAD = 2 // px each side
const ASCENT = 0.95 // * fontHeight above baseline
const DESCENT = 0.3 // * fontHeight below baseline

// Rectangles (canvas px) covering char-range [s,e) on a page. A visual word is often several text items, so
// we emit one rect per overlapping item. WHOLE-ITEM coverage: pdf.js exposes no per-glyph advances, so a
// linear char-fraction box would under-cover a value on a proportional font and leave a recoverable glyph
// outside the box (and the image-only output makes that pixel leak invisible to verifyNoText). Over-redaction
// is the safe error, so any text item a span touches is covered in FULL.
export function rectsForRange(geom: PageGeom, viewport: Viewport, s: number, e: number): Rect[] {
  const rects: Rect[] = []
  const scale = viewport.scale
  for (const item of geom.items) {
    if (item.charEnd <= s || item.charStart >= e || item.charEnd === item.charStart) continue

    const tx = Util.transform(viewport.transform, item.transform)
    const angle = Math.atan2(tx[1], tx[0])
    const fontHeight = Math.hypot(tx[2], tx[3])
    const dirX = Math.cos(angle)
    const dirY = Math.sin(angle)
    const upX = Math.sin(angle)
    const upY = -Math.cos(angle)
    const bx = tx[4]
    const by = tx[5]
    const runLen = item.width * scale
    const asc = fontHeight * ASCENT
    const desc = fontHeight * DESCENT
    const corners = [
      [bx + upX * asc, by + upY * asc],
      [bx + dirX * runLen + upX * asc, by + dirY * runLen + upY * asc],
      [bx - upX * desc, by - upY * desc],
      [bx + dirX * runLen - upX * desc, by + dirY * runLen - upY * desc],
    ]
    let minX = Infinity,
      minY = Infinity,
      maxX = -Infinity,
      maxY = -Infinity
    for (const [cx, cy] of corners) {
      if (cx < minX) minX = cx
      if (cx > maxX) maxX = cx
      if (cy < minY) minY = cy
      if (cy > maxY) maxY = cy
    }
    rects.push({ x: minX - PAD, y: minY - PAD, w: maxX - minX + 2 * PAD, h: maxY - minY + 2 * PAD })
  }
  return rects
}

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
  const viewports: Viewport[] = []
  let paintedRects = 0
  try {
    for (let p = 1; p <= pdf.numPages; p++) {
      const page = await pdf.getPage(p)
      const base = page.getViewport({ scale: 1 }) // rotation-aware visual dimensions
      let scale = opts.scale ?? RASTER_SCALE
      while (base.width * scale * (base.height * scale) > MAX_CANVAS_PX && scale > 0.5) scale -= 0.25
      const viewport = page.getViewport({ scale })
      viewports.push(viewport as unknown as Viewport)

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
      for (const span of activeSpans) {
        const rects = rectsForRange(geom, viewport as unknown as Viewport, span.start, span.end)
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
    const uncovered = findUncoveredSpans(pages, viewports, activeSpans)
    return { blob, uncovered, paintedRects }
  } finally {
    await pdf.destroy()
  }
}

// Active spans that produce NO paintable rect anywhere in the document = a coverage failure: the value is
// in the flat text but no box will be drawn over it (offset drift, or the span lies entirely in a synthetic
// newline / page-join gap). Image-only output makes this invisible to verifyNoText, so it must be caught here.
export function findUncoveredSpans(pages: PageGeom[], viewports: Viewport[], activeSpans: Span[]): Span[] {
  return activeSpans.filter(
    (span) => !pages.some((geom, i) => rectsForRange(geom, viewports[i], span.start, span.end).length > 0),
  )
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
