import type { PageGeom } from './pdf'

export type Rect = { x: number; y: number; w: number; h: number }
export type Viewport = { transform: number[]; scale: number; width: number; height: number }

const PAD = 2 // px each side
const ASCENT = 0.95 // * fontHeight above baseline
const DESCENT = 0.3 // * fontHeight below baseline

function transform(m1: number[], m2: number[]): number[] {
  return [
    m1[0] * m2[0] + m1[2] * m2[1],
    m1[1] * m2[0] + m1[3] * m2[1],
    m1[0] * m2[2] + m1[2] * m2[3],
    m1[1] * m2[2] + m1[3] * m2[3],
    m1[0] * m2[4] + m1[2] * m2[5] + m1[4],
    m1[1] * m2[4] + m1[3] * m2[5] + m1[5],
  ]
}

// Rectangles (canvas px) covering char-range [s,e) on a page. A visual word is often several text items, so
// we emit one rect per overlapping item. WHOLE-ITEM coverage: pdf.js exposes no per-glyph advances, so a
// linear char-fraction box would under-cover a value on a proportional font and leave a recoverable glyph
// outside the box. Over-redaction is the safe error, so any text item a span touches is covered in FULL.
export function rectsForRange(geom: PageGeom, viewport: Viewport, s: number, e: number): Rect[] {
  const rects: Rect[] = []
  const scale = viewport.scale
  for (const item of geom.items) {
    if (item.charEnd <= s || item.charStart >= e || item.charEnd === item.charStart) continue

    const tx = transform(viewport.transform, item.transform)
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
