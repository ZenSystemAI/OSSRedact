import type { PageGeom } from './pdf'

export type Rect = { x: number; y: number; w: number; h: number }
export type Viewport = { transform: number[]; scale: number; width: number; height: number }

const PAD_X = 2 // px each side (horizontal)
const PAD_Y = 1 // px each side (vertical) -- tighter than X so stacked ledger rows don't bleed into adjacent lines
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
// we emit one rect per overlapping item. SUB-RANGE coverage: box only the portion of each item the span
// actually overlaps, mapped onto the item's advance width via CLASS-WEIGHTED per-char advances (see
// charWeight below -- uniform averaging under-covered wide-glyph prefixes). pdf.js merges a whole table
// cell / justified line into ONE text item, so the old whole-item rule blacked out the entire line around a
// single detected value (bank-statement Description / Date columns). +-0.4 avg-char of SLACK is added on
// each side so residual estimation error can never leave a target glyph edge exposed -- under-redaction is
// the real risk; a fraction of a char of local over-cover is the safe error. When a span fully covers the
// item, weights + slack clamp to the item bounds -> identical full-item box (exact, normalization).
//
// WHITESPACE-ONLY items are SKIPPED (str.trim()===''): they carry no glyphs, so skipping can never
// under-redact. Measured on a real bank-statement corpus (7 bank layouts, ~60k text items): inter-column gaps are
// SEPARATE single-space items (str=' ', len 1) whose advance is inflated 30-70x (203-438pt at fontSize 6).
// 100% of advance-inflated items are whitespace-only; ZERO real text items (incl. account numbers) are
// inflated. ~65% of gap items sit immediately before an amount cell their full-advance box overlaps (max 120pt
// overshoot), so a span overlapping a gap item by even one char would otherwise paint a 200-400pt black bar
// across to the amount column (the "account -> amount" over-redaction). Skipping them kills that amplifier
// class outright.
// Helvetica-class per-char advance weights (em). getTextContent exposes only the item's TOTAL advance, so
// sub-range boxes must estimate glyph positions; weights are NORMALIZED against the item's true advance, so
// a full-cover box stays exact and cumulative drift cannot accumulate. Values approximate the Helvetica/Arial
// family bank statements overwhelmingly use -- they only need to beat uniform averaging, which under-covered
// wide-glyph prefixes ("W Sm" of "W Smith": true edge ~26% past len*avg -- Codex review 2026-07-08 CRITICAL).
function charWeight(ch: string): number {
  if (ch === ' ' || ch === '\u00A0') return 0.28
  if (/[iIl1|.,;:'’`!()[\]{}/\\-]/.test(ch)) return 0.3
  if (/[MWmw@]/.test(ch)) return 0.92
  if (/[A-Z0-9]/.test(ch)) return 0.66
  return 0.5
}

// Maps a char boundary k of `str` to its estimated x (px along the run), weight-normalized to `runLen`.
function charPrefixX(str: string, itemLen: number, runLen: number): (k: number) => number {
  const cum = new Float64Array(itemLen + 1)
  for (let i = 0; i < itemLen; i++) cum[i + 1] = cum[i] + charWeight(str[i] ?? 'x')
  const total = cum[itemLen] || 1
  return (k) => (cum[Math.max(0, Math.min(itemLen, k))] / total) * runLen
}

export function rectsForRange(geom: PageGeom, viewport: Viewport, s: number, e: number): Rect[] {
  const rects: Rect[] = []
  const scale = viewport.scale
  for (const item of geom.items) {
    if (item.charEnd <= s || item.charStart >= e || item.charEnd === item.charStart) continue
    if (item.str.trim() === '') continue // whitespace-only gap item: no glyphs -> skip (see header: gap amplifier)

    const tx = transform(viewport.transform, item.transform)
    const angle = Math.atan2(tx[1], tx[0])
    const fontHeight = Math.hypot(tx[2], tx[3])
    const dirX = Math.cos(angle)
    const dirY = Math.sin(angle)
    const upX = Math.sin(angle)
    const upY = -Math.cos(angle)
    const runLen = item.width * scale
    const asc = fontHeight * ASCENT
    const desc = fontHeight * DESCENT

    // Weighted sub-range within the item. Edge rule: if the span edge abuts a SPACE inside the item, snap
    // the cover THROUGH that space -- the blank inter-word gap absorbs any weight-estimation error, so a
    // target glyph can only peek if the error exceeds a full space width (Codex re-verify 2026-07-08: class
    // weights alone left ~3px of a trailing glyph exposed on a realistic Helvetica row). Edges not on a word
    // boundary (mid-word span / item edge) keep the +-0.4 avg-char slack instead.
    const itemLen = item.charEnd - item.charStart
    const avgCharW = runLen / itemLen
    const relStart = Math.max(s, item.charStart) - item.charStart
    const relEnd = Math.min(e, item.charEnd) - item.charStart
    const xAt = charPrefixX(item.str, itemLen, runLen)
    const xStart = relStart > 0 && item.str[relStart - 1] === ' '
      ? xAt(relStart - 1)
      : Math.max(0, xAt(relStart) - 0.4 * avgCharW)
    const xEnd = relEnd < itemLen && item.str[relEnd] === ' '
      ? xAt(relEnd + 1)
      : Math.min(runLen, xAt(relEnd) + 0.4 * avgCharW)
    const segLen = xEnd - xStart
    const bx = tx[4] + dirX * xStart
    const by = tx[5] + dirY * xStart
    const corners = [
      [bx + upX * asc, by + upY * asc],
      [bx + dirX * segLen + upX * asc, by + dirY * segLen + upY * asc],
      [bx - upX * desc, by - upY * desc],
      [bx + dirX * segLen - upX * desc, by + dirY * segLen - upY * desc],
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
    rects.push({ x: minX - PAD_X, y: minY - PAD_Y, w: maxX - minX + 2 * PAD_X, h: maxY - minY + 2 * PAD_Y })
  }
  return rects
}
