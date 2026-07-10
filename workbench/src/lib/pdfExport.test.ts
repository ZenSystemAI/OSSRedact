// Tests for the pure geometry function rectsForRange() in pdfExport.ts.
// renderRedactedPdf / verifyNoText need a real canvas and are tested in plan 013.
// All inputs are synthetic -- no real PII.

import { describe, it, expect } from 'vitest'
import { rectsForRange, findUncoveredSpans } from './pdfExport'
import type { Viewport } from './pdfExport'
import type { Span } from './types'
import type { PageGeom, ItemBox } from './pdf'

// PAD constants from pdfGeometry.ts (applied each side): PAD_X horizontal, PAD_Y vertical
const PAD_X = 2
const PAD_Y = 1

// Build a synthetic viewport: identity (no rotation, no scaling beyond 1px)
function makeViewport(width = 600, height = 800): Viewport {
  // transform is a 6-element affine matrix [a,b,c,d,e,f] (CSS convention)
  return { transform: [1, 0, 0, 1, 0, 0], scale: 1, width, height }
}

// Build a synthetic ItemBox for horizontal left-to-right text at y=100.
// transform [1,0,0,fontH,bx,by] -> angle=0, fontHeight=fontH, baseline at (bx,by).
// After Util.transform with identity viewport the tx is the same matrix.
function makeItem(
  charStart: number,
  charEnd: number,
  bx: number,
  by: number,
  width: number,
  fontH = 12,
  str?: string,
): ItemBox {
  return {
    str: str ?? 'x'.repeat(charEnd - charStart),
    charStart,
    charEnd,
    transform: [1, 0, 0, fontH, bx, by],
    width,
    height: fontH,
    dir: 'ltr',
  }
}

// Build a minimal PageGeom
function makeGeom(items: ItemBox[]): PageGeom {
  return { pageIndex: 0, rotation: 0, viewBoxWidth: 600, viewBoxHeight: 800, items }
}

describe('rectsForRange', () => {
  it('returns one rect for a span that fully covers one item', () => {
    // Item covers chars 0..10 at position (50, 100), width 80, fontH 12
    const geom = makeGeom([makeItem(0, 10, 50, 100, 80, 12)])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 0, 10)
    expect(rects).toHaveLength(1)

    // ASCENT = 0.95, DESCENT = 0.3
    // bx=50, by=100, fontHeight=12, angle=0 (horizontal text)
    // dirX=1, dirY=0, upX=0, upY=-1 (sin(0)=0, -cos(0)=-1)
    // asc = 12*0.95=11.4, desc = 12*0.3=3.6
    // corners: [50+0*11.4, 100+(-1)*11.4] = [50, 88.6]
    //          [50+1*80+0, 100+0*80+(-11.4)] = [130, 88.6]
    //          [50-0*3.6, 100-(-1)*3.6] = [50, 103.6]
    //          [130, 103.6]
    // minX=50, maxX=130, minY=88.6, maxY=103.6
    // rect: x=50-PAD_X=48, y=88.6-PAD_Y=87.6, w=(130-50)+2*PAD_X=84, h=(103.6-88.6)+2*PAD_Y=17
    const r = rects[0]
    expect(r.x).toBeCloseTo(50 - PAD_X, 5)
    expect(r.w).toBeCloseTo(80 + 2 * PAD_X, 5)
    // Height should be ascent+descent + 2*PAD_Y = 12*(0.95+0.3) + 2 = 17
    expect(r.h).toBeCloseTo(12 * (0.95 + 0.3) + 2 * PAD_Y, 5)
  })

  it('returns two rects for a span touching two adjacent items', () => {
    // Item A: chars 0..5 at x=0, Item B: chars 5..10 at x=60
    const geom = makeGeom([makeItem(0, 5, 0, 100, 60, 12), makeItem(5, 10, 60, 100, 60, 12)])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 0, 10)
    expect(rects).toHaveLength(2)
  })

  it('returns zero rects when span range is outside all items', () => {
    const geom = makeGeom([makeItem(0, 10, 50, 100, 80)])
    const vp = makeViewport()
    // Span [20, 30) is entirely outside item [0, 10)
    const rects = rectsForRange(geom, vp, 20, 30)
    expect(rects).toHaveLength(0)
  })

  it('partial span overlap covers ONLY its sub-range of the item (+-0.4 char slack), not the whole item', () => {
    // span [5, 8) inside item [0, 10), width 80 -> avgCharW = 8. Slack: offsets [4.6, 8.4) -> off 36.8, seg 3.8ch.
    const geom = makeGeom([makeItem(0, 10, 50, 100, 80, 12)])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 5, 8)
    expect(rects).toHaveLength(1)
    // NOT the full 80: sub-range (8.4-4.6)*8 = 30.4 + 2*PAD_X, offset by 4.6*8 = 36.8 from the item baseline x.
    expect(rects[0].w).toBeCloseTo(3.8 * 8 + 2 * PAD_X, 5)
    expect(rects[0].x).toBeCloseTo(50 + 36.8 - PAD_X, 5)
  })

  it('regression: a small span inside a long table-cell item does NOT black out the whole cell', () => {
    // The reported bug: pdf.js merges a whole Description line into ONE 60-char item (width 480). A single
    // 13-char detected value inside it must produce a LOCAL box, not cover the entire 480px line.
    const geom = makeGeom([makeItem(0, 60, 20, 100, 480, 10)])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 30, 43) // "value" at chars 30..43
    expect(rects).toHaveLength(1)
    // avgCharW = 8; slack [29.6, 43.4) -> 13.8 chars -> 110.4px, far less than the 480px cell.
    expect(rects[0].w).toBeCloseTo(13.8 * 8 + 2 * PAD_X, 5)
    expect(rects[0].w).toBeLessThan(480 / 3)
  })

  it('a span fully covering the item still yields the full-item box (slack clamps to bounds)', () => {
    const geom = makeGeom([makeItem(0, 10, 50, 100, 80, 12)])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 0, 10)
    expect(rects[0].w).toBeCloseTo(80 + 2 * PAD_X, 5)
    expect(rects[0].x).toBeCloseTo(50 - PAD_X, 5)
  })

  it('span touching zero items returns empty array', () => {
    const geom = makeGeom([])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 0, 10)
    expect(rects).toHaveLength(0)
  })

  it('items with charStart === charEnd are skipped (empty items)', () => {
    // Empty item (charStart == charEnd) must not produce a rect even if range overlaps
    const emptyItem = makeItem(5, 5, 50, 100, 0)
    const geom = makeGeom([emptyItem])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 0, 10)
    expect(rects).toHaveLength(0)
  })

  it('gap-amplifier regression: a whitespace-only gap item (str=" ", width 200) paints NO rect', () => {
    // Bank-statement inter-column gaps are SEPARATE single-space items with 30-70x advance inflation (200pt at
    // fontSize 6). A span overlapping such a gap item must NOT paint its 200pt advance across to the amount cell.
    const gap = makeItem(0, 1, 50, 100, 200, 6, ' ')
    const geom = makeGeom([gap])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 0, 1)
    expect(rects).toHaveLength(0)
  })

  it('mixed row [text][" " gap 200pt][text] over the whole span yields exactly 2 rects, none from the gap advance', () => {
    // account (chars 0..8) | inflated gap item (char 8, 200pt) | amount (chars 9..14). The gap's 200pt advance
    // must never appear as a rect; only the two real text items paint.
    const acct = makeItem(0, 8, 20, 100, 40, 6)
    const gap = makeItem(8, 9, 60, 100, 200, 6, ' ')
    const amount = makeItem(9, 14, 280, 100, 30, 6)
    const geom = makeGeom([acct, gap, amount])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 0, 14)
    expect(rects).toHaveLength(2)
    // Neither rect is the gap's 200pt bar.
    for (const r of rects) expect(r.w).toBeLessThan(200)
  })
})

// Helper to build a minimal Span
function makeSpan(id: string, start: number, end: number): Span {
  return { id, start, end, label: 'test', tier: 0, conf: 1, rule: 'test', source: 'auto', active: true }
}

// NOTE: findUncoveredSpans is pure (no canvas). The optional pixel-sampling step in renderRedactedPdf
// (step 2 of plan 013) is NOT unit-tested here because jsdom has no real canvas and getImageData is
// unavailable. That hardening is verified manually in the browser.

describe('findUncoveredSpans', () => {
  it('returns empty when a span overlaps an item on the single page', () => {
    // Span [0,10) overlaps item [0,10) -- covered on page 0
    const geom = makeGeom([makeItem(0, 10, 50, 100, 80, 12)])
    const vp = makeViewport()
    const span = makeSpan('s1', 0, 10)
    const uncovered = findUncoveredSpans([geom], [vp], [span])
    expect(uncovered).toHaveLength(0)
  })

  it('reports a span that falls entirely in a gap between items (no item overlaps)', () => {
    // Item A covers chars 0..5; item B covers chars 20..30. Span [7,12) is in the gap -- no rect.
    const geom = makeGeom([makeItem(0, 5, 0, 100, 50, 12), makeItem(20, 30, 60, 100, 100, 12)])
    const vp = makeViewport()
    const span = makeSpan('s2', 7, 12)
    const uncovered = findUncoveredSpans([geom], [vp], [span])
    expect(uncovered).toHaveLength(1)
    expect(uncovered[0].id).toBe('s2')
  })

  it('reports a span overlapping ONLY whitespace items as uncovered (whitespace never paints -> fail-closed)', () => {
    // Now that whitespace gap items are skipped, a span landing entirely on them produces no rect and must
    // surface as uncovered so the ship gate flags it -- the desired fail-closed visibility semantics.
    const gap = makeItem(0, 1, 50, 100, 200, 6, ' ')
    const geom = makeGeom([gap])
    const vp = makeViewport()
    const span = makeSpan('sWs', 0, 1)
    const uncovered = findUncoveredSpans([geom], [vp], [span])
    expect(uncovered).toHaveLength(1)
    expect(uncovered[0].id).toBe('sWs')
  })

  it('does NOT report a span covered on page 2 even though page 1 has no matching item', () => {
    // Two-page document. Page 1 has items for chars 0..10; page 2 has items for chars 11..20.
    // Span [11,20) produces zero rects on page 1 but at least one rect on page 2 -> covered.
    const geomPage1 = makeGeom([makeItem(0, 10, 0, 100, 80, 12)])
    const geomPage2 = { ...makeGeom([makeItem(11, 20, 0, 100, 80, 12)]), pageIndex: 1 }
    const vp = makeViewport()
    const span = makeSpan('s3', 11, 20)
    const uncovered = findUncoveredSpans([geomPage1, geomPage2], [vp, vp], [span])
    expect(uncovered).toHaveLength(0)
  })
})

describe('Codex adversarial-review regressions (2026-07-08)', () => {
  it('proportional-font regression: a wide-glyph prefix span covers its true glyph extent', () => {
    // "W Smith" Helvetica advances (em): W .944, sp .278, S .667, m .833, i .222, t .278, h .556 = 3.778em.
    // At fontH 36 the item advance is 136.008px and the TRUE right edge of the "W Sm" prefix is 97.99px.
    // Uniform averaging put the box edge at 4/7*136 + slack ~= 85.5px, exposing ~12px of the 'm'.
    const geom = makeGeom([makeItem(0, 7, 50, 100, 136.008, 36, 'W Smith')])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 0, 4)
    expect(rects).toHaveLength(1)
    const right = rects[0].x + rects[0].w
    expect(right).toBeGreaterThanOrEqual(50 + (0.944 + 0.278 + 0.667 + 0.833) * 36)
    expect(right).toBeLessThan(50 + 136.008) // still a sub-range box, not the whole item
  })
})

describe('word-snap edge cover (Codex re-verify 2026-07-08)', () => {
  it('a span ending at a word boundary snaps through the adjacent space (no trailing-glyph sliver)', () => {
    // Codex trace: "E-TRANSFER 123456 Dianne Okafor 50.00" as ONE Helvetica item, span on "Dianne Okafor";
    // class weights + 0.4 slack alone left ~3px of the final 'r' exposed. True Helvetica advances (em):
    // E.667 -.333 T.611 R.722 A.667 N.722 S.667 F.611 E.667 R.722 sp.278 1-6:.556x6 sp.278 D.722 i.222
    // a.556 n.556 n.556 e.556 sp.278 O.778 k.5 a.556 f.278 o.556 r.333 sp.278 5.556 0.556 ..278 0.556 0.556
    const str = 'E-TRANSFER 123456 Dianne Okafor 50.00'
    const em = [0.667,0.333,0.611,0.722,0.667,0.722,0.667,0.611,0.667,0.722,0.278,0.556,0.556,0.556,0.556,0.556,0.556,0.278,0.722,0.222,0.556,0.556,0.556,0.556,0.278,0.778,0.5,0.556,0.278,0.556,0.333,0.278,0.556,0.556,0.278,0.556,0.556]
    expect(em).toHaveLength(str.length)
    const fontH = 12
    const width = em.reduce((a, b) => a + b, 0) * fontH
    const geom = makeGeom([makeItem(0, str.length, 0, 100, width, fontH, str)])
    const vp = makeViewport()
    const spanStart = str.indexOf('Dianne')
    const spanEnd = spanStart + 'Dianne Okafor'.length
    const rects = rectsForRange(geom, vp, spanStart, spanEnd)
    expect(rects).toHaveLength(1)
    const trueRight = em.slice(0, spanEnd).reduce((a, b) => a + b, 0) * fontH
    const trueLeft = em.slice(0, spanStart).reduce((a, b) => a + b, 0) * fontH
    expect(rects[0].x + rects[0].w).toBeGreaterThanOrEqual(trueRight)
    expect(rects[0].x).toBeLessThanOrEqual(trueLeft)
    expect(rects[0].x + rects[0].w).toBeLessThan(width) // still a sub-range box
  })
})
