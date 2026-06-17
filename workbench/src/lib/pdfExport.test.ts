// Tests for the pure geometry function rectsForRange() in pdfExport.ts.
// renderRedactedPdf / verifyNoText need a real canvas and are tested in plan 013.
// All inputs are synthetic -- no real PII.

import { describe, it, expect } from 'vitest'
import { rectsForRange, findUncoveredSpans } from './pdfExport'
import type { Viewport } from './pdfExport'
import type { Span } from './types'
import type { PageGeom, ItemBox } from './pdf'

// PAD constant from pdfExport.ts (applied each side)
const PAD = 2

// Build a synthetic viewport: identity (no rotation, no scaling beyond 1px)
function makeViewport(width = 600, height = 800): Viewport {
  // transform is a 6-element affine matrix [a,b,c,d,e,f] (CSS convention)
  return { transform: [1, 0, 0, 1, 0, 0], scale: 1, width, height }
}

// Build a synthetic ItemBox for horizontal left-to-right text at y=100.
// transform [1,0,0,fontH,bx,by] -> angle=0, fontHeight=fontH, baseline at (bx,by).
// After Util.transform with identity viewport the tx is the same matrix.
function makeItem(charStart: number, charEnd: number, bx: number, by: number, width: number, fontH = 12): ItemBox {
  return {
    str: 'x'.repeat(charEnd - charStart),
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
    // rect: x=50-2=48, y=88.6-2=86.6, w=(130-50)+4=84, h=(103.6-88.6)+4=19
    const r = rects[0]
    expect(r.x).toBeCloseTo(50 - PAD, 5)
    expect(r.w).toBeCloseTo(80 + 2 * PAD, 5)
    // Height should be ascent+descent + 2*PAD = 12*(0.95+0.3) + 4 = 19
    expect(r.h).toBeCloseTo(12 * (0.95 + 0.3) + 2 * PAD, 5)
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

  it('partial span overlap still produces a rect (whole-item coverage rule)', () => {
    // span [5, 8) overlaps item [0, 10) partially
    // The whole-item rule means the full item width is covered
    const geom = makeGeom([makeItem(0, 10, 50, 100, 80, 12)])
    const vp = makeViewport()
    const rects = rectsForRange(geom, vp, 5, 8)
    expect(rects).toHaveLength(1)
    // Width must be the full item advance (80) + 2*PAD, not a fraction
    expect(rects[0].w).toBeCloseTo(80 + 2 * PAD, 5)
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
