// Span model shared across the detector, the merge step, and the UI.
// Mirrors the appliance's span dict (privacy_gate.py) + the explain() provenance schema, so a
// document redacted here is wire-compatible with the gate's <LABEL_NNN> placeholders + entity map.

export type RawSpan = {
  start: number
  end: number
  label: string
  tier: number
  conf: number
  rule: string
  validator?: string // e.g. 'luhn_ok' | 'luhn_fail'
  cue?: string // context word that promoted a context-cued id
  subtype?: string // secret subtype, etc.
  members?: number // how many raw spans merged into this one
}

// A span as the workbench tracks it: a raw detection plus editable UI state.
export type Span = RawSpan & {
  id: string
  source: 'auto' | 'manual' | 'neural'
  active: boolean // currently redacted? (click-to-unredact toggles this)
}

export type EntityMap = Record<string, string> // placeholder -> original value (sensitive; stays local)

// A manually-drawn redaction rectangle on a PDF page, used to cover VISUAL PII the text layer can't see
// (signatures, ID-card photos, handwriting, stamps, faces) -- the gap auto-detect cannot close on scanned or
// image-bearing pages. Coordinates are normalized [0,1] against the page's rotation-aware visual box
// (top-left origin), so they map identically onto any raster scale at export time.
export type RegionBox = {
  id: string
  pageIndex: number // 0-based
  x: number // left, fraction of page width
  y: number // top, fraction of page height
  w: number // width, fraction of page width
  h: number // height, fraction of page height
  label: string
  active: boolean
}
