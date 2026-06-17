// Span merge + placeholder/entity-map machinery. The merge is a faithful port of privacy_gate.py
// merge_spans() (CONNECTED-COMPONENT UNION): any cluster of overlapping detections becomes ONE
// redaction covering their union, labelled by the highest-confidence (then longest) member. A privacy
// gate must never leave a PII fragment exposed between two overlapping spans, so over-redaction is the
// safe error. Placeholders are <LABEL_NNN>, matching the appliance's gate_service.py /redact contract,
// so a document redacted here round-trips through the same entity map.

import type { RawSpan, Span, EntityMap } from './types'

let _idCounter = 0
export function newId(): string {
  return 's' + (++_idCounter).toString(36)
}

export function mergeSpans(spans: RawSpan[]): RawSpan[] {
  if (!spans.length) return []
  const arr = [...spans].sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start))
  type Acc = RawSpan & { _bc: number; _bl: number }
  const out: Acc[] = []
  for (const s of arr) {
    const cur = out[out.length - 1]
    if (cur && s.start < cur.end) {
      cur.members = (cur.members ?? 1) + 1
      const candC = s.conf
      const candL = s.end - s.start
      if (candC > cur._bc || (candC === cur._bc && candL > cur._bl)) {
        cur.label = s.label
        cur.tier = s.tier
        cur._bc = candC
        cur._bl = candL
        cur.rule = s.rule
        cur.validator = s.validator
        cur.cue = s.cue
        cur.subtype = s.subtype
      }
      cur.end = Math.max(cur.end, s.end)
      cur.conf = Math.max(cur.conf, s.conf)
    } else {
      out.push({ ...s, _bc: s.conf, _bl: s.end - s.start, members: 1 })
    }
  }
  for (const o of out) {
    delete (o as Partial<Acc>)._bc
    delete (o as Partial<Acc>)._bl
    if (!o.validator) delete o.validator
    if (!o.cue) delete o.cue
    if (!o.subtype) delete o.subtype
  }
  return out as RawSpan[]
}

// Turn merged raw detections into editable workbench spans. Redacted-on by default, EXCEPT labels the
// reviewer has muted via the redaction filter (`muted`) come in inactive -- so the filter preference
// survives re-detection (Auto-detect -> Deep detect) instead of silently re-enabling muted categories.
export function toSpans(raw: RawSpan[], source: Span['source'], muted?: Set<string>): Span[] {
  return raw.map((r) => ({ ...r, id: newId(), source, active: !muted?.has(r.label) }))
}

// --- per-label redaction filter (fine-grained "redact this category: yes/no") ---
// The gate always DETECTS every label (you never want to lose detection); the reviewer chooses which
// detected categories to actually mask. This is a redaction-time choice over the existing per-span
// `active` flag, so it composes with individual span toggles and needs no change to detection.

export type LabelActivity = { label: string; total: number; active: number }

// Per-label active/total counts, for driving the filter UI. Sorted most-frequent first.
export function labelActivity(spans: Span[]): LabelActivity[] {
  const m = new Map<string, LabelActivity>()
  for (const s of spans) {
    const e = m.get(s.label) ?? { label: s.label, total: 0, active: 0 }
    e.total += 1
    if (s.active) e.active += 1
    m.set(s.label, e)
  }
  return [...m.values()].sort((a, b) => b.total - a.total || a.label.localeCompare(b.label))
}

// Set the `active` flag for every span of a given label. Returns a new array (immutable update).
export function setLabelActive(spans: Span[], label: string, active: boolean): Span[] {
  return spans.map((s) => (s.label === label ? { ...s, active } : s))
}

// Bulk set the `active` flag for every span whose label is in `labels`. Used for tier-level
// quick actions ("redact all catastrophic", "pass all operational").
export function setLabelsActive(spans: Span[], labels: Set<string>, active: boolean): Span[] {
  return spans.map((s) => (labels.has(s.label) ? { ...s, active } : s))
}

// Insert/replace a span so the active set stays non-overlapping (manual edits win over auto detections
// they overlap -- the reviewer's intent is authoritative). Returns a new array.
export function insertSpan(spans: Span[], next: Span): Span[] {
  const kept = spans.filter((s) => s.end <= next.start || s.start >= next.end)
  return [...kept, next].sort((a, b) => a.start - b.start)
}

// Re-running detection keeps every MANUAL span the reviewer added/kept, and adds freshly-detected spans
// only where they don't overlap a manual one. Prior auto/neural spans are discarded (the new pass replaces
// them). This makes "Auto-detect" and "Deep detect" idempotent and non-destructive to manual work.
export function combineWithManual(prev: Span[], detected: Span[]): Span[] {
  const manual = prev.filter((s) => s.source === 'manual')
  // Only ACTIVE manual spans veto a fresh detection. A manual span the reviewer toggled OFF must NOT suppress
  // a real detection in that region (else re-running detection would silently drop PII the user un-boxed).
  const blockers = manual.filter((m) => m.active)
  const fresh = detected.filter((d) => !blockers.some((m) => d.start < m.end && d.end > m.start))
  return [...manual, ...fresh].sort((a, b) => a.start - b.start)
}

// Shared placeholder index for a SESSION (one document, or one whole same-type batch). Holds the
// running per-label counters AND a value->placeholder dedup table so the SAME original value resolves
// to the SAME placeholder everywhere it appears -- within a doc AND across every file in a batch
// (finding 020). This is the carry-in store the batch threads through every file's buildEntityMap call;
// it is NOT a second store -- it produces the one EntityMap that plan 019's mapStore persists.
export type PlaceholderIndex = {
  counters: Record<string, number> // per-UPPERCASE-label running count -> next placeholder number
  byKey: Map<string, string> // `${LABEL} ${normalizedValue}` -> placeholder (cross-file dedup)
  map: EntityMap // placeholder -> original value (the accumulating shared map)
}

export function newPlaceholderIndex(): PlaceholderIndex {
  return { counters: {}, byKey: new Map(), map: {} }
}

// Dedup key: label + value normalized so trivially-different renderings of the SAME value
// (case, surrounding whitespace) collapse to one placeholder. Kept deliberately conservative -- only
// case-fold + trim + inner-whitespace-collapse -- so distinct values never accidentally merge.
function dedupKey(label: string, value: string): string {
  const norm = value.trim().replace(/\s+/g, ' ').toLowerCase()
  return `${label.toUpperCase()} ${norm}`
}

// Build (or extend) an entity map for one document. Pass a shared `index` to make placeholder numbering
// CONTINUOUS and value-deduplicated across calls (the batch case): the same label+value gets the same
// placeholder in file 1, file 2, ... With no `index`, behaviour is byte-for-byte the per-document legacy
// path (fresh counters, no cross-call dedup) -- the single-file flow is unchanged.
export function buildEntityMap(
  text: string,
  spans: Span[],
  index?: PlaceholderIndex,
): { map: EntityMap; placeholderOf: Map<string, string>; index: PlaceholderIndex } {
  const active = spans.filter((s) => s.active).sort((a, b) => a.start - b.start)
  const idx = index ?? newPlaceholderIndex()
  const placeholderOf = new Map<string, string>()
  for (const s of active) {
    const lab = s.label.toUpperCase()
    const value = text.slice(s.start, s.end)
    const key = dedupKey(s.label, value)
    let ph = idx.byKey.get(key)
    if (!ph) {
      idx.counters[lab] = (idx.counters[lab] ?? 0) + 1
      ph = `<${lab}_${String(idx.counters[lab]).padStart(3, '0')}>`
      idx.byKey.set(key, ph)
      idx.map[ph] = value
    }
    placeholderOf.set(s.id, ph)
  }
  // The returned `map` is the FULL shared map (every value seen so far in this index) when an index is
  // threaded; for the legacy no-index call it is exactly this doc's map. Both callers read `map` the same.
  return { map: idx.map, placeholderOf, index: idx }
}

// Redacted text with <LABEL_NNN> placeholders (round-trip-capable). Inactive spans keep their original text.
// Pass a shared `index` (the batch carry-in) so the same label+value gets the same placeholder across files.
export function redactedText(text: string, spans: Span[], index?: PlaceholderIndex): string {
  const { placeholderOf } = buildEntityMap(text, spans, index)
  const active = spans.filter((s) => s.active).sort((a, b) => a.start - b.start)
  let out = ''
  let last = 0
  for (const s of active) {
    out += text.slice(last, s.start) + placeholderOf.get(s.id)
    last = s.end
  }
  return out + text.slice(last)
}

export function rehydrate(text: string, map: EntityMap): string {
  let out = text
  for (const [ph, v] of Object.entries(map)) out = out.split(ph).join(v)
  return out
}

// Privacy-safe per-span provenance (the appliance's explain() analogue): offsets + metadata only,
// NEVER the redacted value, so it is safe to surface in a Law 25 audit trail.
export function explain(spans: Span[]) {
  return spans
    .filter((s) => s.active)
    .sort((a, b) => a.start - b.start)
    .map((s) => {
      const rec: Record<string, unknown> = {
        label: s.label,
        tier: s.tier,
        rule: s.rule,
        source: s.source,
        conf: Math.round(s.conf * 1000) / 1000,
        start: s.start,
        end: s.end,
        members: s.members ?? 1,
      }
      if (s.validator) rec.validator = s.validator
      if (s.cue) rec.cue = s.cue
      if (s.subtype) rec.subtype = s.subtype
      return rec
    })
}
