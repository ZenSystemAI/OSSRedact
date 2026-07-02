// Span merge + placeholder/entity-map machinery. The merge is a faithful port of privacy_gate.py
// merge_spans() (CONNECTED-COMPONENT UNION): any cluster of overlapping detections becomes ONE
// redaction covering their union, labelled by the highest-confidence (then longest) member -- EXCEPT a
// hard-floor label always wins the cluster primary (FLOOR STICKINESS), and every distinct member label is
// recorded in `labels`. A privacy gate must never leave a PII fragment exposed between two overlapping
// spans, so over-redaction is the safe error. Placeholders are <LABEL_NNN>, matching the appliance's
// gate_service.py /redact contract, so a document redacted here round-trips through the same entity map.

import type { RawSpan, Span, EntityMap } from './types'
import { PLACEHOLDER_CONTRACT_RE } from './placeholder'
import { FLOOR_LABELS } from './labels.js'

let _idCounter = 0
export function newId(): string {
  return 's' + (++_idCounter).toString(36)
}

export function mergeSpans(spans: RawSpan[], sticky: ReadonlySet<string> = FLOOR_LABELS): RawSpan[] {
  if (!spans.length) return []
  const arr = [...spans].sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start))
  // _bc/_bl = the elected primary's (conf, length); _labels = all distinct member labels; _floor/_fc =
  // the STRONGEST floor member (so a floor value out-scored by a soft guess can be restored below).
  type Acc = RawSpan & { _bc: number; _bl: number; _labels: Set<string>; _floor?: RawSpan; _fc?: number }
  const out: Acc[] = []
  for (const s of arr) {
    const floor = sticky.has(s.label)
    const cur = out[out.length - 1]
    if (cur && s.start < cur.end) {
      cur.members = (cur.members ?? 1) + 1
      cur._labels.add(s.label)
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
      if (floor && s.conf > (cur._fc ?? -1)) {
        // remember the strongest floor member so its provenance survives even if a soft guess out-scores it
        cur._floor = s
        cur._fc = s.conf
      }
      cur.end = Math.max(cur.end, s.end)
      cur.conf = Math.max(cur.conf, s.conf)
    } else {
      const nc: Acc = { ...s, _bc: s.conf, _bl: s.end - s.start, members: 1, _labels: new Set([s.label]) }
      if (floor) {
        nc._floor = s
        nc._fc = s.conf
      }
      out.push(nc)
    }
  }
  for (const o of out) {
    // FLOOR STICKINESS: if the elected primary is NOT a floor label but the cluster held a floor member,
    // restore the strongest floor member's label + provenance. The merged span EXTENTS (start/end/conf) are
    // untouched -- floor only ever KEEPS more redaction, never shifts the mask. The downstream floor guards
    // (applyAllowlist, 'off' mode) key off the post-merge LABEL, so a real floor value out-scored by a soft
    // neural guess must exit the merge carrying a floor label or it would lose its protection and leak.
    const fl = o._floor
    if (fl && !sticky.has(o.label)) {
      o.label = fl.label
      o.tier = fl.tier
      o.rule = fl.rule
      o.validator = fl.validator
      o.cue = fl.cue
      o.subtype = fl.subtype
    }
    // union spanned >1 category: keep the elected primary in `label` for the placeholder, but record ALL
    // distinct member labels so a downstream category filter / Law 25 audit sees the true set, not just one.
    if (o._labels.size > 1) o.labels = [...o._labels].sort()
    delete (o as Partial<Acc>)._bc
    delete (o as Partial<Acc>)._bl
    delete (o as Partial<Acc>)._labels
    delete (o as Partial<Acc>)._floor
    delete (o as Partial<Acc>)._fc
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

// Resolve active-over-inactive overlaps for DISPLAY. combineWithManual only treats ACTIVE manual spans as
// blockers (redaction.ts combineWithManual), so an INACTIVE manual span can overlap an ACTIVE detection in
// app state. A naive renderer that picks the lowest-start span then paints its whole range would render the
// inactive "kept" region across the active PII and show the original value as plaintext (a DISPLAY LEAK on
// the review surface, copyable). Active PII MUST always win: keep every active span whole and clip every
// inactive span to the gaps BETWEEN active spans. No-op when nothing overlaps (the common case). Used by
// both DocCanvas (flat) and LayoutCanvas (layout) so neither view can disagree with the redacted output.
export function resolveRenderSpans(spans: Span[]): Span[] {
  const active = spans.filter((s) => s.active).sort((a, b) => a.start - b.start)
  if (!active.length) return [...spans].sort((a, b) => a.start - b.start)
  const out: Span[] = [...active]
  for (const s of spans) {
    if (s.active) continue
    let cursor = s.start
    for (const a of active) {
      if (a.end <= cursor) continue // active interval already behind the cursor
      if (a.start >= s.end) break // remaining active intervals are past this inactive span
      if (a.start > cursor) out.push({ ...s, start: cursor, end: Math.min(a.start, s.end) }) // gap before active
      cursor = Math.max(cursor, a.end)
      if (cursor >= s.end) break
    }
    if (cursor < s.end) out.push({ ...s, start: cursor, end: s.end }) // tail after the last active overlap
  }
  return out.sort((a, b) => a.start - b.start)
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

const CASE_SENSITIVE_LABEL_KEYS = new Set(['password', 'secret', 'username', 'person', 'name', 'accesstoken', 'apikey', 'filepath'])

function labelKey(label: string): string {
  return label.toLowerCase().replace(/[^a-z0-9]/g, '')
}

function isCaseSensitiveLabel(label: string): boolean {
  return CASE_SENSITIVE_LABEL_KEYS.has(labelKey(label))
}

function labelFromPlaceholder(ph: string): string {
  return PLACEHOLDER_CONTRACT_RE.exec(ph)?.[1] ?? ''
}

// Dedup key: label + value normalized so trivially-different renderings of the SAME ordinary non-name PII
// value collapse to one placeholder. Case-significant labels skip the case fold.
// Kept deliberately conservative -- trim + inner-whitespace-collapse -- so distinct values do not merge.
function dedupKey(label: string, value: string): string {
  const compact = value.trim().replace(/\s+/g, ' ')
  const norm = isCaseSensitiveLabel(label) ? compact : compact.toLowerCase()
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

// Minimum value length to sweep -- below this, a value is too generic to mask globally without risking
// spurious matches (and tiny tokens are rarely uniquely-identifying on their own).
const MIN_SWEEP_LEN = 4
const RE_SPECIAL = /[.*+?^${}()|[\]\\]/g
// A <LABEL_NNN> placeholder token (matches the buildEntityMap shape). These are inserted by the positional
// pass and must be PRESERVED verbatim by the sweep -- never rewritten (else a value equal to a label-like
// token, e.g. an org named "EMAIL", would corrupt "<EMAIL_001>"; Codex review 2026-06-17).
const PLACEHOLDER_TOKEN_RE = /<[A-Z0-9_]+_\d{3,}>/g
// Token characters for the boundary guard: letter, number, combining mark (decomposed accents), underscore
// (so a value is not matched inside a `José` / `Live_Wire` compound). Hyphen/slash stay boundaries.
const TOK = '[\\p{L}\\p{N}\\p{M}_]'

// Mask EVERY remaining verbatim occurrence of an already-detected value that positional redaction missed.
// Real-doc Finding C (2026-06-17): positional redaction masks only DETECTED span positions, so a value that
// repeats across a long/multi-page document (per-page footers, repeated headers, line items) leaks at the
// occurrences the detector skipped. This sweeps only KNOWN (already-mapped) values -- never a new guess --
// longest-first, at TOKEN BOUNDARIES so a 7-digit value can NOT be matched inside an 8-digit number and a
// short name can NOT be matched inside a longer word (the boundary guard is what makes the sweep safe -- a
// naive global replace is the known "sweep_known fragility"). The sweep runs ONLY on the literal segments
// BETWEEN placeholders, so it can never rewrite a placeholder the positional pass already inserted. Over-
// masking an already-detected value is the safe error; rehydrate() restores every occurrence regardless.
export function sweepKnownValues(
  redacted: string,
  map: EntityMap,
  insertedPlaceholders?: ReadonlySet<string>,
): string {
  const entries = Object.entries(map)
    .filter(([, v]) => v && v.trim().length >= MIN_SWEEP_LEN)
    .sort((a, b) => b[1].length - a[1].length) // longest first -> the alternation prefers the longer value
  if (!entries.length) return redacted
  const exactEntries = entries.filter(([ph]) => isCaseSensitiveLabel(labelFromPlaceholder(ph)))
  const ciEntries = entries.filter(([ph]) => !isCaseSensitiveLabel(labelFromPlaceholder(ph)))

  const protectedTokens = new Set(
    [...new Set(redacted.match(PLACEHOLDER_TOKEN_RE) ?? [])].filter((t) =>
      insertedPlaceholders ? insertedPlaceholders.has(t) : Object.prototype.hasOwnProperty.call(map, t),
    ),
  )

  const sweepEntries = (
    input: string,
    passEntries: [string, string][],
    caseSensitive: boolean,
  ): { text: string; added: Set<string> } => {
    if (!passEntries.length) return { text: input, added: new Set() }
    const valueToPh = new Map<string, string>()
    for (const [ph, v] of passEntries) {
      const key = caseSensitive ? v : v.toLowerCase()
      if (!valueToPh.has(key)) valueToPh.set(key, ph)
    }
    const alt = passEntries
      .map(([, v]) => v)
      .filter((v, i, vals) => vals.indexOf(v) === i)
      .map((v) => v.replace(RE_SPECIAL, '\\$&'))
      .join('|')
    if (!alt) return { text: input, added: new Set() }
    // ONE combined left-to-right pass per gap. String.replace matches against the ORIGINAL gap and never
    // re-scans the placeholders it inserts, so a later value can NOT rewrite a placeholder produced by an
    // earlier match in the same sweep. Longest-first alternation order prefers the longer value at any position.
    const flags = caseSensitive ? 'gu' : 'giu'
    const re = new RegExp(`(?<!${TOK})(?:${alt})(?!${TOK})`, flags)
    const added = new Set<string>()
    const sweepGap = (gap: string): string =>
      gap.replace(re, (m) => {
        const ph = valueToPh.get(caseSensitive ? m : m.toLowerCase())
        if (!ph) return m
        added.add(ph)
        return ph
      })
    const protectedInText = [...protectedTokens]
      .filter((t) => input.includes(t))
      .sort((a, b) => b.length - a.length)
    if (!protectedInText.length) return { text: sweepGap(input), added }
    const tokenRe = new RegExp(protectedInText.map((p) => p.replace(RE_SPECIAL, '\\$&')).join('|'), 'g')
    const parts = input.split(tokenRe)
    const tokens = input.match(tokenRe) ?? []
    let out = sweepGap(parts[0] ?? '')
    for (let i = 0; i < tokens.length; i++) out += tokens[i] + sweepGap(parts[i + 1] ?? '')
    return { text: out, added }
  }

  // Split into literal gaps (swept) and placeholder tokens (preserved verbatim). split() with a global,
  // capture-free regex drops the delimiters, so parts.length === tokens.length + 1; reassemble interleaved.
  // FINDING 2 (Codex 2026-06-17): protect ONLY the placeholders ACTUALLY inserted into THIS string, not every
  // placeholder-SHAPED token. A placeholder-shaped string the USER typed (or that a known value itself contains)
  // must be SWEPT like any other text, not skipped as if it were an inserted token and leak a repeated value next to
  // it. (Parity with Python _sweep_known.)
  // FINDING 3 (Codex 2026-06-17, batch leak): the caller (redactedText) passes the EXACT set of placeholders it just
  // inserted (placeholderOf.values()). We MUST NOT infer "inserted" from the shared-batch map keys: in the batch /
  // shared-index case the map holds placeholders from OTHER files, so a cross-file placeholder appearing inside THIS
  // file's user content (e.g. a secret value that literally contains "<EMAIL_001>") would be wrongly protected and the
  // containing value would leak. Fall back to map-key membership ONLY for direct callers that pass no set (single-doc,
  // where map IS this doc's map).
  const exact = sweepEntries(redacted, exactEntries, true)
  for (const ph of exact.added) protectedTokens.add(ph)
  return sweepEntries(exact.text, ciEntries, false).text
}

// Redacted text with <LABEL_NNN> placeholders (round-trip-capable). Inactive spans keep their original text.
// Pass a shared `index` (the batch carry-in) so the same label+value gets the same placeholder across files.
export function redactedText(text: string, spans: Span[], index?: PlaceholderIndex): string {
  const { map, placeholderOf } = buildEntityMap(text, spans, index)
  const active = spans.filter((s) => s.active).sort((a, b) => a.start - b.start)
  let out = ''
  let last = 0
  for (const s of active) {
    out += text.slice(last, s.start) + placeholderOf.get(s.id)
    last = s.end
  }
  out += text.slice(last)
  // Finding C hardening: catch any duplicate occurrence positional redaction missed (token-boundary-safe). Pass the
  // EXACT placeholders inserted in THIS call (placeholderOf.values()) so the sweep protects only those, never a
  // cross-file placeholder from the shared batch map that happens to appear in this doc's user content (Codex F3).
  return sweepKnownValues(out, map, new Set(placeholderOf.values()))
}

export function rehydrate(text: string, map: EntityMap): string {
  const tokens = Object.keys(map).filter((ph) => text.includes(ph))
  if (!tokens.length) return text
  const re = new RegExp(tokens.sort((a, b) => b.length - a.length).map((ph) => ph.replace(RE_SPECIAL, '\\$&')).join('|'), 'g')
  return text.replace(re, (ph) => map[ph])
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
