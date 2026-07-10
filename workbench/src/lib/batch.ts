// Batch redaction model (finding 020). The workbench processes one document at a time; repeated
// same-type-file workflows require load, review, export, and reset for each file, while per-file counter
// resets can produce inconsistent placeholders. A batch is an ORDERED set of per-file entries sharing ONE
// entity map, exported as ONE .zip of redacted files with NEUTRAL filenames.
//
// Hard invariants this module enforces / supports:
//   - SAME type per batch (v1): export + rebuild + the fail-closed verify are all format-specific
//     (docx vs xlsx vs pdf vs text), so a batch is homogeneous. `extOf` + `sameTypeError` reject a mismatch.
//   - The shared entity map (originals) is NEVER placed inside the shareable zip -- it is offered as a
//     SEPARATE local download only (mirrors App.tsx:180 / mapStore.ts). This module's zip assembler only
//     ever takes redacted blobs + the values-free audit, never the map.
//   - Redacted files in the zip use NEUTRAL names (`redacted-001.docx`, ...), never the upload filename,
//     which routinely CONTAINS the very PII just redacted (App.tsx exportName rationale).

import JSZip from 'jszip'
import type { Span, RegionBox, EntityMap } from './types'
import type { LoadedDoc } from './formats'
import { sweepKnownValues } from './redaction'

export type BatchStatus = 'pending' | 'detecting' | 'detected' | 'error'

// One file in the batch: its loaded doc + the reviewer's editable span/region state + a detect status.
export type BatchEntry = {
  id: string
  name: string // upload filename -- kept ONLY for the in-app file rail label, NEVER written to an output
  kind: string // normalized extension; the batch is homogeneous so every entry shares this
  doc: LoadedDoc
  spans: Span[]
  regions: RegionBox[]
  status: BatchStatus
  error?: string // populated when status === 'error' (e.g. gate unreachable for this entry)
}

// Normalized lower-case extension of a filename. The batch type is the FIRST file's extension; every
// subsequent file must match. Text-ish extensions (.txt/.md/.csv/...) are bucketed as one "text" type
// because they share the exact same redaction + export path (plain-text splice), so a .txt + .md batch
// is legitimately homogeneous; office (.docx/.xlsx) and .pdf each stand alone.
const TEXT_EXTS = new Set(['txt', 'md', 'markdown', 'csv', 'tsv', 'log', 'json', 'jsonl', 'xml', 'html', 'htm', 'yaml', 'yml'])

export function extOf(filename: string): string {
  return (filename.split('.').pop() || '').toLowerCase()
}

// The batch "type bucket" for an extension: text-ish files collapse to 'text'; office + pdf are their own.
export function typeBucket(ext: string): string {
  return TEXT_EXTS.has(ext) ? 'text' : ext
}

// Same-type check against a batch's established type bucket. Returns null when `ext` is allowed, or an
// explanatory message (stating WHY mixed types are rejected) when it is not.
export function sameTypeError(batchBucket: string, ext: string): string | null {
  if (typeBucket(ext) === batchBucket) return null
  return (
    `This batch is ${batchBucket === 'text' ? 'text files' : '.' + batchBucket + ' files'}; ` +
    `a .${ext} file uses a different export and verification path, so it can't be mixed in. ` +
    `Process .${ext} files as their own batch.`
  )
}

// Neutral, index-stamped output name -- NEVER the upload filename (which may contain the PII we redacted).
// 1-based, zero-padded to the batch width so the zip lists in order.
export function neutralName(index: number, total: number, ext: string): string {
  const width = Math.max(3, String(total).length)
  return `redacted-${String(index + 1).padStart(width, '0')}.${ext}`
}

// One redacted artifact destined for the zip: a blob + the neutral name it gets inside the archive.
export type ZipFile = { name: string; blob: Blob }
export type TextReplacement = { start: number; end: number; text: string }

// Assemble the shareable .zip. Takes ONLY redacted blobs (+ an optional values-free audit JSON). The
// shared entity map is intentionally NOT a parameter: it must never enter the shareable archive.
export async function assembleZip(files: ZipFile[], auditJson?: string): Promise<Blob> {
  const zip = new JSZip()
  for (const f of files) zip.file(f.name, f.blob)
  if (auditJson) zip.file('audit-trail.json', auditJson) // explain() per file -- offsets/metadata only, no values
  return zip.generateAsync({ type: 'blob', mimeType: 'application/zip' })
}

export function entityMapForSpans(text: string, spans: Span[], placeholderOf: Map<string, string>): EntityMap {
  const entryMap: EntityMap = {}
  for (const s of spans) {
    if (!s.active) continue
    const ph = placeholderOf.get(s.id)
    if (ph) entryMap[ph] = text.slice(s.start, s.end)
  }
  return entryMap
}

export function redactTextWithPlaceholders(text: string, spans: Span[], placeholderOf: Map<string, string>): string {
  const active = spans.filter((s) => s.active).sort((a, b) => a.start - b.start)
  let out = ''
  let last = 0
  for (const s of active) {
    out += text.slice(last, s.start) + (placeholderOf.get(s.id) ?? '')
    last = s.end
  }
  return out + text.slice(last)
}

const MIN_SWEEP_LEN = 4
const RE_SPECIAL = /[.*+?^${}()|[\]\\]/g
const TOK = '[\\p{L}\\p{N}\\p{M}_]'
const CASE_SENSITIVE_LABEL_KEYS = new Set(['password', 'secret', 'username', 'person', 'name', 'accesstoken', 'apikey', 'filepath'])

function labelKey(label: string): string {
  return label.toLowerCase().replace(/[^a-z0-9]/g, '')
}

function labelFromPlaceholder(ph: string): string {
  return /^<([A-Z][A-Z0-9_]*)_\d{3,}>$/.exec(ph)?.[1] ?? ''
}

function isCaseSensitivePlaceholder(ph: string): boolean {
  return CASE_SENSITIVE_LABEL_KEYS.has(labelKey(labelFromPlaceholder(ph)))
}

function overlapsAny(ranges: TextReplacement[], start: number, end: number): boolean {
  return ranges.some((r) => r.start < end && r.end > start)
}

function sweepReplacements(text: string, map: EntityMap, occupied: TextReplacement[]): TextReplacement[] {
  const entries = Object.entries(map)
    .filter(([, value]) => value && value.trim().length >= MIN_SWEEP_LEN)
    .sort((a, b) => b[1].length - a[1].length)
  const out: TextReplacement[] = []

  const addPass = (passEntries: [string, string][], caseSensitive: boolean) => {
    if (!passEntries.length) return
    const valueToPh = new Map<string, string>()
    for (const [ph, value] of passEntries) {
      const key = caseSensitive ? value : value.toLowerCase()
      if (!valueToPh.has(key)) valueToPh.set(key, ph)
    }
    const alt = passEntries
      .map(([, value]) => value)
      .filter((value, i, values) => values.indexOf(value) === i)
      .map((value) => value.replace(RE_SPECIAL, '\\$&'))
      .join('|')
    if (!alt) return
    const re = new RegExp(`(?<!${TOK})(?:${alt})(?!${TOK})`, caseSensitive ? 'gu' : 'giu')
    for (const match of text.matchAll(re)) {
      const start = match.index ?? -1
      if (start < 0) continue
      const end = start + match[0].length
      if (overlapsAny(occupied, start, end)) continue
      const ph = valueToPh.get(caseSensitive ? match[0] : match[0].toLowerCase())
      if (!ph) continue
      const repl = { start, end, text: ph }
      out.push(repl)
      occupied.push(repl)
    }
  }

  addPass(entries.filter(([ph]) => isCaseSensitivePlaceholder(ph)), true)
  addPass(entries.filter(([ph]) => !isCaseSensitivePlaceholder(ph)), false)
  return out
}

export function replacementsForText(
  text: string,
  spans: Span[],
  placeholderOf: Map<string, string>,
  sharedMap?: EntityMap,
): TextReplacement[] {
  const active = spans.filter((s) => s.active).sort((a, b) => a.start - b.start)
  const positional = active.map((s) => ({ start: s.start, end: s.end, text: placeholderOf.get(s.id) ?? '' }))
  const occupied = [...positional]
  const map = sharedMap ?? entityMapForSpans(text, spans, placeholderOf)
  return [...positional, ...sweepReplacements(text, map, occupied)].sort((a, b) => a.start - b.start)
}

export function redactedBatchText(
  text: string,
  spans: Span[],
  placeholderOf: Map<string, string>,
  sharedMap?: EntityMap,
): string {
  const positional = redactTextWithPlaceholders(text, spans, placeholderOf)
  const map = sharedMap ?? entityMapForSpans(text, spans, placeholderOf)
  return sweepKnownValues(positional, map, new Set(placeholderOf.values()))
}
