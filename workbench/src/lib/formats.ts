// File loading, in-browser, no upload. Text formats (.txt/.md/.csv/...), .docx + .xlsx (format-preserving),
// and .pdf (text extraction + true image-flatten redaction).

import { loadDocx, type Replacement } from './docx'
import { loadXlsx } from './xlsx'
import type { PageGeom, PageAssessment } from './pdf'
import type { EntityMap } from './types'

export type LoadedDoc = {
  name: string
  text: string
  kind: string
  // present for .docx: rebuild a redacted .docx (formatting preserved) from placeholder replacements
  rebuildDocx?: (repls: Replacement[]) => Promise<Blob>
  // present for .xlsx: rebuild a redacted .xlsx (formatting preserved) from placeholder replacements
  rebuildXlsx?: (repls: Replacement[]) => Promise<Blob>
  // present for .pdf: original bytes + per-page geometry + scanned-page assessment for true redaction
  bytes?: ArrayBuffer
  pages?: PageGeom[]
  assess?: PageAssessment[]
  assessPromise?: Promise<PageAssessment[]>
}

const TEXT_EXT = new Set(['txt', 'md', 'markdown', 'csv', 'tsv', 'log', 'json', 'jsonl', 'xml', 'html', 'htm', 'yaml', 'yml'])
const PENDING_EXT = new Set(['pptx']) // not yet -- give a clear message

export async function loadFile(file: File): Promise<LoadedDoc> {
  const ext = (file.name.split('.').pop() || '').toLowerCase()
  if (PENDING_EXT.has(ext)) {
    throw new Error(`.${ext} support is coming next. For now load .txt, .md, .csv, .docx, .xlsx, or .pdf.`)
  }
  if (ext === 'docx') {
    const { text, rebuild } = await loadDocx(file)
    return { name: file.name, text, kind: 'docx', rebuildDocx: rebuild }
  }
  if (ext === 'xlsx') {
    const { text, rebuild } = await loadXlsx(file)
    return { name: file.name, text, kind: 'xlsx', rebuildXlsx: rebuild }
  }
  if (ext === 'pdf') {
    // Exception: pdf.js is a large PDF-only dependency; static import regresses non-PDF document-open time.
    const { loadPdfDoc } = await import('./pdf')
    const { text, pages, assess, assessPromise, bytes } = await loadPdfDoc(file)
    return { name: file.name, text, kind: 'pdf', pages, assess, assessPromise, bytes }
  }
  const text = await file.text()
  return { name: file.name, text, kind: TEXT_EXT.has(ext) ? ext : ext || 'txt' }
}

const TEXT_MIME: Record<string, string> = { md: 'text/markdown', markdown: 'text/markdown', csv: 'text/csv', json: 'application/json', html: 'text/html', xml: 'application/xml' }

// any `<LABEL_NNN>` shaped token (the redaction placeholder contract, wire-compatible with the gate).
// Exported so mapStore/Rehydrate match the EXACT same token contract -- one source of truth for the
// placeholder shape, never a second divergent regex.
export const PLACEHOLDER_RE = /<[A-Z][A-Z0-9_]*_\d{3,}>/g
const PLACEHOLDER_TOKEN_RE = /^<[A-Z][A-Z0-9_]*_\d{3,}>$/

// The sorted, de-duplicated set of placeholders present in `text`. Shared by the round-trip restore
// and the on-device map matcher so both scan placeholders identically.
export function findPlaceholders(text: string): string[] {
  return [...new Set(text.match(PLACEHOLDER_RE) ?? [])].sort()
}

export function survivingValues(text: string, values: string[]): string[] {
  return [...new Set(values.filter((v) => v && text.includes(v)))]
}

export function validateEntityMap(raw: unknown): EntityMap {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error('The entity map must be a JSON object of placeholder -> value.')

  const map: EntityMap = {}
  for (const [ph, value] of Object.entries(raw)) {
    if (!PLACEHOLDER_TOKEN_RE.test(ph))
      throw new Error('The entity map contains an invalid placeholder key. Use the .json saved from "Download entity map".')
    if (typeof value !== 'string')
      throw new Error('The entity map contains a non-string value. Use the .json saved from "Download entity map".')
    map[ph] = value
  }
  return map
}

function spliceRepls(text: string, repls: Replacement[]): string {
  const sorted = [...repls].sort((a, b) => a.start - b.start)
  let out = ''
  let cur = 0
  for (const r of sorted) {
    if (r.start < cur) continue
    out += text.slice(cur, r.start) + r.text
    cur = r.end
  }
  return out + text.slice(cur)
}

// ROUND-TRIP rehydration (spec C): a colleague edited the redacted document; restore the original values into
// the surviving `<LABEL_NNN>` placeholders while KEEPING every colleague edit. Placeholders are unique anchors,
// so this is anchored token substitution: moved/duplicated placeholders all resolve, deleted ones simply drop
// their value (the entity was removed on purpose), and net-new colleague text is untouched. Fail closed if a
// surviving placeholder is not in the map: that is a wrong/incomplete-map signal, and partial restore can silently
// apply unrelated originals when token names collide. Format-preserving for .docx/.xlsx (reuses the same rebuild()
// that put the placeholders in). PDF can't round-trip (the redacted PDF is image-only, no placeholders survive).
export async function rehydrateFile(
  file: File,
  map: EntityMap,
): Promise<{ blob: Blob; filename: string; restored: number; unknown: string[] }> {
  const safeMap = validateEntityMap(map)
  const ext = (file.name.split('.').pop() || '').toLowerCase()
  if (ext === 'pdf')
    throw new Error('PDF restore is not supported: the redacted PDF is image-only and has no placeholders. Restore from the .docx, .xlsx, or .txt version instead.')

  let text: string
  let rebuild: ((repls: Replacement[]) => Promise<Blob>) | null = null
  let outExt = ext || 'txt'
  if (ext === 'docx') {
    const d = await loadDocx(file)
    text = d.text
    rebuild = d.rebuild
  } else if (ext === 'xlsx') {
    const d = await loadXlsx(file)
    text = d.text
    rebuild = d.rebuild
  } else {
    text = await file.text()
  }

  // classify every placeholder-shaped token present so we can report ones the map can't resolve
  const present = [...new Set(text.match(PLACEHOLDER_RE) ?? [])]
  const unknown = present.filter((ph) => !(ph in safeMap))
  if (unknown.length) {
    throw new Error(
      `The entity map does not resolve ${unknown.length} placeholder(s) in this file. ` +
        `Use the exact entity-map .json saved for this redaction.`,
    )
  }

  // one replacement per occurrence of each known placeholder -> its original value
  const repls: Replacement[] = []
  for (const [ph, value] of Object.entries(safeMap)) {
    let i = text.indexOf(ph)
    while (i !== -1) {
      repls.push({ start: i, end: i + ph.length, text: value })
      i = text.indexOf(ph, i + ph.length)
    }
  }
  const restored = repls.length

  const blob = rebuild
    ? await rebuild(repls)
    : new Blob([spliceRepls(text, repls)], { type: (TEXT_MIME[outExt] ?? 'text/plain') + ';charset=utf-8' })
  return { blob, filename: `restored.${outExt}`, restored, unknown }
}

export function download(filename: string, content: string, mime = 'text/plain') {
  downloadBlob(filename, new Blob([content], { type: mime + ';charset=utf-8' }))
}

export function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
