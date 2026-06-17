// Batch redaction model (finding 020). The workbench processes ONE document at a time today; a reviewer
// with 15 same-type files (Flinks reports, bank statements) had to load/review/export/reset 15 times AND
// got inconsistent placeholders (counters reset per file). A batch is an ORDERED set of per-file entries
// sharing ONE entity map, exported as ONE .zip of redacted files with NEUTRAL filenames.
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
import type { Span, RegionBox } from './types'
import type { LoadedDoc } from './formats'

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

// Assemble the shareable .zip. Takes ONLY redacted blobs (+ an optional values-free audit JSON). The
// shared entity map is intentionally NOT a parameter: it must never enter the shareable archive.
export async function assembleZip(files: ZipFile[], auditJson?: string): Promise<Blob> {
  const zip = new JSZip()
  for (const f of files) zip.file(f.name, f.blob)
  if (auditJson) zip.file('audit-trail.json', auditJson) // explain() per file -- offsets/metadata only, no values
  return zip.generateAsync({ type: 'blob', mimeType: 'application/zip' })
}
