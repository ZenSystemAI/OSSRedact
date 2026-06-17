// On-device entity-map store (IndexedDB). The entity map IS the plaintext originals
// (`types.ts:25` -- placeholder -> original value, sensitive), so it stays on THIS device only and
// NEVER travels inside a shared/redacted artifact. This module persists the map keyed by a CONTENT
// fingerprint of the REDACTED (placeholder-bearing) body -- never the original text, never the upload
// filename -- so a redacted file that comes back can auto-match its map with no separate .json upload.
//
// Design notes the next maintainer must keep:
// - The fingerprint MUST be over the redacted body, never the original. Hashing originals would itself
//   be a (weak) leak and would not match the returned (colleague-edited) file anyway.
// - Raw IndexedDB is used (browser-native, no runtime dep). DB `sparx-maps`, store `entityMaps`,
//   keyPath `id`. `id` == `fpExact`, so a re-redact of the same body is idempotent (matters under
//   React StrictMode, which double-invokes effects in dev -- main.tsx).
// - The record carries a forward-compatible `fingerprints` array (one entry per source body) so a
//   future batch-redaction (finding 020) can key MANY per-file fingerprints under one shared map
//   without an IndexedDB migration. `fpExact`/`placeholders` stay the primary single-file keys.

import type { EntityMap } from './types'

const DB_NAME = 'sparx-maps'
const STORE = 'entityMaps'
const DB_VERSION = 1

// Opt-in preference key. ONLY a boolean preference lives in localStorage -- never the map (which holds
// originals). Default ON for usability: when OFF, putMap callers must write nothing. Shared by the
// redact-side write gate (App.tsx) and the toggle UI (Dropzone.tsx) so there is one source of truth.
const REMEMBER_KEY = 'sparx-remember-maps'

export function getRemember(): boolean {
  try {
    return localStorage.getItem(REMEMBER_KEY) !== '0' // default ON (absent or anything but '0')
  } catch {
    return true
  }
}

export function setRemember(on: boolean): void {
  try {
    localStorage.setItem(REMEMBER_KEY, on ? '1' : '0')
  } catch {
    // private browsing / storage disabled -- the in-session toggle still works for this page load.
  }
}

// A single source body's fingerprint: the redacted-body hash + the placeholder set present in it.
// Forward-compatible container for batch redaction (one record, several source files sharing one map).
export type Fingerprint = { fpExact: string; placeholders: string[] }

export type MapRecord = {
  id: string // == fpExact (idempotency key under StrictMode double-invoke)
  createdAt: number
  neutralLabel: string // date-stamped neutral string -- NEVER the upload filename or original text
  fpExact: string // sha256 of the redacted (placeholder-bearing) body -- own-copy fast path
  placeholders: string[] // sorted set of placeholders present in the redacted body
  map: EntityMap // placeholder -> original value (sensitive; stays on this device only)
  fingerprints?: Fingerprint[] // forward-compat: per-source-file fingerprints for batch redaction (020)
}

// SHA-256 of `s`, hex-encoded. Uses the WebCrypto SubtleCrypto digest (available in browsers + jsdom
// with a crypto polyfill in tests; not previously used in this codebase).
export async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: 'id' })
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function tx(db: IDBDatabase, mode: IDBTransactionMode): IDBObjectStore {
  return db.transaction(STORE, mode).objectStore(STORE)
}

// Persist a record. Idempotent on `id` (use `fpExact` as `id`): a re-redact of the same body just
// overwrites with identical content, so StrictMode's double-invoke does not create duplicates.
export async function putMap(rec: MapRecord): Promise<void> {
  const db = await openDb()
  try {
    await new Promise<void>((resolve, reject) => {
      const req = tx(db, 'readwrite').put(rec)
      req.onsuccess = () => resolve()
      req.onerror = () => reject(req.error)
    })
  } finally {
    db.close()
  }
}

export async function allMaps(): Promise<MapRecord[]> {
  const db = await openDb()
  try {
    return await new Promise<MapRecord[]>((resolve, reject) => {
      const req = tx(db, 'readonly').getAll()
      req.onsuccess = () => resolve((req.result as MapRecord[]) ?? [])
      req.onerror = () => reject(req.error)
    })
  } finally {
    db.close()
  }
}

export async function clearMaps(): Promise<void> {
  const db = await openDb()
  try {
    await new Promise<void>((resolve, reject) => {
      const req = tx(db, 'readwrite').clear()
      req.onsuccess = () => resolve()
      req.onerror = () => reject(req.error)
    })
  } finally {
    db.close()
  }
}

// True iff EVERY present placeholder is resolvable as a key in `rec.map`. This is the cross-map
// collision guard: an auto-match must never rehydrate a placeholder that the matched map cannot
// resolve (that would mean restoring from the wrong map). If any survivor is missing, the caller
// must fall back to manual upload rather than partial-restore from the wrong record.
function allResolvable(rec: MapRecord, present: string[]): boolean {
  return present.every((ph) => ph in rec.map)
}

// Match a returned file to a stored map.
// Priority: exact `fpExact` hit (own copy, untouched body) -> else the stored record with the best
// placeholder-subset overlap where ALL present placeholders are resolvable in that record's map.
// If no single record resolves every survivor, return null and let the caller fall back to manual
// upload. `present` must be non-empty for a subset match (a file with no surviving placeholders has
// nothing to restore).
export async function matchByFingerprint(
  fpExact: string,
  presentPlaceholders: string[],
): Promise<MapRecord | null> {
  const records = await allMaps()
  if (!records.length) return null

  // 1) exact own-copy fast path: the redacted body is byte-identical to what was stored.
  // Guard it with allResolvable too -- a true own-copy always resolves, and this keeps the
  // invariant uniform (never restore an unresolvable survivor).
  const exact = records.find(
    (r) =>
      (r.fpExact === fpExact || (r.fingerprints ?? []).some((f) => f.fpExact === fpExact)) &&
      allResolvable(r, presentPlaceholders),
  )
  if (exact) return exact

  // 2) placeholder-subset match: the colleague edited the body so the hash will not match. A record
  // is a candidate iff at least one placeholder survives AND every survivor is resolvable in its map.
  if (!presentPlaceholders.length) return null
  let best: MapRecord | null = null
  let bestOverlap = 0
  for (const r of records) {
    if (!allResolvable(r, presentPlaceholders)) continue
    const overlap = presentPlaceholders.filter((ph) => ph in r.map).length
    if (overlap >= 1 && overlap > bestOverlap) {
      best = r
      bestOverlap = overlap
    }
  }
  return best
}
