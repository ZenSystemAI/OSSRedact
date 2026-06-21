// Desktop (Node) entity-map store -- a SQLite-backed mirror of the browser IndexedDB store
// (mapStore.ts), for the INSTALLED/desktop build where there is no IndexedDB. Same contract:
//
//   - The entity map IS the plaintext originals (placeholder -> value), so the DB stays on THIS device
//     only and NEVER travels inside a shared/redacted artifact. The redacted file a colleague receives
//     carries only <LABEL_NNN> placeholders; the originals live here so re-opening an exported file can
//     auto-restore WITHOUT a separate .json map upload (the friction this store removes).
//   - Records are keyed by a CONTENT fingerprint of the REDACTED (placeholder-bearing) body -- never the
//     original text, never raw upload bytes -- so an unchanged redacted file auto-matches its map.
//   - Match is EXACT-fingerprint only (placeholder tokens are per-redaction scoped); an ambiguous or
//     unresolvable match refuses rather than restoring the wrong values.
//
// vs the browser store: this one is a class (explicit DB path + lifecycle) so a desktop shell can point
// it at the app's data dir, and tests can use ':memory:'. It also carries an OPTIONAL per-record
// `metadata` blob (e.g. the original filename + export timestamp) -- safe here because, unlike the shared
// web artifact, this DB is fully local. Built on Node's zero-dependency built-in `node:sqlite`.
//
// SECURITY: the DB file holds plaintext PII. It is created 0600 (owner-only) in the user's private app
// dir. This matches the IndexedDB store's threat model (on-device plaintext, never leaves the machine).
// Optional at-rest encryption is a documented future option, not a launch requirement.

import { DatabaseSync } from 'node:sqlite'
import { chmodSync, openSync, closeSync, existsSync } from 'node:fs'
import type { MapRecord } from './mapStore'
import { sha256Hex } from './mapStore'
import type { EntityMap } from './types'

// A desktop record may carry arbitrary LOCAL-ONLY metadata (filename, exportedAt, app version, ...).
// Never written into any shared artifact -- it lives only in this on-device DB.
export type NodeMapRecord = MapRecord & { metadata?: Record<string, unknown> }

// ---- pure helpers (mirror mapStore.ts; kept identical, guarded by mapStore.node.test.ts) ----
function canonicalMap(map: EntityMap): string {
  return JSON.stringify(Object.entries(map).sort(([a], [b]) => a.localeCompare(b)))
}
function sameMap(a: EntityMap, b: EntityMap): boolean {
  return canonicalMap(a) === canonicalMap(b)
}
async function collisionRecordId(rec: MapRecord): Promise<string> {
  const base = rec.fpExact || rec.id
  const mapHash = await sha256Hex(canonicalMap(rec.map))
  return `${base}:map-${mapHash.slice(0, 16)}`
}
function allResolvable(rec: MapRecord, present: string[]): boolean {
  return present.every((ph) => ph in rec.map)
}
function unambiguousMatch(candidates: MapRecord[], present: string[]): MapRecord | null {
  if (!candidates.length) return null
  const signatures = new Set(
    candidates.map((rec) => JSON.stringify(present.map((ph) => [ph, rec.map[ph]]))),
  )
  return signatures.size === 1 ? candidates[0] : null
}

const DDL = `
CREATE TABLE IF NOT EXISTS entity_maps (
  id            TEXT PRIMARY KEY,
  created_at    INTEGER NOT NULL,
  neutral_label TEXT NOT NULL,
  fp_exact      TEXT NOT NULL,
  placeholders  TEXT NOT NULL,
  fingerprints  TEXT,
  metadata      TEXT,
  map_json      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entity_maps_fp ON entity_maps(fp_exact);
`

type Row = {
  id: string
  created_at: number
  neutral_label: string
  fp_exact: string
  placeholders: string
  fingerprints: string | null
  metadata: string | null
  map_json: string
}

function rowToRecord(r: Row): NodeMapRecord {
  return {
    id: r.id,
    createdAt: r.created_at,
    neutralLabel: r.neutral_label,
    fpExact: r.fp_exact,
    placeholders: JSON.parse(r.placeholders),
    map: JSON.parse(r.map_json),
    ...(r.fingerprints ? { fingerprints: JSON.parse(r.fingerprints) } : {}),
    ...(r.metadata ? { metadata: JSON.parse(r.metadata) } : {}),
  }
}

export class SqliteMapStore {
  private db: DatabaseSync

  // dbPath: an absolute file path in the user's private app-data dir, or ':memory:' for tests.
  constructor(dbPath: string) {
    const onDisk = dbPath !== ':memory:'
    // Pre-create the file at 0600 BEFORE SQLite opens it, so it never exists world-readable even briefly
    // (closes the TOCTOU window between open-at-umask-default and a post-hoc chmod). Opening an existing
    // 0600 file preserves its mode.
    if (onDisk && !existsSync(dbPath)) {
      try { closeSync(openSync(dbPath, 'w', 0o600)) } catch { /* fall through to post-hoc chmod below */ }
    }
    this.db = new DatabaseSync(dbPath)
    this.db.exec('PRAGMA journal_mode = WAL;')
    this.db.exec(DDL)
    if (onDisk) {
      // owner-only on the DB AND its WAL/SHM sidecars -- all three carry plaintext originals, and WAL mode
      // creates the sidecars at the process umask (typically 0644) regardless of the main file's mode.
      for (const suffix of ['', '-wal', '-shm']) {
        try {
          if (existsSync(dbPath + suffix)) chmodSync(dbPath + suffix, 0o600)
        } catch {
          // best-effort (e.g. Windows ACLs); the app-data dir is already user-private
        }
      }
    }
  }

  // Persist a record. Idempotent on `id` (== fpExact): a re-redact of the same body overwrites with
  // identical content. If two DIFFERENT originals produced the same redacted body (same id, different
  // map), store the second under a collision-suffixed id rather than clobbering -- matching then refuses
  // the ambiguous restore instead of rehydrating the wrong values.
  async putMap(rec: NodeMapRecord): Promise<void> {
    const existing = this.db
      .prepare('SELECT map_json FROM entity_maps WHERE id = ?')
      .get(rec.id) as { map_json: string } | undefined
    let id = rec.id
    if (existing && !sameMap(JSON.parse(existing.map_json), rec.map)) {
      id = await collisionRecordId(rec)
    }
    this.db
      .prepare(
        `INSERT INTO entity_maps (id, created_at, neutral_label, fp_exact, placeholders, fingerprints, metadata, map_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           created_at=excluded.created_at, neutral_label=excluded.neutral_label, fp_exact=excluded.fp_exact,
           placeholders=excluded.placeholders, fingerprints=excluded.fingerprints, metadata=excluded.metadata,
           map_json=excluded.map_json`,
      )
      .run(
        id,
        rec.createdAt,
        rec.neutralLabel,
        rec.fpExact,
        JSON.stringify(rec.placeholders),
        rec.fingerprints ? JSON.stringify(rec.fingerprints) : null,
        rec.metadata ? JSON.stringify(rec.metadata) : null,
        JSON.stringify(rec.map),
      )
  }

  async allMaps(): Promise<NodeMapRecord[]> {
    const rows = this.db.prepare('SELECT * FROM entity_maps ORDER BY created_at').all() as Row[]
    return rows.map(rowToRecord)
  }

  async clearMaps(): Promise<void> {
    this.db.exec('DELETE FROM entity_maps')
  }

  // Match a returned file to a stored map by EXACT fingerprint of the redacted body. Mirrors
  // mapStore.matchByFingerprint: exact own-copy fast path, guarded by allResolvable + unambiguousMatch.
  async matchByFingerprint(fpExact: string, present: string[]): Promise<NodeMapRecord | null> {
    const records = await this.allMaps()
    if (!records.length) return null
    const exact = records.filter(
      (r) =>
        (r.fpExact === fpExact || (r.fingerprints ?? []).some((f) => f.fpExact === fpExact)) &&
        allResolvable(r, present),
    )
    return unambiguousMatch(exact, present) as NodeMapRecord | null
  }

  close(): void {
    this.db.close()
  }
}
