// @vitest-environment node
// Tests for the desktop SQLite entity-map store (mapStore.node.ts). Runs in the NODE vitest env (not
// jsdom) because it uses Node's built-in `node:sqlite` + global crypto.subtle. ALL inputs are 100%
// synthetic (e.g. <EMAIL_001> -> alice@example.com), mirroring mapStore.test.ts.

import { describe, it, expect, beforeEach } from 'vitest'
import { SqliteMapStore, type NodeMapRecord } from './mapStore.node'

const rec = (id: string, map: Record<string, string>, opts: Partial<NodeMapRecord> = {}): NodeMapRecord => ({
  id,
  createdAt: 1718800000000,
  neutralLabel: 'redacted-document-2026-06-19',
  fpExact: id,
  placeholders: Object.keys(map).sort(),
  map,
  ...opts,
})

describe('SqliteMapStore', () => {
  let store: SqliteMapStore
  beforeEach(() => {
    store = new SqliteMapStore(':memory:')
  })

  it('round-trips a record, including local-only metadata', async () => {
    await store.putMap(
      rec('fpA', { '<EMAIL_001>': 'alice@example.com' }, { metadata: { filename: 'invoice.pdf', exportedAt: 123 } }),
    )
    const all = await store.allMaps()
    expect(all).toHaveLength(1)
    expect(all[0].map['<EMAIL_001>']).toBe('alice@example.com')
    expect(all[0].placeholders).toEqual(['<EMAIL_001>'])
    expect(all[0].metadata).toEqual({ filename: 'invoice.pdf', exportedAt: 123 })
  })

  it('is idempotent on id for an identical re-redact (no duplicate)', async () => {
    const r = rec('fpA', { '<EMAIL_001>': 'alice@example.com' })
    await store.putMap(r)
    await store.putMap(r)
    expect(await store.allMaps()).toHaveLength(1)
  })

  it('keeps BOTH records when the same redacted body maps to different originals (collision)', async () => {
    await store.putMap(rec('fpA', { '<EMAIL_001>': 'alice@example.com' }))
    await store.putMap(rec('fpA', { '<EMAIL_001>': 'bob@example.com' }))
    const all = await store.allMaps()
    expect(all).toHaveLength(2)
    // second stored under a collision-suffixed id, not clobbering the first
    expect(all.map((r) => r.map['<EMAIL_001>']).sort()).toEqual(['alice@example.com', 'bob@example.com'])
  })

  it('matches an exact fingerprint and resolves the original', async () => {
    await store.putMap(rec('fpA', { '<EMAIL_001>': 'alice@example.com' }))
    const hit = await store.matchByFingerprint('fpA', ['<EMAIL_001>'])
    expect(hit?.map['<EMAIL_001>']).toBe('alice@example.com')
  })

  it('refuses to match when a present placeholder is unresolvable (wrong-map guard)', async () => {
    await store.putMap(rec('fpA', { '<EMAIL_001>': 'alice@example.com' }))
    const hit = await store.matchByFingerprint('fpA', ['<EMAIL_001>', '<PHONE_001>'])
    expect(hit).toBeNull()
  })

  it('refuses an ambiguous match (same fp, two different value sets)', async () => {
    await store.putMap(rec('fpA', { '<EMAIL_001>': 'alice@example.com' }))
    await store.putMap(rec('fpA', { '<EMAIL_001>': 'bob@example.com' }))
    const hit = await store.matchByFingerprint('fpA', ['<EMAIL_001>'])
    expect(hit).toBeNull()
  })

  it('matches via a secondary per-file fingerprint (batch records)', async () => {
    await store.putMap(
      rec('fpMain', { '<EMAIL_001>': 'alice@example.com' }, {
        fingerprints: [{ fpExact: 'fpChild', placeholders: ['<EMAIL_001>'] }],
      }),
    )
    const hit = await store.matchByFingerprint('fpChild', ['<EMAIL_001>'])
    expect(hit?.map['<EMAIL_001>']).toBe('alice@example.com')
  })

  it('clearMaps empties the store', async () => {
    await store.putMap(rec('fpA', { '<EMAIL_001>': 'alice@example.com' }))
    await store.clearMaps()
    expect(await store.allMaps()).toHaveLength(0)
  })

  it('creates the on-disk DB and its WAL/SHM sidecars owner-only (0600)', async () => {
    if (process.platform === 'win32') return // POSIX mode bits not meaningful on Windows
    const { mkdtempSync, statSync, existsSync, rmSync } = await import('node:fs')
    const { tmpdir } = await import('node:os')
    const { join } = await import('node:path')
    const dir = mkdtempSync(join(tmpdir(), 'ossr-mapstore-'))
    const dbPath = join(dir, 'maps.db')
    const onDisk = new SqliteMapStore(dbPath)
    try {
      await onDisk.putMap(rec('fpA', { '<EMAIL_001>': 'alice@example.com' }))
      await onDisk.allMaps() // force a read so the WAL/SHM sidecars are materialized
      const mode = (p: string) => statSync(p).mode & 0o777
      expect(mode(dbPath)).toBe(0o600) // the plaintext-PII DB is never world-readable
      for (const suffix of ['-wal', '-shm']) {
        if (existsSync(dbPath + suffix)) expect(mode(dbPath + suffix)).toBe(0o600)
      }
    } finally {
      onDisk.close()
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
