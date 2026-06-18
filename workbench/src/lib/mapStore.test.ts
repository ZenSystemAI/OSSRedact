// Tests for the on-device entity-map store (mapStore.ts) on the plan-011 vitest+jsdom harness.
// jsdom lacks IndexedDB, so we import fake-indexeddb/auto to provide a real, spec-conformant store.
// ALL inputs are 100% synthetic (e.g. <EMAIL_001> -> alice@example.com), mirroring redaction.test.ts.

import 'fake-indexeddb/auto'
import { describe, it, expect, beforeEach } from 'vitest'
import {
  sha256Hex,
  putMap,
  allMaps,
  clearMaps,
  matchByFingerprint,
  getRemember,
  setRemember,
  type MapRecord,
} from './mapStore'
// Assert survivor restoration via the pure string-level `rehydrate` (the in-session twin of the file
// round-trip -- redaction.ts). The File-level `rehydrateFile` is covered by office-redaction.test.ts;
// the jsdom File polyfill lacks `.text()`, so we exercise the restoration on the string body the matcher
// already operates on. Same substitution semantics (split/join every occurrence of every map key).
import { rehydrate } from './redaction'
import type { EntityMap } from './types'

// Synthetic redacted bodies + their maps. The fingerprint is over the REDACTED (placeholder-bearing)
// body, never the original -- this mirrors what App.tsx stores on redact.
const REDACTED_BODY = 'Contact <EMAIL_001> or <EMAIL_002> for info.'
const MAP: EntityMap = {
  '<EMAIL_001>': 'alice@example.com',
  '<EMAIL_002>': 'bob@example.com',
}

async function makeRecord(body: string, map: EntityMap): Promise<MapRecord> {
  const fpExact = await sha256Hex(body)
  const placeholders = [...new Set(body.match(/<[A-Z][A-Z0-9_]*_\d{3,}>/g) ?? [])].sort()
  return {
    id: fpExact,
    createdAt: Date.now(),
    neutralLabel: 'redaction from 2026-06-16',
    fpExact,
    placeholders,
    map,
    fingerprints: [{ fpExact, placeholders }],
  }
}

beforeEach(async () => {
  await clearMaps()
})

describe('sha256Hex', () => {
  it('hashes the REDACTED body deterministically (hex)', async () => {
    const a = await sha256Hex(REDACTED_BODY)
    const b = await sha256Hex(REDACTED_BODY)
    expect(a).toBe(b)
    expect(a).toMatch(/^[0-9a-f]{64}$/)
    // a different body -> a different hash (own-copy fingerprint discriminates docs)
    expect(await sha256Hex(REDACTED_BODY + ' x')).not.toBe(a)
  })
})

describe('matchByFingerprint -- own-copy exact match', () => {
  it('exact fpExact hit returns the stored record and rehydrateFile fully restores', async () => {
    const rec = await makeRecord(REDACTED_BODY, MAP)
    await putMap(rec)

    const fp = await sha256Hex(REDACTED_BODY)
    const present = ['<EMAIL_001>', '<EMAIL_002>']
    const hit = await matchByFingerprint(fp, present)
    expect(hit).not.toBeNull()
    expect(hit!.fpExact).toBe(fp)

    // one-click restore from the matched device map (string-level twin of the file round-trip)
    const out = rehydrate(REDACTED_BODY, hit!.map)
    expect(out).toBe('Contact alice@example.com or bob@example.com for info.')
    // every survivor was resolvable in the matched map -> no leftover placeholders
    expect(out.match(/<[A-Z][A-Z0-9_]*_\d{3,}>/g)).toBeNull()
  })
})

describe('matchByFingerprint -- edited or unrelated files', () => {
  it('does not placeholder-subset match an edited body with a changed fingerprint', async () => {
    const rec = await makeRecord(REDACTED_BODY, MAP)
    await putMap(rec)

    // The colleague edited the body: <EMAIL_002> was deleted, new prose added. The full-body hash no
    // longer matches. Placeholder-only matching is unsafe because tokens are per-redaction, not global.
    const editedBody = 'Hi, please reach <EMAIL_001>. Bob already left the team -- thanks!'
    const present = [...new Set(editedBody.match(/<[A-Z][A-Z0-9_]*_\d{3,}>/g) ?? [])].sort()
    const editedFp = await sha256Hex(editedBody)
    expect(editedFp).not.toBe(rec.fpExact) // edits broke the exact hash

    expect(await matchByFingerprint(editedFp, present)).toBeNull()
  })

  it('does not restore an unrelated one-placeholder document from the only local map', async () => {
    await putMap(await makeRecord('Local <EMAIL_001>', { '<EMAIL_001>': 'alice@example.com' }))

    // Another redacted file from another device/project can legitimately contain the same token. With only
    // one local record, the old placeholder-subset fallback would have restored Alice into this unrelated doc.
    const unrelated = 'Vendor contact <EMAIL_001>'
    expect(await matchByFingerprint(await sha256Hex(unrelated), ['<EMAIL_001>'])).toBeNull()
  })

  it('exact-matches a secondary fingerprint from a batch shared-map record', async () => {
    const fileA = 'A <EMAIL_001>'
    const fileB = 'B <EMAIL_002>'
    const rec = await makeRecord(fileA, MAP)
    const fpB = await sha256Hex(fileB)
    rec.fingerprints = [
      { fpExact: rec.fpExact, placeholders: ['<EMAIL_001>'] },
      { fpExact: fpB, placeholders: ['<EMAIL_002>'] },
    ]
    await putMap(rec)

    const hit = await matchByFingerprint(fpB, ['<EMAIL_002>'])
    expect(hit).not.toBeNull()
    expect(rehydrate(fileB, hit!.map)).toBe('B bob@example.com')
  })

  it('does NOT match when a survivor is unresolvable in any stored map (cross-map collision guard)', async () => {
    const rec = await makeRecord(REDACTED_BODY, MAP)
    await putMap(rec)
    // A returned file bearing a placeholder the stored map cannot resolve -> no match -> manual fallback.
    const hit = await matchByFingerprint('deadbeef', ['<EMAIL_001>', '<PHONE_001>'])
    expect(hit).toBeNull()
  })

  it('refuses ambiguous auto-match when the same placeholder token maps to different originals', async () => {
    const redacted = 'Contact <EMAIL_001>.'
    const recA = await makeRecord(redacted, { '<EMAIL_001>': 'alice@example.com' })
    const recB = await makeRecord(redacted, { '<EMAIL_001>': 'bob@example.com' })
    await putMap(recA)
    await putMap(recB)

    expect(await allMaps()).toHaveLength(2)
    const present = ['<EMAIL_001>']
    expect(await matchByFingerprint(await sha256Hex(redacted), present)).toBeNull()
    expect(await matchByFingerprint('edited-body-fingerprint', present)).toBeNull()
  })
})

describe('matchByFingerprint -- no stored match (fallback path)', () => {
  it('returns null when the store is empty', async () => {
    expect(await matchByFingerprint('whatever', ['<EMAIL_001>'])).toBeNull()
  })

  it('returns null when no placeholders survive and the hash does not match', async () => {
    await putMap(await makeRecord(REDACTED_BODY, MAP))
    expect(await matchByFingerprint('nomatch', [])).toBeNull()
  })
})

describe('putMap idempotency', () => {
  it('re-putting the same fpExact (StrictMode double-invoke) does not duplicate the record', async () => {
    const rec = await makeRecord(REDACTED_BODY, MAP)
    await putMap(rec)
    await putMap(rec)
    const all = await allMaps()
    expect(all).toHaveLength(1)
  })
})

describe('clearMaps', () => {
  it('empties the store', async () => {
    await putMap(await makeRecord(REDACTED_BODY, MAP))
    expect(await allMaps()).toHaveLength(1)
    await clearMaps()
    expect(await allMaps()).toHaveLength(0)
  })
})

describe('opt-in preference (getRemember / setRemember)', () => {
  it('defaults ON and round-trips OFF/ON; OFF means callers must not write', async () => {
    expect(getRemember()).toBe(true) // default ON for usability
    setRemember(false)
    expect(getRemember()).toBe(false)
    // simulate the App.tsx write gate: when OFF, nothing is persisted
    if (getRemember()) await putMap(await makeRecord(REDACTED_BODY, MAP))
    expect(await allMaps()).toHaveLength(0)
    setRemember(true)
    expect(getRemember()).toBe(true)
    if (getRemember()) await putMap(await makeRecord(REDACTED_BODY, MAP))
    expect(await allMaps()).toHaveLength(1)
  })
})
