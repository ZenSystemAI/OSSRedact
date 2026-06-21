// Tests for the pure helpers in DictionaryPanel.tsx.
// No React rendering, no network, no real timers -- pure-function assertions,
// matching the repo idiom (see src/lib/redaction.test.ts, formats.test.ts).
//
// All "secret-shaped" inputs below are SYNTHETIC / structurally-valid-only --
// no real credentials.

import { describe, it, expect } from 'vitest'
import {
  normalizeAllowlist,
  looksLikeSecret,
  diffAllowlist,
  normalizationSummary,
  describeSaveError,
} from './DictionaryPanel'
import { DaemonError } from '../lib/daemon'

// =============================================================================
// normalizeAllowlist
// =============================================================================
describe('normalizeAllowlist', () => {
  it('trims surrounding whitespace on each entry', () => {
    const r = normalizeAllowlist(['  Acme Corp  ', '\tPostgreSQL\n'])
    expect(r.values).toEqual(['Acme Corp', 'PostgreSQL'])
    expect(r.dropped).toBe(0)
    expect(r.deduped).toBe(0)
  })

  it('drops blank and whitespace-only entries and counts them', () => {
    const r = normalizeAllowlist(['ProjectFalcon', '', '   ', '\t', 'Redis'])
    expect(r.values).toEqual(['ProjectFalcon', 'Redis'])
    expect(r.dropped).toBe(3)
    expect(r.deduped).toBe(0)
  })

  it('removes case-insensitive duplicates, keeping the FIRST occurrence and its casing', () => {
    const r = normalizeAllowlist(['PostgreSQL', 'postgresql', 'POSTGRESQL'])
    expect(r.values).toEqual(['PostgreSQL'])
    expect(r.deduped).toBe(2)
  })

  it('dedupes only after trimming (whitespace-different but same value collapses)', () => {
    const r = normalizeAllowlist(['Acme', '  acme  '])
    expect(r.values).toEqual(['Acme'])
    expect(r.deduped).toBe(1)
    expect(r.dropped).toBe(0)
  })

  it('preserves order of distinct values', () => {
    const r = normalizeAllowlist(['gamma', 'alpha', 'beta'])
    expect(r.values).toEqual(['gamma', 'alpha', 'beta'])
  })

  it('reports both dropped and deduped together', () => {
    const r = normalizeAllowlist(['Acme', '', 'acme', 'Beta', '  ', 'BETA'])
    expect(r.values).toEqual(['Acme', 'Beta'])
    expect(r.dropped).toBe(2)
    expect(r.deduped).toBe(2)
  })

  it('returns an empty result for an empty input', () => {
    expect(normalizeAllowlist([])).toEqual({ values: [], dropped: 0, deduped: 0 })
  })

  it('keeps internal whitespace inside multi-word nouns', () => {
    const r = normalizeAllowlist(['  Project   Falcon  '])
    expect(r.values).toEqual(['Project   Falcon'])
  })

  it('does not mutate the input array', () => {
    const input = ['  a ', 'a']
    const copy = [...input]
    normalizeAllowlist(input)
    expect(input).toEqual(copy)
  })
})

// =============================================================================
// looksLikeSecret
// =============================================================================
describe('looksLikeSecret', () => {
  it('does NOT flag ordinary project nouns / brand names', () => {
    for (const v of ['Acme Corp', 'ProjectFalcon', 'PostgreSQL', 'Next.js', 'React', 'us-east-1', 'kubernetes']) {
      expect(looksLikeSecret(v), v).toBe(false)
    }
  })

  it('flags OpenAI-style sk- prefixed keys', () => {
    expect(looksLikeSecret('sk-' + 'A'.repeat(20) + '1234567890')).toBe(true)
    expect(looksLikeSecret('sk-abc123def456ghi789')).toBe(true)
  })

  it('flags AWS access-key-id shapes (AKIA / ASIA prefix), case-insensitively', () => {
    expect(looksLikeSecret('AKIAIOSFODNN7EXAMPLE')).toBe(true)
    expect(looksLikeSecret('akiaiosfodnn7example')).toBe(true)
    expect(looksLikeSecret('ASIAEXAMPLE1234567890')).toBe(true)
  })

  it('flags GitHub token prefixes', () => {
    expect(looksLikeSecret('ghp_' + 'x'.repeat(36))).toBe(true)
    expect(looksLikeSecret('github_pat_' + 'y'.repeat(40))).toBe(true)
  })

  it('flags JWT-ish tokens (eyJ prefix)', () => {
    expect(looksLikeSecret('eyJhbGciOiAiSFMyNTYifQ.payload.signature')).toBe(true)
  })

  it('flags 16-digit card-ish runs, with or without grouping', () => {
    expect(looksLikeSecret('4111111111111111')).toBe(true)
    expect(looksLikeSecret('4111 1111 1111 1111')).toBe(true)
    expect(looksLikeSecret('4111-1111-1111-1111')).toBe(true)
    expect(looksLikeSecret('378282246310005')).toBe(true) // 15-digit amex-ish
  })

  it('does NOT flag short digit runs (years, ports, small ids)', () => {
    expect(looksLikeSecret('2026')).toBe(false)
    expect(looksLikeSecret('8080')).toBe(false)
    expect(looksLikeSecret('123456')).toBe(false)
    expect(looksLikeSecret('1234567890123456789012')).toBe(false) // 22 digits, too long for a card
  })

  it('flags IBAN-ish strings, with or without spaces', () => {
    expect(looksLikeSecret('GB82WEST12345698765432')).toBe(true)
    expect(looksLikeSecret('GB82 WEST 1234 5698 7654 32')).toBe(true)
    expect(looksLikeSecret('DE89370400440532013000')).toBe(true)
  })

  it('flags long high-entropy mixed alphanumeric tokens', () => {
    expect(looksLikeSecret('aZ4kQ9xR2mB7nT1pL5wY8cV3dF6gH0jK')).toBe(true)
    expect(looksLikeSecret('xK7p_Qm2.Rt9-Bn4Lw8Yc3Vd6Fg0Hj')).toBe(true)
  })

  it('does NOT flag long but low-entropy / spaced human text', () => {
    expect(looksLikeSecret('the quick brown fox jumps over')).toBe(false)
    expect(looksLikeSecret('aaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe(false) // long but zero entropy
    expect(looksLikeSecret('My Long Company Name Incorporated')).toBe(false)
  })

  it('does NOT flag a long all-letter slug with no digits', () => {
    // No digits -> not the random-token shape we warn on.
    expect(looksLikeSecret('verylongsinglewordcompanyname')).toBe(false)
  })

  it('returns false for empty / whitespace input', () => {
    expect(looksLikeSecret('')).toBe(false)
    expect(looksLikeSecret('   ')).toBe(false)
  })

  it('trims before evaluating', () => {
    expect(looksLikeSecret('  sk-abc123def456ghi789  ')).toBe(true)
  })
})

// =============================================================================
// diffAllowlist
// =============================================================================
describe('diffAllowlist', () => {
  it('is clean when baseline and draft are identical', () => {
    const d = diffAllowlist(['a', 'b'], ['a', 'b'])
    expect(d.dirty).toBe(false)
    expect(d.added).toEqual([])
    expect(d.removed).toEqual([])
  })

  it('is clean when only order differs', () => {
    expect(diffAllowlist(['a', 'b', 'c'], ['c', 'a', 'b']).dirty).toBe(false)
  })

  it('is clean when only casing differs (case-insensitive membership)', () => {
    expect(diffAllowlist(['Acme'], ['acme']).dirty).toBe(false)
  })

  it('is clean when draft only adds blanks/duplicates (normalized away)', () => {
    expect(diffAllowlist(['a', 'b'], ['a', 'b', '', '  ', 'A']).dirty).toBe(false)
  })

  it('detects an addition', () => {
    const d = diffAllowlist(['a'], ['a', 'b'])
    expect(d.dirty).toBe(true)
    expect(d.added).toEqual(['b'])
    expect(d.removed).toEqual([])
  })

  it('detects a removal', () => {
    const d = diffAllowlist(['a', 'b'], ['a'])
    expect(d.dirty).toBe(true)
    expect(d.added).toEqual([])
    expect(d.removed).toEqual(['b'])
  })

  it('detects simultaneous add and remove', () => {
    const d = diffAllowlist(['a', 'b'], ['a', 'c'])
    expect(d.dirty).toBe(true)
    expect(d.added).toEqual(['c'])
    expect(d.removed).toEqual(['b'])
  })

  it('treats clearing everything as dirty', () => {
    const d = diffAllowlist(['a', 'b'], [])
    expect(d.dirty).toBe(true)
    expect(d.removed.sort()).toEqual(['a', 'b'])
  })
})

// =============================================================================
// normalizationSummary
// =============================================================================
describe('normalizationSummary', () => {
  it('returns null when nothing was normalized away', () => {
    expect(normalizationSummary({ values: ['a'], dropped: 0, deduped: 0 })).toBeNull()
  })

  it('singularizes counts of one', () => {
    expect(normalizationSummary({ values: ['a'], dropped: 1, deduped: 1 })).toBe(
      '1 duplicate removed · 1 blank dropped',
    )
  })

  it('pluralizes counts above one', () => {
    expect(normalizationSummary({ values: ['a'], dropped: 3, deduped: 2 })).toBe(
      '2 duplicates removed · 3 blanks dropped',
    )
  })

  it('reports only deduped when no blanks dropped', () => {
    expect(normalizationSummary({ values: ['a'], dropped: 0, deduped: 2 })).toBe('2 duplicates removed')
  })

  it('reports only dropped when no dupes removed', () => {
    expect(normalizationSummary({ values: ['a'], dropped: 1, deduped: 0 })).toBe('1 blank dropped')
  })
})

// =============================================================================
// describeSaveError
// =============================================================================
describe('describeSaveError', () => {
  it('explains 403 as local-only', () => {
    const msg = describeSaveError(new DaemonError('/api/allowlist -> 403', 403))
    expect(msg).toMatch(/local machine/i)
    expect(msg).toContain('403')
  })

  it('explains 500 as a write failure', () => {
    const msg = describeSaveError(new DaemonError('/api/allowlist -> 500', 500))
    expect(msg).toMatch(/could not write/i)
    expect(msg).toContain('500')
  })

  it('explains 404 as an unknown endpoint', () => {
    expect(describeSaveError(new DaemonError('x', 404))).toMatch(/did not recognize/i)
  })

  it('falls back to the status code for other DaemonError statuses', () => {
    expect(describeSaveError(new DaemonError('x', 418))).toMatch(/\(418\)/)
  })

  it('falls back to the message for non-daemon errors', () => {
    expect(describeSaveError(new Error('network down'))).toMatch(/network down/)
  })

  it('handles non-Error thrown values', () => {
    expect(describeSaveError('boom')).toMatch(/boom/)
  })
})
