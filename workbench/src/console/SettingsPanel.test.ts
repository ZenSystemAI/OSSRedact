// Tests for the pure helpers extracted from SettingsPanel.tsx.
//
// NOTE on the filename: the repo's vitest config collects `src/**/*.test.ts` (NOT `.test.tsx`), and every
// existing test is a `.test.ts`. The panel's logic is pure TypeScript (no JSX), so it belongs in a `.test.ts`
// file that the runner actually picks up. A `.test.tsx` here would be silently skipped and never run. Per the
// repo's pure-function test idiom (see redaction.test.ts / formats.test.ts) we import the helpers and assert
// outputs only -- no React rendering, no network, no real timers. All inputs are synthetic (no real data).

import { describe, it, expect } from 'vitest'
import { formatStatus, bufferPct, ALWAYS_PROTECTED, MODE_OPTIONS, modeOption, type StatusRow } from './SettingsPanel'
import type { LiveStatus, AllowlistState } from '../lib/daemon'

// ---- builders ------------------------------------------------------------------------------------------
function liveStatus(over: Partial<LiveStatus> = {}): LiveStatus {
  return { enabled: true, buffered: 12, max: 500, subscribers: 3, ...over }
}
function allowlist(over: Partial<AllowlistState> = {}): AllowlistState {
  // Phase 4: control API no longer discloses host filesystem paths. Fixture matches the path-free shape.
  // Cast keeps the suite compiling until production AllowlistState drops the required path field.
  return { values: ['Acme', 'PostgreSQL'], active_total: 2, config_values: 1, ...over } as AllowlistState
}
function rowMap(rows: StatusRow[]): Record<string, string> {
  return Object.fromEntries(rows.map((r) => [r.label, r.value]))
}

// ---- formatStatus --------------------------------------------------------------------------------------
describe('formatStatus', () => {
  it('returns the five status rows in a stable order', () => {
    const rows = formatStatus(liveStatus(), allowlist())
    expect(rows.map((r) => r.label)).toEqual([
      'Live activity',
      'Buffered events',
      'Subscribers',
      'Dictionary entries',
      'From config',
    ])
  })

  it('formats enabled/disabled, buffered/max, and the numeric counts', () => {
    const m = rowMap(formatStatus(liveStatus({ enabled: true, buffered: 12, max: 500, subscribers: 3 }), allowlist({ active_total: 2, config_values: 1 })))
    expect(m['Live activity']).toBe('Enabled')
    expect(m['Buffered events']).toBe('12 / 500')
    expect(m['Subscribers']).toBe('3')
    expect(m['Dictionary entries']).toBe('2')
    expect(m['From config']).toBe('1')
  })

  it('renders "Disabled" when live view is off', () => {
    const m = rowMap(formatStatus(liveStatus({ enabled: false }), allowlist()))
    expect(m['Live activity']).toBe('Disabled')
  })

  it('renders zero counts as the string "0" (not blank, not a falsy gap)', () => {
    const m = rowMap(formatStatus(
      liveStatus({ buffered: 0, max: 0, subscribers: 0 }),
      allowlist({ active_total: 0, config_values: 0 }),
    ))
    expect(m['Buffered events']).toBe('0 / 0')
    expect(m['Subscribers']).toBe('0')
    expect(m['Dictionary entries']).toBe('0')
    expect(m['From config']).toBe('0')
  })

  it('every value is a string (safe to drop straight into JSX)', () => {
    for (const r of formatStatus(liveStatus(), allowlist())) {
      expect(typeof r.value).toBe('string')
    }
  })

  it('renders counts/state without requiring a filesystem path field', () => {
    // Path-free AllowlistState must still produce the dictionary count rows (no path row, no path value).
    const body = { values: ['Acme'], active_total: 4, config_values: 2 } as AllowlistState
    expect('path' in body).toBe(false)
    const rows = formatStatus(liveStatus(), body)
    const m = rowMap(rows)
    expect(m['Dictionary entries']).toBe('4')
    expect(m['From config']).toBe('2')
    // Status rows are counts/state only; labels never expose a filesystem path field.
    expect(rows.map((r) => r.label)).not.toContain('Path')
    expect(rows.map((r) => r.label).some((label) => /filesystem|file path|allowlist\.txt|denylist/i.test(label))).toBe(false)
    expect(Object.values(m).some((v) => v.includes('allowlist') || v.includes('denylist') || v.startsWith('/'))).toBe(false)
  })
})

// ---- bufferPct -----------------------------------------------------------------------------------------
describe('bufferPct', () => {
  it('computes a normal partial fill, rounded to an integer', () => {
    expect(bufferPct(250, 500)).toBe(50)
    expect(bufferPct(1, 3)).toBe(33) // 33.33 -> 33
    expect(bufferPct(2, 3)).toBe(67) // 66.66 -> 67
  })

  it('returns 0 for an empty buffer (zero / zero -> no NaN)', () => {
    expect(bufferPct(0, 0)).toBe(0)
    expect(bufferPct(0, 500)).toBe(0)
  })

  it('returns 100 for a full buffer', () => {
    expect(bufferPct(500, 500)).toBe(100)
  })

  it('caps an over-full buffer at 100 (never exceeds)', () => {
    expect(bufferPct(900, 500)).toBe(100)
    expect(bufferPct(501, 500)).toBe(100)
  })

  it('guards a zero or negative max (avoids divide-by-zero / negative pct)', () => {
    expect(bufferPct(10, 0)).toBe(0)
    expect(bufferPct(10, -5)).toBe(0)
  })

  it('clamps a negative buffered value to 0', () => {
    expect(bufferPct(-5, 500)).toBe(0)
  })

  it('returns 0 for non-finite inputs (NaN / Infinity never leak into the width style)', () => {
    expect(bufferPct(NaN, 500)).toBe(0)
    expect(bufferPct(10, NaN)).toBe(0)
    expect(bufferPct(Infinity, 500)).toBe(0) // non-finite buffered -> guarded to 0 (never NaN width)
    expect(bufferPct(10, Infinity)).toBe(0)
  })
})

// ---- ALWAYS_PROTECTED (the hard guarantee) -------------------------------------------------------------
describe('ALWAYS_PROTECTED', () => {
  it('covers the four undisableable categories from the product guarantee', () => {
    const titles = ALWAYS_PROTECTED.map((c) => c.title.toLowerCase())
    expect(titles.some((t) => t.includes('secret') || t.includes('api key'))).toBe(true)
    expect(titles.some((t) => t.includes('card'))).toBe(true)
    expect(titles.some((t) => t.includes('iban') || t.includes('bank'))).toBe(true)
    expect(titles.some((t) => t.includes('government') || t.includes('id'))).toBe(true)
  })

  it('every entry has a non-empty title and detail', () => {
    expect(ALWAYS_PROTECTED.length).toBeGreaterThanOrEqual(4)
    for (const c of ALWAYS_PROTECTED) {
      expect(c.title.trim().length).toBeGreaterThan(0)
      expect(c.detail.trim().length).toBeGreaterThan(0)
    }
  })
})

// ---- MODE_OPTIONS / modeOption (the redaction-mode switch) ---------------------------------------------
describe('MODE_OPTIONS', () => {
  it('offers exactly privacy / coding / off in that order', () => {
    expect(MODE_OPTIONS.map((m) => m.id)).toEqual(['privacy', 'coding', 'off'])
  })

  it('marks only Off as the loosening (warn) mode', () => {
    expect(MODE_OPTIONS.filter((m) => m.warn).map((m) => m.id)).toEqual(['off'])
  })

  it('every option has a non-empty title and detail', () => {
    for (const m of MODE_OPTIONS) {
      expect(m.title.trim().length).toBeGreaterThan(0)
      expect(m.detail.trim().length).toBeGreaterThan(0)
    }
  })
})

describe('modeOption', () => {
  it('resolves each known mode id to its option', () => {
    expect(modeOption('privacy').id).toBe('privacy')
    expect(modeOption('coding').id).toBe('coding')
    expect(modeOption('off').id).toBe('off')
  })

  it('falls back to the privacy option for an unknown mode (fail safe)', () => {
    expect(modeOption('banana').id).toBe('privacy')
    expect(modeOption('').id).toBe('privacy')
  })
})
