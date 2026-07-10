import { describe, expect, it } from 'vitest'
import {
  type DeepScanStatus,
  bumpDeepScanGeneration,
  deriveBatchDeepScanStatus,
  isCurrentDeepScanGeneration,
  requiresDeepScanExportConfirmation,
} from './deepScanState'

// Pure session/export contract for deep detection. UI and App.tsx remain out of scope here;
// these cases lock the status matrix so a cancelled or stale deep run can never be labeled clean.

describe('DeepScanStatus contract', () => {
  it('uses exactly none | clean | degraded | partial', () => {
    const statuses: DeepScanStatus[] = ['none', 'clean', 'degraded', 'partial']
    expect(statuses).toEqual(['none', 'clean', 'degraded', 'partial'])
  })

  it('starts ungated as none (initial session state)', () => {
    const initial: DeepScanStatus = 'none'
    expect(requiresDeepScanExportConfirmation(initial)).toBe(false)
  })
})

describe('requiresDeepScanExportConfirmation', () => {
  it('never gates none or clean', () => {
    expect(requiresDeepScanExportConfirmation('none')).toBe(false)
    expect(requiresDeepScanExportConfirmation('clean')).toBe(false)
  })

  it('gates degraded (model fallback after a requested deep scan)', () => {
    expect(requiresDeepScanExportConfirmation('degraded')).toBe(true)
  })

  it('gates partial (batch aborted before every entry finished)', () => {
    expect(requiresDeepScanExportConfirmation('partial')).toBe(true)
  })
})

describe('deriveBatchDeepScanStatus', () => {
  it('returns clean only when every entry completed with zero fallbacks', () => {
    expect(
      deriveBatchDeepScanStatus({
        completed: 3,
        total: 3,
        degraded: 0,
        aborted: false,
      }),
    ).toBe('clean')
  })

  it('returns degraded when the run completed with one fallback', () => {
    expect(
      deriveBatchDeepScanStatus({
        completed: 3,
        total: 3,
        degraded: 1,
        aborted: false,
      }),
    ).toBe('degraded')
  })

  it('returns degraded when the run completed with all entries falling back', () => {
    expect(
      deriveBatchDeepScanStatus({
        completed: 2,
        total: 2,
        degraded: 2,
        aborted: false,
      }),
    ).toBe('degraded')
  })

  it('returns partial when aborted before the first entry finishes', () => {
    expect(
      deriveBatchDeepScanStatus({
        completed: 0,
        total: 4,
        degraded: 0,
        aborted: true,
      }),
    ).toBe('partial')
  })

  it('returns partial when aborted after one entry finishes', () => {
    expect(
      deriveBatchDeepScanStatus({
        completed: 1,
        total: 4,
        degraded: 0,
        aborted: true,
      }),
    ).toBe('partial')
  })

  it('returns partial on abort even if the finished entries already fell back', () => {
    expect(
      deriveBatchDeepScanStatus({
        completed: 1,
        total: 3,
        degraded: 1,
        aborted: true,
      }),
    ).toBe('partial')
  })
})

describe('deep scan generation guard', () => {
  it('marks a prior generation stale after a newer generation begins', () => {
    const first = 0
    const second = bumpDeepScanGeneration(first)
    const third = bumpDeepScanGeneration(second)

    expect(second).toBeGreaterThan(first)
    expect(third).toBeGreaterThan(second)

    // A handler holding `first` must ignore results once the active generation advanced.
    expect(isCurrentDeepScanGeneration(first, second)).toBe(false)
    expect(isCurrentDeepScanGeneration(first, third)).toBe(false)
    expect(isCurrentDeepScanGeneration(second, third)).toBe(false)

    // Only the live generation is considered current.
    expect(isCurrentDeepScanGeneration(second, second)).toBe(true)
    expect(isCurrentDeepScanGeneration(third, third)).toBe(true)
  })
})
