// Pure deep-scan session contract for the workbench.
// Status matrix + generation helpers only -- no React, no network, no document IO.
// A cancelled or stale deep run must never be labeled clean; partial gates export without
// claiming model degradation.

export type DeepScanStatus = 'none' | 'clean' | 'degraded' | 'partial'

/** Export confirmation is required only after a requested deep scan that did not fully succeed. */
export function requiresDeepScanExportConfirmation(status: DeepScanStatus): boolean {
  return status === 'degraded' || status === 'partial'
}

/**
 * Derive the batch deep-scan result from counters.
 * - aborted (even after some success/fallback) -> partial
 * - completed every entry with any fallback -> degraded
 * - completed every entry with zero fallbacks -> clean
 * - incomplete without abort is not a terminal path used by App; treat as partial for safety
 */
export function deriveBatchDeepScanStatus(input: {
  completed: number
  total: number
  degraded: number
  aborted: boolean
}): DeepScanStatus {
  const { completed, total, degraded, aborted } = input
  if (aborted || completed < total) return 'partial'
  if (degraded > 0) return 'degraded'
  return 'clean'
}

/** Monotonic generation counter: each new document session advances past any in-flight run. */
export function bumpDeepScanGeneration(current: number): number {
  return current + 1
}

/** True only when the handler's captured generation is still the active session generation. */
export function isCurrentDeepScanGeneration(held: number, active: number): boolean {
  return held === active
}
