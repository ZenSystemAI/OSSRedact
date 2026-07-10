// Re-export from the canonical single source: @ossredact/core
// The source of truth lives in packages/redaction-core/src/degrade.ts -- the SAME fail-closed contract
// the public web demo imports, so the two browser surfaces can never drift on what a degraded scan leaks.
export {
  NEURAL_ONLY_LABELS,
  isNeuralOnlyLabel,
  DEEP_DEGRADED_WARNING,
  DEEP_DEGRADED_BADGE,
  DEEP_DEGRADED_EXPORT_CONFIRM,
} from '@ossredact/core'
