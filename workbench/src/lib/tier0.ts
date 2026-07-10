// Re-export from the canonical single source: @ossredact/core
// The source of truth lives in packages/redaction-core/src/tier0.ts
// Any detector change must be made there first, then mirrored to gate/privacy_gate.py (finding F14).
export {
  tier0Spans,
  contextCuedIdSpans,
  cueNameSpans,
  luhnOk,
  ibanOk,
  nameShaped,
  normDash,
  normSpace,
  normCase,
} from '@ossredact/core'
