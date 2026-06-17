// @ossredact/core -- public API barrel
// Tier-0 deterministic detector + span/redaction primitives.
// No runtime dependencies. Browser-safe (no Node APIs).

// Types
export type { RawSpan, Span, EntityMap, RegionBox } from './types.js'

// Tier-0 detector + validators
export {
  tier0Spans,
  contextCuedIdSpans,
  luhnOk,
  ibanOk,
  normDash,
  normSpace,
  normCase,
} from './tier0.js'

// Redaction primitives + span management
export type { LabelActivity, PlaceholderIndex } from './redaction.js'
export {
  mergeSpans,
  toSpans,
  labelActivity,
  setLabelActive,
  setLabelsActive,
  insertSpan,
  combineWithManual,
  newPlaceholderIndex,
  buildEntityMap,
  redactedText,
  rehydrate,
  explain,
  newId,
} from './redaction.js'

// Label metadata + tier classification
export type { LabelMeta, Tier } from './labels.js'
export { labelMeta, labelTier, MANUAL_LABELS } from './labels.js'
