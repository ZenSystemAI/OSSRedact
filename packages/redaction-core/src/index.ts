// @ossredact/core -- public API barrel
// Tier-0 deterministic detector + span/redaction primitives.
// No runtime dependencies. Browser-safe (no Node APIs).

// Types
export type { RawSpan, Span, EntityMap, RegionBox } from './types.js'

// Tier-0 detector + validators
export {
  tier0Spans,
  contextCuedIdSpans,
  cueNameSpans,
  gluedDigitSpans,
  separatedCardSpans,
  cardAuxSpans,
  luhnOk,
  ibanOk,
  nameShaped,
  normDash,
  normSpace,
  normCase,
  hasFormatChars,
  stripFormatChars,
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
  resolveRenderSpans,
  newPlaceholderIndex,
  buildEntityMap,
  redactedText,
  sweepKnownValues,
  rehydrate,
  explain,
  newId,
} from './redaction.js'

// Shared placeholder contract
export { PLACEHOLDER_CONTRACT_PATTERN, PLACEHOLDER_CONTRACT_RE } from './placeholder.js'

// Allowlist (do-not-redact dictionary) -- user-declared known-safe values, value-exact + case-insensitive.
export { normalizeAllowValue, buildAllowSet, isAllowlisted, applyAllowlist } from './allowlist.js'

// Label metadata + tier classification
export type { LabelMeta, Tier } from './labels.js'
export { LABEL_REGISTRY, labelMeta, labelTier, MANUAL_LABELS, FLOOR_LABELS } from './labels.js'

// Fail-closed contract for a degraded (Tier-0-only) in-browser deep scan -- shared by every browser surface.
export {
  NEURAL_ONLY_LABELS,
  isNeuralOnlyLabel,
  DEEP_DEGRADED_WARNING,
  DEEP_DEGRADED_BADGE,
  DEEP_DEGRADED_EXPORT_CONFIRM,
} from './degrade.js'
