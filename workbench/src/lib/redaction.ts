// Re-export from the canonical single source: @ossredact/core
// The source of truth lives in packages/redaction-core/src/redaction.ts
export type { LabelActivity, PlaceholderIndex } from '@ossredact/core'
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
} from '@ossredact/core'
