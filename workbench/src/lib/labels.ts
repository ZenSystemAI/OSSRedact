// Re-export from the canonical single source: @ossredact/core
// The source of truth lives in packages/redaction-core/src/labels.ts
export type { LabelMeta, Tier } from '@ossredact/core'
export { labelMeta, labelTier, MANUAL_LABELS } from '@ossredact/core'
