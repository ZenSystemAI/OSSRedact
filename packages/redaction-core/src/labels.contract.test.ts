import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { LABEL_REGISTRY, labelTier } from './labels'

type LabelsV20 = {
  labels: string[]
}

const LABELS_PATH = new URL('../../../training/labels_v20.json', import.meta.url)
const shippedLabels = new Set((JSON.parse(readFileSync(LABELS_PATH, 'utf8')) as LabelsV20).labels)

// UI-only or backward-compatible labels that intentionally do not appear in training/labels_v20.json.
// 'uuid' + 'sensitive_ref' (2026-07-02 fat-floor diet) are pipeline-minted labels, not model labels:
// 'uuid' is the deterministic UUID-shape mint demoted from the floor, 'sensitive_ref' is the demoted
// form of a MODEL-claimed account/gov identity span (see labels.ts registry comment).
const DOCUMENTED_ALIASES = new Set(['name', 'sensitive_date', 'manual', 'uuid', 'sensitive_ref'])

const CATASTROPHIC_SHIPPED_LABELS = new Set([
  'account_number',
  'card_cvv',
  'card_expiry',
  'date_of_birth',
  'email',
  'government_id',
  'iban',
  'password',
  'payment_card',
  'person',
  'secret',
  'sensitive_account_id',
  'tax_id',
])

describe('label registry contract', () => {
  it('covers every shipped model label', () => {
    const registryLabels = new Set(Object.keys(LABEL_REGISTRY))
    const missing = [...shippedLabels].filter((label) => !registryLabels.has(label)).sort()
    expect(missing).toEqual([])
  })

  it('contains no undocumented labels outside the shipped set', () => {
    const stray = Object.keys(LABEL_REGISTRY)
      .filter((label) => !shippedLabels.has(label) && !DOCUMENTED_ALIASES.has(label))
      .sort()
    expect(stray).toEqual([])
  })

  it('keeps shipped catastrophic labels in the catastrophic tier', () => {
    const wrongTier = [...CATASTROPHIC_SHIPPED_LABELS]
      .filter((label) => shippedLabels.has(label) && labelTier(label) !== 'catastrophic')
      .sort()
    expect(wrongTier).toEqual([])
  })
})
