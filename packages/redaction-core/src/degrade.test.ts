import { describe, it, expect } from 'vitest'
import {
  NEURAL_ONLY_LABELS,
  isNeuralOnlyLabel,
  DEEP_DEGRADED_WARNING,
  DEEP_DEGRADED_EXPORT_CONFIRM,
} from './degrade'
import { FLOOR_LABELS } from './labels'

describe('degrade (fail-closed contract)', () => {
  it('flags the free-text PII labels the Tier-0 floor cannot catch', () => {
    for (const l of ['person', 'organization', 'address', 'account_number']) {
      expect(isNeuralOnlyLabel(l)).toBe(true)
    }
  })

  it('does NOT flag structured labels Tier-0 reliably catches (they survive a degraded scan)', () => {
    for (const l of ['email', 'phone_number', 'ip_address', 'payment_card', 'iban', 'government_id', 'secret']) {
      expect(isNeuralOnlyLabel(l)).toBe(false)
    }
  })

  it('warns explicitly about names, organizations, and addresses (the leaked categories)', () => {
    expect(DEEP_DEGRADED_WARNING).toMatch(/names/i)
    expect(DEEP_DEGRADED_WARNING).toMatch(/organizations/i)
    expect(DEEP_DEGRADED_WARNING).toMatch(/addresses/i)
    expect(DEEP_DEGRADED_EXPORT_CONFIRM).toMatch(/anyway\?/i)
  })

  it('account_number is BOTH a floor label AND neural-only: a degraded scan leaks a floor-grade value', () => {
    // This is why a degraded scan must fail closed on export, not just warn: account_number is never
    // allowlist-exemptable (floor) yet Tier-0 alone cannot emit it.
    expect(FLOOR_LABELS.has('account_number')).toBe(true)
    expect(isNeuralOnlyLabel('account_number')).toBe(true)
  })
})
