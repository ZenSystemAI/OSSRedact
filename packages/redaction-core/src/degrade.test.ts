import { describe, it, expect } from 'vitest'
import {
  NEURAL_ONLY_LABELS,
  isNeuralOnlyLabel,
  DEEP_DEGRADED_WARNING,
  DEEP_DEGRADED_EXPORT_CONFIRM,
} from './degrade'
import { FLOOR_LABELS } from './labels'
import { tier0Spans } from './tier0'

describe('degrade (fail-closed contract)', () => {
  it('flags free-text PII labels the Tier-0 floor cannot catch as neural-only', () => {
    // person is partially cue-backed (mailbox/header/e-transfer), but uncued free-text names remain
    // neural-owned; organization and address have no deterministic floor.
    for (const l of ['person', 'organization', 'address']) {
      expect(isNeuralOnlyLabel(l)).toBe(true)
    }
    expect(NEURAL_ONLY_LABELS.has('person')).toBe(true)
    expect(NEURAL_ONLY_LABELS.has('organization')).toBe(true)
    expect(NEURAL_ONLY_LABELS.has('address')).toBe(true)
  })

  it('does NOT treat cue-backed account_number as neural-only', () => {
    // Phase-1: cueDigitSpans / tier0:cue_digit already emit account_number under financial cues.
    // Uncued free-text accounts can still need the neural tier, but the label itself is not neural-only.
    expect(isNeuralOnlyLabel('account_number')).toBe(false)
    expect(NEURAL_ONLY_LABELS.has('account_number')).toBe(false)
  })

  it('does NOT flag structured labels Tier-0 reliably catches (they survive a degraded scan)', () => {
    for (const l of ['email', 'phone_number', 'ip_address', 'payment_card', 'iban', 'government_id', 'secret', 'account_number']) {
      expect(isNeuralOnlyLabel(l)).toBe(false)
    }
  })

  it('warns explicitly about names, organizations, and addresses (the leaked categories)', () => {
    expect(DEEP_DEGRADED_WARNING).toMatch(/names/i)
    expect(DEEP_DEGRADED_WARNING).toMatch(/organizations/i)
    expect(DEEP_DEGRADED_WARNING).toMatch(/addresses/i)
    expect(DEEP_DEGRADED_EXPORT_CONFIRM).toMatch(/anyway\?/i)
    // Keep the user-facing promise narrow: do not claim account numbers are unscanned when degraded.
    expect(DEEP_DEGRADED_WARNING).not.toMatch(/account numbers were NOT scanned/i)
  })

  it('cue-backed account_number is a floor label Tier-0 can emit under an account cue', () => {
    // Positive coverage: degraded Tier-0 still catches cued account numbers (synthetic digits only).
    expect(FLOOR_LABELS.has('account_number')).toBe(true)
    const text = 'No de compte: 006-02761-1234567'
    const hit = tier0Spans(text).find((s) => s.label === 'account_number')
    expect(hit).toBeDefined()
    expect(hit!.rule).toBe('tier0:cue_digit')
    expect(text.slice(hit!.start, hit!.end).replace(/\D/g, '')).toBe('006027611234567')
  })
})
