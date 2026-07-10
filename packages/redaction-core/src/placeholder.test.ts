import { describe, expect, it } from 'vitest'
import {
  PLACEHOLDER_CONTRACT_PATTERN,
  PLACEHOLDER_CONTRACT_RE,
  buildEntityMap,
} from './index'
import type { Span } from './types'

function span(start: number, end: number, label: string): Span {
  return { start, end, label, tier: 0, conf: 1, rule: 'test', id: `s_${start}_${end}`, source: 'auto', active: true }
}

describe('placeholder contract', () => {
  it('matches the canonical Python regex pattern', () => {
    expect(PLACEHOLDER_CONTRACT_PATTERN).toBe('^<([A-Z0-9_]+)_\\d{3,}>$')
  })

  it('freshly minted placeholders match the shared contract', () => {
    const text = 'Contact user@example.com.'
    const { map } = buildEntityMap(text, [span(8, 24, 'email')])
    const ph = Object.keys(map)[0]
    expect(ph).toBe('<EMAIL_001>')
    expect(PLACEHOLDER_CONTRACT_RE.test(ph)).toBe(true)
  })

  it('recognizes fixed literals minted by the Python side and rejects drift forms', () => {
    for (const ph of ['<EMAIL_001>', '<SENSITIVEACCOUNTID_123>', '<SENSITIVE_ACCOUNT_ID_123>', '<A1_1000>']) {
      expect(PLACEHOLDER_CONTRACT_RE.test(ph), ph).toBe(true)
    }
    for (const ph of ['<EMAIL_01>', '<email_001>', '<PERSON_1>', '<PERSON_ABC>', '<PERSON-001>']) {
      expect(PLACEHOLDER_CONTRACT_RE.test(ph), ph).toBe(false)
    }
  })
})

