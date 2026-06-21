// SHARED deterministic parity vectors -- the TypeScript (@ossredact/core) leg.
//
// Twin of gate/tests/test_gate_parity_vectors.py and appliance/tests/test_appliance_parity_vectors.py: all three
// load the SAME validation/parity_vectors.json and assert the SAME safety-core spans (email, UUID,
// mod-97 IBAN, Luhn card, Luhn SIN + Business-Number suppression + SIN-cue override, and cue-anchored
// mailbox/header person names). The floors are
// TIERED -- the client TS floor is THICK (phone/date/postal/ip/generic-digit-run + Quebec cue IDs),
// like the appliance -- so we assert by PRESENCE (label + value substring), never by exact span-set
// equality. Tiered-only spans (e.g. a generic sensitive_account_id over the IBAN digit tail) are
// expected and do not break safety-core parity. The one ABSENCE we assert is the Business Number
// suppression, which every surface must honour identically. If a future edit drifts the safety core
// on ANY surface, exactly one of these three suites goes red.
//
// We read the JSON from disk with a relative path from THIS test file (not a bundled copy) so the TS
// suite and the two Python suites are provably running the same vectors. All inputs are synthetic;
// Luhn / mod-97 values are standard public test vectors -- no real PII.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { tier0Spans } from './tier0'

interface ExpectSpan {
  label: string
  value: string
  digits_only?: boolean
}
interface ParityCase {
  id: string
  text: string
  expect: ExpectSpan[]
  suppress?: string[]
}

// src/ -> packages/redaction-core/src; the JSON lives at <repo>/validation/parity_vectors.json.
const HERE = dirname(fileURLToPath(import.meta.url))
const VECTORS_PATH = join(HERE, '..', '..', '..', 'validation', 'parity_vectors.json')
const VECTORS: ParityCase[] = JSON.parse(readFileSync(VECTORS_PATH, 'utf-8'))

// (label, substring) pairs as tier0Spans reports them, offsets indexing the original text.
function spansOf(text: string): Array<[string, string]> {
  return tier0Spans(text).map((s) => [s.label, text.slice(s.start, s.end)] as [string, string])
}

// Presence test: some span has this label whose substring contains the expected value. digits_only
// compares on digits only so separator spacing (space / NBSP / hyphen) is immaterial.
function has(spans: Array<[string, string]>, label: string, value: string, digitsOnly = false): boolean {
  if (digitsOnly) {
    const want = value.replace(/\D/g, '')
    return spans.some(([lab, sub]) => lab === label && sub.replace(/\D/g, '').includes(want))
  }
  return spans.some(([lab, sub]) => lab === label && sub.includes(value))
}

describe('safety-core parity vectors (shared with gate + appliance)', () => {
  it.each(VECTORS.map((c) => [c.id, c] as const))('%s', (_id, c) => {
    const spans = spansOf(c.text)
    for (const exp of c.expect) {
      expect(
        has(spans, exp.label, exp.value, exp.digits_only),
        `${c.id}: expected safety-core span ${exp.label}=${exp.value} not found in ${JSON.stringify(spans)}`,
      ).toBe(true)
    }
    for (const lab of c.suppress ?? []) {
      expect(
        spans.some(([l]) => l === lab),
        `${c.id}: label ${lab} must be SUPPRESSED on the TS floor but was emitted: ${JSON.stringify(spans)}`,
      ).toBe(false)
    }
  })
})
