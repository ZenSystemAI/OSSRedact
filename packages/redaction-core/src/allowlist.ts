// @ossredact/core -- allowlist (the "do-not-redact" dictionary)
//
// A user-declared set of KNOWN-SAFE exact values that must NEVER be redacted, even when a detector
// flags them. This is the INVERSE of detection: the user opts specific values OUT of redaction so the
// gate stops interfering with their own workflow -- their name inside file paths, their own email,
// internal project codenames. It is OPT-IN and the default set is empty (fail toward redaction).
//
// VALUE-EXACT, never substring: a span is dropped only when its WHOLE text equals a declared value, so
// allowlisting "alex" can never accidentally un-redact a larger sensitive string that merely contains
// it (e.g. "alex@acme-bank.example" stays redacted unless that full address is itself allowlisted).
//
// Matching is Unicode-NFC + whitespace-trimmed + case-insensitive so a value declared once ("alex")
// passes through in every casing it appears -- prose "Alex", path "/home/alex", shout "ALEX". This
// also dissolves the case-mangle the known-value sweep would otherwise inflict on coding-agent paths: an
// allowlisted name is never redacted, so it is never minted into the entity map, never swept, never
// rehydrated to a different case.
//
// SECURITY CONTRACT: allowlisted values DO reach the cloud verbatim -- that is the explicit point. Only
// add values you are comfortable the model seeing. Credentials/secrets are NOT exempt from redaction by
// this list at the gate (the gate keeps the secret floor non-negotiable); the allowlist is for the
// user's own non-secret identifiers.
//
// This module is the SINGLE source of the filter logic; the Python gate (appliance/allowlist.py) mirrors
// it 1:1 for detector-twin parity (D1).

import { FLOOR_LABELS } from './labels.js'

export function normalizeAllowValue(v: string): string {
  return v.normalize('NFC').trim().toLowerCase()
}

export function buildAllowSet(values: Iterable<string>): Set<string> {
  const out = new Set<string>()
  for (const v of values) {
    const n = normalizeAllowValue(v)
    if (n) out.add(n)
  }
  return out
}

export function isAllowlisted(value: string, allow: Set<string>): boolean {
  return allow.size > 0 && allow.has(normalizeAllowValue(value))
}

// Drop every span whose exact (normalized) text is in the allowlist. Generic over any span carrying
// {start,end} (and an optional label) so it composes with RawSpan/Span here and the gate's span dicts alike.
//
// FLOOR GUARD: a hard-floor span (credential / payment card / bank / IBAN / government / tax ID / DOB) is
// NEVER exempt, even when its exact text is allowlisted. The guard is baked INTO the shared filter -- not
// left to the caller -- so a future consumer cannot lose the floor by forgetting to check it (mirrors the
// Python gate's FLOOR_NEVER_EXEMPT). Label-less spans are unaffected (no label -> not a floor span).
export function applyAllowlist<T extends { start: number; end: number; label?: string }>(
  spans: T[],
  text: string,
  allow: Set<string>,
): T[] {
  if (!allow.size) return spans
  return spans.filter(
    (s) =>
      (s.label !== undefined && FLOOR_LABELS.has(s.label)) ||
      !allow.has(normalizeAllowValue(text.slice(s.start, s.end))),
  )
}
