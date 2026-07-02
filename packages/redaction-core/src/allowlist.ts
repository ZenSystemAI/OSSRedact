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
// POSSESSIVE-TOLERANT (live 2026-07-02): normalization also strips ONE trailing possessive suffix --
// ASCII "'s" or typographic U+2019 "'s" -- so allowlisting "steven" covers the span "Steven's" (and
// "Steven's" with a curly quote) instead of burning a fresh PERSON map entry on a near-identical string.
// Because DECLARED values and SPAN lookups flow through the SAME normalizer, the fold widens both ways:
// declaring "McDonald's" also covers bare "mcdonald" (and vice versa). That widening is deliberate and
// safe under the security contract -- it only ever REDUCES redaction of strings the user already chose to
// expose (base vs possessive of the SAME identifier); it never touches detection, and hard-floor spans
// remain never-exempt regardless of what is declared (guard below is untouched).
//
// SECURITY CONTRACT: allowlisted values DO reach the cloud verbatim -- that is the explicit point. Only
// add values you are comfortable the model seeing. Credentials/secrets are NOT exempt from redaction by
// this list at the gate (the gate keeps the secret floor non-negotiable); the allowlist is for the
// user's own non-secret identifiers.
//
// This module is the SINGLE source of the filter logic; the Python gate (appliance/allowlist.py) mirrors
// it 1:1 for detector-twin parity (D1).

import { FLOOR_LABELS } from './labels.js'
import { DENY_LABEL } from './denylist.js'

// One trailing possessive suffix is folded away AFTER lowercasing: ASCII apostrophe+s and the
// typographic RIGHT SINGLE QUOTATION MARK (U+2019)+s -- the two forms real editors/IMEs emit. NFC does
// not unify U+0027 with U+2019, so both are listed explicitly. ONE strip only (no loop): "alex's's"
// folds to "alex's", never all the way to "alex" -- a double possessive is not a near-identical variant.
//
// DIRECTION (tightened after adversarial review, 2026-07-02): the fold applies to the LOOKUP side only.
// Folding declared values too made allowlisting "Sam's" (a brand) silently exempt every unrelated person
// named "Sam" -- a widening the user never asked for. Now: declaring "steven" covers the spans "steven" AND
// "Steven's" (span-side fold), but declaring "Sam's" covers only "Sam's" (and "Sam's's"), never bare "Sam".
const POSSESSIVE_SUFFIXES = ["'s", '’s'] as const

export function normalizeAllowValue(v: string): string {
  // NFC, then trim, then lowercase -- same order + ops as the Python mirror. NO possessive fold here: this
  // normalizer shapes DECLARED values; the fold is a lookup-side extra (see isAllowlisted).
  return v.normalize('NFC').trim().toLowerCase()
}

function foldPossessive(n: string): string {
  for (const suf of POSSESSIVE_SUFFIXES) {
    if (n.endsWith(suf)) return n.slice(0, -suf.length)
  }
  return n
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
  if (allow.size === 0) return false
  const n = normalizeAllowValue(value)
  return allow.has(n) || allow.has(foldPossessive(n))
}

// Drop every span whose exact (normalized) text is in the allowlist. Generic over any span carrying
// {start,end} (and an optional label) so it composes with RawSpan/Span here and the gate's span dicts alike.
//
// FLOOR GUARD: a hard-floor span (credential / payment card / bank / IBAN / government / tax ID / DOB) is
// NEVER exempt, even when its exact text is allowlisted. The guard is baked INTO the shared filter -- not
// left to the caller -- so a future consumer cannot lose the floor by forgetting to check it (mirrors the
// Python gate's FLOOR_NEVER_EXEMPT). Label-less spans are unaffected (no label -> not a floor span).
// DENYLIST GUARD (defense in depth, 2026-07-02): an always-redact 'custom' span is never allowlist-exempt
// either -- a term the user declared must-redact beats a term they declared safe. The Python gate enforces
// this ordering at the pipeline layer (denylist spans are injected AFTER the allowlist filter); baking it
// into the shared filter too means no future consumer can invert the precedence by calling this helper alone.
export function applyAllowlist<T extends { start: number; end: number; label?: string }>(
  spans: T[],
  text: string,
  allow: Set<string>,
): T[] {
  if (!allow.size) return spans
  return spans.filter(
    (s) =>
      (s.label !== undefined && (FLOOR_LABELS.has(s.label) || s.label === DENY_LABEL)) ||
      !isAllowlisted(text.slice(s.start, s.end), allow),
  )
}
