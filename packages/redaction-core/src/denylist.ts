// @ossredact/core -- denylist (the "always-redact" dictionary)
//
// A user-declared set of exact terms/phrases that must ALWAYS be redacted, even when no detector flags
// them. This is the TWIN/INVERSE of the allowlist: where the allowlist opts known-safe values OUT of
// redaction, the denylist forces user-chosen values IN -- internal codenames, client names, hostnames
// the NER model does not recognize as PII. It is OPT-IN and the default set is empty.
//
// It only ADDS redaction, so it can never weaken the firewall: a bad entry over-redacts (safe), never
// under-redacts.
//
// KEY DIFFERENCE FROM THE ALLOWLIST: the allowlist is a value-exact FILTER on already-detected spans. The
// denylist is a SCANNER over raw field text -- it must FIND occurrences of declared terms, because the
// whole point is that the detector did NOT flag them.
//
// SEMANTICS (identical in Python and TS):
//  - Normalization: Unicode-NFC + whitespace-trim. Matching is CASE-INSENSITIVE.
//  - Token boundaries: a term must NOT match inside a larger word. Lookarounds (?<!\w)(?:ALT)(?!\w) with
//    the 'iu' flags, so "acme" matches standalone "Acme", "acme." and "acme-corp" but NOT "acmecorp".
//  - Multi-word phrases ("Project Falcon") match literally -- every regex metachar in each term is escaped.
//  - MIN_TERM_LEN = 2: terms shorter than 2 chars after normalize are silently ignored (guards against a
//    1-char term redacting the inside of everything).
//  - LONGEST-FIRST: when terms overlap, the longest declared term wins -- the alternation is sorted by
//    term length descending (then alphabetical) before compiling.
//  - Label: every denylist span carries label 'custom'. Span shape
//    {start, end, label: 'custom', score: 1.0, source: 'denylist'}. (Downstream this mints a <CUSTOM_n>
//    placeholder; that wiring is NOT this module's job.)
//  - Empty/whitespace values -> no terms. compile of an empty term list -> null.
//
// This module is the SINGLE source of the scanner logic; the Python gate (appliance/denylist.py) mirrors
// it 1:1 for detector-twin parity (D1).

export const MIN_TERM_LEN = 2
export const DENY_LABEL = 'custom'

// A denylist span. The fixed score/source distinguish user-forced spans from detector output downstream.
export type DenySpan = {
  start: number
  end: number
  label: string
  score: number
  source: string
}

// NFC, then trim -- do NOT lowercase the stored form (matching is case-insensitive at compile time).
export function normalizeTerm(v: string): string {
  return v.normalize('NFC').trim()
}

// Normalize, drop empty + sub-MIN_TERM_LEN terms, dedup case-insensitively, sort longest-first.
// Dedup keeps the first stored casing seen for a given lowercased key; the sort is by term length
// descending then by value ascending, so the compiled alternation prefers the longest match.
export function buildTerms(values: string[]): string[] {
  const seen = new Set<string>()
  const terms: string[] = []
  for (const v of values) {
    const n = normalizeTerm(v)
    if (n.length < MIN_TERM_LEN) continue
    const key = n.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    terms.push(n)
  }
  terms.sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0))
  return terms
}

// Escape every regex metacharacter so a term is matched literally inside the alternation.
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// Compile declared terms into a single token-bounded, case-insensitive alternation.
// Returns null when no usable terms remain (empty input, all-whitespace, all sub-MIN_TERM_LEN).
export function compileDenylist(values: string[]): RegExp | null {
  const terms = buildTerms(values)
  if (!terms.length) return null
  const alternation = terms.map(escapeRegExp).join('|')
  // 'g' scan every occurrence, 'i' case-insensitive, 'u' unicode. Token boundaries use an explicit Unicode
  // word class [\p{L}\p{N}_] -- NOT \w: in JS \w is ASCII-only even under /u, which would disagree with the
  // Python twin's re.UNICODE \w wherever a term abuts a non-ASCII letter (é, ñ, Cyrillic), e.g. "acme" in
  // "acmeé". Using \p{L}\p{N}_ keeps the boundary identical to Python for real names like Hydro-Québec.
  return new RegExp('(?<![\\p{L}\\p{N}_])(?:' + alternation + ')(?![\\p{L}\\p{N}_])', 'giu')
}

// Combining-mark test (Unicode category M = Mn|Mc|Me). A decomposed accent (e.g. U+0301 COMBINING ACUTE)
// is a combining mark; it follows the base char it decorates. Mirrors Python's unicodedata.combining(ch) > 0.
const COMBINING_MARK_RE = /\p{M}/u

// Zero-width/format (Cf) + control (Cc) test. Dropping these while building the NFC units closes the denylist
// analogue of the Tier-0 floor's zero-width bypass: an input that injects a ZWSP/TAB between the letters of a
// declared term ("fiddle<ZWSP>head") would otherwise slip the boundary-aware scan. Mirrors the Cf/Cc skip in
// Python denylist.py _nfc_with_map (unicodedata.category(ch) in ('Cf','Cc')).
const FORMAT_CONTROL_RE = /[\p{Cf}\p{Cc}]/u

// NFC-normalize `text` and return [nfc, idxMap] where idxMap[i] is the ORIGINAL (UTF-16) start index of the
// unit that produced nfc[i], plus a trailing sentinel idxMap[nfc.length] = text.length. Each base code point
// plus its trailing combining marks is composed as ONE unit, so a match on the NFC string always aligns on
// unit boundaries and maps cleanly back: [m.index, m.index + m[0].length) -> [idxMap[start], idxMap[end]).
// Mirrors Python denylist.py _nfc_with_map. Why this and not a bare text.normalize('NFC'): NFC can change
// string LENGTH (NFD 'e'+U+0301 -> NFC 'é' collapses 2 code points to 1), so offsets into the normalized
// string no longer index the original. Grouping base+marks and recording each unit's original start keeps the
// remap exact. Iterates by code POINT (for..of) but records per-UTF-16-unit so offsets stay in string-index
// space (each emitted nfc char contributes c.length entries pointing at the unit's original start).
export function nfcWithMap(text: string): [string, number[]] {
  const nfcChars: string[] = []
  const idxMap: number[] = []
  // Walk by code point, tracking the UTF-16 index of each.
  const cps: Array<{ ch: string; idx: number }> = []
  let pos = 0
  for (const ch of text) {
    cps.push({ ch, idx: pos })
    pos += ch.length
  }
  let i = 0
  const n = cps.length
  while (i < n) {
    if (FORMAT_CONTROL_RE.test(cps[i].ch)) {
      i += 1 // DROP zero-width/format/control codepoints (closes the ZWSP/TAB-injected denylist bypass)
      continue
    }
    let j = i + 1
    while (j < n && COMBINING_MARK_RE.test(cps[j].ch)) j++
    const unitStart = cps[i].idx // ORIGINAL UTF-16 start of this base+marks unit
    const unit = cps
      .slice(i, j)
      .map((c) => c.ch)
      .join('')
    for (const c of unit.normalize('NFC')) {
      nfcChars.push(c)
      for (let k = 0; k < c.length; k++) idxMap.push(unitStart) // every NFC code unit maps to the unit start
    }
    i = j
  }
  idxMap.push(text.length)
  return [nfcChars.join(''), idxMap]
}

// Scan text for every declared-term occurrence; return one span per match. Returns [] when re is null.
// Uses matchAll so the global lastIndex is owned per-iteration and never leaks across calls.
//
// The text is matched in Unicode-NFC form so a term declared NFC (compileDenylist stores NFC) is caught
// whichever way the INPUT encodes its accents -- an NFD-decomposed input ('cafe' + U+0301 ...) would
// otherwise slip the scanner entirely (a confirmed denylist bypass). Match offsets are mapped back onto the
// ORIGINAL text so the caller masks the right bytes. Mirrors Python denylist.py find_spans.
export function findSpans(text: string, re: RegExp | null, label: string = DENY_LABEL): DenySpan[] {
  if (re === null) return []
  const [nfc, idxMap] = nfcWithMap(text)
  if (nfc === text) {
    // Fast path: already NFC, no remap needed (offsets index the original directly).
    const out: DenySpan[] = []
    for (const m of text.matchAll(re)) {
      out.push({ start: m.index, end: m.index + m[0].length, label, score: 1.0, source: 'denylist' })
    }
    return out
  }
  const out: DenySpan[] = []
  for (const m of nfc.matchAll(re)) {
    out.push({ start: idxMap[m.index], end: idxMap[m.index + m[0].length], label, score: 1.0, source: 'denylist' })
  }
  return out
}
