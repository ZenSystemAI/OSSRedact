import { describe, it, expect } from 'vitest'
import {
  MIN_TERM_LEN,
  DENY_LABEL,
  normalizeTerm,
  buildTerms,
  compileDenylist,
  findSpans,
  nfcWithMap,
} from './denylist.js'
import * as publicApi from './index.js'

describe('public barrel exports', () => {
  it('exports the browser-safe denylist scanner alongside the allowlist API', () => {
    const re = publicApi.compileDenylist(['Project Falcon'])
    expect(publicApi.DENY_LABEL).toBe('custom')
    expect(publicApi.findSpans('ship Project Falcon', re)).toEqual([
      { start: 5, end: 19, label: 'custom', score: 1.0, source: 'denylist' },
    ])
  })
})

describe('normalizeTerm', () => {
  it('NFC-normalizes and trims, but does NOT lowercase the stored form', () => {
    expect(normalizeTerm('  Acme ')).toBe('Acme')
    expect(normalizeTerm('Project Falcon')).toBe('Project Falcon')
    // NFC: composed vs decomposed e-acute collapse to the same stored form.
    expect(normalizeTerm('André')).toBe(normalizeTerm('André'))
    expect(normalizeTerm('André').length).toBe(5)
  })
})

describe('buildTerms', () => {
  it('normalizes, drops empties + sub-MIN_TERM_LEN, dedups case-insensitively', () => {
    const terms = buildTerms(['Acme', 'acme', '  ', 'x', 'Project Falcon'])
    // 'acme' dedups against 'Acme' (first casing kept), '  ' empty, 'x' is sub-MIN_TERM_LEN.
    expect(terms).toContain('Acme')
    expect(terms).toContain('Project Falcon')
    expect(terms).not.toContain('acme')
    expect(terms).not.toContain('x')
    expect(MIN_TERM_LEN).toBe(2)
  })

  it('sorts longest-first, then alphabetical', () => {
    const terms = buildTerms(['ab', 'Project Falcon', 'acme', 'zeta'])
    // length desc: 'Project Falcon'(14) > 'acme'/'zeta'(4, alpha) > 'ab'(2)
    expect(terms).toEqual(['Project Falcon', 'acme', 'zeta', 'ab'])
  })
})

describe('compileDenylist', () => {
  it('returns null for an empty / all-whitespace / all-too-short term list', () => {
    expect(compileDenylist([])).toBeNull()
    expect(compileDenylist(['   ', '\t'])).toBeNull()
    expect(compileDenylist(['a', 'x'])).toBeNull()
  })

  it('compiles a usable RegExp when at least one term survives', () => {
    expect(compileDenylist(['acme'])).toBeInstanceOf(RegExp)
  })
})

describe('findSpans', () => {
  it('returns [] when the pattern is null', () => {
    expect(findSpans('anything at all', null)).toEqual([])
  })

  it('finds a term the detector missed', () => {
    const re = compileDenylist(['acme'])
    const text = 'deploy to Acme tonight'
    const spans = findSpans(text, re)
    expect(spans).toHaveLength(1)
    expect(text.slice(spans[0].start, spans[0].end)).toBe('Acme')
  })

  it('matches case-insensitively (every casing of one declared term)', () => {
    const re = compileDenylist(['acme'])
    const text = 'acme ACME Acme aCmE'
    const spans = findSpans(text, re)
    expect(spans).toHaveLength(4)
    for (const s of spans) {
      expect(text.slice(s.start, s.end).toLowerCase()).toBe('acme')
    }
  })

  it('respects token boundaries: no match inside "acmecorp", matches "acme-corp"', () => {
    const re = compileDenylist(['acme'])
    // "acmecorp" -> no match (term is inside a larger word).
    expect(findSpans('acmecorp', re)).toHaveLength(0)
    // "acme-corp" -> match ('-' is a non-word char, a boundary). Also a trailing-dot form.
    const text = 'acme-corp and acme.'
    const spans = findSpans(text, re)
    expect(spans).toHaveLength(2)
    expect(text.slice(spans[0].start, spans[0].end)).toBe('acme')
    expect(text.slice(spans[1].start, spans[1].end)).toBe('acme')
  })

  it('matches a multi-word phrase as a single span', () => {
    const re = compileDenylist(['Project Falcon'])
    const text = 'codename Project Falcon ships Friday'
    const spans = findSpans(text, re)
    expect(spans).toHaveLength(1)
    expect(text.slice(spans[0].start, spans[0].end)).toBe('Project Falcon')
  })

  it('ignores a 1-char term (MIN_TERM_LEN guard) -- does not redact every letter', () => {
    const re = compileDenylist(['a'])
    expect(re).toBeNull()
    expect(findSpans('a man a plan a canal', re)).toEqual([])
  })

  it('LONGEST-FIRST: an overlapping pair yields one span for the longest declared term', () => {
    // "acme" and "acme corp" both declared; in "acme corp", the longer term wins as one span.
    const re = compileDenylist(['acme', 'acme corp'])
    const text = 'ship acme corp now'
    const spans = findSpans(text, re)
    expect(spans).toHaveLength(1)
    expect(text.slice(spans[0].start, spans[0].end)).toBe('acme corp')
  })

  it('matches unicode terms across NFC-equivalent input forms', () => {
    // Term declared with a composed e-acute; input uses the decomposed form -- NFC folds them.
    const re = compileDenylist(['André'])
    const text = 'ping André about it'.normalize('NFC')
    const spans = findSpans(text, re)
    expect(spans).toHaveLength(1)
    expect(text.slice(spans[0].start, spans[0].end).normalize('NFC')).toBe('André')
  })

  it('emits the exact contract span shape (label custom, score 1.0, source denylist)', () => {
    const re = compileDenylist(['acme'])
    const spans = findSpans('use Acme', re)
    expect(spans).toHaveLength(1)
    expect(spans[0]).toEqual({
      start: 4,
      end: 8,
      label: DENY_LABEL,
      score: 1.0,
      source: 'denylist',
    })
    expect(DENY_LABEL).toBe('custom')
  })

  it('honors a caller-supplied label override while keeping score/source fixed', () => {
    const re = compileDenylist(['acme'])
    const spans = findSpans('Acme', re, 'client')
    expect(spans[0].label).toBe('client')
    expect(spans[0].source).toBe('denylist')
    expect(spans[0].score).toBe(1.0)
  })

  it('escapes regex metacharacters so a phrase with specials matches literally', () => {
    const re = compileDenylist(['a.c+m'])
    // Must match the literal "a.c+m", not the regex it would otherwise denote.
    const spans = findSpans('token a.c+m here', re)
    expect(spans).toHaveLength(1)
    expect(findSpans('token axcxm here', re)).toHaveLength(0)
  })

  it('uses Unicode word boundaries (parity lock vs the Python re.UNICODE twin)', () => {
    // JS \w is ASCII-only even under /u; this twin uses \p{L}\p{N}_ so a term abutting a non-ASCII LETTER
    // is NOT a boundary -> no match, identical to Python's re.UNICODE \w. (Without the fix TS over-redacted.)
    const re = compileDenylist(['acme'])
    expect(findSpans('ship acmeé now', re)).toHaveLength(0)   // 'é' is a word char -> mid-word -> no match
    expect(findSpans('ship éacme now', re)).toHaveLength(0)
    expect(findSpans('use acme-corp ok', re)).toHaveLength(1) // '-' not a word char -> boundary -> match
    expect(findSpans('an acmecorp x', re)).toHaveLength(0)    // ASCII letter neighbour -> no match
  })

  // -------------------------
  // NFD-input bypass fix (port of Python denylist.py _nfc_with_map + the find_spans NFC change)
  // -------------------------
  it('catches a denylisted accented term given in DECOMPOSED (NFD) form, with correct offsets', () => {
    // Term stored NFC ('café-secret'); the INPUT decomposes the accent. Before the fix the NFC-stored term
    // never matched the NFD haystack -> a confirmed denylist bypass.
    const re = compileDenylist(['café-secret'])
    const nfd = 'le café-secret ici'.normalize('NFD')
    expect(nfd === nfd.normalize('NFC')).toBe(false) // confirm the input really is decomposed
    const spans = findSpans(nfd, re)
    expect(spans).toHaveLength(1)
    // offsets index the ORIGINAL (NFD) text; the raw slice re-normalizes back to the term
    expect(nfd.slice(spans[0].start, spans[0].end).normalize('NFC')).toBe('café-secret')
    expect(spans[0]).toMatchObject({ label: DENY_LABEL, score: 1.0, source: 'denylist' })
  })

  // -------------------------
  // Zero-width / control (Cf/Cc) injection bypass fix (round-2; port of denylist.py _nfc_with_map Cf/Cc drop)
  // -------------------------
  it('catches a denylisted term split by an injected ZWSP, with offsets spanning the invisible', () => {
    // "fiddle<ZWSP>head" reads as "fiddlehead" to a human/LLM but the boundary-aware scanner saw two tokens.
    // nfcWithMap now DROPS the Cf codepoint so the term matches; offsets map back over the original (incl ZWSP).
    const re = compileDenylist(['fiddlehead'])
    const ZW = '​'
    const text = 'order fiddle' + ZW + 'head now'
    const spans = findSpans(text, re)
    expect(spans).toHaveLength(1)
    expect(text.slice(spans[0].start, spans[0].end).replace(new RegExp(ZW, 'g'), '')).toBe('fiddlehead')
    expect(spans[0]).toMatchObject({ label: DENY_LABEL, score: 1.0, source: 'denylist' })
  })

  it('catches a denylisted term split by an injected TAB (Cc control)', () => {
    const re = compileDenylist(['bluebird'])
    const text = 'codename blue\tbird here'
    const spans = findSpans(text, re)
    expect(spans).toHaveLength(1)
    expect(text.slice(spans[0].start, spans[0].end).replace(/\t/g, '')).toBe('bluebird')
  })

  it('fast path: pure-NFC input maps offsets directly onto the original', () => {
    const re = compileDenylist(['café-secret'])
    const text = 'le café-secret ici' // already NFC
    const spans = findSpans(text, re)
    expect(spans).toHaveLength(1)
    expect(text.slice(spans[0].start, spans[0].end)).toBe('café-secret')
  })

  it('nfcWithMap composes base+combining marks into single units with a length sentinel', () => {
    const nfd = 'café'.normalize('NFD') // c a f e + U+0301 (5 code units)
    const [nfc, idxMap] = nfcWithMap(nfd)
    expect(nfc).toBe('café'.normalize('NFC')) // 4 code units
    expect(nfc.length).toBe(4)
    // trailing sentinel maps an end-of-string offset to the original length
    expect(idxMap[nfc.length]).toBe(nfd.length)
    // the composed 'é' (nfc index 3) maps back to the start of the 'e'+accent unit in the NFD original
    expect(idxMap[3]).toBe(3)
  })
})
