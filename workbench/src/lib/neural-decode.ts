// Pure (no transformers, no DOM) decode helpers for the in-browser neural tier -- unit-testable in
// isolation. This is a hand-port of the server BIO decode + chunking (plan 021 maintenance note); it
// must track gate/privacy_gate.py `NPUTier.spans` and deploy/gate_service_cpu.py `_chunks`/`_windows`.
// If those change, mirror here. All offsets are CHAR offsets into the input string (offset-true is the
// load-bearing contract: redaction.ts indexes text.slice(start,end)).
//
// NOTE: this file is kept byte-identical to the in-browser decode used by the OSSRedact web demo.
// One decode, two embeddings (the web /demo and this workbench). Edit both together.
import type { RawSpan } from '@ossredact/core'

// Matches deploy/gate_service_cpu.py: 600-char windows keep a dense chunk under the model's token
// window; 80-char overlap so a value straddling a boundary is caught whole in at least one window
// (and union-merged downstream by mergeSpans).
export const CHUNK_CHARS = 600
export const CHUNK_OVERLAP = 80

/** Char windows (with overlap, preferring a word boundary near the end) for a single over-long line.
 *  Verbatim port of gate_service_cpu.py `_windows`. Yields [chunk, absoluteOffset]. */
export function* windows(
  s: string,
  base: number,
  size = CHUNK_CHARS,
  overlap = CHUNK_OVERLAP,
): Generator<[string, number]> {
  const n = s.length
  let i = 0
  while (i < n) {
    let end = Math.min(i + size, n)
    if (end < n) {
      // Python: s.rfind(' ', max(i+size-overlap, i+1), end) -- last space in [lo, end)
      const lo = Math.max(i + size - overlap, i + 1)
      const j = s.lastIndexOf(' ', end - 1)
      if (j >= lo && j > i) end = j
    }
    yield [s.slice(i, end), base + i]
    if (end >= n) break
    i = Math.max(end - overlap, i + 1)
  }
}

/** Prefer line boundaries, hard-window any single line longer than `size`. Verbatim port of
 *  gate_service_cpu.py `_chunks`. Yields [chunk, absoluteOffset]. Never mutates text -> offsets exact. */
export function* lineChunks(text: string, size = CHUNK_CHARS): Generator<[string, number]> {
  // splitlines(keepends=True) equivalent: keep the newline attached to the preceding line.
  const lines = text.split(/(?<=\n)/)
  let buf = ''
  let start = 0
  let pos = 0
  for (const ln of lines) {
    if (ln.length > size) {
      if (buf) {
        yield [buf, start]
        buf = ''
      }
      yield* windows(ln, pos)
      pos += ln.length
      start = pos
      continue
    }
    if (buf && buf.length + ln.length > size) {
      yield [buf, start]
      buf = ''
      start = pos
    }
    buf += ln
    pos += ln.length
  }
  if (buf) yield [buf, start]
}

/** SentencePiece offset reconstruction. transformers.js does NOT expose return_offsets_mapping
 *  (HF discuss 171412), so we rebuild char offsets from the `_` (U+2581)-marked pieces by walking the
 *  source. `_` marks a preceding space; whitespace in the source (incl. NBSP, which JS \s matches) is
 *  skipped so normalized separators do not shift offsets. Returns one [start,end] per piece. */
export function reconstructOffsets(text: string, pieces: string[]): [number, number][] {
  const offs: [number, number][] = []
  let cur = 0
  for (const t of pieces) {
    const hadSpace = t.startsWith('▁')
    const piece = t.replace(/▁/g, '')
    if (hadSpace) while (cur < text.length && /\s/.test(text[cur])) cur++
    if (piece.length === 0) {
      offs.push([cur, cur])
      continue
    }
    const begin = cur
    let pi = 0
    while (pi < piece.length && cur < text.length) {
      if (text[cur] === piece[pi]) {
        pi++
        cur++
      } else if (/\s/.test(text[cur])) {
        cur++
      } else {
        // normalization mismatch (e.g. lowercased / NFKC-folded char): best-effort 1:1 advance.
        pi++
        cur++
      }
    }
    offs.push([begin, cur])
  }
  return offs
}

export function softmax(a: number[]): number[] {
  const m = Math.max(...a)
  const e = a.map((x) => Math.exp(x - m))
  const s = e.reduce((p, c) => p + c, 0)
  return e.map((x) => x / s)
}

/** Re-port of gate/privacy_gate.py `NPUTier.spans` BIO decode. `pieces` are the content tokens (no
 *  specials); `logits` is the full per-token logit matrix INCLUDING the leading <s> -- so piece i maps
 *  to logits[i+1]. Clamps to the logit length so a truncated (max_length) chunk never over-reads.
 *  Skips zero-width pieces, merges B-/I- runs, conf = min over the run, filters conf >= minScore. */
export function decodeChunk(
  text: string,
  pieces: string[],
  logits: number[][],
  id2label: Record<number, string>,
  minScore = 0.5,
): RawSpan[] {
  const offs = reconstructOffsets(text, pieces)
  const spans: RawSpan[] = []
  let cur: RawSpan | null = null
  const push = () => {
    if (cur && cur.conf >= minScore) spans.push(cur)
    cur = null
  }
  // logits includes <s> ... </s>; content tokens are logits[1 .. n-2]. Never read past that.
  const n = Math.min(pieces.length, Math.max(0, logits.length - 2))
  for (let i = 0; i < n; i++) {
    const [s, e] = offs[i]
    if (s === e) {
      push()
      continue
    }
    const probs = softmax(logits[i + 1])
    let ci = 0
    for (let k = 1; k < probs.length; k++) if (probs[k] > probs[ci]) ci = k
    const lab = id2label[ci]
    const conf = probs[ci]
    if (!lab || lab === 'O') {
      push()
      continue
    }
    const dash = lab.indexOf('-')
    const bio = lab.slice(0, dash)
    const ent = lab.slice(dash + 1)
    if (bio === 'B' || !cur || cur.label !== ent) {
      push()
      cur = { start: s, end: e, label: ent, tier: 1, conf, rule: 'neural' }
    } else {
      cur.end = e
      cur.conf = Math.min(cur.conf, conf)
    }
  }
  push()
  return spans
}
