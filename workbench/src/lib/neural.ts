// In-browser neural tier. Runs transformers.js + the xlm-r-base INT8 ONNX fully client-side.
// detectNeural() returns RawSpan[] (the deepDetect contract) -- the caller merges with Tier-0.
//
// Everything is same-origin: the model and the onnxruntime WASM are served from this origin, so a
// detection makes ZERO off-origin requests. The big cost is a one-time ~300 MB download (model + WASM),
// after which the browser cache serves it instantly and it runs wifi-off.
//
// EMBED REQUIREMENT: the host origin must serve the model at `/model/` and the onnxruntime WASM at
// `/ort/` (absolute, site root). The OSSRedact web demo stages both there (gitignored, CI-copied),
// and this workbench is iframed same-origin under `/app/`, so the absolute paths resolve to the host root
// and ONE 277 MB model is shared by /demo and the workbench. Served standalone (npm run preview) those
// paths 404 and deepDetect falls back to Tier-0 only -- acceptable; the embed is the shipped surface.
//
// Implementation note: transformers.js is loaded via a LAZY dynamic import (not in the initial bundle --
// it loads only when the user opts in) and runs on the main thread. The model load is async (no freeze);
// only the brief per-window inference runs synchronously.
//
// Kept in lockstep with the OSSRedact web demo's neural module -- same recipe, two embeddings.
import type { RawSpan } from '@ossredact/core'
import { lineChunks, decodeChunk } from './neural-decode'

export type NeuralProgress = {
  status: string // "initiate" | "download" | "progress" | "done" | "ready" (transformers.js)
  file?: string
  name?: string
  loaded?: number
  total?: number
  progress?: number // 0..100
}

export type NeuralPhase = 'idle' | 'loading' | 'ready' | 'error' | 'unsupported'

const MODEL_ID = 'model' // -> /model/config.json, /model/tokenizer.json, /model/onnx/model_int8.onnx
const MAX_LEN = 512 // matches the server (gate/privacy_gate.py NPUTier): dense 600-char chunks reach ~300 tokens

// transformers.js runtime objects (untyped here -- the lib is dynamically imported).
type Tokenizer = { (text: string, opts?: unknown): Promise<unknown>; tokenize: (t: string) => string[] }
type Model = {
  (enc: unknown): Promise<{ logits: { tolist: () => number[][][] } }>
  config: { id2label: Record<number, string> }
}

let tok: Tokenizer | null = null
let model: Model | null = null
let id2label: Record<number, string> = {}
let readyPromise: Promise<void> | null = null
let phase: NeuralPhase = 'idle'
let progressCb: ((p: NeuralProgress) => void) | undefined

/** True only where WebAssembly is available (i.e. a real browser). */
export function neuralSupported(): boolean {
  return typeof window !== 'undefined' && typeof WebAssembly !== 'undefined'
}

export function neuralStatus(): NeuralPhase {
  return phase
}

function ensureLoaded(): Promise<void> {
  if (readyPromise) return readyPromise
  readyPromise = (async () => {
    const { AutoTokenizer, AutoModelForTokenClassification, env } = await import('@huggingface/transformers')
    // --- zero-egress, self-hosted asset wiring (the product's core promise) ---
    env.allowRemoteModels = false // never reach the HF Hub at runtime
    env.allowLocalModels = true // load from same-origin /model/ (RELATIVE path -- an absolute URL skips
    env.localModelPath = '/' //   transformers' local-file existence check and silently returns []).
    // Serve the onnxruntime-web WASM from our own origin (default is a jsdelivr CDN -- that would be egress).
    // Single-threaded: no SharedArrayBuffer, so the page needs no COOP/COEP cross-origin-isolation headers.
    const wasm = env.backends?.onnx?.wasm
    if (wasm) {
      wasm.wasmPaths = '/ort/'
      wasm.numThreads = 1
    }
    const progress_callback = (p: NeuralProgress) => progressCb?.(p)
    // The model weights are a single ~278 MB file served with no content-length. On a COLD cache Chrome
    // can abort the cache write (ERR_CACHE_WRITE_FAILURE -- the entry exceeds its per-entry disk-cache
    // cap) and truncate the stream, so the FIRST from_pretrained throws while the bytes are still warming.
    // A re-fetch then reliably succeeds. Without a retry the first "Deep detect" click silently degrades to
    // Tier-0 and looks like "nothing was detected"; the user has to click again. Retry transparently here.
    const ATTEMPTS = 4
    let lastErr: unknown
    for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
      try {
        tok = (await AutoTokenizer.from_pretrained(MODEL_ID, { progress_callback })) as unknown as Tokenizer
        const m = (await AutoModelForTokenClassification.from_pretrained(MODEL_ID, {
          dtype: 'int8', // -> onnx/model_int8.onnx (the parity-gated deployed quantization)
          device: 'wasm',
          progress_callback,
        })) as unknown as Model
        model = m
        id2label = m.config.id2label
        return
      } catch (e) {
        lastErr = e
        tok = null
        model = null
        if (attempt < ATTEMPTS) await new Promise((r) => setTimeout(r, 700 * attempt))
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error('on-device model failed to load')
  })()
  // Reset on failure so a "retry" actually re-attempts instead of re-returning the rejected promise.
  readyPromise.catch(() => {
    readyPromise = null
  })
  return readyPromise
}

/** Trigger the one-time model download + init. Idempotent: repeated calls share one promise.
 *  `onProgress` is forwarded the transformers.js progress events for a download UI. */
export function loadNeural(onProgress?: (p: NeuralProgress) => void): Promise<void> {
  if (onProgress) progressCb = onProgress
  if (!neuralSupported()) {
    phase = 'unsupported'
    return Promise.reject(new Error('This browser does not support the on-device model.'))
  }
  phase = 'loading'
  return ensureLoaded()
    .then(() => {
      phase = 'ready'
    })
    .catch((e) => {
      phase = 'error'
      throw e
    })
}

/** Run the on-device neural detector over `text`. Loads the model first if needed. Returns offset-true
 *  RawSpan[] for free-text PII (names, addresses, orgs) -- the same shape Tier-0 emits, ready to merge. */
export async function detectNeural(text: string, minScore = 0.5): Promise<RawSpan[]> {
  await loadNeural(progressCb)
  const spans: RawSpan[] = []
  for (const [chunk, off] of lineChunks(text)) {
    // tok(...) gives input_ids (with specials); tok.tokenize gives the content pieces for offset
    // reconstruction. Truncate so an over-long dense chunk never exceeds the model's position window.
    const enc = await tok!(chunk, { truncation: true, max_length: MAX_LEN })
    const pieces = tok!.tokenize(chunk)
    const out = await model!(enc)
    const logits = out.logits.tolist()[0]
    for (const s of decodeChunk(chunk, pieces, logits, id2label, minScore)) {
      spans.push({ ...s, start: s.start + off, end: s.end + off })
    }
  }
  return spans
}
