// The OPTIONAL deep tier -- now running FULLY IN-BROWSER (zero egress). Previously this fetched a local
// network gate (a GPU appliance ran Tier-0 + neural XLM-R + union merge). That path made
// text leave the browser; here the same pipeline runs client-side via transformers.js, so deep detect
// makes ZERO network requests after the one-time model download. The workbench is still fully functional
// without the model (client-side Tier-0 in tier0.ts); the neural tier is opt-in.

import type { RawSpan } from './types'
import { mergeSpans, tier0Spans } from '@ossredact/core'
import {
  detectNeural,
  loadNeural,
  neuralSupported,
  neuralStatus,
  type NeuralProgress,
  type NeuralPhase,
} from './neural'

export type GateHealth = { ok: boolean; model?: string; uptime_s?: number }

// "Health" now means: can this browser run the on-device model, and is it loaded yet. No network call.
export async function gateHealth(): Promise<GateHealth> {
  return {
    ok: neuralStatus() === 'ready',
    model: neuralSupported() ? 'xlm-r base INT8 (on-device)' : undefined,
  }
}

export { loadNeural, neuralSupported, neuralStatus }
export type { NeuralProgress, NeuralPhase }

// In-browser deep detect: Tier-0 (deterministic) UNION neural (XLM-R INT8), then mergeSpans collapses
// chunk-overlap duplicates and resolves Tier-0/neural overlaps by confidence -- the same RawSpan[]
// contract the appliance used to return, but nothing leaves the browser. `signal` lets the batch loop
// abort between the (long) neural pass and the rest.
export async function deepDetect(text: string, minScore = 0.5, signal?: AbortSignal): Promise<RawSpan[]> {
  if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
  const neural = await detectNeural(text, minScore)
  if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
  return mergeSpans([...tier0Spans(text), ...neural])
}
