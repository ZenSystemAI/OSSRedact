// The OPTIONAL deep tier has two local providers:
// 1. On-prem/install workbench: call the local OSSRedact gate through the same-origin /gate proxy.
// 2. Hosted website demo: if /gate is absent, run the base INT8 model in-browser via transformers.js.
// Neither provider calls a cloud detector. The local gate path sends text only to the user's own appliance;
// the browser path keeps text in the tab after self-hosted model assets are loaded.

import type { RawSpan } from './types'
import { mergeSpans, propagateRepeats, tier0Spans } from '@ossredact/core'
import { daemonBase, getControlToken } from './daemon'
import {
  detectNeural,
  loadNeural,
  neuralSupported,
  neuralStatus,
  type NeuralProgress,
  type NeuralPhase,
} from './neural'

// /gate/* lives on the DAEMON (egress :8011 forwards to the neural gate), so the probe must follow the
// same base as every other daemon call: '' (same-origin) when the console is served by the daemon or the
// Vite dev proxy, the Tauri-injected daemon, or the operator's Connect-panel override. A bare relative
// fetch here is what made the desktop/gate-served console 404 the probe and silently fall back to the
// in-browser model while a healthy GPU gate sat one hop away (2026-07-04).
function gateHeaders(post: boolean): Record<string, string> {
  const headers: Record<string, string> = {}
  if (post) {
    headers['content-type'] = 'application/json'
    headers['x-ossredact-control'] = '1' // CSRF guard header, required by the daemon on POST
  }
  const tok = getControlToken()
  if (tok) headers['x-ossredact-control-token'] = tok
  return headers
}

export type DeepProvider = 'gateway' | 'browser'
type ProviderConfig = DeepProvider | 'auto'
export type GateHealth = { ok: boolean; provider?: DeepProvider; model?: string; uptime_s?: number }

function configuredProvider(): ProviderConfig {
  const raw = import.meta.env.VITE_OSSREDACT_DEEP_PROVIDER
  return raw === 'gateway' || raw === 'browser' ? raw : 'auto'
}

async function gatewayHealth(signal?: AbortSignal): Promise<GateHealth> {
  try {
    const res = await fetch(daemonBase() + '/gate/healthz', { signal, headers: gateHeaders(false) })
    if (!res.ok) return { ok: false, provider: 'gateway' }
    const d = await res.json()
    return { ok: d.status === 'ok', provider: 'gateway', model: d.model, uptime_s: d.uptime_s }
  } catch {
    return { ok: false, provider: 'gateway' }
  }
}

function browserHealth(): GateHealth {
  return {
    ok: neuralStatus() === 'ready',
    provider: 'browser',
    model: neuralSupported() ? 'xlm-r base INT8 (on-device)' : undefined,
  }
}

export async function gateHealth(signal?: AbortSignal): Promise<GateHealth> {
  const configured = configuredProvider()
  if (configured === 'gateway') return gatewayHealth(signal)
  if (configured === 'browser') return browserHealth()
  const gateway = await gatewayHealth(signal)
  return gateway.ok ? gateway : browserHealth()
}

export async function selectDeepProvider(signal?: AbortSignal): Promise<DeepProvider> {
  const configured = configuredProvider()
  if (configured === 'gateway' || configured === 'browser') return configured
  const gateway = await gatewayHealth(signal)
  return gateway.ok ? 'gateway' : 'browser'
}

export async function prepareDeepDetect(onProgress?: (p: NeuralProgress) => void, signal?: AbortSignal): Promise<DeepProvider> {
  const provider = await selectDeepProvider(signal)
  if (provider === 'browser') await loadNeural(onProgress)
  return provider
}

export function deepProviderLabel(provider: DeepProvider): string {
  return provider === 'gateway' ? 'local gate' : 'browser model'
}

export type { NeuralProgress, NeuralPhase }

type WireSpan = {
  start: number
  end: number
  label: string
  tier: number
  conf: number
  rule?: string
  validator?: string
  cue?: string
  subtype?: string
  members?: number
}

async function gatewayDetect(text: string, minScore: number, signal?: AbortSignal): Promise<RawSpan[]> {
  const res = await fetch(daemonBase() + '/gate/detect', {
    method: 'POST',
    headers: gateHeaders(true),
    body: JSON.stringify({ text, min_score: minScore }),
    signal,
  })
  if (!res.ok) throw new Error(`appliance returned ${res.status}`)
  const data = (await res.json()) as { spans?: WireSpan[] }
  // Merge the LOCAL deterministic Tier-0 floor with the gateway spans, mirroring browserDetect below.
  // Without this the gateway path silently drops the high-recall numeric floor, so bare account
  // numbers in documents (e.g. bank statements) that the GPU NER misses would leak unredacted.
  const gatewaySpans = (data.spans ?? []).map((s) => ({
    start: s.start,
    end: s.end,
    label: s.label,
    tier: s.tier,
    conf: s.conf,
    rule: s.rule ?? (s.tier === 0 ? 'tier0' : 'npu'),
    validator: s.validator,
    cue: s.cue,
    subtype: s.subtype,
    members: s.members,
  }))
  // Repeat propagation runs client-side too (not only in the gate service): the deployed gate may lag
  // this build, and the browser path below needs it regardless. mergeSpans unions any duplicates.
  return mergeSpans(propagateRepeats(text, [...tier0Spans(text), ...gatewaySpans]))
}

async function browserDetect(text: string, minScore: number, signal?: AbortSignal): Promise<RawSpan[]> {
  if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
  const neural = await detectNeural(text, minScore)
  if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
  return mergeSpans(propagateRepeats(text, [...tier0Spans(text), ...neural]))
}

export async function deepDetect(
  text: string,
  minScore = 0.5,
  signal?: AbortSignal,
  provider?: DeepProvider,
): Promise<RawSpan[]> {
  const selected = provider ?? await selectDeepProvider(signal)
  return selected === 'gateway'
    ? gatewayDetect(text, minScore, signal)
    : browserDetect(text, minScore, signal)
}
