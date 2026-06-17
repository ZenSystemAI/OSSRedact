// OPTIONAL neural tier. A local gate (reached via the Vite /gate proxy, default = the P620 GPU gate on the
// tailnet) runs the full gate (Tier-0 + neural XLM-R + union merge) and returns spans WITH provenance. This
// is the only path where text leaves the browser, and only to the user's own local gate over the tailnet --
// never to the cloud. The workbench is fully functional without it (client-side Tier-0 in tier0.ts).

import type { RawSpan } from './types'

export type GateHealth = { ok: boolean; model?: string; uptime_s?: number }

export async function gateHealth(signal?: AbortSignal): Promise<GateHealth> {
  try {
    const res = await fetch('/gate/healthz', { signal })
    if (!res.ok) return { ok: false }
    const d = await res.json()
    return { ok: d.status === 'ok', model: d.model, uptime_s: d.uptime_s }
  } catch {
    return { ok: false }
  }
}

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

// Returns spans already merged by the appliance (its /detect runs tier0+npu+union merge).
export async function deepDetect(text: string, minScore = 0.5, signal?: AbortSignal): Promise<RawSpan[]> {
  const res = await fetch('/gate/detect', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text, min_score: minScore }),
    signal,
  })
  if (!res.ok) throw new Error(`appliance returned ${res.status}`)
  const data = (await res.json()) as { spans?: WireSpan[] }
  return (data.spans ?? []).map((s) => ({
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
}
