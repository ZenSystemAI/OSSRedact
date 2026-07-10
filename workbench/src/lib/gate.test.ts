// Tests for deep-detect provider selection.
// All inputs are synthetic -- no real PII, no model load, no real network.

import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('./neural', () => ({
  detectNeural: vi.fn(async () => [{ start: 6, end: 18, label: 'person', tier: 1, conf: 0.94, rule: 'neural' }]),
  loadNeural: vi.fn(async () => undefined),
  neuralSupported: vi.fn(() => true),
  neuralStatus: vi.fn(() => 'idle'),
}))

import { deepDetect, gateHealth, prepareDeepDetect } from './gate'
import { detectNeural, loadNeural } from './neural'

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('deep-detect providers', () => {
  it('uses the local gate when /gate/healthz is reachable', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url === '/gate/healthz') return jsonResponse({ status: 'ok', model: 'local-cpu', uptime_s: 12 })
      if (url === '/gate/detect') {
        expect(init?.method).toBe('POST')
        expect(JSON.parse(String(init?.body))).toEqual({ text: 'hello Alice Zephyr', min_score: 0.5 })
        return jsonResponse({ spans: [{ start: 6, end: 18, label: 'person', tier: 1, conf: 0.91 }] })
      }
      return jsonResponse({}, { status: 404 })
    })
    vi.stubGlobal('fetch', fetchMock)

    await expect(gateHealth()).resolves.toMatchObject({ ok: true, provider: 'gateway', model: 'local-cpu' })
    const provider = await prepareDeepDetect()
    expect(provider).toBe('gateway')
    expect(loadNeural).not.toHaveBeenCalled()

    const spans = await deepDetect('hello Alice Zephyr', 0.5, undefined, provider)
    // gatewayDetect now merges the local Tier-0 floor (parity with browserDetect). The floor adds
    // nothing for this text, so the single gateway span survives, normalized through mergeSpans.
    expect(spans).toHaveLength(1)
    expect(spans[0]).toMatchObject({ start: 6, end: 18, label: 'person', tier: 1, conf: 0.91, rule: 'npu' })
  })

  it('falls back to the browser model when /gate is absent', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({}, { status: 404 })))

    await expect(gateHealth()).resolves.toMatchObject({ ok: false, provider: 'browser' })
    const provider = await prepareDeepDetect()
    expect(provider).toBe('browser')
    expect(loadNeural).toHaveBeenCalledTimes(1)

    const spans = await deepDetect('hello Alice Zephyr', 0.5, undefined, provider)
    expect(detectNeural).toHaveBeenCalledWith('hello Alice Zephyr', 0.5)
    expect(spans.some((s) => s.label === 'person' && s.start === 6 && s.end === 18)).toBe(true)
  })

  // Fail-closed contract: a neural model-load/inference failure must PROPAGATE out of deepDetect, NEVER be
  // silently swallowed into a Tier-0-only result. The UI relies on the throw to mark the doc degraded and gate
  // export; if deepDetect ever returned Tier-0 spans on neural failure, the fail-open bug would be back.
  it('PROPAGATES a neural failure (does not silently degrade to Tier-0)', async () => {
    vi.mocked(detectNeural).mockRejectedValueOnce(new Error('on-device model failed to load'))
    // 'Daniel Brooks' is a free-text name Tier-0 cannot catch -- if the failure were swallowed, deepDetect
    // would resolve with Tier-0 spans that do NOT cover it, and the caller would treat the output as scanned.
    await expect(deepDetect('memo from Daniel Brooks', 0.5, undefined, 'browser')).rejects.toThrow(
      /model failed to load/,
    )
  })
})
