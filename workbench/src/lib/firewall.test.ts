// Focused bridge/readiness tests for firewall.ts.
// Synthetic only: Tauri invoke, isTauri, and health probes are mocked or injected.
// waitForFirewallReady is the Phase 3 contract (not yet implemented) -- these cases define its red bar.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const invokeMock = vi.hoisted(() => vi.fn())
const isTauriMock = vi.hoisted(() => vi.fn(() => false))

vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}))

vi.mock('../tauri-bootstrap', () => ({
  isTauri: () => isTauriMock(),
}))

import * as firewall from './firewall'
import { setDaemonOverride } from './daemon'

import {
  firewallControl,
  waitForFirewallReady,
  type FirewallStatus,
  type WaitForFirewallReadyOptions,
} from './firewall'

function enableTauri(): void {
  isTauriMock.mockReturnValue(true)
}

function disableTauri(): void {
  isTauriMock.mockReturnValue(false)
}

afterEach(() => {
  vi.useRealTimers()
  vi.clearAllMocks()
  disableTauri()
})

// ---------------------------------------------------------------------------
// firewallControl -- desktop bridge
// ---------------------------------------------------------------------------
describe('firewallControl', () => {
  it('rejects browser use (no Tauri shell)', async () => {
    disableTauri()
    await expect(firewallControl('status')).rejects.toThrow(
      /firewall control is only available in the desktop app/i,
    )
    expect(invokeMock).not.toHaveBeenCalled()
  })

  it('maps each action to the Tauri firewall_control command', async () => {
    enableTauri()
    const actions = ['start', 'stop', 'restart', 'status'] as const
    for (const action of actions) {
      invokeMock.mockResolvedValueOnce('inactive')
      await firewallControl(action)
      expect(invokeMock).toHaveBeenLastCalledWith('firewall_control', { action })
    }
    expect(invokeMock).toHaveBeenCalledTimes(actions.length)
  })

  it('normalizes only the exact "active" string to active; everything else is inactive', async () => {
    enableTauri()

    invokeMock.mockResolvedValueOnce('active')
    await expect(firewallControl('status')).resolves.toBe('active' satisfies FirewallStatus)

    for (const raw of ['inactive', 'failed', 'ACTIVE', 'Active', '', 'unknown', 'running']) {
      invokeMock.mockResolvedValueOnce(raw)
      await expect(firewallControl('status')).resolves.toBe('inactive')
    }
  })
})

// ---------------------------------------------------------------------------
// waitForFirewallReady -- bounded dual-health readiness poll
//
// Contract (Phase 3):
//   waitForFirewallReady(options?: WaitForFirewallReadyOptions): Promise<void>
//   WaitForFirewallReadyOptions = {
//     signal?: AbortSignal
//     timeoutMs?: number        // default 30_000
//     intervalMs?: number       // short; next poll starts only after the prior finishes
//     ping?: () => Promise<boolean>
//     gatewayHealth?: (signal?: AbortSignal) => Promise<{ ok: boolean }>
//   }
// Polls daemon ping() AND proxy-mediated gatewayHealth() until both succeed, or
// rejects on budget timeout / AbortSignal. Injected probes keep this hermetic.
// ---------------------------------------------------------------------------
describe('waitForFirewallReady', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  it('exports the concrete readiness helper used by desktop start controls', () => {
    expect(typeof waitForFirewallReady).toBe('function')
  })

  it('resolves after delayed failed probes once both daemon and gateway are healthy', async () => {
    let round = 0
    const ping = vi.fn(async () => {
      round += 1
      // rounds 1-2: daemon still cold; round 3+: both sides ready
      return round >= 3
    })
    const gatewayHealth = vi.fn(async (_signal?: AbortSignal) => ({
      ok: round >= 3,
    }))

    const opts: WaitForFirewallReadyOptions = {
      timeoutMs: 5_000,
      intervalMs: 100,
      ping,
      gatewayHealth,
    }
    const ready = waitForFirewallReady(opts)

    // Immediate first probe (failed), then two intervals to reach round 3.
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(100)
    await vi.advanceTimersByTimeAsync(100)
    await expect(ready).resolves.toBeUndefined()

    expect(ping.mock.calls.length).toBeGreaterThanOrEqual(3)
    expect(gatewayHealth.mock.calls.length).toBeGreaterThanOrEqual(3)
    // At least one earlier attempt must have failed before success (round counter starts at 1, succeeds at 3).
    expect(ping.mock.calls.length).toBeGreaterThan(1)
  })

  it('continues readiness polling without Promise.withResolvers', async () => {
    const originalWithResolvers = Object.getOwnPropertyDescriptor(Promise, 'withResolvers')

    try {
      expect(Reflect.deleteProperty(Promise, 'withResolvers')).toBe(true)

      let round = 0
      const ping = vi.fn(async () => {
        round += 1
        return round >= 2
      })
      const gatewayHealth = vi.fn(async () => ({ ok: round >= 2 }))
      const ready = waitForFirewallReady({
        timeoutMs: 1_000,
        intervalMs: 100,
        ping,
        gatewayHealth,
      })
      const readiness = expect(ready).resolves.toBeUndefined()
      void readiness.catch(() => undefined)

      await vi.advanceTimersByTimeAsync(0)
      expect(ping).toHaveBeenCalledTimes(1)
      expect(gatewayHealth).toHaveBeenCalledTimes(1)

      await vi.advanceTimersByTimeAsync(100)
      await readiness

      expect(ping).toHaveBeenCalledTimes(2)
      expect(gatewayHealth).toHaveBeenCalledTimes(2)
    } finally {
      if (originalWithResolvers) {
        Object.defineProperty(Promise, 'withResolvers', originalWithResolvers)
      } else {
        Reflect.deleteProperty(Promise, 'withResolvers')
      }
    }
  })

  it('requires both health conditions; one healthy side alone does not settle', async () => {
    const ping = vi.fn(async () => true)
    const gatewayHealth = vi.fn(async () => ({ ok: false }))

    const ready = waitForFirewallReady({
      timeoutMs: 500,
      intervalMs: 100,
      ping,
      gatewayHealth,
    })
    const expectation = expect(ready).rejects.toThrow(/timeout|not ready|timed out/i)

    await vi.advanceTimersByTimeAsync(600)
    await expectation

    expect(ping).toHaveBeenCalled()
    expect(gatewayHealth).toHaveBeenCalled()
  })

  it('times out when probes never satisfy both health conditions within the budget', async () => {
    const ping = vi.fn(async () => false)
    const gatewayHealth = vi.fn(async () => ({ ok: false }))

    const ready = waitForFirewallReady({
      timeoutMs: 1_000,
      intervalMs: 200,
      ping,
      gatewayHealth,
    })
    const expectation = expect(ready).rejects.toThrow(/timeout|not ready|timed out/i)

    await vi.advanceTimersByTimeAsync(1_200)
    await expectation

    // Several non-overlapping attempts within the budget, but never success.
    expect(ping.mock.calls.length).toBeGreaterThanOrEqual(2)
    expect(gatewayHealth.mock.calls.length).toBe(ping.mock.calls.length)
  })

  it('rejects on AbortController abort and stops further probes', async () => {
    const ctrl = new AbortController()
    let inFlight = 0
    let maxInFlight = 0
    let releaseProbe: (() => void) | undefined
    const ping = vi.fn(async () => {
      inFlight += 1
      maxInFlight = Math.max(maxInFlight, inFlight)
      try {
        // Hold the first probe open so abort lands while a round is outstanding.
        await new Promise<void>((resolve) => {
          releaseProbe = resolve
        })
        return false
      } finally {
        inFlight -= 1
      }
    })
    const gatewayHealth = vi.fn(async () => ({ ok: false }))

    const ready = waitForFirewallReady({
      signal: ctrl.signal,
      timeoutMs: 10_000,
      intervalMs: 100,
      ping,
      gatewayHealth,
    })

    await Promise.resolve()
    expect(ping.mock.calls.length).toBeGreaterThanOrEqual(1)

    ctrl.abort()
    releaseProbe?.()
    await expect(ready).rejects.toSatisfy(
      (err: unknown) =>
        (err instanceof DOMException && err.name === 'AbortError') ||
        (err instanceof Error && (/abort/i.test(err.name) || /abort/i.test(err.message))),
    )

    const callsAtAbort = ping.mock.calls.length
    // Advance well past several intervals; no additional probe rounds after abort cleanup.
    await vi.advanceTimersByTimeAsync(1_000)
    expect(ping.mock.calls.length).toBe(callsAtAbort)
    expect(gatewayHealth.mock.calls.length).toBeLessThanOrEqual(callsAtAbort)
    // Non-overlapping: never two ping probes concurrent in this helper.
    expect(maxInFlight).toBeLessThanOrEqual(1)
  })

  it('defaults the readiness budget to 30 seconds when timeoutMs is omitted', async () => {
    const ping = vi.fn(async () => false)
    const gatewayHealth = vi.fn(async () => ({ ok: false }))

    const ready = waitForFirewallReady({
      intervalMs: 1_000,
      ping,
      gatewayHealth,
    })
    const expectation = expect(ready).rejects.toThrow(/timeout|not ready|timed out/i)

    // Still inside a 30s budget: must not reject yet.
    await vi.advanceTimersByTimeAsync(29_000)
    let settled = false
    void ready.then(
      () => {
        settled = true
      },
      () => {
        settled = true
      },
    )
    await Promise.resolve()
    expect(settled).toBe(false)

    await vi.advanceTimersByTimeAsync(2_000)
    await expectation
  })
})

type LocalFirewallReadiness = (
  options?: Pick<WaitForFirewallReadyOptions, 'intervalMs' | 'signal' | 'timeoutMs'>,
) => Promise<void>

describe('waitForLocalFirewallReady', () => {
  it('pins a local service start to loopback health endpoints despite a saved remote override', async () => {
    setDaemonOverride('http://remote-gate.example.test:8011')
    try {
      const waitForLocalFirewallReady = Reflect.get(
        firewall,
        'waitForLocalFirewallReady',
      ) as LocalFirewallReadiness | undefined
      if (typeof waitForLocalFirewallReady !== 'function') {
        throw new Error(
          'Local firewall readiness contract is missing: local starts must probe fixed loopback health endpoints.',
        )
      }

      const calls: string[] = []
      vi.stubGlobal(
        'fetch',
        vi.fn(async (input: RequestInfo | URL) => {
          const url = typeof input === 'string' ? input : input.toString()
          calls.push(url)
          return {
            ok: true,
            json: async () => ({ status: 'ok' }),
          } as Response
        }),
      )

      await expect(
        waitForLocalFirewallReady({ timeoutMs: 1_000, intervalMs: 10 }),
      ).resolves.toBeUndefined()

      expect(calls).toEqual([
        'http://127.0.0.1:8011/healthz',
        'http://127.0.0.1:8011/gate/healthz',
      ])
    } finally {
      setDaemonOverride('')
      vi.unstubAllGlobals()
    }
  })
})
