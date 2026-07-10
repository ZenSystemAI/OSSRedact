// Point-and-click firewall control from the desktop console: start/stop the local OSSRedact user services
// and toggle whether Claude Code routes through the firewall. These call native Tauri commands (see
// src-tauri/src/lib.rs) and ONLY work inside the desktop app -- in a plain browser they throw, so callers
// guard with isTauri() (the controls are hidden in the browser).

import { isTauri } from '../tauri-bootstrap'
import { daemonBase, getControlToken, ping as daemonPing } from './daemon'

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  // Lazy import so the browser bundle never hard-depends on the Tauri API at module load.
  // Platform-specific: @tauri-apps/api/core is only present in the desktop build.
  const { invoke } = await import('@tauri-apps/api/core')
  return invoke<T>(cmd, args)
}

export type FirewallStatus = 'active' | 'inactive'

/** Start / stop / restart the two user services, or query status. Returns the resulting status. */
export async function firewallControl(
  action: 'start' | 'stop' | 'restart' | 'status',
): Promise<FirewallStatus> {
  if (!isTauri()) throw new Error('firewall control is only available in the desktop app')
  const s = await invoke<string>('firewall_control', { action })
  return s === 'active' ? 'active' : 'inactive'
}

/** Read / set whether Claude Code routes through the firewall (flips ANTHROPIC_BASE_URL in settings.json). */
export async function routingConfig(action: 'get' | 'enable' | 'disable'): Promise<boolean> {
  if (!isTauri()) throw new Error('routing control is only available in the desktop app')
  return invoke<boolean>('routing_config', { action })
}

const DEFAULT_READY_TIMEOUT_MS = 30_000
const DEFAULT_READY_INTERVAL_MS = 250

export type WaitForFirewallReadyOptions = {
  /** Overall readiness budget. Defaults to 30 seconds. */
  timeoutMs?: number
  /** Delay between sequential non-overlapping probe rounds. */
  intervalMs?: number
  /** Abort in-flight readiness wait (e.g. component unmount). */
  signal?: AbortSignal
  /** Injectable daemon health probe. Defaults to `ping()`. */
  ping?: (signal?: AbortSignal) => Promise<boolean>
  /** Injectable proxy-mediated gate health probe. Defaults to `/gate/healthz` via the daemon. */
  gatewayHealth?: (signal?: AbortSignal) => Promise<{ ok: boolean }>
}

function abortError(): DOMException {
  return new DOMException('The operation was aborted.', 'AbortError')
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortError()
}

function isAbortError(err: unknown): boolean {
  return (
    (err instanceof DOMException && err.name === 'AbortError') ||
    (err instanceof Error && (/abort/i.test(err.name) || /abort/i.test(err.message)))
  )
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  throwIfAborted(signal)
  if (ms <= 0) return Promise.resolve()
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup()
      resolve()
    }, ms)
    const onAbort = () => {
      cleanup()
      reject(abortError())
    }
    const cleanup = () => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

/** Default probe: proxy-mediated gate /gate/healthz (model service behind egress). */
async function gatewayHealth(
  signal?: AbortSignal,
  base = daemonBase(),
): Promise<{ ok: boolean }> {
  try {
    const headers: Record<string, string> = {}
    const tok = getControlToken()
    if (tok) headers['x-ossredact-control-token'] = tok
    const res = await fetch(base + '/gate/healthz', { signal, headers })
    if (!res.ok) return { ok: false }
    const d = (await res.json()) as { status?: string }
    return { ok: d.status === 'ok' }
  } catch (err) {
    if (isAbortError(err) || signal?.aborted) throw isAbortError(err) ? err : abortError()
    return { ok: false }
  }
}

const LOCAL_FIREWALL_BASE = 'http://127.0.0.1:8011'

async function localPing(signal?: AbortSignal): Promise<boolean> {
  try {
    return (await fetch(LOCAL_FIREWALL_BASE + '/healthz', { signal })).ok
  } catch (err) {
    if (isAbortError(err) || signal?.aborted) throw isAbortError(err) ? err : abortError()
    return false
  }
}

/**
 * Poll until both the egress daemon and the proxy-mediated gate report healthy, or the budget expires.
 * Rounds are sequential and non-overlapping; each round requires both probes to succeed.
 */
export async function waitForFirewallReady(options: WaitForFirewallReadyOptions = {}): Promise<void> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_READY_TIMEOUT_MS
  const intervalMs = options.intervalMs ?? DEFAULT_READY_INTERVAL_MS
  const signal = options.signal
  const probePing = options.ping ?? daemonPing
  const probeGateway = options.gatewayHealth ?? gatewayHealth
  const deadline = Date.now() + timeoutMs

  for (;;) {
    throwIfAborted(signal)

    let daemonOk = false
    let gateOk = false
    try {
      daemonOk = await probePing(signal)
      throwIfAborted(signal)
      const health = await probeGateway(signal)
      gateOk = Boolean(health?.ok)
    } catch (err) {
      if (isAbortError(err) || signal?.aborted) {
        throw isAbortError(err) ? err : abortError()
      }
      daemonOk = false
      gateOk = false
    }

    if (daemonOk && gateOk) return

    throwIfAborted(signal)
    const remaining = deadline - Date.now()
    if (remaining <= 0) {
      throw new Error('Firewall services timed out waiting to become ready')
    }
    await sleep(Math.min(intervalMs, remaining), signal)
  }
}

/**
 * Poll fixed loopback health endpoints after starting desktop-managed local services.
 * Remote daemon overrides remain exclusive to waitForFirewallReady.
 */
export function waitForLocalFirewallReady(
  options: Pick<WaitForFirewallReadyOptions, 'timeoutMs' | 'intervalMs' | 'signal'> = {},
): Promise<void> {
  const { timeoutMs, intervalMs, signal } = options
  return waitForFirewallReady({
    timeoutMs,
    intervalMs,
    signal,
    ping: localPing,
    gatewayHealth: (probeSignal) => gatewayHealth(probeSignal, LOCAL_FIREWALL_BASE),
  })
}
