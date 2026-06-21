// Client for the local OSSRedact egress daemon (the always-on firewall).
//
// The daemon serves a loopback-only control API (allowlist, live-activity SSE, health). The Workbench
// (document redaction) NEVER needs this -- it runs fully in-browser, offline. Only the Firewall console
// tabs use it, and they degrade gracefully when no daemon is reachable (plain browser, firewall not running).
//
// Origin: when the console is served BY the daemon (or wrapped in the Tauri app pointing at the daemon),
// requests are same-origin. When the console is a standalone static web app on another port, requests are
// cross-origin to 127.0.0.1:8011 and rely on the daemon's loopback-CORS headers (see egress_proxy CORS).
// Base URL is overridable via VITE_OSSREDACT_DAEMON or window.__OSSREDACT_DAEMON__ (the Tauri shell sets it).

// Same-origin by default: works when the console is served BY the daemon, and in dev via the Vite proxy
// (/api + /healthz -> the daemon, see vite.config.ts). The Tauri shell injects window.__OSSREDACT_DAEMON__
// to point at the supervised daemon; a hosted static deploy can set VITE_OSSREDACT_DAEMON (cross-origin then
// needs the daemon's loopback-CORS headers).
export const DEFAULT_DAEMON = ''

export function daemonBase(): string {
  const w = typeof window !== 'undefined' ? (window as unknown as { __OSSREDACT_DAEMON__?: string }) : undefined
  const fromWin = w?.__OSSREDACT_DAEMON__
  // Direct member access (not a cast) so Vite's build-time replacement and vitest's vi.stubEnv both apply.
  const fromEnv = import.meta.env?.VITE_OSSREDACT_DAEMON
  return (fromWin || fromEnv || DEFAULT_DAEMON).replace(/\/$/, '')
}

/**
 * The concrete loopback address a coding agent on THIS machine should point at. daemonBase() is '' when the
 * console is served same-origin by the daemon, so fall back to the page origin (the daemon's own address),
 * then to the documented default. Always an absolute URL the user can paste into ANTHROPIC_BASE_URL.
 */
export function connectBase(): string {
  const b = daemonBase()
  if (b) return b
  const origin = typeof window !== 'undefined' ? window.location?.origin : ''
  return origin || 'http://127.0.0.1:8011'
}

// ---- response shapes (mirror appliance/egress_proxy.py) ----
export interface AllowlistState {
  values: string[]
  active_total: number
  config_values: number
  path: string
}

export interface LiveStatus {
  enabled: boolean
  buffered: number
  max: number
  subscribers: number
}

export interface HealthState {
  ok: boolean
  // /healthz payload is best-effort; we only rely on reachability + ok.
  [k: string]: unknown
}

// A live-activity event off /api/stream. `kind` is 'request' (outbound: what was redacted before forwarding)
// or 'response' (inbound rehydration). Entities carry the REAL value -> placeholder mapping (the proof); they
// are loopback-only and never persisted.
export interface LiveEntity {
  placeholder: string
  value: string
  label: string
}
export interface LiveEvent {
  seq: number
  ts: number
  kind: string
  route: string
  client: string
  session: string
  redaction?: string
  n_spans?: number
  n_new?: number
  n_swept?: number
  by_label?: Record<string, number>
  degraded?: boolean
  stream?: boolean
  entities?: LiveEntity[]
}

const TIMEOUT_MS = 4000

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS)
  try {
    // State-changing control calls carry a non-safelisted custom header so the daemon's CSRF guard accepts
    // them. Cross-origin = the daemon preflights it (allowed only for loopback/Tauri origins); GETs skip it
    // to avoid a needless preflight on every read.
    const headers: Record<string, string> = { ...(init?.headers as Record<string, string> | undefined) }
    if (init?.method && init.method.toUpperCase() !== 'GET') headers['x-ossredact-control'] = '1'
    const res = await fetch(daemonBase() + path, { ...init, headers, signal: ctrl.signal })
    if (!res.ok) throw new DaemonError(`${path} -> ${res.status}`, res.status)
    return (await res.json()) as T
  } finally {
    clearTimeout(t)
  }
}

export class DaemonError extends Error {
  status?: number
  constructor(message: string, status?: number) {
    super(message)
    this.name = 'DaemonError'
    this.status = status
  }
}

/** True if the daemon answers /healthz. Used to drive graceful degradation. */
export async function ping(): Promise<boolean> {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(daemonBase() + '/healthz', { signal: ctrl.signal })
    return res.ok
  } catch {
    return false
  } finally {
    clearTimeout(t)
  }
}

export const getAllowlist = () => jsonFetch<AllowlistState>('/api/allowlist')

export const setAllowlist = (values: string[]) =>
  jsonFetch<{ ok: boolean; values: string[]; active_total: number }>('/api/allowlist', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ values }),
  })

// The always-redact denylist mirrors the allowlist endpoints + response shape (values/active_total/
// config_values/path). It is the INVERSE list: terms force-redacted even when the model misses them.
export const getDenylist = () => jsonFetch<AllowlistState>('/api/denylist')

export const setDenylist = (values: string[]) =>
  jsonFetch<{ ok: boolean; values: string[]; active_total: number }>('/api/denylist', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ values }),
  })

export const getLiveStatus = () => jsonFetch<LiveStatus>('/api/live/status')

export const clearLive = () =>
  jsonFetch<{ ok: boolean }>('/api/live/clear', { method: 'POST' })

export type RedactionMode = 'privacy' | 'coding' | 'off'

export interface SettingsState {
  mode: RedactionMode
  modes: RedactionMode[]
  /** The deterministic floor (secrets/cards/IDs) redacts in every mode -- 'off' is never a credential bypass. */
  floor_always_on: boolean
  path: string
}

export const getSettings = () => jsonFetch<SettingsState>('/api/settings')

export const setMode = (mode: RedactionMode) =>
  jsonFetch<{ ok: boolean; mode: RedactionMode }>('/api/settings', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ mode }),
  })

/**
 * Subscribe to the live-activity SSE feed. Returns an unsubscribe fn. `onEvent` receives each parsed
 * LiveEvent (backlog first, then live). `onState` reports connection transitions for UI status. The
 * EventSource auto-reconnects; call the returned fn to close it.
 */
export function subscribeLive(
  onEvent: (ev: LiveEvent) => void,
  onState?: (s: 'connecting' | 'open' | 'error') => void,
): () => void {
  const url = daemonBase() + '/api/stream'
  let es: EventSource | null = null
  let closed = false
  try {
    es = new EventSource(url)
  } catch {
    onState?.('error')
    return () => {}
  }
  onState?.('connecting')
  es.onopen = () => onState?.('open')
  es.onerror = () => onState?.('error')
  es.onmessage = (m) => {
    if (closed || !m.data) return
    try {
      onEvent(JSON.parse(m.data) as LiveEvent)
    } catch {
      /* keep-alive comment or malformed line: ignore */
    }
  }
  return () => {
    closed = true
    es?.close()
  }
}
