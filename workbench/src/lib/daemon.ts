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

// ---------------------------------------------------------------------------
// Runtime gate connection (off-device support). The operator can point this console at a gate running on
// ANOTHER machine (e.g. a tailnet host) WITHOUT rebuilding: the chosen address + optional control token are
// persisted in localStorage and take precedence over the build-time/injected defaults. A loopback gate needs
// no token; a remote gate that has GATEWAY_CONTROL_TOKEN set requires it (sent as a header on control fetches,
// and as ?token= on the SSE feed since EventSource cannot set headers). Storage-safe: a webview with storage
// disabled simply falls back to the injected/default base and behaves exactly as before.
//
// SECURITY TRADE-OFF (deliberate): the control token is persisted at rest so the tray-resident desktop app
// reconnects to an off-device gate across restarts without re-prompting -- that convenience is the whole point
// of off-device "ease of connection". The cost is a credential readable by same-origin script / local
// inspection, so this is appropriate only for the trusted single-user desktop/loopback surface, NOT a
// multi-tenant hosted console. The token only gates the control plane (proof feed + settings), never the LLM
// credential, which is always forwarded verbatim and never stored. Clear it with "Use this machine".
// ---------------------------------------------------------------------------
const LS_DAEMON = 'ossredact.daemon'
const LS_TOKEN = 'ossredact.token'

function lsGet(key: string): string {
  try {
    return (typeof localStorage !== 'undefined' && localStorage.getItem(key)) || ''
  } catch {
    return ''
  }
}
function lsSet(key: string, val: string): void {
  try {
    if (typeof localStorage === 'undefined') return
    if (val) localStorage.setItem(key, val)
    else localStorage.removeItem(key)
  } catch {
    /* storage disabled: the override just won't persist this session */
  }
}

/** The operator-set gate address override (empty when none). Highest precedence in daemonBase(). */
export function getDaemonOverride(): string {
  return lsGet(LS_DAEMON).replace(/\/$/, '')
}
/** Persist (or clear, when given '') the gate address override. Trailing slash trimmed. */
export function setDaemonOverride(url: string): void {
  lsSet(LS_DAEMON, url.trim().replace(/\/$/, ''))
}
/** The control token sent to authenticate against a remote gate (empty = none / loopback gate). */
export function getControlToken(): string {
  return lsGet(LS_TOKEN)
}
/** Persist (or clear, when given '') the control token. */
export function setControlToken(tok: string): void {
  lsSet(LS_TOKEN, tok.trim())
}

export function daemonBase(): string {
  // An explicit operator override (off-device gate) wins over everything.
  const override = getDaemonOverride()
  if (override) return override
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
    // Authenticate against a remote (off-device) gate when a control token is configured; a loopback gate
    // ignores it. Harmless when empty (header omitted) -> same wire as before for the local case.
    const tok = getControlToken()
    if (tok) headers['x-ossredact-control-token'] = tok
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

/** Result of probing a candidate gate address (the "Test connection" + discovery primitive). */
export interface ProbeResult {
  /** True only if a reachable endpoint positively identifies as an OSSRedact gate (service marker). */
  ok: boolean
  /** The normalized base that was probed. */
  base: string
  service?: string
  version?: string
  /** Whether the gate accepts authenticated off-device control (GATEWAY_CONTROL_TOKEN set). */
  remoteControl?: boolean
  status?: number
  error?: string
}

/**
 * Probe a candidate gate address by reading its public /healthz. Confirms it is really an OSSRedact gate
 * (not just any HTTP server) via the `service` marker, and reports its version + whether it accepts remote
 * control. Defaults to the current daemonBase(). Never throws -- failures come back as { ok: false }.
 */
export async function probe(base?: string): Promise<ProbeResult> {
  const b = (base ?? daemonBase()).replace(/\/$/, '')
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(b + '/healthz', { signal: ctrl.signal })
    if (!res.ok) return { ok: false, base: b, status: res.status }
    const body = (await res.json()) as Record<string, unknown>
    const service = typeof body?.service === 'string' ? body.service : undefined
    return {
      ok: service === 'ossredact-egress',
      base: b,
      service,
      version: typeof body?.version === 'string' ? body.version : undefined,
      remoteControl: body?.remote_control === true,
      status: res.status,
    }
  } catch (e) {
    return { ok: false, base: b, error: e instanceof Error ? e.message : 'unreachable' }
  } finally {
    clearTimeout(t)
  }
}

/** Result of an authenticated control round-trip against a candidate gate (before persisting). */
export interface VerifyResult {
  ok: boolean
  status?: number
  error?: string
}

/**
 * One authenticated control round-trip (GET /api/live/status) against an EXPLICIT base + token, used to
 * validate a control token BEFORE persisting it. /healthz is PUBLIC, so probe() alone cannot tell a correct
 * token from a wrong/empty one -- without this, a bad token reads green then every /api/* call 403s silently.
 * Never throws; a 403/401 means "reached the gate but the token is rejected".
 */
export async function verifyControl(base: string, token: string): Promise<VerifyResult> {
  const b = base.replace(/\/$/, '')
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS)
  try {
    const headers: Record<string, string> = {}
    if (token) headers['x-ossredact-control-token'] = token
    const res = await fetch(b + '/api/live/status', { headers, signal: ctrl.signal })
    return { ok: res.status === 200, status: res.status }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'unreachable' }
  } finally {
    clearTimeout(t)
  }
}

/** True when a base points at this machine's loopback (gate-side control is always allowed locally, no token). */
function isLoopbackBase(base: string): boolean {
  const b = base.trim()
  if (b === '' || b.startsWith('/')) return true   // same-origin / relative -> served from this machine
  try {
    const h = new URL(b).hostname.replace(/^\[|\]$/g, '')
    return h === '127.0.0.1' || h === 'localhost' || h === '::1'
  } catch {
    return false
  }
}

export type ConnectReason = 'unreachable' | 'not-a-gate' | 'no-remote-control' | 'unauthorized' | 'error'

export type ConnectOutcome =
  | { ok: true; result: ProbeResult }
  | { ok: false; reason: ConnectReason; result: ProbeResult; status?: number }

/**
 * Connect this console to a gate END-TO-END, persisting the address + token ONLY when control access is
 * actually authorized -- not merely when the public /healthz answers (the "reads green then silently 403s"
 * bug). Steps: (1) probe /healthz; (2) a NON-loopback gate reporting no remote control (GATEWAY_CONTROL_TOKEN
 * unset) is refused -- every /api/* would 403; (3) a remote-control gate gets ONE authenticated round-trip and
 * persists only on 200, surfacing a distinct 'unauthorized' on 403/401; (4) a loopback gate needs no token and
 * persists directly. Never weakens the gate-side constant-time token check or the stream-only query-token rule.
 */
export async function connectGate(base: string, token: string): Promise<ConnectOutcome> {
  const b = base.trim().replace(/\/$/, '')
  const tok = token.trim()
  const result = await probe(b)
  if (!result.ok) {
    return { ok: false, reason: result.status ? 'not-a-gate' : 'unreachable', result, status: result.status }
  }
  if (!result.remoteControl) {
    if (!isLoopbackBase(b)) {
      return { ok: false, reason: 'no-remote-control', result }   // remote gate has no token -> uncontrollable
    }
    setDaemonOverride(b)   // loopback: control is always allowed locally, no token required
    setControlToken(tok)
    return { ok: true, result }
  }
  const v = await verifyControl(b, tok)
  if (v.ok) {
    setDaemonOverride(b)
    setControlToken(tok)
    return { ok: true, result }
  }
  if (v.status === 403 || v.status === 401) {
    return { ok: false, reason: 'unauthorized', result, status: v.status }
  }
  return { ok: false, reason: 'error', result, status: v.status }
}

/**
 * Heuristic: does connecting THIS console (running at `consoleProtocol`) to `gateBase` risk a browser
 * mixed-content block? A secure console origin (an https: hosted build, or the Tauri tauri:// webview) cannot
 * fetch()/EventSource a plain http:// REMOTE gate -- the browser silently blocks it, so the off-device feature
 * appears broken from exactly the surface it targets. A loopback http gate (localhost / 127.0.0.1 / ::1) is
 * exempt: browsers treat it as potentially-trustworthy. Mixed-content behaviour is webview/OS-specific, so this
 * drives an ADVISORY warning, never a hard block.
 */
export function mixedContentRisk(gateBase: string, consoleProtocol: string): boolean {
  const g = gateBase.trim()
  if (!/^http:\/\//i.test(g)) return false   // https gate, relative, or same-origin -> no mixed content
  try {
    const h = new URL(g).hostname.replace(/^\[|\]$/g, '')
    if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return false   // loopback gate is trustworthy
  } catch {
    return false
  }
  const p = (consoleProtocol || '').toLowerCase()
  return p === 'https:' || p === 'tauri:'   // secure console + remote http gate = blocked
}

/**
 * True when the gate base is a non-loopback `http://` address: the redaction traffic AND the live PII proof
 * feed travel in CLEARTEXT over the network, and `/v1/*` on such a gate is an unauthenticated relay. Distinct
 * from mixedContentRisk (which is about a SECURE console being browser-blocked); this fires regardless of the
 * console's own scheme, so a plain-http console talking to a remote http gate -- which works, but insecurely --
 * still gets warned.
 */
export function cleartextRisk(gateBase: string): boolean {
  const g = gateBase.trim()
  if (!/^http:\/\//i.test(g)) return false   // https gate, relative, or same-origin -> encrypted / local
  try {
    const h = new URL(g).hostname.replace(/^\[|\]$/g, '')
    return !(h === 'localhost' || h === '127.0.0.1' || h === '::1')
  } catch {
    return false
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
  // EventSource cannot set headers, so a remote gate's control token rides as ?token= (loopback gate: omitted).
  const tok = getControlToken()
  const url = daemonBase() + '/api/stream' + (tok ? `?token=${encodeURIComponent(tok)}` : '')
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
