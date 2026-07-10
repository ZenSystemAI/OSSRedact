// Tests for the OSSRedact egress-daemon client in daemon.ts.
//
// The network is fully mocked -- no real daemon is ever contacted. `fetch` is
// replaced with vi.stubGlobal fakes so every path (ok / non-ok / throw / SSE
// transitions) is deterministic and offline. All values are synthetic; no real PII.
// Phase 3 remote-control contract: session-only control token, fetch-based SSE with
// X-OSSRedact-Control-Token header (never a query token), incremental data: parse,
// abortable reconnect, and unsubscribe cleanup.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  daemonBase,
  ping,
  probe,
  verifyControl,
  connectGate,
  mixedContentRisk,
  cleartextRisk,
  getAllowlist,
  setAllowlist,
  getDenylist,
  getSettings,
  getLiveStatus,
  clearLive,
  subscribeLive,
  getDaemonOverride,
  setDaemonOverride,
  getControlToken,
  setControlToken,
  DaemonError,
  DEFAULT_DAEMON,
  type LiveEvent,
} from './daemon'

// ---------------------------------------------------------------------------
// fetch fakes
// ---------------------------------------------------------------------------

// A minimal Response-like object. `ok` derives from status the way the real Response does so
// non-2xx tests stay honest. `json()` returns the supplied body.
function fakeResponse(body: unknown, init?: { status?: number; ok?: boolean }): Response {
  const status = init?.status ?? 200
  const ok = init?.ok ?? (status >= 200 && status < 300)
  return {
    ok,
    status,
    json: async () => body,
  } as unknown as Response
}

// Records every fetch call (url + init) and returns whatever the queued handler produces.
interface FetchCall {
  url: string
  init?: RequestInit
}

function installFetch(handler: (url: string, init?: RequestInit) => Promise<Response>): FetchCall[] {
  const calls: FetchCall[] = []
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    calls.push({ url, init })
    return handler(url, init)
  })
  vi.stubGlobal('fetch', fn)
  return calls
}

/** Case-insensitive header lookup for RequestInit headers (plain object, Headers, or tuples). */
function headerOf(init: RequestInit | undefined, name: string): string | undefined {
  const h = init?.headers
  if (!h) return undefined
  if (typeof Headers !== 'undefined' && h instanceof Headers) {
    return h.get(name) ?? undefined
  }
  if (Array.isArray(h)) {
    const hit = h.find(([k]) => k.toLowerCase() === name.toLowerCase())
    return hit?.[1]
  }
  const rec = h as Record<string, string>
  const key = Object.keys(rec).find((k) => k.toLowerCase() === name.toLowerCase())
  return key ? rec[key] : undefined
}

const LS_TOKEN = 'ossredact.token'
const LS_DAEMON = 'ossredact.daemon'

const sampleLive: LiveEvent = {
  seq: 1,
  ts: 1718900000,
  kind: 'request',
  route: '/v1/messages',
  client: 'claude-code',
  session: 'sess-1',
  n_spans: 2,
  by_label: { email: 1, person: 1 },
  entities: [{ placeholder: '<EMAIL_001>', value: 'a@example.test', label: 'email' }],
}

// Controllable SSE body: tests push chunks, close, or error the stream.
class ControllableSseBody {
  private controller: ReadableStreamDefaultController<Uint8Array> | null = null
  private closed = false
  readonly stream: ReadableStream<Uint8Array>

  constructor() {
    this.stream = new ReadableStream<Uint8Array>({
      start: (c) => {
        this.controller = c
      },
      cancel: () => {
        this.closed = true
        this.controller = null
      },
    })
  }

  push(text: string): void {
    if (this.closed || !this.controller) return
    this.controller.enqueue(new TextEncoder().encode(text))
  }

  close(): void {
    if (this.closed || !this.controller) return
    this.closed = true
    this.controller.close()
    this.controller = null
  }

  error(err: unknown = new Error('stream reset')): void {
    if (this.closed || !this.controller) return
    this.closed = true
    this.controller.error(err)
    this.controller = null
  }

  get cancelled(): boolean {
    return this.closed
  }
}

function fakeSseResponse(body: ControllableSseBody, init?: { status?: number }): Response {
  const status = init?.status ?? 200
  const ok = status >= 200 && status < 300
  return {
    ok,
    status,
    body: body.stream,
    headers: new Headers({ 'content-type': 'text/event-stream' }),
  } as unknown as Response
}

// ---------------------------------------------------------------------------
// daemonBase()
// ---------------------------------------------------------------------------
describe('daemonBase', () => {
  afterEach(() => {
    delete (window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__
    vi.unstubAllEnvs()
  })

  it('defaults to the empty same-origin base (DEFAULT_DAEMON)', () => {
    expect(daemonBase()).toBe(DEFAULT_DAEMON)
    expect(daemonBase()).toBe('')
  })

  it('prefers the window.__OSSREDACT_DAEMON__ injection over the env override', () => {
    ;(window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__ = 'http://127.0.0.1:8011'
    vi.stubEnv('VITE_OSSREDACT_DAEMON', 'http://env.example:9000')
    expect(daemonBase()).toBe('http://127.0.0.1:8011')
  })

  it('falls back to VITE_OSSREDACT_DAEMON when no window injection is set', () => {
    vi.stubEnv('VITE_OSSREDACT_DAEMON', 'http://daemon.local:9000')
    expect(daemonBase()).toBe('http://daemon.local:9000')
  })

  it('strips a trailing slash from the window injection', () => {
    ;(window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__ = 'http://127.0.0.1:8011/'
    expect(daemonBase()).toBe('http://127.0.0.1:8011')
  })

  it('strips a trailing slash from the env override too', () => {
    vi.stubEnv('VITE_OSSREDACT_DAEMON', 'http://daemon.local:9000/')
    expect(daemonBase()).toBe('http://daemon.local:9000')
  })
})

// ---------------------------------------------------------------------------
// ping()
// ---------------------------------------------------------------------------
describe('ping', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    delete (window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__
  })

  it('returns true when /healthz answers ok', async () => {
    const calls = installFetch(async () => fakeResponse({ ok: true }, { status: 200 }))
    await expect(ping()).resolves.toBe(true)
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toBe('/healthz') // same-origin default -> '' + '/healthz'
  })

  it('returns false when /healthz responds non-ok', async () => {
    installFetch(async () => fakeResponse({ ok: false }, { status: 503 }))
    await expect(ping()).resolves.toBe(false)
  })

  it('returns false when fetch throws (no daemon reachable -> graceful degrade)', async () => {
    installFetch(async () => {
      throw new TypeError('Failed to fetch')
    })
    await expect(ping()).resolves.toBe(false)
  })

  it('hits the configured base origin when one is set', async () => {
    ;(window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__ = 'http://127.0.0.1:8011'
    const calls = installFetch(async () => fakeResponse({ ok: true }))
    await ping()
    expect(calls[0].url).toBe('http://127.0.0.1:8011/healthz')
  })
})

// ---------------------------------------------------------------------------
// getAllowlist / setAllowlist
// ---------------------------------------------------------------------------
describe('getAllowlist', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('GETs /api/allowlist and parses the path-free AllowlistState body', async () => {
    // Phase 4: allowlist/denylist/settings JSON omit host filesystem path; fixtures match the new shape.
    const body = { values: ['acme', 'quickcredit'], active_total: 2, config_values: 1 }
    const calls = installFetch(async () => fakeResponse(body))
    const res = await getAllowlist()
    expect(res).toEqual(body)
    expect('path' in res).toBe(false)
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toBe('/api/allowlist')
    // GET: no explicit method passed -> init.method is undefined
    expect(calls[0].init?.method).toBeUndefined()
  })

  it('throws a DaemonError carrying the HTTP status on a non-2xx response', async () => {
    installFetch(async () => fakeResponse({ error: 'boom' }, { status: 500 }))
    await expect(getAllowlist()).rejects.toBeInstanceOf(DaemonError)
    await expect(getAllowlist()).rejects.toMatchObject({ status: 500 })
  })

  it('the thrown DaemonError message names the path and status', async () => {
    installFetch(async () => fakeResponse({}, { status: 404 }))
    await expect(getAllowlist()).rejects.toThrow('/api/allowlist -> 404')
  })

  it('accepts allowlist JSON that has counts/state without a path field', async () => {
    const body = { values: ['acme'], active_total: 1, config_values: 0 }
    installFetch(async () => fakeResponse(body))
    const res = await getAllowlist()
    expect(res.values).toEqual(['acme'])
    expect(res.active_total).toBe(1)
    expect(res.config_values).toBe(0)
    expect(Object.prototype.hasOwnProperty.call(res, 'path')).toBe(false)
  })
})

describe('path-free control API fixtures', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('getDenylist accepts counts/state JSON without a path field', async () => {
    const body = { values: ['bluebird'], active_total: 1, config_values: 0 }
    installFetch(async () => fakeResponse(body))
    const res = await getDenylist()
    expect(res).toEqual(body)
    expect(Object.prototype.hasOwnProperty.call(res, 'path')).toBe(false)
  })

  it('getSettings accepts mode/state JSON without a path field', async () => {
    const body = {
      mode: 'privacy' as const,
      modes: ['privacy', 'coding', 'off'] as const,
      floor_always_on: true,
    }
    installFetch(async () => fakeResponse(body))
    const res = await getSettings()
    expect(res.mode).toBe('privacy')
    expect(res.floor_always_on).toBe(true)
    expect(res.modes).toEqual(['privacy', 'coding', 'off'])
    expect(Object.prototype.hasOwnProperty.call(res, 'path')).toBe(false)
  })
})

describe('setAllowlist', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('POSTs /api/allowlist with a JSON {"values":[...]} body and content-type', async () => {
    const reply = { ok: true, values: ['acme'], active_total: 1 }
    const calls = installFetch(async () => fakeResponse(reply))
    const res = await setAllowlist(['acme', 'quickcredit'])
    expect(res).toEqual(reply)

    expect(calls).toHaveLength(1)
    const { url, init } = calls[0]
    expect(url).toBe('/api/allowlist')
    expect(init?.method).toBe('POST')
    expect((init?.headers as Record<string, string>)['content-type']).toBe('application/json')
    // the body is exactly {"values":[...]}
    expect(init?.body).toBe('{"values":["acme","quickcredit"]}')
    expect(JSON.parse(init?.body as string)).toEqual({ values: ['acme', 'quickcredit'] })
  })

  it('serializes an empty allowlist as {"values":[]}', async () => {
    const calls = installFetch(async () => fakeResponse({ ok: true, values: [], active_total: 0 }))
    await setAllowlist([])
    expect(calls[0].init?.body).toBe('{"values":[]}')
  })

  it('throws DaemonError with the status when the POST is rejected', async () => {
    installFetch(async () => fakeResponse({}, { status: 422 }))
    await expect(setAllowlist(['x'])).rejects.toMatchObject({
      name: 'DaemonError',
      status: 422,
    })
  })
})

// ---------------------------------------------------------------------------
// getLiveStatus / clearLive
// ---------------------------------------------------------------------------
describe('getLiveStatus', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('GETs /api/live/status and parses the LiveStatus body', async () => {
    const body = { enabled: true, buffered: 7, max: 500, subscribers: 2 }
    const calls = installFetch(async () => fakeResponse(body))
    const res = await getLiveStatus()
    expect(res).toEqual(body)
    expect(calls[0].url).toBe('/api/live/status')
    expect(calls[0].init?.method).toBeUndefined() // GET
  })

  it('throws DaemonError with the status on failure', async () => {
    installFetch(async () => fakeResponse({}, { status: 500 }))
    await expect(getLiveStatus()).rejects.toMatchObject({ status: 500 })
  })
})

describe('clearLive', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('POSTs /api/live/clear and parses the {ok} body', async () => {
    const calls = installFetch(async () => fakeResponse({ ok: true }))
    const res = await clearLive()
    expect(res).toEqual({ ok: true })
    expect(calls[0].url).toBe('/api/live/clear')
    expect(calls[0].init?.method).toBe('POST')
  })

  it('throws DaemonError with the status on failure', async () => {
    installFetch(async () => fakeResponse({}, { status: 503 }))
    await expect(clearLive()).rejects.toMatchObject({ status: 503 })
  })
})

// ---------------------------------------------------------------------------
// subscribeLive() -- fetch-based SSE (Phase 3)
// ---------------------------------------------------------------------------
describe('subscribeLive', () => {
  let bodies: ControllableSseBody[]
  let calls: FetchCall[]

  beforeEach(() => {
    bodies = []
    vi.useFakeTimers()
    try { localStorage.clear() } catch { /* storage off */ }
    setControlToken('')
    setDaemonOverride('')
    delete (window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__
    calls = installFetch(async () => {
      const body = new ControllableSseBody()
      bodies.push(body)
      // yield so subscribeLive can wire readers before we push
      return fakeSseResponse(body)
    })
  })

  afterEach(() => {
    try { localStorage.clear() } catch { /* storage off */ }
    setControlToken('')
    setDaemonOverride('')
    delete (window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  async function flushMicrotasks(times = 8): Promise<void> {
    for (let i = 0; i < times; i++) {
      await Promise.resolve()
    }
  }

  it('opens a fetch stream against /api/stream on the daemon base (no EventSource)', async () => {
    ;(window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__ = 'http://127.0.0.1:8011'
    const unsub = subscribeLive(() => {})
    await flushMicrotasks()
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toBe('http://127.0.0.1:8011/api/stream')
    expect(calls[0].url).not.toMatch(/[?&]token=/)
    unsub()
  })

  it('reports connecting then open when the stream response is ok', async () => {
    const states: string[] = []
    const unsub = subscribeLive(() => {}, (s) => states.push(s))
    expect(states[0]).toBe('connecting')
    await flushMicrotasks()
    expect(states).toContain('open')
    unsub()
  })

  it('parses incremental data: frames into LiveEvent objects (including split chunks)', async () => {
    const events: LiveEvent[] = []
    const unsub = subscribeLive((ev) => events.push(ev))
    await flushMicrotasks()
    expect(bodies).toHaveLength(1)

    const json = JSON.stringify(sampleLive)
    // Split mid-payload so the reader must reassemble across chunks.
    bodies[0].push(`data: ${json.slice(0, 12)}`)
    await flushMicrotasks()
    expect(events).toHaveLength(0)

    bodies[0].push(`${json.slice(12)}\n\n`)
    await flushMicrotasks()
    expect(events).toHaveLength(1)
    expect(events[0]).toEqual(sampleLive)
    expect(events[0].entities?.[0].placeholder).toBe('<EMAIL_001>')
    unsub()
  })

  it('delivers multiple data: events from one stream body', async () => {
    const events: LiveEvent[] = []
    const unsub = subscribeLive((ev) => events.push(ev))
    await flushMicrotasks()

    const second: LiveEvent = { ...sampleLive, seq: 2, session: 'sess-2' }
    bodies[0].push(
      `data: ${JSON.stringify(sampleLive)}\n\n` +
        `: keep-alive\n\n` +
        `data: ${JSON.stringify(second)}\n\n`,
    )
    await flushMicrotasks()
    expect(events).toHaveLength(2)
    expect(events[0].seq).toBe(1)
    expect(events[1].seq).toBe(2)
    unsub()
  })

  it('ignores malformed JSON data lines without throwing or invoking onEvent', async () => {
    const events: LiveEvent[] = []
    const unsub = subscribeLive((ev) => events.push(ev))
    await flushMicrotasks()
    bodies[0].push('data: { this is not json\n\n')
    await flushMicrotasks()
    expect(events).toHaveLength(0)
    unsub()
  })

  it('ignores comments / empty data lines (no onEvent, no throw)', async () => {
    const events: LiveEvent[] = []
    const unsub = subscribeLive((ev) => events.push(ev))
    await flushMicrotasks()
    bodies[0].push(': ping\n\ndata:\n\ndata: \n\n')
    await flushMicrotasks()
    expect(events).toHaveLength(0)
    unsub()
  })

  it('sends X-OSSRedact-Control-Token on the stream fetch and never puts the token in the URL', async () => {
    setControlToken('tok-xyz')
    const unsub = subscribeLive(() => {})
    await flushMicrotasks()
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toBe('/api/stream')
    expect(calls[0].url).not.toMatch(/[?&]token=/)
    // Canonical header name (HTTP is case-insensitive; assert presence + value).
    expect(headerOf(calls[0].init, 'X-OSSRedact-Control-Token')).toBe('tok-xyz')
    unsub()
  })

  it('omits the control-token header on the stream when no token is set', async () => {
    const unsub = subscribeLive(() => {})
    await flushMicrotasks()
    expect(headerOf(calls[0].init, 'X-OSSRedact-Control-Token')).toBeUndefined()
    unsub()
  })

  it('passes an AbortSignal on the stream fetch so unsubscribe can cancel the body', async () => {
    const unsub = subscribeLive(() => {})
    await flushMicrotasks()
    expect(calls[0].init?.signal).toBeInstanceOf(AbortSignal)
    expect(calls[0].init?.signal?.aborted).toBe(false)
    unsub()
    expect(calls[0].init?.signal?.aborted).toBe(true)
  })

  it('reconnects after a transient stream error with a bounded delay and reuses header auth', async () => {
    setControlToken('sess-tok')
    ;(window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__ = 'http://127.0.0.1:8011'
    const states: string[] = []
    const unsub = subscribeLive(() => {}, (s) => states.push(s))
    await flushMicrotasks()
    expect(calls).toHaveLength(1)

    // Transient failure on the open body.
    bodies[0].error(new TypeError('network reset'))
    await flushMicrotasks()
    expect(states).toContain('error')
    expect(calls).toHaveLength(1) // not immediate; delay first

    // Bounded reconnect delay: fire within 5s, not zero.
    await vi.advanceTimersByTimeAsync(0)
    expect(calls.length).toBe(1)
    await vi.advanceTimersByTimeAsync(5_000)
    await flushMicrotasks()
    expect(calls.length).toBeGreaterThanOrEqual(2)
    expect(calls[1].url).toBe('http://127.0.0.1:8011/api/stream')
    expect(calls[1].url).not.toMatch(/[?&]token=/)
    expect(headerOf(calls[1].init, 'X-OSSRedact-Control-Token')).toBe('sess-tok')
    unsub()
  })

  it('unsubscribe aborts the active stream and prevents a pending reconnect', async () => {
    const states: string[] = []
    const unsub = subscribeLive(() => {}, (s) => states.push(s))
    await flushMicrotasks()
    expect(calls).toHaveLength(1)
    const firstSignal = calls[0].init?.signal

    bodies[0].error(new TypeError('stream drop'))
    await flushMicrotasks()
    expect(states).toContain('error')

    // Unsubscribe while a reconnect is scheduled.
    unsub()
    expect(firstSignal?.aborted).toBe(true)

    await vi.advanceTimersByTimeAsync(10_000)
    await flushMicrotasks()
    expect(calls).toHaveLength(1) // no second connect after unsubscribe
  })

  it('drops events after unsubscribe (closed guard)', async () => {
    const events: LiveEvent[] = []
    const unsub = subscribeLive((ev) => events.push(ev))
    await flushMicrotasks()
    unsub()
    bodies[0].push(`data: ${JSON.stringify(sampleLive)}\n\n`)
    await flushMicrotasks()
    expect(events).toHaveLength(0)
  })

  it('reports error state when the stream response is non-ok', async () => {
    vi.unstubAllGlobals()
    const localCalls: FetchCall[] = []
    const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString()
      localCalls.push({ url, init })
      return fakeResponse({ error: 'no' }, { status: 503 })
    })
    vi.stubGlobal('fetch', fn)

    const states: string[] = []
    const unsub = subscribeLive(() => {}, (s) => states.push(s))
    await flushMicrotasks()
    expect(states).toContain('error')
    expect(() => unsub()).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// off-device gate connection: address override (persisted) + session-only token
// ---------------------------------------------------------------------------
describe('gate connection override', () => {
  beforeEach(() => {
    try { localStorage.clear() } catch { /* storage off */ }
    setControlToken('')
    setDaemonOverride('')
  })
  afterEach(() => {
    try { localStorage.clear() } catch { /* storage off */ }
    setControlToken('')
    setDaemonOverride('')
    delete (window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__
    vi.unstubAllEnvs()
  })

  it('an operator override wins over the window injection AND the env override', () => {
    setDaemonOverride('http://gate-host:8011')
    ;(window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__ = 'http://127.0.0.1:8011'
    vi.stubEnv('VITE_OSSREDACT_DAEMON', 'http://env.example:9000')
    expect(daemonBase()).toBe('http://gate-host:8011')
    expect(getDaemonOverride()).toBe('http://gate-host:8011')
  })

  it('strips a trailing slash on save and clearing falls back to the default chain', () => {
    setDaemonOverride('http://gate-host:8011/')
    expect(daemonBase()).toBe('http://gate-host:8011')
    setDaemonOverride('')
    expect(getDaemonOverride()).toBe('')
    expect(daemonBase()).toBe('') // back to same-origin default
  })

  it('holds a trimmed control token in session memory only (never under ossredact.token)', () => {
    setControlToken('  s3cret-token  ')
    expect(getControlToken()).toBe('s3cret-token')
    expect(localStorage.getItem(LS_TOKEN)).toBeNull()
    // Address key remains the only persisted connection secret-adjacent surface (non-secret URL).
    setDaemonOverride('http://gate-host:8011')
    expect(localStorage.getItem(LS_DAEMON)).toBe('http://gate-host:8011')
    expect(localStorage.getItem(LS_TOKEN)).toBeNull()

    setControlToken('')
    expect(getControlToken()).toBe('')
    expect(localStorage.getItem(LS_TOKEN)).toBeNull()
  })

  it('does not read a stale ossredact.token value left in localStorage', () => {
    localStorage.setItem(LS_TOKEN, 'stale-from-previous-build')
    expect(getControlToken()).toBe('')
    setControlToken('fresh-session')
    expect(getControlToken()).toBe('fresh-session')
    expect(localStorage.getItem(LS_TOKEN)).toBe('stale-from-previous-build') // untouched
  })
})

describe('control-token request wiring', () => {
  beforeEach(() => {
    try { localStorage.clear() } catch { /* storage off */ }
    setControlToken('')
  })
  afterEach(() => {
    try { localStorage.clear() } catch { /* storage off */ }
    setControlToken('')
    vi.unstubAllGlobals()
  })

  it('attaches x-ossredact-control-token to control fetches when a token is set', async () => {
    setControlToken('tok-123')
    const calls = installFetch(async () =>
      fakeResponse({ values: [], active_total: 0, config_values: 0 }))
    await getAllowlist()
    expect(headerOf(calls[0].init, 'x-ossredact-control-token')).toBe('tok-123')
    expect(localStorage.getItem(LS_TOKEN)).toBeNull()
  })

  it('omits the token header entirely when no token is set (local gate wire unchanged)', async () => {
    const calls = installFetch(async () =>
      fakeResponse({ values: [], active_total: 0, config_values: 0 }))
    await getAllowlist()
    expect(headerOf(calls[0].init, 'x-ossredact-control-token')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// probe() -- the "Test connection" + discovery primitive
// ---------------------------------------------------------------------------
describe('probe', () => {
  afterEach(() => {
    try { localStorage.clear() } catch { /* storage off */ }
    vi.unstubAllGlobals()
  })

  it('confirms an OSSRedact gate and reports version + remoteControl', async () => {
    installFetch(async () =>
      fakeResponse({ status: 'ok', service: 'ossredact-egress', version: '0.2.0', remote_control: true }))
    const r = await probe('http://gate-host:8011/')
    expect(r.ok).toBe(true)
    expect(r.base).toBe('http://gate-host:8011') // trailing slash normalized
    expect(r.service).toBe('ossredact-egress')
    expect(r.version).toBe('0.2.0')
    expect(r.remoteControl).toBe(true)
  })

  it('is NOT ok when a reachable endpoint is not an OSSRedact gate', async () => {
    installFetch(async () => fakeResponse({ hello: 'world' }))
    const r = await probe('http://nginx.example')
    expect(r.ok).toBe(false)
    expect(r.service).toBeUndefined()
  })

  it('reports the HTTP status on a non-2xx /healthz', async () => {
    installFetch(async () => fakeResponse({}, { status: 502 }))
    const r = await probe('http://x:1')
    expect(r.ok).toBe(false)
    expect(r.status).toBe(502)
  })

  it('returns { ok:false, error } when the host is unreachable (never throws)', async () => {
    installFetch(async () => {
      throw new TypeError('Failed to fetch')
    })
    const r = await probe('http://nope:1')
    expect(r.ok).toBe(false)
    expect(r.error).toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// verifyControl() + connectGate() -- authorize before accepting a session token
// ---------------------------------------------------------------------------
describe('verifyControl', () => {
  afterEach(() => { try { localStorage.clear() } catch { /* off */ } ; vi.unstubAllGlobals() })

  it('sends the token header to /api/live/status and is ok only on 200', async () => {
    const calls = installFetch(async () => fakeResponse({ enabled: true }, { status: 200 }))
    const v = await verifyControl('http://gate-host:8011/', 'tok-123')
    expect(v.ok).toBe(true)
    expect(v.status).toBe(200)
    expect(calls[0].url).toBe('http://gate-host:8011/api/live/status')
    expect(headerOf(calls[0].init, 'x-ossredact-control-token')).toBe('tok-123')
  })

  it('is not ok on a 403 (token rejected)', async () => {
    installFetch(async () => fakeResponse({ error: 'local-only' }, { status: 403 }))
    const v = await verifyControl('http://gate-host:8011', 'wrong')
    expect(v.ok).toBe(false)
    expect(v.status).toBe(403)
  })
})

describe('connectGate', () => {
  beforeEach(() => {
    try { localStorage.clear() } catch { /* off */ }
    setControlToken('')
    setDaemonOverride('')
  })
  afterEach(() => {
    try { localStorage.clear() } catch { /* off */ }
    setControlToken('')
    setDaemonOverride('')
    vi.unstubAllGlobals()
    delete (window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__
  })

  // /healthz OK but the control token is wrong -> do NOT accept session state.
  it('does NOT accept connection state when /healthz is OK but /api/live/status returns 403', async () => {
    const calls = installFetch(async (url) => {
      if (url.endsWith('/healthz')) return fakeResponse({ service: 'ossredact-egress', version: '0.2.0', remote_control: true })
      if (url.endsWith('/api/live/status')) return fakeResponse({ error: 'local-only' }, { status: 403 })
      return fakeResponse({}, { status: 404 })
    })
    const o = await connectGate('http://gate-host:8011', 'wrong-token')
    expect(o.ok).toBe(false)
    expect(o).toMatchObject({ reason: 'unauthorized', status: 403 })
    expect(getDaemonOverride()).toBe('')   // nothing accepted
    expect(getControlToken()).toBe('')
    expect(localStorage.getItem(LS_TOKEN)).toBeNull()
    // it actually attempted the authenticated round-trip (healthz then live/status)
    expect(calls.map((c) => c.url)).toEqual([
      'http://gate-host:8011/healthz',
      'http://gate-host:8011/api/live/status',
    ])
  })

  it('accepts address (persisted) + session-only token when the authenticated round-trip returns 200', async () => {
    installFetch(async (url) => {
      if (url.endsWith('/healthz')) return fakeResponse({ service: 'ossredact-egress', version: '0.2.0', remote_control: true })
      return fakeResponse({ enabled: true }, { status: 200 })
    })
    const o = await connectGate('http://gate-host:8011/', '  good-token  ')
    expect(o.ok).toBe(true)
    expect(getDaemonOverride()).toBe('http://gate-host:8011')
    expect(localStorage.getItem(LS_DAEMON)).toBe('http://gate-host:8011')
    expect(getControlToken()).toBe('good-token')   // trimmed, session memory
    expect(localStorage.getItem(LS_TOKEN)).toBeNull() // never persisted
  })

  it('refuses a NON-loopback gate that reports no remote control (no token would 403 everything)', async () => {
    const calls = installFetch(async () =>
      fakeResponse({ service: 'ossredact-egress', remote_control: false }))
    const o = await connectGate('http://gate-host:8011', '')
    expect(o.ok).toBe(false)
    expect(o).toMatchObject({ reason: 'no-remote-control' })
    expect(getDaemonOverride()).toBe('')
    expect(calls).toHaveLength(1)   // only /healthz; never attempts the control round-trip
  })

  it('accepts a loopback gate with no remote control (local control needs no token)', async () => {
    const calls = installFetch(async () =>
      fakeResponse({ service: 'ossredact-egress', remote_control: false }))
    const o = await connectGate('http://127.0.0.1:8011', '')
    expect(o.ok).toBe(true)
    expect(getDaemonOverride()).toBe('http://127.0.0.1:8011')
    expect(calls).toHaveLength(1)   // loopback shortcut: no auth round-trip
    expect(localStorage.getItem(LS_TOKEN)).toBeNull()
  })

  it('does not accept an unreachable address', async () => {
    installFetch(async () => { throw new TypeError('Failed to fetch') })
    const o = await connectGate('http://nope:1', 'x')
    expect(o.ok).toBe(false)
    expect(o).toMatchObject({ reason: 'unreachable' })
    expect(getDaemonOverride()).toBe('')
  })
})

// ---------------------------------------------------------------------------
// mixedContentRisk() -- B3: a secure console cannot reach a plain http:// remote gate
// ---------------------------------------------------------------------------
describe('mixedContentRisk', () => {
  it('flags a remote http:// gate from an https console', () => {
    expect(mixedContentRisk('http://gate-host:8011', 'https:')).toBe(true)
  })
  it('flags a remote http:// gate from a Tauri (tauri:) console', () => {
    expect(mixedContentRisk('http://gate-host:8011', 'tauri:')).toBe(true)
  })
  it('does not flag an https:// gate from a secure console', () => {
    expect(mixedContentRisk('https://gate.example.ts.net', 'https:')).toBe(false)
  })
  it('does not flag http gate from a plain-http (loopback dev) console -- both http, no mixed content', () => {
    expect(mixedContentRisk('http://gate-host:8011', 'http:')).toBe(false)
  })
  it('exempts a loopback http gate even from a secure console (potentially-trustworthy)', () => {
    expect(mixedContentRisk('http://127.0.0.1:8011', 'https:')).toBe(false)
    expect(mixedContentRisk('http://localhost:8011', 'tauri:')).toBe(false)
  })
  it('does not flag a relative / same-origin base', () => {
    expect(mixedContentRisk('', 'https:')).toBe(false)
    expect(mixedContentRisk('/api', 'https:')).toBe(false)
  })
})

describe('cleartextRisk', () => {
  it('flags a non-loopback http:// gate regardless of console scheme', () => {
    expect(cleartextRisk('http://gate-host:8011')).toBe(true)
    expect(cleartextRisk('http://192.168.1.50:8011')).toBe(true)
  })
  it('does not flag an https:// gate', () => {
    expect(cleartextRisk('https://gate.example.ts.net')).toBe(false)
  })
  it('does not flag a loopback http gate (local, never leaves the machine)', () => {
    expect(cleartextRisk('http://127.0.0.1:8011')).toBe(false)
    expect(cleartextRisk('http://localhost:8011')).toBe(false)
  })
  it('does not flag a relative / same-origin base', () => {
    expect(cleartextRisk('')).toBe(false)
    expect(cleartextRisk('/api')).toBe(false)
  })
})
