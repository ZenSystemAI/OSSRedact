// Tests for the OSSRedact egress-daemon client in daemon.ts.
//
// The network is fully mocked -- no real daemon is ever contacted. `fetch` and `EventSource` are
// replaced with vi.stubGlobal fakes so every path (ok / non-ok / throw / SSE transitions) is
// deterministic and offline. All values are synthetic; no real PII.

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

// ---------------------------------------------------------------------------
// daemonBase()
// ---------------------------------------------------------------------------
describe('daemonBase', () => {
  afterEach(() => {
    delete (window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__
    vi.unstubAllEnvs()
  })

  it('defaults to the same-origin empty base when nothing is set', () => {
    expect(DEFAULT_DAEMON).toBe('')
    expect(daemonBase()).toBe('')
  })

  it('honors window.__OSSREDACT_DAEMON__ (the Tauri shell injection)', () => {
    ;(window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__ = 'http://127.0.0.1:8011'
    expect(daemonBase()).toBe('http://127.0.0.1:8011')
  })

  it('honors the VITE_OSSREDACT_DAEMON env override', () => {
    vi.stubEnv('VITE_OSSREDACT_DAEMON', 'http://daemon.local:9000')
    expect(daemonBase()).toBe('http://daemon.local:9000')
  })

  it('prefers the window injection over the env override', () => {
    ;(window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__ = 'http://win.example:1'
    vi.stubEnv('VITE_OSSREDACT_DAEMON', 'http://env.example:2')
    expect(daemonBase()).toBe('http://win.example:1')
  })

  it('strips a single trailing slash from the window override', () => {
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

  it('GETs /api/allowlist and parses the AllowlistState body', async () => {
    const body = { values: ['acme', 'quickcredit'], active_total: 2, config_values: 1, path: '/cfg/allow.txt' }
    const calls = installFetch(async () => fakeResponse(body))
    const res = await getAllowlist()
    expect(res).toEqual(body)
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
// subscribeLive() -- fake EventSource
// ---------------------------------------------------------------------------

// A controllable EventSource stand-in. Tests drive it via the emit* helpers; the source records
// its construction URL and whether close() was called. The newest instance is tracked statically
// so a test can grab the one subscribeLive() built without exposing it.
class FakeEventSource {
  static instances: FakeEventSource[] = []
  static last(): FakeEventSource {
    const es = FakeEventSource.instances[FakeEventSource.instances.length - 1]
    if (!es) throw new Error('no FakeEventSource was constructed')
    return es
  }

  url: string
  closed = false
  onopen: ((ev: Event) => void) | null = null
  onerror: ((ev: Event) => void) | null = null
  onmessage: ((ev: MessageEvent) => void) | null = null

  constructor(url: string) {
    this.url = url
    FakeEventSource.instances.push(this)
  }

  close(): void {
    this.closed = true
  }

  // --- test drivers ---
  emitOpen(): void {
    this.onopen?.(new Event('open'))
  }
  emitError(): void {
    this.onerror?.(new Event('error'))
  }
  emitData(data: string): void {
    this.onmessage?.({ data } as MessageEvent)
  }
  emitRaw(ev: Partial<MessageEvent>): void {
    this.onmessage?.(ev as MessageEvent)
  }
}

// A constructor that throws, to exercise the "EventSource unavailable" branch.
class ThrowingEventSource {
  constructor() {
    throw new Error('EventSource not supported')
  }
}

describe('subscribeLive', () => {
  beforeEach(() => {
    FakeEventSource.instances = []
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    delete (window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__
  })

  it('opens an EventSource against /api/stream on the daemon base', () => {
    ;(window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__ = 'http://127.0.0.1:8011'
    const unsub = subscribeLive(() => {})
    expect(FakeEventSource.last().url).toBe('http://127.0.0.1:8011/api/stream')
    unsub()
  })

  it('reports the connecting -> open -> error state transitions in order', () => {
    const states: string[] = []
    const unsub = subscribeLive(() => {}, (s) => states.push(s))
    // subscribeLive synchronously reports 'connecting' before any network event
    expect(states).toEqual(['connecting'])
    FakeEventSource.last().emitOpen()
    FakeEventSource.last().emitError()
    expect(states).toEqual(['connecting', 'open', 'error'])
    unsub()
  })

  it('delivers each well-formed line as a PARSED LiveEvent object', () => {
    const events: LiveEvent[] = []
    const unsub = subscribeLive((ev) => events.push(ev))
    const ev: LiveEvent = {
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
    FakeEventSource.last().emitData(JSON.stringify(ev))
    expect(events).toHaveLength(1)
    // it's the parsed object, not the raw string
    expect(events[0]).toEqual(ev)
    expect(events[0].entities?.[0].placeholder).toBe('<EMAIL_001>')
    unsub()
  })

  it('ignores malformed JSON lines without throwing or invoking onEvent', () => {
    const events: LiveEvent[] = []
    const unsub = subscribeLive((ev) => events.push(ev))
    expect(() => FakeEventSource.last().emitData('{ this is not json')).not.toThrow()
    expect(events).toHaveLength(0)
    unsub()
  })

  it('ignores keepalive / empty-data lines (no onEvent, no throw)', () => {
    const events: LiveEvent[] = []
    const unsub = subscribeLive((ev) => events.push(ev))
    const es = FakeEventSource.last()
    expect(() => es.emitData('')).not.toThrow() // empty keep-alive payload
    expect(() => es.emitRaw({})).not.toThrow() // message with no .data at all
    expect(events).toHaveLength(0)
    unsub()
  })

  it('the unsubscribe fn closes the underlying EventSource', () => {
    const unsub = subscribeLive(() => {})
    const es = FakeEventSource.last()
    expect(es.closed).toBe(false)
    unsub()
    expect(es.closed).toBe(true)
  })

  it('drops events that arrive AFTER unsubscribe (closed guard)', () => {
    const events: LiveEvent[] = []
    const unsub = subscribeLive((ev) => events.push(ev))
    const es = FakeEventSource.last()
    unsub()
    es.emitData(JSON.stringify({ seq: 9, ts: 0, kind: 'request', route: '/r', client: 'c', session: 's' }))
    expect(events).toHaveLength(0) // the closed flag suppresses post-unsubscribe delivery
  })

  it('reports error state and returns a safe no-op unsubscribe when EventSource construction throws', () => {
    vi.stubGlobal('EventSource', ThrowingEventSource as unknown as typeof EventSource)
    const states: string[] = []
    const unsub = subscribeLive(() => {}, (s) => states.push(s))
    expect(states).toEqual(['error'])
    // the fallback unsubscribe must be callable without throwing
    expect(() => unsub()).not.toThrow()
  })

  it('appends ?token= to the stream URL when an off-device control token is set', () => {
    setControlToken('tok-xyz')
    try {
      const unsub = subscribeLive(() => {})
      expect(FakeEventSource.last().url).toBe('/api/stream?token=tok-xyz')
      unsub()
    } finally {
      setControlToken('')
    }
  })
})

// ---------------------------------------------------------------------------
// off-device gate connection: address override + control token (localStorage-backed)
// ---------------------------------------------------------------------------
describe('gate connection override', () => {
  beforeEach(() => {
    try { localStorage.clear() } catch { /* storage off */ }
  })
  afterEach(() => {
    try { localStorage.clear() } catch { /* storage off */ }
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

  it('persists + trims the control token; empty clears it', () => {
    setControlToken('  s3cret-token  ')
    expect(getControlToken()).toBe('s3cret-token')
    setControlToken('')
    expect(getControlToken()).toBe('')
  })
})

describe('control-token request wiring', () => {
  beforeEach(() => {
    try { localStorage.clear() } catch { /* storage off */ }
  })
  afterEach(() => {
    try { localStorage.clear() } catch { /* storage off */ }
    vi.unstubAllGlobals()
  })

  it('attaches x-ossredact-control-token to control fetches when a token is set', async () => {
    setControlToken('tok-123')
    const calls = installFetch(async () =>
      fakeResponse({ values: [], active_total: 0, config_values: 0, path: '' }))
    await getAllowlist()
    expect((calls[0].init?.headers as Record<string, string>)['x-ossredact-control-token']).toBe('tok-123')
  })

  it('omits the token header entirely when no token is set (local gate wire unchanged)', async () => {
    const calls = installFetch(async () =>
      fakeResponse({ values: [], active_total: 0, config_values: 0, path: '' }))
    await getAllowlist()
    expect((calls[0].init?.headers as Record<string, string>)['x-ossredact-control-token']).toBeUndefined()
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
// verifyControl() + connectGate() -- B4: persist a control token only after it AUTHORIZES
// ---------------------------------------------------------------------------
describe('verifyControl', () => {
  afterEach(() => { try { localStorage.clear() } catch { /* off */ } ; vi.unstubAllGlobals() })

  it('sends the token header to /api/live/status and is ok only on 200', async () => {
    const calls = installFetch(async () => fakeResponse({ enabled: true }, { status: 200 }))
    const v = await verifyControl('http://gate-host:8011/', 'tok-123')
    expect(v.ok).toBe(true)
    expect(v.status).toBe(200)
    expect(calls[0].url).toBe('http://gate-host:8011/api/live/status')
    expect((calls[0].init?.headers as Record<string, string>)['x-ossredact-control-token']).toBe('tok-123')
  })

  it('is not ok on a 403 (token rejected)', async () => {
    installFetch(async () => fakeResponse({ error: 'local-only' }, { status: 403 }))
    const v = await verifyControl('http://gate-host:8011', 'wrong')
    expect(v.ok).toBe(false)
    expect(v.status).toBe(403)
  })
})

describe('connectGate', () => {
  beforeEach(() => { try { localStorage.clear() } catch { /* off */ } })
  afterEach(() => {
    try { localStorage.clear() } catch { /* off */ }
    vi.unstubAllGlobals()
    delete (window as unknown as { __OSSREDACT_DAEMON__?: string }).__OSSREDACT_DAEMON__
  })

  // The whole point of B4: /healthz OK but the control token is wrong -> do NOT persist.
  it('does NOT persist when /healthz is OK but /api/live/status returns 403', async () => {
    const calls = installFetch(async (url) => {
      if (url.endsWith('/healthz')) return fakeResponse({ service: 'ossredact-egress', version: '0.2.0', remote_control: true })
      if (url.endsWith('/api/live/status')) return fakeResponse({ error: 'local-only' }, { status: 403 })
      return fakeResponse({}, { status: 404 })
    })
    const o = await connectGate('http://gate-host:8011', 'wrong-token')
    expect(o.ok).toBe(false)
    expect(o).toMatchObject({ reason: 'unauthorized', status: 403 })
    expect(getDaemonOverride()).toBe('')   // nothing persisted
    expect(getControlToken()).toBe('')
    // it actually attempted the authenticated round-trip (healthz then live/status)
    expect(calls.map((c) => c.url)).toEqual([
      'http://gate-host:8011/healthz',
      'http://gate-host:8011/api/live/status',
    ])
  })

  it('persists address + token when the authenticated round-trip returns 200', async () => {
    installFetch(async (url) => {
      if (url.endsWith('/healthz')) return fakeResponse({ service: 'ossredact-egress', version: '0.2.0', remote_control: true })
      return fakeResponse({ enabled: true }, { status: 200 })
    })
    const o = await connectGate('http://gate-host:8011/', '  good-token  ')
    expect(o.ok).toBe(true)
    expect(getDaemonOverride()).toBe('http://gate-host:8011')
    expect(getControlToken()).toBe('good-token')   // trimmed
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

  it('persists a loopback gate with no remote control (local control needs no token)', async () => {
    const calls = installFetch(async () =>
      fakeResponse({ service: 'ossredact-egress', remote_control: false }))
    const o = await connectGate('http://127.0.0.1:8011', '')
    expect(o.ok).toBe(true)
    expect(getDaemonOverride()).toBe('http://127.0.0.1:8011')
    expect(calls).toHaveLength(1)   // loopback shortcut: no auth round-trip
  })

  it('does not persist an unreachable address', async () => {
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
