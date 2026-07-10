import { useCallback, useEffect, useRef, useState } from 'react'
import { subscribeLive, clearLive, type LiveEvent, type LiveEntity } from '../lib/daemon'

// Live-activity proof: the SSE feed of what the firewall redacted before forwarding upstream. Each event
// shows real value -> placeholder mappings (loopback-only, never persisted). This is the "watch it work"
// surface: newest on top, capped, with per-event expand revealing the redaction map.

export const MAX_ROWS = 300

export type ConnState = 'connecting' | 'open' | 'error'

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested in LivePanel.test.tsx). Keep these free of React /
// DOM / network so the test file can import and assert them directly.
// ---------------------------------------------------------------------------

/**
 * Human relative time for an event timestamp. `tsSeconds` is epoch SECONDS (ev.ts); `nowMs` is the
 * current time in MILLISECONDS (Date.now()). Returns coarse, deterministic buckets: "just now", "Ns",
 * "Nm", "Nh", "Nd". A future-dated event (clock skew) clamps to "just now". Non-finite input -> "–".
 */
export function relativeTime(tsSeconds: number, nowMs: number): string {
  if (!Number.isFinite(tsSeconds) || !Number.isFinite(nowMs)) return '–'
  const deltaSec = Math.floor(nowMs / 1000 - tsSeconds)
  if (deltaSec <= 4) return 'just now'
  if (deltaSec < 60) return `${deltaSec}s`
  const min = Math.floor(deltaSec / 60)
  if (min < 60) return `${min}m`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}h`
  const day = Math.floor(hr / 24)
  return `${day}d`
}

/** Number of redactions an event represents. Prefers the explicit entity list, falls back to n_spans. */
export function eventCount(ev: LiveEvent): number {
  if (ev.entities && ev.entities.length > 0) return ev.entities.length
  return ev.n_spans ?? 0
}

/** 'request' = outbound redaction (PII stripped before upstream); 'response' = inbound rehydration. */
export function kindMeta(kind: string): { label: string; verb: string; tone: 'out' | 'in' } {
  if (kind === 'response') return { label: 'response', verb: 'rehydrated', tone: 'in' }
  // default to the outbound interpretation for 'request' and any unknown kind
  return { label: 'request', verb: 'redacted', tone: 'out' }
}

/** Connection state -> dot color class + human label, matching the console's teal/amber/gray palette. */
export function statusMeta(conn: ConnState): { label: string; dot: string } {
  switch (conn) {
    case 'open':
      return { label: 'Live', dot: 'bg-teal-500' }
    case 'connecting':
      return { label: 'Connecting…', dot: 'bg-amber-400' }
    default:
      return { label: 'Disconnected', dot: 'bg-gray-300' }
  }
}

/**
 * A compact one-line title for an event row: "<client> · <route>" with sensible fallbacks so a
 * field-light event never renders a stray separator or an empty string.
 */
export function eventTitle(ev: LiveEvent): string {
  const left = (ev.client || '').trim()
  const right = (ev.route || '').trim()
  if (left && right) return `${left} · ${right}`
  return left || right || 'unknown'
}

/** Distinct entity labels for an event, in first-seen order (for the chip row, label-only by default). */
export function eventLabels(ev: LiveEvent): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const e of ev.entities ?? []) {
    if (e.label && !seen.has(e.label)) {
      seen.add(e.label)
      out.push(e.label)
    }
  }
  return out
}

/**
 * Roll up redaction counts by label across a set of events (the visible window). Counts every entity
 * occurrence (not distinct values) so the summary reflects volume. Events with no entities contribute
 * nothing. Result is a plain Record for easy assertion.
 */
export function summarizeByLabel(events: LiveEvent[]): Record<string, number> {
  const out: Record<string, number> = {}
  for (const ev of events) {
    for (const e of ev.entities ?? []) {
      if (!e.label) continue
      out[e.label] = (out[e.label] ?? 0) + 1
    }
  }
  return out
}

/** Stable, sorted (desc by count, then label asc) entries from a label summary, for rendering. */
export function summaryEntries(summary: Record<string, number>): Array<[string, number]> {
  return Object.entries(summary).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
}

// ---------------------------------------------------------------------------
// Presentational subcomponents
// ---------------------------------------------------------------------------

function LabelChip({ label }: { label: string }) {
  return (
    <span className="rounded bg-teal-50 dark:bg-teal-400/10 px-1.5 py-0.5 font-mono text-[11px] text-teal-700 dark:text-teal-300">{label}</span>
  )
}

function EntityRow({ entity }: { entity: LiveEntity }) {
  return (
    <div className="flex items-center gap-2 py-1 text-xs">
      <code className="min-w-0 flex-1 truncate font-mono text-gray-900 dark:text-neutral-100" title={entity.value}>
        {entity.value}
      </code>
      <span aria-hidden className="shrink-0 text-gray-300">
        →
      </span>
      <code className="shrink-0 font-mono text-teal-700 dark:text-teal-300">{entity.placeholder}</code>
      <span className="shrink-0">
        <LabelChip label={entity.label} />
      </span>
    </div>
  )
}

function EventCard({ ev, nowMs }: { ev: LiveEvent; nowMs: number }) {
  const [open, setOpen] = useState(false)
  const k = kindMeta(ev.kind)
  const count = eventCount(ev)
  const labels = eventLabels(ev)
  const hasDetail = (ev.entities?.length ?? 0) > 0
  const rel = relativeTime(ev.ts, nowMs)

  return (
    <li className="rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-[#191919] p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm">
            <span
              className={`inline-flex shrink-0 items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${
                k.tone === 'in' ? 'bg-gray-100 dark:bg-white/10 text-gray-600 dark:text-neutral-300' : 'bg-teal-50 dark:bg-teal-400/10 text-teal-700 dark:text-teal-300'
              }`}
            >
              {k.label}
            </span>
            <span className="truncate font-medium text-gray-900 dark:text-neutral-100" title={eventTitle(ev)}>
              {eventTitle(ev)}
            </span>
          </div>
          <div className="mt-0.5 text-xs text-gray-400 dark:text-neutral-500">
            {k.verb} <span className="font-mono text-gray-500 dark:text-neutral-400">{count}</span>{' '}
            {count === 1 ? 'value' : 'values'} · {rel}
            {ev.degraded && <span className="ml-1 text-amber-500">· degraded</span>}
          </div>
        </div>
        {hasDetail && (
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            aria-label={open ? 'Hide redaction detail' : 'Show redaction detail'}
            className="shrink-0 rounded-md border border-gray-200 dark:border-white/10 px-2 py-1 text-xs font-medium text-gray-600 dark:text-neutral-300 hover:bg-gray-50 dark:hover:bg-white/5 focus:outline-none focus:ring-2 focus:ring-teal-500"
          >
            {open ? 'Hide' : 'Detail'}
          </button>
        )}
      </div>

      {labels.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {labels.map((l) => (
            <LabelChip key={l} label={l} />
          ))}
        </div>
      )}

      {open && hasDetail && (
        <div className="mt-2 border-t border-gray-100 dark:border-white/10 pt-2">
          <div className="divide-y divide-gray-50 dark:divide-white/10">
            {ev.entities!.map((e) => (
              <EntityRow key={e.placeholder + e.value} entity={e} />
            ))}
          </div>
          <p className="mt-1.5 text-[11px] text-gray-400 dark:text-neutral-500">
            Original values are shown locally only -- they never leave this machine.
          </p>
        </div>
      )}
    </li>
  )
}

// ---------------------------------------------------------------------------
// Panel
// ---------------------------------------------------------------------------

export default function LivePanel() {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [conn, setConn] = useState<ConnState>('connecting')
  const [paused, setPaused] = useState(false)
  // A periodically-refreshed clock so relative timestamps tick without re-subscribing.
  const [nowMs, setNowMs] = useState(() => Date.now())

  // `paused` is read inside the subscription callback; a ref keeps it current without resubscribing.
  const pausedRef = useRef(paused)
  pausedRef.current = paused

  useEffect(() => {
    const off = subscribeLive((ev) => {
      if (pausedRef.current) return
      setEvents((prev) => {
        if (prev.length && prev[0].seq === ev.seq) return prev // de-dupe a re-emitted backlog head
        return [ev, ...prev].slice(0, MAX_ROWS)
      })
    }, setConn)
    return off
  }, [])

  // Tick the relative-time clock every 15s (cheap; no network).
  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 15_000)
    return () => clearInterval(id)
  }, [])

  const clear = useCallback(() => {
    clearLive().catch(() => {})
    setEvents([])
  }, [])

  const status = statusMeta(conn)
  const summary = summaryEntries(summarizeByLabel(events))
  const capped = events.length >= MAX_ROWS

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-neutral-400">
          <span
            aria-hidden
            className={`inline-block h-2 w-2 rounded-full ${status.dot} ${conn === 'connecting' ? 'animate-pulse' : ''}`}
          />
          <span aria-live="polite">{status.label}</span>
          <span className="text-gray-300">·</span>
          <span className="font-mono text-gray-500 dark:text-neutral-400">{events.length}</span>
          <span className="text-gray-400 dark:text-neutral-500">{capped ? `events (cap ${MAX_ROWS})` : 'events'}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setPaused((p) => !p)}
            aria-pressed={paused}
            className={`rounded-md border px-2.5 py-1 text-xs font-medium focus:outline-none focus:ring-2 focus:ring-teal-500 ${
              paused
                ? 'border-amber-300 bg-amber-50 dark:bg-amber-400/10 text-amber-700 dark:text-amber-300 hover:bg-amber-100'
                : 'border-gray-300 text-gray-600 dark:text-neutral-300 hover:bg-gray-50 dark:hover:bg-white/5'
            }`}
          >
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            type="button"
            onClick={clear}
            className="rounded-md border border-gray-300 px-2.5 py-1 text-xs font-medium text-gray-600 dark:text-neutral-300 hover:bg-gray-50 dark:hover:bg-white/5 focus:outline-none focus:ring-2 focus:ring-teal-500"
          >
            Clear
          </button>
        </div>
      </div>

      {paused && (
        <p className="mb-2 rounded-md bg-amber-50 dark:bg-amber-400/10 px-2.5 py-1 text-xs text-amber-700 dark:text-amber-300">
          Paused -- the feed stays connected; new events are dropped from the list until you resume.
        </p>
      )}

      {summary.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-gray-400 dark:text-neutral-500">By label:</span>
          {summary.map(([label, n]) => (
            <span
              key={label}
              className="inline-flex items-center gap-1 rounded bg-gray-50 dark:bg-white/5 px-1.5 py-0.5 text-[11px] text-gray-600 dark:text-neutral-300"
            >
              <span className="font-mono text-teal-700 dark:text-teal-300">{label}</span>
              <span className="font-mono text-gray-400 dark:text-neutral-500">{n}</span>
            </span>
          ))}
        </div>
      )}

      {conn === 'error' && events.length === 0 ? (
        <p className="py-12 text-center text-sm text-gray-400 dark:text-neutral-500">
          Not connected to the firewall feed. It will resume automatically when the service is reachable.
        </p>
      ) : events.length === 0 ? (
        <p className="py-12 text-center text-sm text-gray-400 dark:text-neutral-500">
          No activity yet. Requests through the firewall will appear here in real time.
        </p>
      ) : (
        <ul className="space-y-2">
          {events.map((ev) => (
            <EventCard key={ev.seq} ev={ev} nowMs={nowMs} />
          ))}
        </ul>
      )}
    </div>
  )
}
