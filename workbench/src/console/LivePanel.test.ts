// Tests for the pure helpers in LivePanel.tsx. No React rendering, no network, no real timers --
// the panel's logic is extracted into pure functions and asserted directly. All inputs are synthetic.

import { describe, it, expect } from 'vitest'
import {
  MAX_ROWS,
  relativeTime,
  eventCount,
  eventLabels,
  eventTitle,
  kindMeta,
  statusMeta,
  summarizeByLabel,
  summaryEntries,
} from './LivePanel'
import type { LiveEvent, LiveEntity } from '../lib/daemon'

// ---- builders ----
function entity(label: string, value = 'v', placeholder = `<${label.toUpperCase()}_001>`): LiveEntity {
  return { label, value, placeholder }
}

function ev(partial: Partial<LiveEvent> = {}): LiveEvent {
  return {
    seq: 1,
    ts: 1_000_000,
    kind: 'request',
    route: '/v1/messages',
    client: 'claude-code',
    session: 's1',
    ...partial,
  }
}

// A fixed "now" for deterministic relative-time math. ts is in seconds; nowMs in milliseconds.
const NOW = 2_000_000_000_000 // ms
const nowSec = NOW / 1000

// ---------------------------------------------------------------------------
// relativeTime
// ---------------------------------------------------------------------------
describe('relativeTime', () => {
  it('treats sub-5s deltas as "just now"', () => {
    expect(relativeTime(nowSec, NOW)).toBe('just now')
    expect(relativeTime(nowSec - 4, NOW)).toBe('just now')
  })

  it('shows seconds between 5s and a minute', () => {
    expect(relativeTime(nowSec - 5, NOW)).toBe('5s')
    expect(relativeTime(nowSec - 59, NOW)).toBe('59s')
  })

  it('rolls over to minutes, hours, then days', () => {
    expect(relativeTime(nowSec - 60, NOW)).toBe('1m')
    expect(relativeTime(nowSec - 119, NOW)).toBe('1m') // floors
    expect(relativeTime(nowSec - 60 * 60, NOW)).toBe('1h')
    expect(relativeTime(nowSec - 60 * 60 * 25, NOW)).toBe('1d')
    expect(relativeTime(nowSec - 60 * 60 * 24 * 3, NOW)).toBe('3d')
  })

  it('clamps a future-dated (clock-skewed) event to "just now"', () => {
    expect(relativeTime(nowSec + 30, NOW)).toBe('just now')
  })

  it('returns an em-dash placeholder for non-finite input', () => {
    expect(relativeTime(Number.NaN, NOW)).toBe('–')
    expect(relativeTime(nowSec, Number.POSITIVE_INFINITY)).toBe('–')
  })
})

// ---------------------------------------------------------------------------
// eventCount
// ---------------------------------------------------------------------------
describe('eventCount', () => {
  it('counts entities when present', () => {
    expect(eventCount(ev({ entities: [entity('email'), entity('phone')] }))).toBe(2)
  })

  it('falls back to n_spans when there are no entities (response-side / counts-only events)', () => {
    expect(eventCount(ev({ n_spans: 5 }))).toBe(5)
  })

  it('is 0 when neither entities nor n_spans are present', () => {
    expect(eventCount(ev())).toBe(0)
    expect(eventCount(ev({ entities: [] }))).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// eventLabels
// ---------------------------------------------------------------------------
describe('eventLabels', () => {
  it('returns [] for an event with no entities', () => {
    expect(eventLabels(ev())).toEqual([])
    expect(eventLabels(ev({ entities: [] }))).toEqual([])
  })

  it('dedupes labels and preserves first-seen order', () => {
    const e = ev({ entities: [entity('email'), entity('person'), entity('email')] })
    expect(eventLabels(e)).toEqual(['email', 'person'])
  })

  it('ignores entities with an empty label', () => {
    const e = ev({ entities: [entity(''), entity('iban')] })
    expect(eventLabels(e)).toEqual(['iban'])
  })
})

// ---------------------------------------------------------------------------
// eventTitle
// ---------------------------------------------------------------------------
describe('eventTitle', () => {
  it('joins client and route with a middot', () => {
    expect(eventTitle(ev({ client: 'codex', route: '/v1/responses' }))).toBe('codex · /v1/responses')
  })

  it('falls back to whichever field is present, with no stray separator', () => {
    expect(eventTitle(ev({ client: 'codex', route: '' }))).toBe('codex')
    expect(eventTitle(ev({ client: '', route: '/v1/messages' }))).toBe('/v1/messages')
  })

  it('returns "unknown" when both are blank', () => {
    expect(eventTitle(ev({ client: '   ', route: '' }))).toBe('unknown')
  })
})

// ---------------------------------------------------------------------------
// kindMeta
// ---------------------------------------------------------------------------
describe('kindMeta', () => {
  it('maps request -> outbound redaction', () => {
    expect(kindMeta('request')).toEqual({ label: 'request', verb: 'redacted', tone: 'out' })
  })

  it('maps response -> inbound rehydration', () => {
    expect(kindMeta('response')).toEqual({ label: 'response', verb: 'rehydrated', tone: 'in' })
  })

  it('defaults an unknown kind to the outbound interpretation', () => {
    expect(kindMeta('weird').tone).toBe('out')
  })
})

// ---------------------------------------------------------------------------
// statusMeta
// ---------------------------------------------------------------------------
describe('statusMeta', () => {
  it('maps each connection state to a teal/amber/gray dot', () => {
    expect(statusMeta('open')).toEqual({ label: 'Live', dot: 'bg-teal-500' })
    expect(statusMeta('connecting')).toEqual({ label: 'Connecting…', dot: 'bg-amber-400' })
    expect(statusMeta('error')).toEqual({ label: 'Disconnected', dot: 'bg-gray-300' })
  })
})

// ---------------------------------------------------------------------------
// summarizeByLabel
// ---------------------------------------------------------------------------
describe('summarizeByLabel', () => {
  it('is empty for no events', () => {
    expect(summarizeByLabel([])).toEqual({})
  })

  it('is empty when events carry no entities', () => {
    expect(summarizeByLabel([ev(), ev({ n_spans: 3 })])).toEqual({})
  })

  it('counts a single event by label', () => {
    const e = ev({ entities: [entity('email'), entity('email'), entity('person')] })
    expect(summarizeByLabel([e])).toEqual({ email: 2, person: 1 })
  })

  it('rolls counts up across multiple events', () => {
    const a = ev({ seq: 1, entities: [entity('email'), entity('iban')] })
    const b = ev({ seq: 2, entities: [entity('email'), entity('email')] })
    expect(summarizeByLabel([a, b])).toEqual({ email: 3, iban: 1 })
  })

  it('counts every occurrence (volume), not distinct values', () => {
    const e = ev({
      entities: [
        entity('email', 'a@x.test', '<EMAIL_001>'),
        entity('email', 'a@x.test', '<EMAIL_001>'), // same value repeated
      ],
    })
    expect(summarizeByLabel([e])).toEqual({ email: 2 })
  })

  it('skips entities with an empty label', () => {
    const e = ev({ entities: [entity(''), entity('phone')] })
    expect(summarizeByLabel([e])).toEqual({ phone: 1 })
  })
})

// ---------------------------------------------------------------------------
// summaryEntries
// ---------------------------------------------------------------------------
describe('summaryEntries', () => {
  it('sorts by count desc, then label asc, deterministically', () => {
    expect(summaryEntries({ person: 2, email: 5, iban: 2 })).toEqual([
      ['email', 5],
      ['iban', 2], // tie with person -> label asc
      ['person', 2],
    ])
  })

  it('is empty for an empty summary', () => {
    expect(summaryEntries({})).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// cap behaviour: the panel slices the running list to MAX_ROWS. We assert the
// pure slice contract the component relies on (newest-first, capped length).
// ---------------------------------------------------------------------------
describe('cap / prepend contract', () => {
  // Mirrors the component's reducer: prepend newest, slice to the cap.
  function prepend(prev: LiveEvent[], next: LiveEvent): LiveEvent[] {
    return [next, ...prev].slice(0, MAX_ROWS)
  }

  it('keeps newest on top and never exceeds MAX_ROWS', () => {
    let list: LiveEvent[] = []
    for (let i = 0; i < MAX_ROWS + 50; i++) {
      list = prepend(list, ev({ seq: i }))
    }
    expect(list).toHaveLength(MAX_ROWS)
    expect(list[0].seq).toBe(MAX_ROWS + 49) // most recent prepend is first
    // the oldest 50 fell off the end
    expect(list[list.length - 1].seq).toBe(50)
  })

  it('a single event yields a one-row list', () => {
    expect(prepend([], ev({ seq: 7 }))).toHaveLength(1)
  })
})
