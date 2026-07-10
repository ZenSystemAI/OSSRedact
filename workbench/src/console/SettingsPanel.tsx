import { useEffect, useState } from 'react'
import {
  getLiveStatus, getAllowlist, getSettings, setMode,
  type LiveStatus, type AllowlistState, type SettingsState, type RedactionMode,
} from '../lib/daemon'

// Settings / status. Reports the firewall's live posture (reachable, live-view, buffered events, subscribers,
// dictionary counts), states the hard guarantee (always-protected categories that can never be disabled), and
// drives the live redaction-MODE switch (privacy / coding / off) -- POSTing to the daemon's /api/settings.

// ---------------------------------------------------------------------------------------------------------
// Pure helpers (exported for unit tests -- see SettingsPanel.test.ts). No React, no I/O.
// ---------------------------------------------------------------------------------------------------------

export interface StatusRow {
  label: string
  value: string
}

/**
 * Flatten the two daemon status payloads into an ordered, render-ready list of label/value rows.
 * Pure + total: never throws, always returns the same six rows in the same order. The component renders
 * these verbatim, so the row labels and formatting live here (and are asserted in tests).
 */
export function formatStatus(live: LiveStatus, allow: AllowlistState): StatusRow[] {
  return [
    { label: 'Live activity', value: live.enabled ? 'Enabled' : 'Disabled' },
    { label: 'Buffered events', value: `${live.buffered} / ${live.max}` },
    { label: 'Subscribers', value: String(live.subscribers) },
    { label: 'Dictionary entries', value: String(allow.active_total) },
    { label: 'From config', value: String(allow.config_values) },
  ]
}

/**
 * Buffer fill as an integer percentage, clamped to 0..100. Guards the empty buffer (max 0 -> 0%, no NaN)
 * and an over-full buffer (buffered > max -> capped at 100). Negative inputs clamp to 0.
 */
export function bufferPct(buffered: number, max: number): number {
  if (!Number.isFinite(buffered) || !Number.isFinite(max) || max <= 0) return 0
  const pct = Math.round((buffered / max) * 100)
  if (pct < 0) return 0
  if (pct > 100) return 100
  return pct
}

// The product's hard guarantee. These categories are redacted server-side by the daemon's Tier-0 floor and
// can NEVER be exempted via the dictionary or any mode. Kept as data so the test can pin the list if needed.
export interface ProtectedCategory {
  title: string
  detail: string
}

export const ALWAYS_PROTECTED: ProtectedCategory[] = [
  { title: 'Secrets & API keys', detail: 'Tokens, private keys, connection strings, bearer credentials.' },
  { title: 'Payment cards', detail: 'Card numbers (Luhn-validated) and related payment data.' },
  { title: 'IBANs & bank accounts', detail: 'International bank account numbers and routing details.' },
  { title: 'Government IDs', detail: 'Social-insurance, national-ID, and equivalent identifiers.' },
]

// The redaction-mode options (data so the test can pin labels/order). `tone` drives accent styling; `warn`
// marks a mode that loosens protection (shown with a caution affordance).
export interface ModeOption {
  id: RedactionMode
  title: string
  detail: string
  warn?: boolean
}

export const MODE_OPTIONS: ModeOption[] = [
  { id: 'privacy', title: 'Privacy', detail: 'Redact all detected PII -- names, organizations, addresses, emails, and more. Maximum protection.' },
  { id: 'coding', title: 'Coding', detail: 'Let organization and framework names through so AI coding agents keep their context. Everything else still redacts.' },
  { id: 'off', title: 'Off', detail: 'Pass personal data (names, addresses, emails) through, for when redaction gets in the way.', warn: true },
]

/** Resolve a mode id to its option, falling back to the privacy option for an unknown value. */
export function modeOption(mode: string): ModeOption {
  return MODE_OPTIONS.find((m) => m.id === mode) ?? MODE_OPTIONS[0]
}

// ---------------------------------------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------------------------------------

type Load = 'loading' | 'ready' | 'error'

export default function SettingsPanel() {
  const [live, setLive] = useState<LiveStatus | null>(null)
  const [allow, setAllow] = useState<AllowlistState | null>(null)
  const [settings, setSettings] = useState<SettingsState | null>(null)
  const [state, setState] = useState<Load>('loading')
  const [err, setErr] = useState<string | null>(null)
  const [modeBusy, setModeBusy] = useState<RedactionMode | null>(null)
  const [modeErr, setModeErr] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    setState('loading')
    Promise.all([getLiveStatus(), getAllowlist(), getSettings()])
      .then(([l, a, s]) => {
        if (!alive) return
        setLive(l)
        setAllow(a)
        setSettings(s)
        setErr(null)
        setState('ready')
      })
      .catch((e) => {
        if (!alive) return
        setErr(String((e as Error)?.message ?? e))
        setState('error')
      })
    return () => {
      alive = false
    }
  }, [])

  const changeMode = async (mode: RedactionMode) => {
    if (!settings || settings.mode === mode || modeBusy) return
    setModeBusy(mode)
    setModeErr(null)
    try {
      const res = await setMode(mode)
      setSettings((s) => (s ? { ...s, mode: res.mode } : s))
    } catch (e) {
      setModeErr(String((e as Error)?.message ?? e))
    } finally {
      setModeBusy(null)
    }
  }

  const reachable = state === 'ready'
  const rows = live && allow ? formatStatus(live, allow) : []
  const pct = live ? bufferPct(live.buffered, live.max) : 0

  return (
    <div className="space-y-5">
      {/* Daemon-reachable banner */}
      <div
        role="status"
        className={`flex items-center gap-2.5 rounded-lg border px-3.5 py-2.5 text-sm ${
          reachable
            ? 'border-teal-200 dark:border-teal-400/20 bg-teal-50 dark:bg-teal-400/10 text-teal-800 dark:text-teal-200'
            : state === 'error'
              ? 'border-red-200 dark:border-red-400/20 bg-red-50 dark:bg-red-400/10 text-red-700 dark:text-red-300'
              : 'border-gray-200 dark:border-white/10 bg-gray-50 dark:bg-white/5 text-gray-500 dark:text-neutral-400'
        }`}
      >
        <span
          aria-hidden="true"
          className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${
            reachable ? 'bg-teal-500' : state === 'error' ? 'bg-red-500' : 'bg-gray-300'
          }`}
        />
        <span className="font-medium">
          {reachable
            ? 'Firewall daemon connected'
            : state === 'error'
              ? 'Cannot reach the firewall daemon'
              : 'Connecting to the firewall daemon…'}
        </span>
      </div>

      {/* Live status board */}
      <section aria-label="Firewall status">
        <h2 className="mb-2 text-sm font-semibold text-gray-900 dark:text-neutral-100">Firewall status</h2>

        {state === 'error' ? (
          <div className="rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-[#191919] px-4 py-6 text-center">
            <p className="text-sm text-red-600 dark:text-red-400">Status unavailable.</p>
            {err && <p className="mt-1 font-mono text-xs break-all text-gray-400 dark:text-neutral-500">{err}</p>}
          </div>
        ) : (
          <div className="rounded-xl border border-gray-200 dark:border-white/10 bg-white dark:bg-[#191919] px-4 py-1 shadow-sm">
            {state === 'loading'
              ? // Loading skeleton rows
                Array.from({ length: 5 }).map((_, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between border-b border-gray-100 dark:border-white/10 py-2.5 last:border-0"
                  >
                    <span className="h-3 w-28 animate-pulse rounded bg-gray-100 dark:bg-white/10" />
                    <span className="h-3 w-16 animate-pulse rounded bg-gray-100 dark:bg-white/10" />
                  </div>
                ))
              : rows.map((r) => (
                  <div
                    key={r.label}
                    className="flex items-center justify-between border-b border-gray-100 dark:border-white/10 py-2.5 last:border-0"
                  >
                    <span className="text-sm text-gray-500 dark:text-neutral-400">{r.label}</span>
                    <span className="font-mono text-sm text-gray-900 dark:text-neutral-100">{r.value}</span>
                  </div>
                ))}

            {/* Buffer fill bar (only once we have real numbers) */}
            {reachable && live && (
              <div className="border-t border-gray-100 dark:border-white/10 py-3">
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="text-xs text-gray-400 dark:text-neutral-500">Buffer fill</span>
                  <span className="font-mono text-xs text-gray-500 dark:text-neutral-400">{pct}%</span>
                </div>
                <div
                  className="h-1.5 w-full overflow-hidden rounded-full bg-gray-100 dark:bg-white/10"
                  role="progressbar"
                  aria-label="Live-event buffer fill"
                  aria-valuenow={pct}
                  aria-valuemin={0}
                  aria-valuemax={100}
                >
                  <div
                    className="h-full rounded-full bg-teal-500 transition-[width]"
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Hard guarantee: always-protected categories */}
      <section aria-label="What's always protected">
        <div className="rounded-xl border border-teal-200 dark:border-teal-400/20 bg-teal-50/60 dark:bg-teal-400/10 p-4 shadow-sm">
          <div className="mb-3 flex items-center gap-2">
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#0d9488"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
              className="shrink-0"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
            <h2 className="text-sm font-semibold text-teal-900 dark:text-teal-200">What's always protected</h2>
          </div>
          <p className="mb-3 text-xs leading-relaxed text-teal-800/80 dark:text-teal-200">
            These categories are redacted server-side and <strong>cannot be disabled</strong> -- not by the
            dictionary, not by any mode. This is the firewall's hard guarantee.
          </p>
          <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {ALWAYS_PROTECTED.map((c) => (
              <li
                key={c.title}
                className="flex items-start gap-2 rounded-lg border border-teal-200/70 dark:border-teal-400/20 bg-white dark:bg-[#191919] px-3 py-2.5"
              >
                <svg
                  width="14"
                  height="14"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#0d9488"
                  strokeWidth="3"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                  className="mt-0.5 shrink-0"
                >
                  <path d="M20 6 9 17l-5-5" />
                </svg>
                <span>
                  <span className="block text-sm font-medium text-gray-900 dark:text-neutral-100">{c.title}</span>
                  <span className="block text-xs leading-snug text-gray-500 dark:text-neutral-400">{c.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* Live redaction-mode switch */}
      <section aria-label="Redaction mode">
        <h2 className="mb-1 text-sm font-semibold text-gray-900 dark:text-neutral-100">Redaction mode</h2>
        <p className="mb-3 text-xs leading-relaxed text-gray-500 dark:text-neutral-400">
          How much the firewall redacts. The always-protected categories above stay on in every mode.
        </p>

        <fieldset
          className="rounded-xl border border-gray-200 dark:border-white/10 bg-white dark:bg-[#191919] shadow-sm"
          disabled={!reachable || modeBusy !== null}
          aria-busy={modeBusy !== null}
        >
          <legend className="sr-only">Redaction mode</legend>
          {MODE_OPTIONS.map((opt) => {
            const active = settings?.mode === opt.id
            const busy = modeBusy === opt.id
            return (
              <label
                key={opt.id}
                className={`flex cursor-pointer items-start gap-3 border-b border-gray-100 dark:border-white/10 px-4 py-3 last:border-0 ${
                  active ? (opt.warn ? 'bg-amber-50/60 dark:bg-amber-400/10' : 'bg-teal-50/50 dark:bg-teal-400/10') : 'hover:bg-gray-50 dark:hover:bg-white/5'
                } ${!reachable || modeBusy ? 'cursor-not-allowed' : ''}`}
              >
                <input
                  type="radio"
                  name="redaction-mode"
                  checked={!!active}
                  onChange={() => changeMode(opt.id)}
                  className={`mt-0.5 ${opt.warn ? 'accent-amber-600' : 'accent-teal-600'}`}
                  aria-label={`${opt.title} mode`}
                />
                <span className="min-w-0">
                  <span className="flex items-center gap-2">
                    <span className={`text-sm font-medium ${active && opt.warn ? 'text-amber-800 dark:text-amber-300' : 'text-gray-900 dark:text-neutral-100'}`}>
                      {opt.title}
                    </span>
                    {active && (
                      <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                        opt.warn ? 'bg-amber-100 dark:bg-amber-400/15 text-amber-700 dark:text-amber-300' : 'bg-teal-100 dark:bg-teal-400/15 text-teal-700 dark:text-teal-300'
                      }`}>
                        {busy ? 'Saving' : 'Active'}
                      </span>
                    )}
                  </span>
                  <span className="mt-0.5 block text-xs leading-snug text-gray-500 dark:text-neutral-400">{opt.detail}</span>
                </span>
              </label>
            )
          })}
        </fieldset>

        {/* When Off is active, restate plainly what is still protected -- this is the honesty guard. */}
        {settings?.mode === 'off' && (
          <p className="mt-2 flex items-start gap-1.5 text-xs leading-relaxed text-amber-700 dark:text-amber-300">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="mt-0.5 shrink-0">
              <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <span>
              Personal data is passing through. Secrets, payment cards, IBANs, and government IDs are
              <strong> still redacted</strong> -- Off is never a credential bypass.
            </span>
          </p>
        )}
        {modeErr && <p className="mt-2 text-xs text-red-500 dark:text-red-400">Could not change mode: {modeErr}</p>}
      </section>
    </div>
  )
}
