import { useEffect, useState } from 'react'
import { firewallControl, routingConfig, type FirewallStatus } from '../lib/firewall'

/**
 * Desktop-only firewall control bar at the top of the console: a Firewall On/Off switch (starts/stops the
 * `systemctl --user` services, no sudo) and a "Route Claude Code" switch (flips ANTHROPIC_BASE_URL in
 * ~/.claude/settings.json). Replaces the copy-paste CLI snippets the service-model app used to show. Hidden
 * in a plain browser (rendered only when isTauri()); see Console.tsx. Conventional settings rows: label on
 * the left, switch on the right, stacked.
 */
export default function FirewallControls({ onFirewallChange }: { onFirewallChange?: () => void }) {
  const [fw, setFw] = useState<FirewallStatus | 'unknown'>('unknown')
  const [routing, setRouting] = useState<boolean | null>(null)
  const [busy, setBusy] = useState<'fw' | 'route' | null>(null)
  const [err, setErr] = useState<string | null>(null)

  async function refresh() {
    try {
      setFw(await firewallControl('status'))
    } catch {
      setFw('unknown')
    }
    try {
      setRouting(await routingConfig('get'))
    } catch {
      setRouting(null)
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  async function toggleFw() {
    setBusy('fw')
    setErr(null)
    try {
      const next = fw === 'active' ? 'stop' : 'start'
      setFw(await firewallControl(next))
      onFirewallChange?.()
      // the gate loads its model over a few seconds; re-poll so the state + console catch up
      window.setTimeout(() => {
        void refresh()
        onFirewallChange?.()
      }, 4000)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  async function toggleRoute() {
    setBusy('route')
    setErr(null)
    try {
      setRouting(await routingConfig(routing ? 'disable' : 'enable'))
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const on = fw === 'active'
  return (
    <div className="mb-5 overflow-hidden rounded-xl border border-gray-200 dark:border-white/10 bg-gray-50 dark:bg-black/30">
      <Row
        label="Firewall"
        sub={busy === 'fw' ? 'working…' : on ? 'redacting your AI traffic' : 'off -- traffic goes direct'}
        on={on}
        busy={busy === 'fw'}
        onClick={toggleFw}
      />
      <div className="h-px bg-gray-200 dark:bg-white/10" />
      <Row
        label="Route Claude Code"
        sub={
          busy === 'route'
            ? 'working…'
            : routing === null
              ? 'unavailable'
              : routing
                ? 'all sessions go through the firewall'
                : 'opt-in per session'
        }
        on={!!routing}
        busy={busy === 'route'}
        disabled={routing === null}
        onClick={toggleRoute}
      />
      {(err || routing) && (
        <div className="px-4 pb-3 pt-0">
          {err && <p className="text-xs text-red-600 dark:text-red-400">{err}</p>}
          {routing && !err && (
            <p className="text-[11px] text-gray-400 dark:text-neutral-500">
              Applies to NEW Claude Code sessions -- restart any running session to pick it up.
            </p>
          )}
        </div>
      )}
    </div>
  )
}

function Row({
  label,
  sub,
  on,
  busy,
  disabled,
  onClick,
}: {
  label: string
  sub: string
  on: boolean
  busy: boolean
  disabled?: boolean
  onClick: () => void
}) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-3">
      <div className="min-w-0">
        <div className="text-sm font-medium text-gray-900 dark:text-neutral-100">{label}</div>
        <div className="truncate text-[11px] text-gray-500 dark:text-neutral-400">{sub}</div>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={on}
        aria-label={label}
        disabled={busy || disabled}
        onClick={onClick}
        className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${
          on ? 'bg-teal-600' : 'bg-gray-300 dark:bg-neutral-600'
        } ${busy || disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'}`}
      >
        <span
          className="inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform"
          style={{ transform: on ? 'translateX(22px)' : 'translateX(2px)' }}
        />
      </button>
    </div>
  )
}
