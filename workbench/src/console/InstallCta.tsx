import { useEffect, useRef, useState } from 'react'
import { isTauri } from '../tauri-bootstrap'
import { connectBase } from '../lib/daemon'
import { isHostedDemo, HOSTED_DOC_BASE } from '../lib/hosted'
import { firewallControl, waitForLocalFirewallReady } from '../lib/firewall'

/**
 * Shown in the Firewall console tabs when no local daemon is reachable. Two very different situations:
 *  - In the desktop app (Tauri): the app does NOT bundle-spawn the daemon (service model), so the user just
 *    needs to START the firewall service, then retry -- NOT "get the desktop app" (they already have it).
 *  - In a plain browser: point them at the desktop app / Quickstart.
 * The Redact workbench works without a daemon; only the firewall console tabs need one.
 */
export default function InstallCta({ onRetry }: { onRetry: () => void }) {
  const inApp = isTauri()
  const hosted = isHostedDemo()
  // On the hosted demo, connectBase() falls back to the PAGE origin (the website) -- document the
  // gate's loopback default instead so nobody points an agent at the web host.
  const base = hosted ? HOSTED_DOC_BASE : connectBase()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const readyAbortRef = useRef<AbortController | null>(null)

  useEffect(() => {
    return () => {
      readyAbortRef.current?.abort()
      readyAbortRef.current = null
    }
  }, [])

  async function start() {
    setBusy(true)
    setErr(null)
    try {
      await firewallControl('start')
      readyAbortRef.current?.abort()
      const ctrl = new AbortController()
      readyAbortRef.current = ctrl
      await waitForLocalFirewallReady({ signal: ctrl.signal })
      onRetry()
    } catch (e) {
      if (
        (e instanceof DOMException && e.name === 'AbortError') ||
        (e instanceof Error && (/abort/i.test(e.name) || /abort/i.test(e.message)))
      ) {
        return
      }
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="mx-auto max-w-xl py-16 text-center">
      <div className="mx-auto mb-5 flex h-14 w-14 items-center justify-center rounded-2xl bg-teal-50 dark:bg-teal-400/10 text-teal-700 dark:text-teal-300">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
        </svg>
      </div>
      <h2 className="text-lg font-semibold tracking-tight text-gray-900 dark:text-neutral-100">Firewall not running</h2>
      <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-gray-500 dark:text-neutral-400">
        {inApp
          ? 'The firewall service is not answering yet. Start it, then retry -- the live activity, dictionary, and settings tabs control it. Document redaction in the Redact tab works without it.'
          : 'The live activity, dictionary, and settings tabs control the always-on OSSRedact firewall that redacts your AI traffic. Document redaction in the Redact tab works without it.'}
      </p>

      {inApp && (
        <div className="mx-auto mt-5 max-w-md rounded-lg border border-gray-200 dark:border-white/10 bg-gray-50 dark:bg-black/30 p-4 text-center">
          <button
            type="button"
            onClick={start}
            disabled={busy}
            className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50"
          >
            {busy ? 'Starting…' : 'Start the firewall'}
          </button>
          {err && <p className="mt-2 text-xs text-red-600 dark:text-red-400">{err}</p>}
          <p className="mt-2 text-[11px] text-gray-400 dark:text-neutral-500">
            Starts the local services -- no admin needed. Or use the Firewall switch at the top.
          </p>
        </div>
      )}

      <div className="mt-6 flex items-center justify-center gap-3">
        <a
          href={inApp ? 'https://github.com/ZenSystemAI/OSSRedact#quickstart' : 'https://github.com/ZenSystemAI/OSSRedact#desktop-app'}
          target="_blank"
          rel="noreferrer"
          className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700"
        >
          {inApp ? 'Setup guide' : 'Get the desktop app'}
        </a>
        <button
          onClick={onRetry}
          className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 dark:text-neutral-300 hover:bg-gray-50 dark:hover:bg-white/5"
        >
          Retry connection
        </button>
      </div>

      {hosted ? (
        <p className="mx-auto mt-5 max-w-md text-xs leading-relaxed text-gray-400 dark:text-neutral-500">
          This hosted page cannot control a gate. On the machine running the gate, open{' '}
          <code className="font-mono">{HOSTED_DOC_BASE}/console</code> (the gate serves its own console), or use
          the desktop app.
        </p>
      ) : (
        <p className="mx-auto mt-5 max-w-md text-xs leading-relaxed text-gray-400 dark:text-neutral-500">
          Running the gate on another machine (a home server or tailnet host)? Set its address in the{' '}
          <strong className="font-medium text-gray-500 dark:text-neutral-400">Connect</strong> tab →{' '}
          <strong className="font-medium text-gray-500 dark:text-neutral-400">Gate connection</strong>.
        </p>
      )}

      {!inApp && !hosted && (
        <p className="mt-4 text-xs text-gray-400 dark:text-neutral-500">
          Already running it? The service listens on <code className="font-mono">{base}</code>.
        </p>
      )}
    </div>
  )
}
