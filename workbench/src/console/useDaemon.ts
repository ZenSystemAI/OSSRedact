import { useEffect, useRef, useState } from 'react'
import { ping } from '../lib/daemon'

export type DaemonReach = 'checking' | 'online' | 'offline'

/**
 * Polls the local egress daemon for reachability. Drives the Firewall console's graceful degradation:
 * 'online' -> render the live/dictionary/settings panels; 'offline' -> render the install / start-firewall
 * CTA. Polls every `intervalMs` (default 5s) and immediately on mount. The Workbench (Redact) never calls
 * this -- it is daemon-independent.
 */
export function useDaemon(intervalMs = 5000): { reach: DaemonReach; recheck: () => void } {
  const [reach, setReach] = useState<DaemonReach>('checking')
  const alive = useRef(true)

  // ping() already swallows its own errors, but guard the fire-and-forget calls so a future change can never
  // surface an unhandled rejection from the poll loop.
  const check = useRef(async () => {
    const ok = await ping().catch(() => false)
    if (alive.current) setReach(ok ? 'online' : 'offline')
  })

  useEffect(() => {
    alive.current = true
    void check.current()
    const id = setInterval(() => void check.current(), intervalMs)
    return () => {
      alive.current = false
      clearInterval(id)
    }
  }, [intervalMs])

  return { reach, recheck: () => void check.current() }
}
