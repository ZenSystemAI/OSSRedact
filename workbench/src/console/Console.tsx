import { useState } from 'react'
import { useDaemon } from './useDaemon'
import InstallCta from './InstallCta'
import ConnectPanel from './ConnectPanel'
import LivePanel from './LivePanel'
import DictionaryPanel from './DictionaryPanel'
import DenylistPanel from './DenylistPanel'
import SettingsPanel from './SettingsPanel'

type Tab = 'connect' | 'live' | 'dictionary' | 'settings'
const TABS: { id: Tab; label: string }[] = [
  { id: 'connect', label: 'Connect' },
  { id: 'live', label: 'Live activity' },
  { id: 'dictionary', label: 'Dictionary' },
  { id: 'settings', label: 'Settings' },
]

/**
 * The Firewall console: live proof + do-not-redact dictionary + settings, talking to the local egress
 * daemon. When no daemon is reachable it shows the install / start CTA (the Workbench stays usable). This is
 * the surface that, wrapped in Tauri, becomes the tray-resident firewall console.
 */
export default function Console() {
  const { reach, recheck } = useDaemon()
  const [tab, setTab] = useState<Tab>('connect')

  return (
    <div className="mx-auto max-w-3xl px-5 py-6">
      <nav className="mb-5 flex gap-1 border-b border-gray-200 dark:border-white/10">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              tab === t.id
                ? 'border-teal-600 text-teal-700 dark:text-teal-300'
                : 'border-transparent text-gray-500 dark:text-neutral-400 hover:text-gray-800 dark:hover:text-neutral-100'
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {/* Connect instructions are useful whether or not the daemon is reachable yet (the user may be
          setting up); show them in every state. The other tabs need a live daemon. */}
      {tab === 'connect' && <ConnectPanel />}
      {tab !== 'connect' && reach === 'checking' && <p className="py-12 text-center text-sm text-gray-400 dark:text-neutral-500">Connecting to the firewall…</p>}
      {tab !== 'connect' && reach === 'offline' && <InstallCta onRetry={recheck} />}
      {tab !== 'connect' && reach === 'online' && (
        <>
          {tab === 'live' && <LivePanel />}
          {tab === 'dictionary' && (
            <div className="space-y-8">
              <DictionaryPanel />
              <div className="border-t border-gray-100 dark:border-white/10" />
              <DenylistPanel />
            </div>
          )}
          {tab === 'settings' && <SettingsPanel />}
        </>
      )}
    </div>
  )
}
