import { lazy, Suspense, useEffect, useState } from 'react'
import { initTheme, toggleTheme, type Theme } from './lib/theme'
import { isTauri } from './tauri-bootstrap'

// The unified OSSRedact app shell. A thin top-level switch between two surfaces that share one codebase:
//   - Redact   : the document workbench (in-browser, offline, daemon-independent) -- the universal-reach
//                surface that runs in any browser with no install.
//   - Firewall : the console for the always-on egress daemon (live proof, dictionary, settings) -- the
//                surface that, Tauri-wrapped, becomes the tray-resident firewall control panel.
//
// Both ship from one Vite build: as a static web app (reach) AND wrapped in Tauri (native tray app). The
// heavy workbench (pdf.js, transformers.web) is lazy-loaded so the Firewall console stays light to mount.
// App.tsx is rendered UNCHANGED as the Redact view. Light/dark is driven by a single `.dark` class on
// <html> (see src/lib/theme.ts) -- the workbench's CSS-var styling and the console's dark: utilities follow it.

const Redact = lazy(() => import('./App'))
const Console = lazy(() => import('./console/Console'))

type Surface = 'redact' | 'firewall'

export default function AppShell() {
  // Surface default by context: the Tauri tray app IS the "Firewall Console" (and its 440px window is too
  // narrow for the Redact inspector), so it opens on Firewall; a plain-browser visitor still lands on the
  // daemon-independent Redact tool, unchanged from today. Either is one click from the other via the segments.
  const [surface, setSurface] = useState<Surface>(() => (isTauri() ? 'firewall' : 'redact'))
  const [theme, setThemeState] = useState<Theme>('light')

  useEffect(() => {
    setThemeState(initTheme())
  }, [])

  return (
    <div className="flex h-screen flex-col bg-[var(--color-bg)] text-[var(--color-text)]">
      <div className="flex items-center gap-1 border-b border-gray-200 bg-white/80 px-3 py-1.5 backdrop-blur dark:border-white/10 dark:bg-[#141414]/80">
        <span className="mr-3 select-none px-1 text-sm font-semibold tracking-tight text-gray-900 dark:text-neutral-100">
          OSS<span className="text-teal-600 dark:text-teal-400">Redact</span>
        </span>
        <SegBtn active={surface === 'redact'} onClick={() => setSurface('redact')}>Redact</SegBtn>
        <SegBtn active={surface === 'firewall'} onClick={() => setSurface('firewall')}>Firewall</SegBtn>
        <div className="ml-auto">
          <ThemeToggle theme={theme} onToggle={() => setThemeState(toggleTheme())} />
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <Suspense fallback={<div className="py-20 text-center text-sm text-gray-400 dark:text-neutral-500">Loading…</div>}>
          {surface === 'redact' ? <Redact /> : <Console />}
        </Suspense>
      </div>
    </div>
  )
}

function SegBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-md px-3 py-1 text-sm font-medium transition-colors ${
        active
          ? 'bg-teal-50 text-teal-700 dark:bg-teal-400/10 dark:text-teal-300'
          : 'text-gray-500 hover:text-gray-800 dark:text-neutral-400 dark:hover:text-neutral-100'
      }`}
    >
      {children}
    </button>
  )
}

function ThemeToggle({ theme, onToggle }: { theme: Theme; onToggle: () => void }) {
  const dark = theme === 'dark'
  return (
    <button
      onClick={onToggle}
      aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'}
      title={dark ? 'Light theme' : 'Dark theme'}
      className="flex h-7 w-7 items-center justify-center rounded-md text-gray-500 transition-colors hover:bg-gray-100 hover:text-gray-800 focus:outline-none focus:ring-2 focus:ring-teal-500 dark:text-neutral-400 dark:hover:bg-white/10 dark:hover:text-neutral-100"
    >
      {dark ? (
        // sun
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
        </svg>
      ) : (
        // moon
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      )}
    </button>
  )
}
