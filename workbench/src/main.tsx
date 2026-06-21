import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
// Self-hosted variable fonts (bundled by Vite, served same-origin) -- the app makes
// NO third-party request on load, so "the document never leaves the machine" holds literally.
import '@fontsource-variable/inter'
import '@fontsource-variable/inter-tight'
import '@fontsource-variable/jetbrains-mono'
import './index.css'
import AppShell from './AppShell.tsx'
import { ensureDaemonBase } from './tauri-bootstrap'
import { initTheme } from './lib/theme'

// Apply the saved/system theme BEFORE the first paint to avoid a light-then-dark flash.
initTheme()

// No-op in a plain browser; inside the Tauri shell it guarantees the loopback daemon base is set even
// if the native init script did not run (the shell normally injects it). Safe + idempotent.
ensureDaemonBase()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AppShell />
  </StrictMode>,
)
