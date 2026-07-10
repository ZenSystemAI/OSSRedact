// Light/dark theme. A single `.dark` class on <html> drives everything: the workbench's CSS-variable
// styling (index.css .dark block) and the console's Tailwind `dark:` utilities both key off it. Default
// follows the OS preference until the user picks one; the choice persists in localStorage.

export type Theme = 'light' | 'dark'

const KEY = 'ossredact-theme'

function hasWindow(): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined'
}

/** The user's explicitly-chosen theme, or null if they have never picked one (follow the system). */
export function storedTheme(): Theme | null {
  if (!hasWindow()) return null
  try {
    const v = localStorage.getItem(KEY)
    return v === 'light' || v === 'dark' ? v : null
  } catch {
    return null
  }
}

/** The OS preference (defaults to light when matchMedia is unavailable). */
export function systemTheme(): Theme {
  if (!hasWindow() || !window.matchMedia) return 'light'
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

/** The theme that should currently be showing: the stored choice, else the system preference. */
export function resolvedTheme(): Theme {
  return storedTheme() ?? systemTheme()
}

function apply(theme: Theme): void {
  if (!hasWindow()) return
  document.documentElement.classList.toggle('dark', theme === 'dark')
  document.documentElement.style.colorScheme = theme
}

/** Apply the resolved theme at startup. Call once before/at render. Returns what was applied. */
export function initTheme(): Theme {
  const t = resolvedTheme()
  apply(t)
  return t
}

/** Persist and apply an explicit theme choice. */
export function setTheme(theme: Theme): void {
  if (hasWindow()) {
    try {
      localStorage.setItem(KEY, theme)
    } catch {
      /* storage may be unavailable (private mode) -- still apply for this session */
    }
  }
  apply(theme)
}

/** Flip light<->dark from the currently-resolved theme, persist, and return the new theme. */
export function toggleTheme(): Theme {
  const next: Theme = resolvedTheme() === 'dark' ? 'light' : 'dark'
  setTheme(next)
  return next
}
