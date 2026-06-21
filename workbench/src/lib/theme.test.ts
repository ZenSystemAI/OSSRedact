// Tests for the light/dark theme module. jsdom provides document + localStorage; matchMedia is stubbed
// per-test. We assert the persisted value, the resolved theme, and the `.dark` class side effect. No real
// data, no network.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { storedTheme, systemTheme, resolvedTheme, setTheme, toggleTheme, initTheme } from './theme'

function setSystem(prefersDark: boolean | undefined) {
  if (prefersDark === undefined) {
    // simulate an environment without matchMedia
    ;(window as unknown as { matchMedia?: unknown }).matchMedia = undefined
    return
  }
  window.matchMedia = vi.fn().mockImplementation((q: string) => ({
    matches: prefersDark && q.includes('dark'),
    media: q,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })) as unknown as typeof window.matchMedia
}

const isDarkClass = () => document.documentElement.classList.contains('dark')

beforeEach(() => {
  localStorage.clear()
  document.documentElement.classList.remove('dark')
  document.documentElement.style.colorScheme = ''
  setSystem(false)
})
afterEach(() => {
  vi.restoreAllMocks()
})

describe('storedTheme', () => {
  it('is null when nothing has been chosen', () => {
    expect(storedTheme()).toBeNull()
  })
  it('returns a valid stored choice', () => {
    localStorage.setItem('ossredact-theme', 'dark')
    expect(storedTheme()).toBe('dark')
  })
  it('ignores a garbage stored value', () => {
    localStorage.setItem('ossredact-theme', 'chartreuse')
    expect(storedTheme()).toBeNull()
  })
})

describe('systemTheme', () => {
  it('is dark when the OS prefers dark', () => {
    setSystem(true)
    expect(systemTheme()).toBe('dark')
  })
  it('is light when the OS prefers light', () => {
    setSystem(false)
    expect(systemTheme()).toBe('light')
  })
  it('defaults to light when matchMedia is unavailable', () => {
    setSystem(undefined)
    expect(systemTheme()).toBe('light')
  })
})

describe('resolvedTheme', () => {
  it('prefers the stored choice over the system preference', () => {
    setSystem(true) // system dark...
    localStorage.setItem('ossredact-theme', 'light') // ...but user chose light
    expect(resolvedTheme()).toBe('light')
  })
  it('falls back to the system preference when unset', () => {
    setSystem(true)
    expect(resolvedTheme()).toBe('dark')
  })
})

describe('setTheme', () => {
  it('applies dark: adds the .dark class + persists + sets colorScheme', () => {
    setTheme('dark')
    expect(isDarkClass()).toBe(true)
    expect(localStorage.getItem('ossredact-theme')).toBe('dark')
    expect(document.documentElement.style.colorScheme).toBe('dark')
  })
  it('applies light: removes the .dark class', () => {
    setTheme('dark')
    setTheme('light')
    expect(isDarkClass()).toBe(false)
    expect(localStorage.getItem('ossredact-theme')).toBe('light')
  })
})

describe('toggleTheme', () => {
  it('flips light -> dark and persists', () => {
    setSystem(false) // resolved = light
    expect(toggleTheme()).toBe('dark')
    expect(isDarkClass()).toBe(true)
    expect(storedTheme()).toBe('dark')
  })
  it('flips dark -> light', () => {
    setTheme('dark')
    expect(toggleTheme()).toBe('light')
    expect(isDarkClass()).toBe(false)
  })
})

describe('initTheme', () => {
  it('applies the system preference on first run (no stored choice)', () => {
    setSystem(true)
    expect(initTheme()).toBe('dark')
    expect(isDarkClass()).toBe(true)
  })
  it('applies the stored choice over system', () => {
    setSystem(true)
    localStorage.setItem('ossredact-theme', 'light')
    expect(initTheme()).toBe('light')
    expect(isDarkClass()).toBe(false)
  })
})
