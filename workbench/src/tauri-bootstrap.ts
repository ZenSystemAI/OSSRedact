// Tauri shell bootstrap helpers (OPTIONAL, side-effect-free).
//
// The native shell (src-tauri/) injects `window.__OSSREDACT_DAEMON__ = "http://127.0.0.1:8011"` via a
// webview initialization script that runs BEFORE any page script (see src-tauri/src/lib.rs). So by the
// time the React app boots inside the Tauri window, daemon.ts::daemonBase() already reads the right
// loopback base with zero frontend changes.
//
// This module is NOT imported by the existing entrypoints (main.tsx is untouched); it exists so future
// code can detect the Tauri runtime and read the injected daemon base in a typed way. Importing it has
// no side effects -- it only declares globals and exports pure functions.

declare global {
  interface Window {
    /** Injected by the Tauri shell's init script; absent in a plain browser. */
    __OSSREDACT_DAEMON__?: string
    /** Present when running inside a Tauri v2 webview. */
    __TAURI_INTERNALS__?: unknown
  }
}

/** True when the app is running inside the Tauri native shell (vs a plain browser tab). */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && typeof window.__TAURI_INTERNALS__ !== 'undefined'
}

/**
 * The daemon base URL the shell injected, or undefined in a plain browser (where the app talks to the
 * daemon same-origin via the Vite proxy / a hosted static deploy). Mirrors how daemon.ts reads it.
 */
export function injectedDaemonBase(): string | undefined {
  if (typeof window === 'undefined') return undefined
  return window.__OSSREDACT_DAEMON__
}

/**
 * Idempotent fallback: if the shell's init script did not run for some reason but we ARE inside Tauri,
 * set the loopback daemon base so the Firewall console can still reach the local egress. A no-op in a
 * plain browser (so the same bundle stays a pure static web app there). Returns the effective base.
 *
 * Safe to call at startup; it never overwrites an already-injected value.
 */
export function ensureDaemonBase(fallback = 'http://127.0.0.1:8011'): string | undefined {
  if (typeof window === 'undefined') return undefined
  if (!window.__OSSREDACT_DAEMON__ && isTauri()) {
    window.__OSSREDACT_DAEMON__ = fallback
  }
  return window.__OSSREDACT_DAEMON__
}

export {}
