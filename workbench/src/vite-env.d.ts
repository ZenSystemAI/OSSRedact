/// <reference types="vite/client" />

// Custom build-time env: a hosted static deploy can bake the daemon base URL into the bundle. Runtime
// override is window.__OSSREDACT_DAEMON__ (Tauri injects it); see src/lib/daemon.ts.
interface ImportMetaEnv {
  readonly VITE_OSSREDACT_DAEMON?: string
}
