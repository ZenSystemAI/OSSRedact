import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

// Optional neural "deep detect" tier for on-prem installs: a local gate exposing /detect (default :8001).
// Point at your own gate with OSSREDACT_GATE_URL. A browser fetch from the Vite origin would be
// cross-origin, so the dev proxy forwards /gate/* (no CORS change needed). If /gate is absent, the app
// can use the in-browser demo model, and Tier-0 still works without either deep provider.
const GATE = process.env.OSSREDACT_GATE_URL || 'http://127.0.0.1:8001'
// The always-on egress daemon (firewall control API: /api/allowlist, /api/stream SSE, /healthz). The
// Firewall console talks to it same-origin; in dev the proxy forwards to it so no CORS change is needed.
// Point at a running daemon with OSSREDACT_DAEMON_URL (default the standard local egress on :8011).
const DAEMON = process.env.OSSREDACT_DAEMON_URL || 'http://127.0.0.1:8011'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@ossredact/core': fileURLToPath(new URL('../packages/redaction-core/src/index.ts', import.meta.url)),
    },
  },
  server: {
    port: 5180,
    proxy: {
      '/gate': {
        target: GATE,
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/gate/, ''),
      },
      // Firewall control API + SSE live feed. ws:false because SSE is plain HTTP streaming, not WebSocket.
      '/api': { target: DAEMON, changeOrigin: true },
      '/healthz': { target: DAEMON, changeOrigin: true },
    },
  },
  // relative base so `dist/` can be opened/served from any path on any PC (the deploy constraint)
  base: './',
  // Emit dist/manifest.json (every chunk/asset, incl. dynamic-import chunks the HTML never names).
  // The website's offline service worker precaches /app/ from it -- without the manifest an offline
  // first visit renders the shell but cannot fetch the lazily imported App/Console chunks.
  build: { manifest: 'manifest.json' },
})
