import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

// Optional neural "deep detect" tier: a local gate exposing /detect (default :8001). Point at your
// own gate with OSSREDACT_GATE_URL. A browser fetch from the Vite origin would be cross-origin, so the
// dev proxy below forwards /gate/* (no CORS change needed). The app works fully offline without it
// (client Tier-0 detectors).
const GATE = process.env.OSSREDACT_GATE_URL || 'http://127.0.0.1:8001'

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
    },
  },
  // relative base so `dist/` can be opened/served from any path on any PC (the deploy constraint)
  base: './',
})
