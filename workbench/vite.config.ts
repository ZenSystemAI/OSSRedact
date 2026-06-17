import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

// The optional neural "deep detect" tier lives on a local gate (tailnet :8001). Default = the P620 GPU gate
// (xlm-r-large fp16 on the 3090 Ti, the strongest tier -- for own-use redaction). The Beelink NPU gate
// (http://100.119.28.26:8001) stays the always-on appliance for the ci-pdf-parser; point at it via
// SPARX_GATE_URL if wanted. A browser fetch from the Vite origin would be cross-origin; the dev proxy
// forwards /gate/* so the gate needs no CORS change. The app works fully offline without it (client Tier-0).
const GATE = process.env.SPARX_GATE_URL || 'http://100.65.111.24:8001'

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
