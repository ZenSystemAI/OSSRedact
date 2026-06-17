import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: false,
  // pure data + regex -- no shims needed
  target: 'es2022',
  outDir: 'dist',
})
