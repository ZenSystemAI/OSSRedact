# PDF-batch peak-heap measurement (plan 020 Phase 2 / LAUNCH-CHECKLIST #2)

> **PII-free.** Aggregate memory numbers only. The corpus is 14 PUBLIC sample PDFs from
> `datasets/scaffolds/` (government forms, bank/credit statement guides) -- no personal data.
> Rerun 2026-06-18 against current `master` after the PDF coverage-rescan and lazy-load changes.

## Why this run exists

Plan 020 Phase 2 (PDF batch) is **lazy one-PDF-at-a-time by construction** (`renderRedactedPdf`
rasterizes one full-page canvas at a time and frees it at `pdfExport.ts:123`, then `page.cleanup()`
and `pdf.destroy()` at `:124`/`:131`). LAUNCH-CHECKLIST #2 (LOW) flagged that the "heap returns to
baseline between files" claim was asserted from code, never **empirically measured** (the original work
ran headless). This run measures it in a real browser before promising large-PDF batches.

## Method

- Real browser: system Google Chrome 149, headless, launched isolated via Playwright (`--enable-precise-memory-info`
  + `--js-flags=--expose-gc`). No source edits; no MCP-browser collision.
- Gate-down: Playwright intercepted `/gate/*` in the tab and returned a local 503, and the measurement drove only
  `loadFile()` plus `renderRedactedPdf(bytes, pages, [], [])`. No `deepDetect`, no `/detect`, no appliance proxy,
  no GPU gate.
- Drives the **exact production functions** from the running workbench origin (`http://localhost:5180`):
  `loadFile()` (intake, holds N `LoadedDoc`s with bytes+pages, mirroring `handleLoadBatch`), then a lazy
  loop of `renderRedactedPdf(bytes, pages, [], [])` per file, **retaining each output blob** exactly like
  the real `zipFiles[]` accumulation in `App.tsx` `handleExportBatch`. Empty spans/regions => image-only
  raster (the heavy path runs unconditionally; avoids the per-file uncovered-span block).
- Sampled `performance.memory.usedJSHeapSize` before/after each render, and **after a forced GC** (`window.gc()`)
  per file to read the true post-collection trough.
- Corpus: 14 PDFs, **245 pages total**, largest single doc **94 pages** (a worst-case multi-page form).
- Reproduce: `/tmp/ossredact_heap_measure_current.cjs` (Playwright) against `npm run dev` (workbench, :5180)
  + a CORS static server over `datasets/scaffolds/` (:8109). Both kept out of the repo.

## Result

| | JS heap (usedJSHeapSize) |
|---|---|
| baseline (empty app, post-GC) | **8.6 MB** |
| after intake of all 14 PDFs (held in `docs[]`) | **31.7 MB** |
| **peak during the whole batch** | **159.1 MB** -- transient, during the 94-page doc only |
| done (after full 14-file batch, post-GC) | **32.6 MB** (net +24 MB over baseline) |
| retained output blobs (sum of all 14 redacted PDFs) | **81.1 MB** -- native-backed, NOT in the JS heap |

Per-file post-GC trough (over the 8.6 MB baseline), in batch order:

```
file:   0    1    2    3    4    5    6    7    8    9   10   11   12   13
pages:  1    1    6    6   36   18    2   43   12    5   16    3    2   94
trough:+25  +25  +29  +31  +24  +35  +26  +52  +33  +30  +40  +28  +27 +104  (MB over baseline)
```

## Conclusions

1. **No heap blowup; heap returns to the running baseline between files -- CONFIRMED.** The post-GC trough
   does NOT climb with batch position: file 12 (near the end, after 13 retained input docs and 42 MB of
   retained output blobs) troughs at +27 MB over the empty-app baseline, essentially identical to file 0
   (+25 MB). The final post-loop GC is 32.6 MB. Raster canvases and the per-file pdf-lib document are freed
   each iteration; nothing accumulates across files. The lazy one-at-a-time design holds empirically.
2. **Peak is governed by the LARGEST SINGLE document's page count, not by batch size N.** A 1-page PDF adds
   ~2.7 MB; the 94-page PDF transiently peaked the JS heap at 159.1 MB while sampled during render, then
   was 139.7 MB immediately after render (pdf-lib's output document accumulating all 94 embedded JPEGs +
   the ~41 MB output byte array before `save()`), then dropped back.
   So a "10-15 PDF batch" is safe regardless of count -- the only scaling lever is the biggest individual
   file. For typical statements/reports (1-40 pages) the single-file peak stays under ~85 MB.
3. **Output blobs are native-backed and outside the JS heap.** `done` JS heap is 32.6 MB while 81.1 MB of
   redacted output blobs are held in the zip set -- they accumulate linearly (expected for a zip) without
   pressuring the JS heap.
4. **Linear, bounded input retention.** Holding 14 input byte buffers adds ~24 MB JS heap (the `done`
   delta). Linear in N x file size, by design, not a blowup.

## Caveats (honest scope of the measure)

- `usedJSHeapSize` is the **main-thread** isolate. pdf.js parses in a Web Worker with a separate heap not
  captured here; but `renderRedactedPdf` calls `pdf.destroy()` per file (`pdfExport.ts:131`), tearing down
  the per-file worker doc, and the flat main-thread troughs corroborate no leak.
- Full-page canvas pixel buffers (RASTER_SCALE 2.0) are native/GPU-backed and only partially reflected in
  `usedJSHeapSize`. By construction exactly ONE page's canvas exists at a time (freed at `:123`), one file
  at a time, so the native raster footprint is bounded by the single largest page (~7-9 MB for Letter/A4/
  Legal at 2x), independent of N.
- The single-file peak (conclusion 2) grows with ONE doc's page count. A pathologically huge single PDF
  (hundreds of pages) would raise that transient; the batch dimension (number of files) does not.

**Verdict: LAUNCH-CHECKLIST #2 closed.** Large-PDF *batches* are safe to promise (memory is flat in N).
The only documented limit is a single enormous (100+ page) document, whose transient peak scales with that
one file -- not with batch size.
