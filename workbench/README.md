# ossredact Workbench

A local-first redaction workbench: load a document, review the suggested redactions (with the reason each
was flagged), redact anything else by hand, toggle individual redactions off, and export a redacted copy or
save a redacted PDF. **The document never leaves the machine** -- auto-detect runs in the browser.

This is the manual-review companion to the ossredact egress gateway. It shares the same detection logic and the
same `<LABEL_NNN>` placeholder + entity-map format, so a document redacted here round-trips through the
appliance's entity map.

## Run

```bash
npm install
npm run dev        # http://localhost:5180
npm run build      # -> dist/ (static, deploy by copying the folder)
npm run preview    # serve the built dist/ locally
npm test           # vitest (unit + round-trip)
```

Node 20.19+ / 22.12+.

## What works today (MVP)

- **Load**: `.txt`, `.md`, `.csv`, `.json`, `.log`, `.xml`, `.html`, plus `.docx`, `.xlsx`, and `.pdf` --
  drag-drop, file picker, or paste. Word (`.docx`) and Excel (`.xlsx`) redaction is format-preserving
  (formatting, styles, tables, images survive); PDF export is a true image-only redaction (each page
  rasterized, black boxes painted, no recoverable text layer). (`.pptx` is the next format.)
- **Auto-detect (local, offline)**: a faithful TypeScript port of the appliance's Tier-0 deterministic
  detector -- email, phone, postal code, IP, UUID, dates, payment cards (Luhn), SIN, account/reference IDs,
  and Presidio-style context-cued IDs. Runs entirely in the browser; nothing is uploaded.
- **Deep detect (on-device)** *(optional)*: calls the local appliance (`:8001`, via the Vite `/gate` proxy) to add
  the neural tier (names, addresses, free-text PII). The only path where text leaves the browser -- and only
  to your own local appliance, never to the cloud. The app is fully usable without it.
- **Click-to-inspect**: every redaction shows *why* it was flagged -- recognizer/rule, tier, confidence, Luhn
  validator result, the context cue that promoted it, and how many raw spans merged into it. This is the
  appliance's `explain()` provenance schema rendered as a review UI (Law 25 audit trail).
- **Manual redaction**: select any text to redact it; relabel; **click-to-unredact** any span.
- **Export**: copy/download the redacted file (`<LABEL_NNN>` placeholders, round-trip-capable), download the
  entity map (sensitive -- stays local), download a value-free audit trail, or **print / save a redacted PDF**
  (solid blocks -- no original text in the PDF text layer).
- **Restore (round-trip)**: drop an edited copy back in the **Restore** tab. If you redacted it on this
  device, the saved map is matched automatically and the originals go back into the surviving placeholders --
  no separate file needed. Colleague edits are kept; deleted placeholders simply drop their value.

## On-device map store (no separate map upload)

To restore originals without hand-managing a separate `entity-map.json`, the workbench remembers the entity
map LOCALLY in the browser (IndexedDB, DB `ossredact-maps`), keyed by a content fingerprint of the **redacted
(placeholder-bearing) body** -- never the original text and never the upload filename. When a redacted file
comes back, the app hashes/scans it and auto-matches the stored map.

- **Security invariant (do not regress)**: the entity map IS the plaintext originals. It is written ONLY to
  IndexedDB on THIS device. It is NEVER embedded in the exported `.docx` / `.xlsx` / `.txt` / `.pdf`, and
  the fingerprint hashes the redacted body, never the original. Maps stay on this device only -- never share
  them or store them alongside the redacted copy.
- **Match priority**: exact fingerprint (your own untouched copy) -> else best placeholder-subset overlap
  where every surviving placeholder is resolvable in one stored map -> else the manual upload fallback.
- **Opt-in + clear**: the Restore tab has a "Remember redaction maps on this device" toggle (default ON) and
  a "Clear stored maps" button. With the toggle OFF, nothing is persisted.
- **Fallback (kept forever)**: a different machine, cleared storage, or private browsing has no stored map,
  so the Restore tab reveals the manual `entity-map.json` picker and the original two-file flow still works.

## Roadmap (see `memory/project_ossredact-workbench-and-integrations.md`)

- `.pptx` (PowerPoint) format-preserving redaction.
- In-browser neural detection (run the model in the tab via onnxruntime-web, zero install).
- Tauri wrap for a double-click installer (this exact frontend, no rewrite).

## Architecture

```
src/lib/
  tier0.ts       client-side Tier-0 detector (port of privacy_gate.py tier0_spans)
  redaction.ts   union-merge, placeholder/entity-map, redacted-text, explain()
  gate.ts        optional on-device deep-detect via the local appliance
  mapStore.ts    on-device entity-map store (IndexedDB) for no-upload rehydration
  formats.ts     file loading (text + docx/xlsx/pdf) + round-trip rehydrate
  labels.ts      label display names (FR/EN) + colors
src/components/  Header · Dropzone · DocCanvas · Inspector · Toolbar
```
