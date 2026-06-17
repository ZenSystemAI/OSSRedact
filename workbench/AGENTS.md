# AGENTS.md -- workbench (ossredact client-side redaction app)

The **app domain** of `ossredact-privacy-gateway`. Working here you do NOT need the model/training
context -- this is a self-contained front end. (The repo-root `AGENTS.md` covers the model/gate
domain; read it only if your change touches the shared detection contract -- see below.)

## What this is
A fully client-side PII-redaction tool: load a `.txt` / `.docx` / `.xlsx` / `.pdf`, detect spans
(offline Tier-0 regex/checksum detectors, optionally augmented by the gate's NER endpoint),
review and edit spans, and export a redacted file that is verified to leak nothing.

- Stack: TypeScript, React 19, Vite 7. ES2022 target.
- Entry: `src/main.tsx` -> `src/App.tsx`. Lib logic in `src/lib/`. UI in `src/components/`.

## How to work here
```bash
cd workbench
npm install
npm run dev        # Vite dev server
npm run build      # tsc + vite build (typecheck gate)
npm test           # vitest (added by plans/011 -- the redaction-completeness net)
```

## Core invariant (do not regress)
Exported "redacted" output must contain **no** original PII -- in body text, in box coverage
(PDF), or in document metadata (`docProps`). The export paths are fail-closed: `verifyNoText` /
`verifyDocx` / `verifyXlsx` block the download if a redacted value survives. Any change to
`src/lib/redaction.ts`, `tier0.ts`, `pdfExport.ts`, `docx.ts`, or `xlsx.ts` must keep that gate intact.

## Cross-domain coupling (the one reason to look at the model side)
`src/lib/tier0.ts` is a hand-ported twin of the Python `validated_floor` in
`../gate/privacy_gate.py`, and `src/lib/labels.ts` mirrors `../training/labels_v20.json`. They
drift silently. If you change the label set or a Tier-0 detector, mirror it on the Python side
(and vice versa). Durable fix is direction **D1** (codegen from one source) in `../plans/README.md`.

## Notes
- Design tokens in `src/index.css` mirror the landing page palette, now at
  `~/dev/ossredact-web/landing/index.html :root` (the canonical source). The comment at the top of
  `src/index.css` still points at the old in-repo path -- update it when you next touch that file.
- No em dashes; use `--`. Never commit without the maintainer's approval.
