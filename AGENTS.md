# AGENTS.md -- sparx-privacy-gateway

This repo holds **two domains**. Scope your context to the one you are working in.

## Domains
1. **model / gate** (core IP) -- the detection model and the redaction library/CLI.
   - `gate/` -- `privacy_gate.py` (tier-0 validated floor + NER tiers + merge + redact/rehydrate) + tests.
   - `training/` -- synthetic data generators + trainer + the 20-label scheme (`labels_v20.json`).
   - `validation/` -- eval harness + results.
   - Root docs: `README.md`, `ARCHITECTURE.md`, `MODEL_CARD.md`, `MODEL-RESULTS.md`, `QUICKSTART.md`.
   - **This `AGENTS.md` (repo root) is the model/gate domain context.**
2. **workbench** (the client-side redaction app) -- `workbench/`.
   - TS / React 19 / Vite. Has its **own `workbench/AGENTS.md`** -- read that when working there.

> The web/marketing surface (landing page + promo) was split out to `~/dev/sparx-web` on 2026-06-16.

## Why scoped
The two domains are coupled only by a **detection contract** (the 20-label set, the
`<LABEL_NNN>` placeholder format, and the Tier-0 detector that exists as a Python source of
truth in `gate/` and a hand-ported TypeScript twin in `workbench/src/lib/tier0.ts`). Until that
contract is codegen'd from a single source (tracked as direction **D1** in `plans/README.md`),
treat changes that touch the label set or Tier-0 as cross-domain and mirror them on both sides.

## Hard constraints (all agents, both domains)
- **Synthetic data only.** Never read `ci-pdf-parser/private/data/`. Never put real PII in code,
  tests, fixtures, docs, or commits.
- **ONNX-INT8 CPU export and any deploy are STOP-and-ask gates.** Do not run them autonomously.
- **P620 training/gate runs on card 4 ONLY**: `CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=4`.
- **No em dashes** anywhere; use `--`. `grep -rlP "\x{2014}"` over edited files must be empty.
- Never reproduce secret values; reference `file:line` + type only.
- Never commit or push without Steven's explicit approval.

## Plans
`plans/` holds advisory implementation plans from `/improve` (executor-ready, zero-context).
Read `plans/README.md` for the active set, dependency order, and status.
