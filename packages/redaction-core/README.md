# @ossredact/core

Tier-0 deterministic PII detector and span/redaction core for OSSRedact.

Pure TypeScript, browser-safe, zero runtime dependencies.

## What is in this package

- **Tier-0 detector** (`tier0Spans`, `contextCuedIdSpans`) -- regex + checksum-validated patterns for
  emails, phone numbers, SIN/SSN, credit cards, IBANs, passport numbers, IP addresses, dates, and more.
- **Span management** (`mergeSpans`, `toSpans`, `insertSpan`, `combineWithManual`) -- overlap resolution
  and manual annotation support.
- **Redaction primitives** (`redactedText`, `rehydrate`, `explain`, `buildEntityMap`) -- placeholder
  substitution, round-trip rehydration, and entity-map construction.
- **Label metadata** (`labelMeta`, `labelTier`, `MANUAL_LABELS`) -- tier classification and display
  names for all entity types.

## Install

```
npm install @ossredact/core
```

## Usage

```ts
import { tier0Spans, redactedText, buildEntityMap } from '@ossredact/core'

const text = 'Call John at 514-555-0199 or john@example.com'
const spans = tier0Spans(text)
const map = buildEntityMap(spans)
const redacted = redactedText(text, spans, map)
// "Call John at [PHONE-1] or [EMAIL-1]"
```

## Build

```
npm run build   # emits dist/ via tsup (ESM + .d.ts)
```

## Test

```
npm test        # vitest run (56 unit tests)
```

## License

MIT
