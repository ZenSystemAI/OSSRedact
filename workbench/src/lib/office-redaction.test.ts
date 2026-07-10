// Round-trip completeness tests for .docx and .xlsx redaction.
// Verifies that every active span's original value is removed from the rebuilt file,
// and that the fail-closed verifier actually detects survival when no spans are active.
// Also verifies that docProps metadata (author, lastModifiedBy, custom properties) is
// scrubbed on rebuild even when those values never appear in the document body.
// All content is synthetic -- no real PII.

import { describe, it, expect } from 'vitest'
import JSZip from 'jszip'
import { loadDocx, verifyDocx, docxLeakParts } from './docx'
import { loadXlsx, verifyXlsx } from './xlsx'
import { tier0Spans } from './tier0'
import { mergeSpans, toSpans, buildEntityMap } from './redaction'
import { replacementsForText } from './batch'
import type { Span } from './types'
import { makeDocxBlob, blobToFile as docxBlobToFile } from '../../test/fixtures/make-docx'
import { makeXlsxBlob, blobToFile as xlsxBlobToFile } from '../../test/fixtures/make-xlsx'

// Synthetic PII (all invented)
const SYNTHETIC_NAME = 'Sylvie Bouchard'
// Public SIN test vector -- passes Luhn check
const SYNTHETIC_SIN = '046 454 286'
const REPEATED_EMAIL = 'repeat.office@example.test'

function emailSpan(text: string): Span {
  const start = text.indexOf(REPEATED_EMAIL)
  if (start < 0) throw new Error('missing repeated email in fixture')
  return {
    id: 'email-1',
    start,
    end: start + REPEATED_EMAIL.length,
    label: 'email',
    tier: 0,
    conf: 0.99,
    rule: 'test:email',
    source: 'auto',
    active: true,
  }
}

function valueSpan(text: string, value: string, label = 'person'): Span {
  const start = text.indexOf(value)
  if (start < 0) throw new Error('missing synthetic value in fixture')
  return {
    id: `${label}-manual-1`,
    start,
    end: start + value.length,
    label,
    tier: 1,
    conf: 1,
    rule: 'test:manual',
    source: 'manual',
    active: true,
  }
}

// -------------------------
// .docx round-trip
// -------------------------
describe('docx round-trip', () => {
  it('produces zero leaked values after redacting active spans', async () => {
    // Build a minimal .docx with synthetic PII
    const blob = await makeDocxBlob([
      `Contact: ${SYNTHETIC_NAME}`,
      `NAS: ${SYNTHETIC_SIN}`,
      'Montant: 1 500,00 $',
    ])
    const file = docxBlobToFile(blob, 'test.docx')
    const { text, rebuild } = await loadDocx(file)

    // Auto-detect + merge
    const rawSpans = mergeSpans(tier0Spans(text))
    const spans = toSpans(rawSpans, 'auto')

    // Must have found at least the SIN
    const sinSpan = spans.find((s) => text.slice(s.start, s.end).replace(/\D/g, '') === '046454286')
    expect(sinSpan).toBeDefined()

    // Build replacements (mirror App.tsx:162-164)
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const repls = spans
      .filter((s) => s.active)
      .map((s) => ({ start: s.start, end: s.end, text: placeholderOf.get(s.id) ?? '' }))

    // Rebuild and verify
    const outputBlob = await rebuild(repls)
    const leaked = await verifyDocx(outputBlob, Object.values(map))
    expect(leaked).toHaveLength(0)
  })

  it('sweeps repeated known values that were missed positionally', async () => {
    const blob = await makeDocxBlob([
      `First: ${REPEATED_EMAIL}`,
      `Second: ${REPEATED_EMAIL}`,
    ])
    const file = docxBlobToFile(blob, 'repeat.docx')
    const { text, rebuild } = await loadDocx(file)
    const spans = [emailSpan(text)] // simulate detector finding only the first occurrence
    const { map, placeholderOf } = buildEntityMap(text, spans)

    const outputBlob = await rebuild(replacementsForText(text, spans, placeholderOf, map))
    const leaked = await verifyDocx(outputBlob, Object.values(map))
    expect(leaked).toHaveLength(0)
  })

  it('negative case: verifyDocx detects survival when no spans are active', async () => {
    // Build same document but redact NOTHING (all spans inactive)
    const blob = await makeDocxBlob([
      `Contact: ${SYNTHETIC_NAME}`,
      `NAS: ${SYNTHETIC_SIN}`,
    ])
    const file = docxBlobToFile(blob, 'test-neg.docx')
    const { text, rebuild } = await loadDocx(file)

    // Detect but mark all inactive
    const rawSpans = mergeSpans(tier0Spans(text))
    const spans = toSpans(rawSpans, 'auto').map((s) => ({ ...s, active: false }))

    // With no active spans, map is empty, repls is empty -> original values survive
    const { map } = buildEntityMap(text, spans)
    expect(Object.keys(map)).toHaveLength(0) // confirms no active spans entered the map

    // Rebuild with empty repls -> original content unchanged
    const outputBlob = await rebuild([])

    // The SIN (with spaces, as it appears in the docx text) must still be present in the output
    const leaked = await verifyDocx(outputBlob, [SYNTHETIC_SIN])
    expect(leaked.length).toBeGreaterThan(0)
  })
})

// -------------------------
// .docx non-body parts (customXml data stores, glossary, cached chart/diagram data)
// -------------------------
// These parts can MIRROR body PII (content controls bound to a customXml store, cached chart labels, etc.).
// They are not in BODY_PART_RE, so before the fix a mapped value survived there. Each fixture puts the value
// in the body (so it is detected + mapped -> a replacement is produced) AND in the extra part.

// Decode the serialized-XML entities so a <LABEL_NNN> placeholder (which serializes as &lt;LABEL_NNN&gt;)
// can be matched literally in the assertions.
function decodeEntities(s: string): string {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&')
}

// Attach an extra XML part to a base .docx blob and return the new blob.
async function withExtraPart(blob: Blob, partName: string, xml: string): Promise<Blob> {
  const zip = await JSZip.loadAsync(blob)
  zip.file(partName, xml)
  return zip.generateAsync({ type: 'blob', mimeType: blob.type })
}

describe('docx non-body value sweep', () => {
  it('sweeps a mapped value out of a customXml data store (text nodes AND attribute values)', async () => {
    const base = await makeDocxBlob({ paragraphs: [`Contact: ${SYNTHETIC_NAME}`] })
    const blob = await withExtraPart(
      base,
      'customXml/item1.xml',
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<root xmlns="urn:test"><client full="${SYNTHETIC_NAME}">${SYNTHETIC_NAME}</client></root>`,
    )

    const file = docxBlobToFile(blob, 'customxml-test.docx')
    const { text, rebuild } = await loadDocx(file)
    const spans = [valueSpan(text, SYNTHETIC_NAME)]
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const placeholder = placeholderOf.get(spans[0].id)!
    const outputBlob = await rebuild(replacementsForText(text, spans, placeholderOf, map))

    const postZip = await JSZip.loadAsync(outputBlob)
    const postItem = await postZip.file('customXml/item1.xml')!.async('string')
    expect(postItem).not.toContain(SYNTHETIC_NAME) // gone from both the text node and the attribute
    expect(decodeEntities(postItem)).toContain(placeholder) // placeholder written in its place
    // Fail-closed gate now scans customXml/ too -> passes because the value was actually removed.
    expect(await verifyDocx(outputBlob, Object.values(map))).toHaveLength(0)
  })

  it('sweeps a mapped value out of a cached chart label', async () => {
    const base = await makeDocxBlob({ paragraphs: [`Region owner: ${SYNTHETIC_NAME}`] })
    const blob = await withExtraPart(
      base,
      'word/charts/chart1.xml',
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart">
  <c:ser><c:cat><c:strRef><c:strCache><c:pt idx="0"><c:v>${SYNTHETIC_NAME}</c:v></c:pt></c:strCache></c:strRef></c:cat></c:ser>
</c:chartSpace>`,
    )

    const file = docxBlobToFile(blob, 'chart-test.docx')
    const { text, rebuild } = await loadDocx(file)
    const spans = [valueSpan(text, SYNTHETIC_NAME)]
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const placeholder = placeholderOf.get(spans[0].id)!
    const outputBlob = await rebuild(replacementsForText(text, spans, placeholderOf, map))

    const postZip = await JSZip.loadAsync(outputBlob)
    const postChart = await postZip.file('word/charts/chart1.xml')!.async('string')
    expect(postChart).not.toContain(SYNTHETIC_NAME)
    expect(decodeEntities(postChart)).toContain(placeholder)
    expect(await verifyDocx(outputBlob, Object.values(map))).toHaveLength(0)
  })

  it('sweeps a mapped value out of the glossary document', async () => {
    const base = await makeDocxBlob({ paragraphs: [`Signed: ${SYNTHETIC_NAME}`] })
    const blob = await withExtraPart(
      base,
      'word/glossary/document.xml',
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:glossaryDocument xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docParts><w:docPart><w:docPartBody><w:p><w:r><w:t>${SYNTHETIC_NAME}</w:t></w:r></w:p></w:docPartBody></w:docPart></w:docParts>
</w:glossaryDocument>`,
    )

    const file = docxBlobToFile(blob, 'glossary-test.docx')
    const { text, rebuild } = await loadDocx(file)
    const spans = [valueSpan(text, SYNTHETIC_NAME)]
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const placeholder = placeholderOf.get(spans[0].id)!
    const outputBlob = await rebuild(replacementsForText(text, spans, placeholderOf, map))

    const postZip = await JSZip.loadAsync(outputBlob)
    const postGlossary = await postZip.file('word/glossary/document.xml')!.async('string')
    expect(postGlossary).not.toContain(SYNTHETIC_NAME)
    expect(decodeEntities(postGlossary)).toContain(placeholder)
    expect(await verifyDocx(outputBlob, Object.values(map))).toHaveLength(0)
  })

  it('fail-closed retained: a verified-but-unswept part still BLOCKS and is named', async () => {
    // word/unsweepable.xml is scanned by the verifier (matches word/*.xml) but is NOT in NONBODY_SWEEP_RE,
    // so the mirrored value cannot be removed there -> the export must stay blocked, naming the part.
    const base = await makeDocxBlob({ paragraphs: [`Contact: ${SYNTHETIC_NAME}`] })
    const blob = await withExtraPart(
      base,
      'word/unsweepable.xml',
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<root xmlns="urn:x"><v>${SYNTHETIC_NAME}</v></root>`,
    )

    const file = docxBlobToFile(blob, 'unsweepable-test.docx')
    const { text, rebuild } = await loadDocx(file)
    const spans = [valueSpan(text, SYNTHETIC_NAME)]
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const outputBlob = await rebuild(replacementsForText(text, spans, placeholderOf, map))

    // Body was redacted, but the unswept part still holds the value -> gate blocks.
    const leaked = await verifyDocx(outputBlob, Object.values(map))
    expect(leaked).toContain(SYNTHETIC_NAME)

    // FIX 3: the blocking part is named for the UI message, and it is NOT word/document.xml (body is clean).
    const parts = await docxLeakParts(outputBlob, leaked)
    expect(parts).toContain('word/unsweepable.xml')
    expect(parts).not.toContain('word/document.xml')
  })

  it('verifyDocx now scans customXml/ (silent-leak hole closed)', async () => {
    // A value living only in a customXml store, with no body redaction, must be reported by the gate.
    const base = await makeDocxBlob({ paragraphs: ['Dossier 2026-001'] })
    const blob = await withExtraPart(
      base,
      'customXml/item1.xml',
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<root xmlns="urn:test"><client>${SYNTHETIC_NAME}</client></root>`,
    )
    const leaked = await verifyDocx(blob, [SYNTHETIC_NAME])
    expect(leaked).toContain(SYNTHETIC_NAME)
    expect(await docxLeakParts(blob, [SYNTHETIC_NAME])).toContain('customXml/item1.xml')
  })
})

// -------------------------
// .xlsx round-trip
// -------------------------
describe('xlsx round-trip', () => {
  it('produces zero leaked values after redacting active spans', async () => {
    // Build a minimal .xlsx with synthetic PII (one value per row)
    const blob = await makeXlsxBlob([
      `Contact: ${SYNTHETIC_NAME}`,
      `NAS: ${SYNTHETIC_SIN}`,
      'Montant: 1 500,00 $',
    ])
    const file = xlsxBlobToFile(blob, 'test.xlsx')
    const { text, rebuild } = await loadXlsx(file)

    // Auto-detect + merge
    const rawSpans = mergeSpans(tier0Spans(text))
    const spans = toSpans(rawSpans, 'auto')

    // Must have found the SIN
    const sinSpan = spans.find((s) => text.slice(s.start, s.end).replace(/\D/g, '') === '046454286')
    expect(sinSpan).toBeDefined()

    // Build replacements (mirror App.tsx:162-164)
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const repls = spans
      .filter((s) => s.active)
      .map((s) => ({ start: s.start, end: s.end, text: placeholderOf.get(s.id) ?? '' }))

    // Rebuild and verify
    const outputBlob = await rebuild(repls)
    const leaked = await verifyXlsx(outputBlob, Object.values(map))
    expect(leaked).toHaveLength(0)
  })

  it('sweeps repeated known values that were missed positionally', async () => {
    const blob = await makeXlsxBlob([
      `First: ${REPEATED_EMAIL}`,
      `Second: ${REPEATED_EMAIL}`,
    ])
    const file = xlsxBlobToFile(blob, 'repeat.xlsx')
    const { text, rebuild } = await loadXlsx(file)
    const spans = [emailSpan(text)] // simulate detector finding only the first occurrence
    const { map, placeholderOf } = buildEntityMap(text, spans)

    const outputBlob = await rebuild(replacementsForText(text, spans, placeholderOf, map))
    const leaked = await verifyXlsx(outputBlob, Object.values(map))
    expect(leaked).toHaveLength(0)
  })

  it('negative case: verifyXlsx detects survival when no spans are active', async () => {
    const blob = await makeXlsxBlob([
      `Contact: ${SYNTHETIC_NAME}`,
      `NAS: ${SYNTHETIC_SIN}`,
    ])
    const file = xlsxBlobToFile(blob, 'test-neg.xlsx')
    const { text, rebuild } = await loadXlsx(file)

    // Detect only to confirm the SIN is in the text; we don't activate any spans
    const rawSpans = mergeSpans(tier0Spans(text))
    expect(rawSpans.length).toBeGreaterThan(0) // sanity: detector found something

    // Rebuild with empty repls -> original content unchanged
    const outputBlob = await rebuild([])

    // The SIN must still be present in the output
    const leaked = await verifyXlsx(outputBlob, [SYNTHETIC_SIN])
    expect(leaked.length).toBeGreaterThan(0)
  })
})

// -------------------------
// .docx metadata scrub
// -------------------------
// Synthetic metadata values -- neither appears in any document paragraph
const META_AUTHOR = 'Sylvie Bouchard'
const META_CUSTOM_VALUE = 'Finance Fraud Unit'

describe('docx metadata scrub', () => {
  it('scrubs creator and lastModifiedBy from docProps/core.xml on rebuild', async () => {
    // Build a .docx with metadata -- the body paragraphs contain no trace of META_AUTHOR
    const blob = await makeDocxBlob({
      paragraphs: ['Dossier 2026-001', 'Montant: 5 000,00 $'],
      metadata: { creator: META_AUTHOR, lastModifiedBy: META_AUTHOR },
    })

    // Negative control: confirm the fixture actually contains the metadata before rebuild
    const preZip = await JSZip.loadAsync(blob)
    const preCoreXml = await preZip.file('docProps/core.xml')!.async('string')
    expect(preCoreXml).toContain(META_AUTHOR)

    // Rebuild (no body replacements -- the metadata is not a detected span)
    const file = docxBlobToFile(blob, 'meta-test.docx')
    const { rebuild } = await loadDocx(file)
    const outputBlob = await rebuild([])

    // Post-rebuild: metadata must be gone
    const postZip = await JSZip.loadAsync(outputBlob)
    const postCoreXml = await postZip.file('docProps/core.xml')!.async('string')
    expect(postCoreXml).not.toContain(META_AUTHOR)
  })

  it('scrubs custom property values from docProps/custom.xml on rebuild', async () => {
    const blob = await makeDocxBlob({
      paragraphs: ['Dossier 2026-001'],
      customProperties: { Department: META_CUSTOM_VALUE },
    })

    // Negative control: fixture contains the custom property value before rebuild
    const preZip = await JSZip.loadAsync(blob)
    const preCustomXml = await preZip.file('docProps/custom.xml')!.async('string')
    expect(preCustomXml).toContain(META_CUSTOM_VALUE)

    // Rebuild
    const file = docxBlobToFile(blob, 'meta-custom-test.docx')
    const { rebuild } = await loadDocx(file)
    const outputBlob = await rebuild([])

    // Post-rebuild: custom property value must be gone
    const postZip = await JSZip.loadAsync(outputBlob)
    const postCustomXml = await postZip.file('docProps/custom.xml')!.async('string')
    expect(postCustomXml).not.toContain(META_CUSTOM_VALUE)
  })

  it('scrubs custom property names from docProps/custom.xml on rebuild', async () => {
    const blob = await makeDocxBlob({
      paragraphs: [`Contact: ${SYNTHETIC_NAME}`],
      customProperties: { [SYNTHETIC_NAME]: 'neutral value' },
    })

    const preZip = await JSZip.loadAsync(blob)
    const preCustomXml = await preZip.file('docProps/custom.xml')!.async('string')
    expect(preCustomXml).toContain(SYNTHETIC_NAME)

    const file = docxBlobToFile(blob, 'meta-custom-name-test.docx')
    const { text, rebuild } = await loadDocx(file)
    const spans = [valueSpan(text, SYNTHETIC_NAME)]
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const repls = spans.map((s) => ({ start: s.start, end: s.end, text: placeholderOf.get(s.id) ?? '' }))
    const outputBlob = await rebuild(repls)

    const postZip = await JSZip.loadAsync(outputBlob)
    const postCustomXml = await postZip.file('docProps/custom.xml')!.async('string')
    expect(postCustomXml).not.toContain(SYNTHETIC_NAME)
    expect(await verifyDocx(outputBlob, Object.values(map))).toHaveLength(0)
  })

  it('verifyDocx detects redacted values that survive only in XML attributes', async () => {
    const blob = await makeDocxBlob({
      paragraphs: ['Dossier 2026-001'],
      customProperties: { [SYNTHETIC_NAME]: 'neutral value' },
    })

    const leaked = await verifyDocx(blob, [SYNTHETIC_NAME])
    expect(leaked).toContain(SYNTHETIC_NAME)
  })

  it('scrubs comment author metadata from word/comments*.xml on rebuild', async () => {
    const base = await makeDocxBlob({
      paragraphs: [`Contact: ${SYNTHETIC_NAME}`],
    })
    const zip = await JSZip.loadAsync(base)
    zip.file(
      'word/comments.xml',
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:comment w:id="0" w:author="${SYNTHETIC_NAME}" w:initials="SB">
    <w:p><w:r><w:t>neutral comment</w:t></w:r></w:p>
  </w:comment>
</w:comments>`,
    )
    const blob = await zip.generateAsync({ type: 'blob', mimeType: base.type })

    const file = docxBlobToFile(blob, 'comment-author-test.docx')
    const { text, rebuild } = await loadDocx(file)
    const spans = [valueSpan(text, SYNTHETIC_NAME)]
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const repls = spans.map((s) => ({ start: s.start, end: s.end, text: placeholderOf.get(s.id) ?? '' }))
    const outputBlob = await rebuild(repls)

    const postZip = await JSZip.loadAsync(outputBlob)
    const postCommentsXml = await postZip.file('word/comments.xml')!.async('string')
    expect(postCommentsXml).not.toContain(SYNTHETIC_NAME)
    expect(await verifyDocx(outputBlob, Object.values(map))).toHaveLength(0)
  })

  it('body redaction still works when metadata is also present', async () => {
    const blob = await makeDocxBlob({
      paragraphs: [`Contact: ${SYNTHETIC_NAME}`, `NAS: ${SYNTHETIC_SIN}`],
      metadata: { creator: META_AUTHOR, lastModifiedBy: META_AUTHOR },
    })
    const file = docxBlobToFile(blob, 'meta-body-test.docx')
    const { text, rebuild } = await loadDocx(file)

    const rawSpans = mergeSpans(tier0Spans(text))
    const spans = toSpans(rawSpans, 'auto')
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const repls = spans
      .filter((s) => s.active)
      .map((s) => ({ start: s.start, end: s.end, text: placeholderOf.get(s.id) ?? '' }))

    const outputBlob = await rebuild(repls)
    const leaked = await verifyDocx(outputBlob, Object.values(map))
    expect(leaked).toHaveLength(0)
  })
})

// -------------------------
// .xlsx metadata scrub
// -------------------------
describe('xlsx metadata scrub', () => {
  it('scrubs creator and lastModifiedBy from docProps/core.xml on rebuild', async () => {
    // Build a .xlsx with metadata -- neither META_AUTHOR nor META_CUSTOM_VALUE appears in any cell
    const blob = await makeXlsxBlob({
      rows: ['Dossier 2026-001', 'Montant: 5 000,00 $'],
      metadata: { creator: META_AUTHOR, lastModifiedBy: META_AUTHOR },
    })

    // Negative control: confirm the fixture contains the metadata before rebuild
    const preZip = await JSZip.loadAsync(blob)
    const preCoreXml = await preZip.file('docProps/core.xml')!.async('string')
    expect(preCoreXml).toContain(META_AUTHOR)

    // Rebuild (no body replacements)
    const file = xlsxBlobToFile(blob, 'meta-test.xlsx')
    const { rebuild } = await loadXlsx(file)
    const outputBlob = await rebuild([])

    // Post-rebuild: metadata must be gone
    const postZip = await JSZip.loadAsync(outputBlob)
    const postCoreXml = await postZip.file('docProps/core.xml')!.async('string')
    expect(postCoreXml).not.toContain(META_AUTHOR)
  })

  it('scrubs custom property values from docProps/custom.xml on rebuild', async () => {
    const blob = await makeXlsxBlob({
      rows: ['Dossier 2026-001'],
      customProperties: { Department: META_CUSTOM_VALUE },
    })

    // Negative control: fixture contains the custom property value before rebuild
    const preZip = await JSZip.loadAsync(blob)
    const preCustomXml = await preZip.file('docProps/custom.xml')!.async('string')
    expect(preCustomXml).toContain(META_CUSTOM_VALUE)

    // Rebuild
    const file = xlsxBlobToFile(blob, 'meta-custom-test.xlsx')
    const { rebuild } = await loadXlsx(file)
    const outputBlob = await rebuild([])

    // Post-rebuild: custom property value must be gone
    const postZip = await JSZip.loadAsync(outputBlob)
    const postCustomXml = await postZip.file('docProps/custom.xml')!.async('string')
    expect(postCustomXml).not.toContain(META_CUSTOM_VALUE)
  })

  it('scrubs custom property names from docProps/custom.xml on rebuild', async () => {
    const blob = await makeXlsxBlob({
      rows: [`Contact: ${SYNTHETIC_NAME}`],
      customProperties: { [SYNTHETIC_NAME]: 'neutral value' },
    })

    const preZip = await JSZip.loadAsync(blob)
    const preCustomXml = await preZip.file('docProps/custom.xml')!.async('string')
    expect(preCustomXml).toContain(SYNTHETIC_NAME)

    const file = xlsxBlobToFile(blob, 'meta-custom-name-test.xlsx')
    const { text, rebuild } = await loadXlsx(file)
    const spans = [valueSpan(text, SYNTHETIC_NAME)]
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const outputBlob = await rebuild(replacementsForText(text, spans, placeholderOf, map))

    const postZip = await JSZip.loadAsync(outputBlob)
    const postCustomXml = await postZip.file('docProps/custom.xml')!.async('string')
    expect(postCustomXml).not.toContain(SYNTHETIC_NAME)
    expect(await verifyXlsx(outputBlob, Object.values(map))).toHaveLength(0)
  })

  it('scrubs worksheet names from xl/workbook.xml on rebuild', async () => {
    const blob = await makeXlsxBlob({
      rows: [`Contact: ${SYNTHETIC_NAME}`],
      sheetName: SYNTHETIC_NAME,
    })

    const preZip = await JSZip.loadAsync(blob)
    const preWorkbookXml = await preZip.file('xl/workbook.xml')!.async('string')
    expect(preWorkbookXml).toContain(SYNTHETIC_NAME)

    const file = xlsxBlobToFile(blob, 'sheet-name-test.xlsx')
    const { text, rebuild } = await loadXlsx(file)
    const spans = [valueSpan(text, SYNTHETIC_NAME)]
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const outputBlob = await rebuild(replacementsForText(text, spans, placeholderOf, map))

    const postZip = await JSZip.loadAsync(outputBlob)
    const postWorkbookXml = await postZip.file('xl/workbook.xml')!.async('string')
    expect(postWorkbookXml).not.toContain(SYNTHETIC_NAME)
    expect(await verifyXlsx(outputBlob, Object.values(map))).toHaveLength(0)
  })

  it('verifyXlsx detects redacted values that survive only in XML attributes', async () => {
    const blob = await makeXlsxBlob({
      rows: ['Dossier 2026-001'],
      sheetName: SYNTHETIC_NAME,
    })

    const leaked = await verifyXlsx(blob, [SYNTHETIC_NAME])
    expect(leaked).toContain(SYNTHETIC_NAME)
  })

  it('scrubs comment author metadata from xl comment parts on rebuild', async () => {
    const base = await makeXlsxBlob({
      rows: [`Contact: ${SYNTHETIC_NAME}`],
    })
    const zip = await JSZip.loadAsync(base)
    zip.file(
      'xl/comments1.xml',
      `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <authors><author>${SYNTHETIC_NAME}</author></authors>
  <commentList>
    <comment ref="A1" authorId="0"><text><t>neutral comment</t></text></comment>
  </commentList>
</comments>`,
    )
    const blob = await zip.generateAsync({ type: 'blob', mimeType: base.type })

    const file = xlsxBlobToFile(blob, 'comment-author-test.xlsx')
    const { text, rebuild } = await loadXlsx(file)
    const spans = [valueSpan(text, SYNTHETIC_NAME)]
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const outputBlob = await rebuild(replacementsForText(text, spans, placeholderOf, map))

    const postZip = await JSZip.loadAsync(outputBlob)
    const postCommentsXml = await postZip.file('xl/comments1.xml')!.async('string')
    expect(postCommentsXml).not.toContain(SYNTHETIC_NAME)
    expect(await verifyXlsx(outputBlob, Object.values(map))).toHaveLength(0)
  })

  it('body redaction still works when metadata is also present', async () => {
    const blob = await makeXlsxBlob({
      rows: [`Contact: ${SYNTHETIC_NAME}`, `NAS: ${SYNTHETIC_SIN}`],
      metadata: { creator: META_AUTHOR, lastModifiedBy: META_AUTHOR },
    })
    const file = xlsxBlobToFile(blob, 'meta-body-test.xlsx')
    const { text, rebuild } = await loadXlsx(file)

    const rawSpans = mergeSpans(tier0Spans(text))
    const spans = toSpans(rawSpans, 'auto')
    const { map, placeholderOf } = buildEntityMap(text, spans)
    const repls = spans
      .filter((s) => s.active)
      .map((s) => ({ start: s.start, end: s.end, text: placeholderOf.get(s.id) ?? '' }))

    const outputBlob = await rebuild(repls)
    const leaked = await verifyXlsx(outputBlob, Object.values(map))
    expect(leaked).toHaveLength(0)
  })
})
