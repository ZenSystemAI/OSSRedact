// Builds a minimal valid .xlsx in memory using JSZip.
// Used only in tests -- all content is synthetic (no real PII).

import JSZip from 'jszip'

const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>
</Types>`

const RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>
</Relationships>`

const WORKBOOK_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`

const WORKBOOK = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>`

/**
 * Build a worksheet XML with one column of string cells (inlineStr).
 * Each entry in `rows` becomes one row with one cell (column A).
 */
function buildSheetXml(rows: string[]): string {
  const rowElems = rows
    .map((text, i) => {
      const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      return `<row r="${i + 1}"><c r="A${i + 1}" t="inlineStr"><is><t xml:space="preserve">${escaped}</t></is></c></row>`
    })
    .join('\n')
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
${rowElems}
  </sheetData>
</worksheet>`
}

function buildCoreXml(creator: string, lastModifiedBy: string): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/">
  <dc:creator>${creator.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</dc:creator>
  <cp:lastModifiedBy>${lastModifiedBy.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</cp:lastModifiedBy>
  <dcterms:created>2026-01-01T00:00:00Z</dcterms:created>
  <dcterms:modified>2026-01-02T00:00:00Z</dcterms:modified>
</cp:coreProperties>`
}

function buildCustomXml(properties: Record<string, string>): string {
  const props = Object.entries(properties)
    .map(
      ([name, value], i) =>
        `  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="${i + 2}" name="${name.replace(/&/g, '&amp;').replace(/</g, '&lt;')}"><vt:lpwstr xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">${value.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</vt:lpwstr></property>`,
    )
    .join('\n')
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties">
${props}
</Properties>`
}

export interface MakeXlsxOptions {
  /** Rows to include in the worksheet, one string per row in column A (all synthetic) */
  rows: string[]
  /** Optional metadata to inject into docProps/core.xml (for testing scrubDocProps) */
  metadata?: {
    creator?: string
    lastModifiedBy?: string
  }
  /** Optional custom properties to inject into docProps/custom.xml */
  customProperties?: Record<string, string>
}

/**
 * Build a minimal valid .xlsx blob in memory with synthetic content.
 * When metadata or customProperties are provided, docProps parts are included.
 *
 * @param rowsOrOptions - Array of strings (one per row in column A) or MakeXlsxOptions object.
 *                        Array form is accepted for backward compatibility.
 */
export async function makeXlsxBlob(rowsOrOptions: string[] | MakeXlsxOptions): Promise<Blob> {
  const opts: MakeXlsxOptions = Array.isArray(rowsOrOptions)
    ? { rows: rowsOrOptions }
    : rowsOrOptions

  const zip = new JSZip()
  zip.file('[Content_Types].xml', CONTENT_TYPES)
  zip.file('_rels/.rels', RELS)
  zip.file('xl/_rels/workbook.xml.rels', WORKBOOK_RELS)
  zip.file('xl/workbook.xml', WORKBOOK)
  zip.file('xl/worksheets/sheet1.xml', buildSheetXml(opts.rows))

  if (opts.metadata) {
    zip.file(
      'docProps/core.xml',
      buildCoreXml(opts.metadata.creator ?? '', opts.metadata.lastModifiedBy ?? ''),
    )
  }
  if (opts.customProperties && Object.keys(opts.customProperties).length > 0) {
    zip.file('docProps/custom.xml', buildCustomXml(opts.customProperties))
  }

  return zip.generateAsync({
    type: 'blob',
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  })
}

/**
 * Convert a Blob to a File so loadXlsx() can consume it.
 */
export function blobToFile(blob: Blob, name: string): File {
  return new File([blob], name, { type: blob.type })
}
