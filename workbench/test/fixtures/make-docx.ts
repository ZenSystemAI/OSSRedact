// Builds a minimal valid .docx in memory using JSZip.
// Used only in tests -- all content is synthetic (no real PII).

import JSZip from 'jszip'

const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>
</Types>`

const RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>
</Relationships>`

const WORD_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>`

function buildDocumentXml(paragraphs: string[]): string {
  const paras = paragraphs
    .map(
      (text) =>
        `<w:p><w:r><w:t xml:space="preserve">${text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</w:t></w:r></w:p>`,
    )
    .join('\n')
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:xml="http://www.w3.org/XML/1998/namespace">
  <w:body>
${paras}
  </w:body>
</w:document>`
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

export interface MakeDocxOptions {
  /** Paragraphs to include in the document body (all synthetic) */
  paragraphs: string[]
  /** Optional metadata to inject into docProps/core.xml (for testing scrubDocProps) */
  metadata?: {
    creator?: string
    lastModifiedBy?: string
  }
  /** Optional custom properties to inject into docProps/custom.xml */
  customProperties?: Record<string, string>
}

/**
 * Build a minimal valid .docx blob in memory with synthetic content.
 * When metadata or customProperties are provided, docProps parts are included.
 *
 * @param paragraphs - Array of paragraph text strings (all synthetic)
 * @param options - Optional: pass an MakeDocxOptions object instead; paragraphs array is also accepted
 *                  for backward compatibility
 */
export async function makeDocxBlob(
  paragraphsOrOptions: string[] | MakeDocxOptions,
): Promise<Blob> {
  const opts: MakeDocxOptions =
    Array.isArray(paragraphsOrOptions)
      ? { paragraphs: paragraphsOrOptions }
      : paragraphsOrOptions

  const zip = new JSZip()
  zip.file('[Content_Types].xml', CONTENT_TYPES)
  zip.file('_rels/.rels', RELS)
  zip.file('word/_rels/document.xml.rels', WORD_RELS)
  zip.file('word/document.xml', buildDocumentXml(opts.paragraphs))

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
    mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  })
}

/**
 * Convert a Blob to a File so loadDocx() can consume it (loadDocx takes File).
 */
export function blobToFile(blob: Blob, name: string): File {
  return new File([blob], name, { type: blob.type })
}
