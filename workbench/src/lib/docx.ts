// Format-PRESERVING .docx redaction. A .docx is a zip; body text lives across several XML parts
// (word/document.xml plus headers, footers, footnotes, endnotes, comments) as trees of <w:t> run-text
// nodes. We extract the concatenated text of ALL those parts (with paragraph breaks) for the canvas + the
// detector, keep a map of each <w:t> node's char range, and on export rewrite only the redacted slices in
// place -- formatting, styles, images, tables survive. Everything runs in-browser.
//
// Leak hardening: ALL body parts are scanned + redacted (not just document.xml), tracked-change deletions
// (<w:del>/<w:moveFrom>) are stripped so deleted PII can't survive, and App runs verifyDocx() as a
// fail-closed gate (re-opens the output and blocks the download if any redacted value remains).

import JSZip from 'jszip'

const XML_SPACE_NS = 'http://www.w3.org/XML/1998/namespace'
const DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
// body-text parts that can hold PII (numbered headers/footers included)
const BODY_PART_RE = /^word\/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$/

export type Replacement = { start: number; end: number; text: string } // text = placeholder for the span

type TNode = { node: Element; start: number; end: number }

// Deterministic traversal of one part: concatenate <w:t> text in document order, '\n' per new paragraph.
// Tracked-deletion subtrees are skipped (their text must not enter detection OR survive export).
function buildTextAndMap(xmlDoc: Document, base: number): { text: string; tmap: TNode[] } {
  const tmap: TNode[] = []
  let text = ''
  let firstPara = true
  const walk = (el: Element) => {
    for (const child of Array.from(el.children)) {
      const local = child.localName
      if (local === 'del' || local === 'moveFrom') continue // tracked-change deletion -> ignore entirely
      if (local === 'p') {
        if (!firstPara) text += '\n'
        firstPara = false
        walk(child)
      } else if (local === 't') {
        const start = base + text.length
        const s = child.textContent ?? ''
        text += s
        tmap.push({ node: child, start, end: base + text.length })
      } else if (local === 'tab') {
        text += '\t'
      } else if (local === 'br' || local === 'cr') {
        text += '\n'
      } else {
        walk(child)
      }
    }
  }
  walk(xmlDoc.documentElement)
  return { text, tmap }
}

function stripTrackedDeletions(xmlDoc: Document) {
  for (const tag of ['del', 'moveFrom']) {
    for (const el of Array.from(xmlDoc.getElementsByTagName('w:' + tag))) el.parentNode?.removeChild(el)
  }
}

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&')
}

function searchableXml(xml: string): string {
  return decodeXmlEntities(xml) + '\n' + decodeXmlEntities(xml.replace(/<[^>]+>/g, ''))
}

function applyRepls(tmap: TNode[], repls: Replacement[]) {
  const sorted = [...repls].sort((a, b) => a.start - b.start)
  for (const { node, start: ns, end: ne } of tmap) {
    const original = node.textContent ?? ''
    const overlapping = sorted.filter((r) => r.start < ne && r.end > ns)
    if (overlapping.length === 0) continue
    let out = ''
    let cursor = ns
    for (const r of overlapping) {
      const ps = Math.max(r.start, ns)
      const pe = Math.min(r.end, ne)
      out += original.slice(cursor - ns, ps - ns) // text before the redaction
      if (r.start >= ns) out += r.text // this run owns the start -> emit the placeholder once
      cursor = pe // continuation runs emit nothing
    }
    out += original.slice(cursor - ns)
    node.textContent = out
    node.setAttributeNS(XML_SPACE_NS, 'xml:space', 'preserve')
  }
}

function partOrder(a: string, b: string): number {
  if (a === 'word/document.xml') return -1
  if (b === 'word/document.xml') return 1
  return a.localeCompare(b)
}

// PII-bearing element localNames in docProps/core.xml and docProps/app.xml.
// Timestamps (dcterms:created, dcterms:modified) are intentionally excluded.
const DOCPROPS_PII_TAGS = new Set([
  // core.xml (Dublin Core)
  'creator',
  'lastModifiedBy',
  'title',
  'subject',
  'description',
  'keywords',
  // app.xml (extended properties)
  'Company',
  'Manager',
])

// Blank the text content of PII-bearing elements across all docProps/* parts.
// The XML structure is kept valid (elements remain, text is emptied) so the
// package stays a well-formed OOXML zip. custom.xml <property> values are
// also blanked because they can hold arbitrary data.
async function scrubDocProps(zip: JSZip) {
  for (const name of Object.keys(zip.files)) {
    if (zip.files[name].dir) continue
    if (!/^docProps\/.*\.xml$/.test(name)) continue
    const xml = await zip.file(name)!.async('string')
    const doc = new DOMParser().parseFromString(xml, 'application/xml')
    let customPropN = 0
    for (const el of Array.from(doc.getElementsByTagName('*'))) {
      const local = el.localName
      if (local === 'property') el.setAttribute('name', `property-${++customPropN}`)
      // Blank named PII tags (core.xml + app.xml)
      if (DOCPROPS_PII_TAGS.has(local)) {
        el.textContent = ''
        continue
      }
      // Blank custom property values (custom.xml): <property> children that hold a typed value
      // The value is a single child element like <vt:lpwstr>, <vt:i4>, etc.
      if (el.parentElement && el.parentElement.localName === 'property') {
        el.textContent = ''
      }
    }
    zip.file(name, new XMLSerializer().serializeToString(doc))
  }
}

async function scrubCommentMetadata(zip: JSZip) {
  for (const name of Object.keys(zip.files)) {
    if (zip.files[name].dir) continue
    if (!/^word\/comments.*\.xml$/i.test(name)) continue
    const xml = await zip.file(name)!.async('string')
    const doc = new DOMParser().parseFromString(xml, 'application/xml')
    for (const el of Array.from(doc.getElementsByTagName('*'))) {
      for (const attr of Array.from(el.attributes)) {
        if (attr.localName === 'author' || attr.localName === 'initials') {
          el.setAttributeNS(attr.namespaceURI, attr.name, '')
        }
      }
    }
    zip.file(name, new XMLSerializer().serializeToString(doc))
  }
}

export type LoadedDocx = {
  text: string
  rebuild: (repls: Replacement[]) => Promise<Blob>
}

export async function loadDocx(file: File): Promise<LoadedDocx> {
  const zip = await JSZip.loadAsync(file)
  if (!zip.file('word/document.xml')) throw new Error('Not a Word document (no word/document.xml).')
  const partNames = Object.keys(zip.files)
    .filter((n) => !zip.files[n].dir && BODY_PART_RE.test(n))
    .sort(partOrder)
  const xmlByPart: Record<string, string> = {}
  for (const n of partNames) xmlByPart[n] = await zip.file(n)!.async('string')

  // build the combined flat text exactly the way rebuild will, so offsets are consistent across parts
  // (each part rebased by previous parts' lengths + the 2-char '\n\n' join).
  let docOffset = 0
  const chunks: string[] = []
  for (const n of partNames) {
    const { text } = buildTextAndMap(new DOMParser().parseFromString(xmlByPart[n], 'application/xml'), docOffset)
    chunks.push(text)
    docOffset += text.length + 2
  }

  const rebuild = async (repls: Replacement[]): Promise<Blob> => {
    let off = 0
    for (const n of partNames) {
      const xmlDoc = new DOMParser().parseFromString(xmlByPart[n], 'application/xml')
      const { text, tmap } = buildTextAndMap(xmlDoc, off) // identical deterministic walk -> offsets match
      applyRepls(tmap, repls)
      stripTrackedDeletions(xmlDoc)
      zip.file(n, new XMLSerializer().serializeToString(xmlDoc))
      off += text.length + 2
    }
    await scrubDocProps(zip)
    await scrubCommentMetadata(zip)
    return zip.generateAsync({ type: 'blob', mimeType: DOCX_MIME })
  }

  return { text: chunks.join('\n\n'), rebuild }
}

// Fail-closed gate: re-open the produced .docx and confirm none of the original sensitive values survive in
// ANY xml part (run-split values are caught by checking the tag-stripped text). Returns the leaked values.
export async function verifyDocx(blob: Blob, values: string[]): Promise<string[]> {
  const zip = await JSZip.loadAsync(blob)
  let all = ''
  for (const n of Object.keys(zip.files)) {
    if (!/^(word|docProps)\/.*\.xml$/.test(n) || zip.files[n].dir) continue
    const xml = await zip.file(n)!.async('string')
    all += searchableXml(xml)
  }
  return values.filter((v) => v && all.includes(v))
}
