// Format-PRESERVING .docx redaction. A .docx is a zip; body text lives across several XML parts
// (word/document.xml plus headers, footers, footnotes, endnotes, comments) as trees of <w:t> run-text
// nodes. We extract the concatenated text of ALL those parts (with paragraph breaks) for the canvas + the
// detector, keep a map of each <w:t> node's char range, and on export rewrite only the redacted slices in
// place -- formatting, styles, images, tables survive. Everything runs in-browser.
//
// Leak hardening: ALL body parts are scanned + redacted (not just document.xml), tracked-change deletions
// (<w:del>/<w:moveFrom>) are stripped so deleted PII can't survive, non-body parts that can MIRROR body PII
// (customXml data stores, the glossary doc, cached chart + SmartArt-diagram data) get a value-sweep so the
// mapped originals are removed there too, and App runs verifyDocx() as a fail-closed gate that re-opens the
// output and blocks the download if any redacted value remains in word/*, docProps/*, OR customXml/*.

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

// Non-body parts that can mirror body PII: content-control / mail-merge custom-XML data stores, the
// glossary (building-block / AutoText) document, and cached chart + SmartArt-diagram data. None are in
// BODY_PART_RE (they have no run-offset map), so they get a straight value SWEEP instead of positional
// replacement: every mapped original value is replaced with its placeholder inside XML TEXT NODES *and*
// attribute VALUES (customXml frequently stores its data in attributes). Element/attribute NAMES -- the
// structure -- are never touched, so each part stays well-formed after re-serialization.
const NONBODY_SWEEP_RE =
  /^(customXml\/item\d+\.xml|word\/glossary\/document\.xml|word\/charts\/[^/]+\.xml|word\/diagrams\/[^/]+\.xml)$/

function sweepValue(s: string, pairs: [string, string][]): string {
  if (!s) return s
  let out = s
  for (const [value, ph] of pairs) if (out.includes(value)) out = out.split(value).join(ph)
  return out
}

// Replace every mapped original value with its placeholder inside the text nodes and attribute values of
// each non-body part. `pairs` is value->placeholder, sorted longest value first so a value nested inside a
// longer one resolves after the longer value is already masked.
async function scrubValueParts(zip: JSZip, pairs: [string, string][]) {
  if (!pairs.length) return
  for (const name of Object.keys(zip.files)) {
    if (zip.files[name].dir || !NONBODY_SWEEP_RE.test(name)) continue
    const xml = await zip.file(name)!.async('string')
    const doc = new DOMParser().parseFromString(xml, 'application/xml')
    let changed = false
    const visit = (el: Element) => {
      for (const attr of Array.from(el.attributes)) {
        const rep = sweepValue(attr.value, pairs)
        if (rep !== attr.value) {
          attr.value = rep
          changed = true
        }
      }
      for (const child of Array.from(el.childNodes)) {
        if (child.nodeType === 3 || child.nodeType === 4) {
          // TEXT_NODE or CDATA_SECTION_NODE
          const cur = child.nodeValue ?? ''
          const rep = sweepValue(cur, pairs)
          if (rep !== cur) {
            child.nodeValue = rep
            changed = true
          }
        } else if (child.nodeType === 1) {
          visit(child as Element)
        }
      }
    }
    if (doc.documentElement) visit(doc.documentElement)
    if (changed) zip.file(name, new XMLSerializer().serializeToString(doc))
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
  // The combined body text -- offsets in `repls` index into THIS string (App passes doc.text back), so a
  // repl's slice IS the original value. Used to sweep those values out of the non-body parts on rebuild.
  const combinedText = chunks.join('\n\n')

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
    // Derive value->placeholder pairs from the body replacements (offsets index into combinedText, so the
    // slice is the exact original value), then sweep those values out of the non-body parts.
    const valueToPh = new Map<string, string>()
    for (const r of repls) {
      const value = combinedText.slice(r.start, r.end)
      if (value && r.text && !valueToPh.has(value)) valueToPh.set(value, r.text)
    }
    const pairs = [...valueToPh.entries()].sort((a, b) => b[0].length - a[0].length)

    await scrubDocProps(zip)
    await scrubCommentMetadata(zip)
    await scrubValueParts(zip, pairs)
    return zip.generateAsync({ type: 'blob', mimeType: DOCX_MIME })
  }

  return { text: combinedText, rebuild }
}

// Parts scanned by the fail-closed gate. customXml/* is included: a content-control / mail-merge data
// store previously matched NEITHER the redaction nor the verify regex -> PII there leaked while the export
// reported clean. word/* also covers glossary + chart + diagram parts (verified AND now swept).
const VERIFY_PART_RE = /^(word|docProps|customXml)\/.*\.xml$/

async function docxSearchableParts(blob: Blob): Promise<Record<string, string>> {
  const zip = await JSZip.loadAsync(blob)
  const parts: Record<string, string> = {}
  for (const n of Object.keys(zip.files)) {
    if (!VERIFY_PART_RE.test(n) || zip.files[n].dir) continue
    parts[n] = searchableXml(await zip.file(n)!.async('string'))
  }
  return parts
}

// Fail-closed gate: re-open the produced .docx and confirm none of the original sensitive values survive in
// any scanned xml part (run-split values are caught by checking the tag-stripped text). Returns leaked values.
export async function verifyDocx(blob: Blob, values: string[]): Promise<string[]> {
  const parts = await docxSearchableParts(blob)
  const all = Object.values(parts).join('\n')
  return values.filter((v) => v && all.includes(v))
}

// Which scanned parts still contain any of the given (leaked) values, so the BLOCKED message can name WHERE
// the leak is instead of leaving the operator at a dead end. Sorted, deduped part names.
export async function docxLeakParts(blob: Blob, values: string[]): Promise<string[]> {
  const present = values.filter((v) => !!v)
  if (!present.length) return []
  const parts = await docxSearchableParts(blob)
  return Object.keys(parts)
    .filter((n) => present.some((v) => parts[n].includes(v)))
    .sort()
}
