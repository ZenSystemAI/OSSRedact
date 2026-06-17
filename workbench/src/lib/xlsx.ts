// Format-PRESERVING .xlsx redaction. A .xlsx is a zip (SpreadsheetML). Most cell text lives DE-DUPLICATED in
// xl/sharedStrings.xml and cells reference it by index (t="s"), with the rest as inline strings (t="inlineStr"),
// formula-string results (t="str"), or raw numbers. We extract every cell's displayed value in reading order
// (sheet -> row -> cell), keep a map of each cell's char range in that flat text, and on export rewrite only the
// redacted slices -- cell styles, formulas in untouched cells, numbers, tables and charts survive.
//
// Leak hardening (the shared-string trap): a value the gate must hide could be referenced by many cells, and a
// half-removed string can linger in sharedStrings.xml even after every cell that showed it is redacted. So on
// export we DE-SHARE every shared-string cell into a self-contained inline string and then BLANK
// sharedStrings.xml entirely. Result: every surviving value lives in exactly one place (its own cell), there is
// no shared-table residue, and verifyXlsx() re-opens the output as a fail-closed gate before it is allowed to
// download. Comment text (xl/comments*, threaded comments) is scrubbed too.
//
// Known limit: dates stored as serial numbers display via a number format the cell value doesn't contain, so a
// serial-stored date is not seen by the text detector (string/inline-stored dates and all other PII are).

import JSZip from 'jszip'

const XML_SPACE_NS = 'http://www.w3.org/XML/1998/namespace'
const REL_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
const XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
const SST_EMPTY =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
  '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="0" uniqueCount="0"/>'

export type Replacement = { start: number; end: number; text: string }

type Cell = { node: Element; start: number; end: number; text: string }

// concatenated text of all <t> descendants of an element (handles both <si><t> and rich-text <si><r><t> runs)
function elementText(el: Element): string {
  let s = ''
  for (const node of Array.from(el.getElementsByTagName('*'))) {
    if (node.localName === 't') s += node.textContent ?? ''
  }
  return s
}

function parseSst(xml: string | null): string[] {
  if (!xml) return []
  const doc = new DOMParser().parseFromString(xml, 'application/xml')
  return Array.from(doc.getElementsByTagName('si')).map((si) => elementText(si))
}

// displayed text of one <c> cell ('' when it has none we care about: booleans, errors, empty)
function cellText(c: Element, sst: string[]): string {
  const t = c.getAttribute('t')
  if (t === 'inlineStr') {
    const is = c.getElementsByTagName('is')[0]
    return is ? elementText(is) : ''
  }
  if (t === 'b' || t === 'e') return '' // boolean / error -> not PII text
  const v = c.getElementsByTagName('v')[0]
  if (!v) return ''
  const raw = v.textContent ?? ''
  if (t === 's') {
    const i = parseInt(raw, 10)
    return Number.isFinite(i) && i >= 0 && i < sst.length ? sst[i] : ''
  }
  // t === 'str' (formula string result), numeric (no t / 'n') -> raw value as shown
  return raw
}

// Deterministic walk of one worksheet: cells in document order (row by row), text joined by '\t' within a row
// and '\n' between rows. base rebases this sheet's offsets into the document-wide flat text. Identical on load
// and rebuild, so char offsets map provably onto the same cells.
function walkSheet(sheetDoc: Document, sst: string[], base: number): { text: string; cells: Cell[] } {
  const cells: Cell[] = []
  let text = ''
  const sheetData = sheetDoc.getElementsByTagName('sheetData')[0]
  if (!sheetData) return { text, cells }
  const rows = Array.from(sheetData.getElementsByTagName('row'))
  let firstRow = true
  for (const row of rows) {
    if (!firstRow) text += '\n'
    firstRow = false
    let firstCell = true
    for (const c of Array.from(row.getElementsByTagName('c'))) {
      const ct = cellText(c, sst)
      if (ct === '') continue // empty / non-text cell contributes no redactable range
      if (!firstCell) text += '\t'
      firstCell = false
      const start = base + text.length
      text += ct
      cells.push({ node: c, start, end: base + text.length, text: ct })
    }
  }
  return { text, cells }
}

function applyToText(orig: string, repls: Replacement[], base: number): string {
  if (!repls.length) return orig
  const len = orig.length
  const sorted = [...repls].sort((a, b) => a.start - b.start)
  let out = ''
  let cursor = 0
  for (const r of sorted) {
    const ps = Math.max(r.start - base, 0)
    const pe = Math.min(r.end - base, len)
    if (pe <= cursor) continue
    if (ps > cursor) out += orig.slice(cursor, ps)
    if (r.start >= base) out += r.text // the cell owning the span start emits the placeholder once
    cursor = pe
  }
  out += orig.slice(cursor)
  return out
}

function rewriteCellInline(c: Element, text: string, doc: Document, ns: string | null) {
  c.setAttribute('t', 'inlineStr')
  while (c.firstChild) c.removeChild(c.firstChild) // drop <v>/<is>/<f>
  const is = ns ? doc.createElementNS(ns, 'is') : doc.createElement('is')
  const t = ns ? doc.createElementNS(ns, 't') : doc.createElement('t')
  t.setAttributeNS(XML_SPACE_NS, 'xml:space', 'preserve')
  t.textContent = text
  is.appendChild(t)
  c.appendChild(is)
}

function resolveTarget(target: string): string {
  if (target.startsWith('/')) return target.slice(1)
  if (target.startsWith('xl/')) return target
  return 'xl/' + target
}

async function orderedSheetPaths(zip: JSZip): Promise<string[]> {
  try {
    const wbXml = await zip.file('xl/workbook.xml')?.async('string')
    const relsXml = await zip.file('xl/_rels/workbook.xml.rels')?.async('string')
    if (wbXml && relsXml) {
      const wb = new DOMParser().parseFromString(wbXml, 'application/xml')
      const rels = new DOMParser().parseFromString(relsXml, 'application/xml')
      const ridToTarget: Record<string, string> = {}
      for (const rel of Array.from(rels.getElementsByTagName('Relationship'))) {
        const id = rel.getAttribute('Id')
        const tgt = rel.getAttribute('Target')
        if (id && tgt) ridToTarget[id] = tgt
      }
      const order: string[] = []
      for (const sheet of Array.from(wb.getElementsByTagName('sheet'))) {
        const rid = sheet.getAttributeNS(REL_NS, 'id') || sheet.getAttribute('r:id')
        if (rid && ridToTarget[rid]) {
          const path = resolveTarget(ridToTarget[rid])
          if (zip.file(path)) order.push(path)
        }
      }
      if (order.length) return order
    }
  } catch {
    /* fall through to filename order */
  }
  return Object.keys(zip.files)
    .filter((n) => /^xl\/worksheets\/sheet\d+\.xml$/.test(n) && !zip.files[n].dir)
    .sort((a, b) => (parseInt(a.replace(/\D/g, ''), 10) || 0) - (parseInt(b.replace(/\D/g, ''), 10) || 0))
}

export type LoadedXlsx = {
  text: string
  rebuild: (repls: Replacement[]) => Promise<Blob>
}

export async function loadXlsx(file: File): Promise<LoadedXlsx> {
  const zip = await JSZip.loadAsync(file)
  if (!zip.file('xl/workbook.xml')) throw new Error('Not an Excel workbook (no xl/workbook.xml).')
  const sst = parseSst((await zip.file('xl/sharedStrings.xml')?.async('string')) ?? null)
  const sheetPaths = await orderedSheetPaths(zip)
  if (!sheetPaths.length) throw new Error('This workbook has no readable worksheets.')

  const sheetXml: Record<string, string> = {}
  for (const p of sheetPaths) sheetXml[p] = await zip.file(p)!.async('string')

  // build the combined flat text exactly the way rebuild will (same walk, same '\n\n' sheet join)
  let off = 0
  const chunks: string[] = []
  for (const p of sheetPaths) {
    const { text } = walkSheet(new DOMParser().parseFromString(sheetXml[p], 'application/xml'), sst, off)
    chunks.push(text)
    off += text.length + 2
  }

  const rebuild = async (repls: Replacement[]): Promise<Blob> => {
    let cur = 0
    for (const p of sheetPaths) {
      const doc = new DOMParser().parseFromString(sheetXml[p], 'application/xml')
      const ns = doc.documentElement.namespaceURI
      const { text, cells } = walkSheet(doc, sst, cur)
      for (const cell of cells) {
        const overlapping = repls.filter((r) => r.start < cell.end && r.end > cell.start)
        const isShared = cell.node.getAttribute('t') === 's'
        if (isShared || overlapping.length) {
          rewriteCellInline(cell.node, applyToText(cell.text, overlapping, cell.start), doc, ns)
        }
      }
      zip.file(p, new XMLSerializer().serializeToString(doc))
      cur += text.length + 2
    }
    // every shared-string cell is now inline -> the shared table is unreferenced; blank it so no value lingers
    if (zip.file('xl/sharedStrings.xml')) zip.file('xl/sharedStrings.xml', SST_EMPTY)
    await scrubComments(zip)
    await scrubDocProps(zip)
    return zip.generateAsync({ type: 'blob', mimeType: XLSX_MIME })
  }

  return { text: chunks.join('\n\n'), rebuild }
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
// The XML structure is kept valid so the package remains a well-formed OOXML zip.
// custom.xml <property> child values are also blanked.
async function scrubDocProps(zip: JSZip) {
  for (const name of Object.keys(zip.files)) {
    if (zip.files[name].dir) continue
    if (!/^docProps\/.*\.xml$/.test(name)) continue
    const xml = await zip.file(name)!.async('string')
    const doc = new DOMParser().parseFromString(xml, 'application/xml')
    for (const el of Array.from(doc.getElementsByTagName('*'))) {
      const local = el.localName
      // Blank named PII tags (core.xml + app.xml)
      if (DOCPROPS_PII_TAGS.has(local)) {
        el.textContent = ''
        continue
      }
      // Blank custom property values (custom.xml): child element of <property>
      if (el.parentElement && el.parentElement.localName === 'property') {
        el.textContent = ''
      }
    }
    zip.file(name, new XMLSerializer().serializeToString(doc))
  }
}

// Comment text can hold PII the cell grid doesn't show. Blank the text of every comment part (legacy <t> runs +
// threaded-comment <text> nodes); the structure stays valid, the words are gone.
async function scrubComments(zip: JSZip) {
  for (const name of Object.keys(zip.files)) {
    if (zip.files[name].dir) continue
    if (!/^xl\/(threadedComments\/)?[^/]*comment[^/]*\.xml$/i.test(name)) continue
    const xml = await zip.file(name)!.async('string')
    const doc = new DOMParser().parseFromString(xml, 'application/xml')
    for (const el of Array.from(doc.getElementsByTagName('*'))) {
      if (el.localName === 't' || el.localName === 'text') el.textContent = ''
    }
    zip.file(name, new XMLSerializer().serializeToString(doc))
  }
}

// Fail-closed gate: re-open the produced .xlsx and confirm none of the redacted values survive in ANY xml part
// (sheets, the blanked shared table, comments, doc properties). Run-split values are caught by stripping tags
// before the substring check. Returns the leaked values (empty == safe to download).
export async function verifyXlsx(blob: Blob, values: string[]): Promise<string[]> {
  const zip = await JSZip.loadAsync(blob)
  let all = ''
  for (const name of Object.keys(zip.files)) {
    if (zip.files[name].dir) continue
    if (!/^(xl|docProps)\/.*\.xml$/.test(name)) continue
    const xml = await zip.file(name)!.async('string')
    all += xml.replace(/<[^>]+>/g, '')
  }
  all = all
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&')
  return values.filter((v) => v && all.includes(v))
}
