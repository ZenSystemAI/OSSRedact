// PDF text extraction + per-text-item geometry (in-browser, via Mozilla pdf.js). Lets the workbench LOAD a
// PDF, detect + redact its text, and export a TRUE redacted PDF: each page is rasterized to a canvas, black
// boxes are painted over the detected words, and the result is reassembled as an IMAGE-ONLY PDF (no text
// layer = nothing recoverable under the boxes). See pdfExport.ts for the render/paint/verify pipeline.
//
// INVARIANT: the flat text (offsets the detector uses) and the per-item geometry are built in ONE
// getTextContent() pass with the default normalization, so span char-offsets map provably onto item rects.

import * as pdfjsLib from 'pdfjs-dist'
import { OPS } from 'pdfjs-dist'
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url'

pdfjsLib.GlobalWorkerOptions.workerSrc = workerUrl

export type ItemBox = {
  str: string
  charStart: number // document char offset (into the flat text), str only -- not the synthetic '\n'
  charEnd: number
  transform: number[] // 6-el text-space matrix (pre-viewport)
  width: number // text-space advance
  height: number
  dir: string
}
export type PageGeom = {
  pageIndex: number
  rotation: number
  viewBoxWidth: number // points, scale 1, pre-rotation
  viewBoxHeight: number
  items: ItemBox[]
}
export type PageStatus = 'text-clean' | 'image-only' | 'has-image'
export type PageAssessment = { pageIndex: number; status: PageStatus; strChars: number; hasImage: boolean }

export type LoadedPdf = { text: string; pages: PageGeom[]; assess: PageAssessment[]; bytes: ArrayBuffer }

export async function loadPdfDoc(file: File): Promise<LoadedPdf> {
  const bytes = await file.arrayBuffer()
  let pdf
  try {
    // slice(0) -> a throwaway copy for the worker (getDocument detaches its buffer); keep `bytes` intact
    pdf = await pdfjsLib.getDocument({ data: bytes.slice(0) }).promise
  } catch (e) {
    const name = (e as { name?: string })?.name
    if (name === 'PasswordException') throw new Error('This PDF is password-protected. Unlock it first, then load it.')
    throw e
  }

  const pages: PageGeom[] = []
  const assess: PageAssessment[] = []
  const pageTexts: string[] = []
  let docOffset = 0

  for (let p = 1; p <= pdf.numPages; p++) {
    const page = await pdf.getPage(p)
    const view = page.view // [x0,y0,x1,y1] scale 1, pre-rotation
    const viewBoxWidth = view[2] - view[0]
    const viewBoxHeight = view[3] - view[1]
    const content = await page.getTextContent()

    let pageText = ''
    const items: ItemBox[] = []
    for (const it of content.items) {
      if (!('str' in it)) continue
      const charStart = pageText.length
      pageText += it.str
      items.push({
        str: it.str,
        charStart,
        charEnd: charStart + it.str.length,
        transform: it.transform,
        width: it.width,
        height: it.height,
        dir: it.dir,
      })
      if (it.hasEOL) pageText += '\n'
    }

    const trimmed = pageText.trimEnd() // EXACTLY as loadPdfText did, so flat text stays byte-identical
    const tlen = trimmed.length
    for (const item of items) {
      // clamp trailing-whitespace items dropped by trimEnd, then rebase page-local -> document offsets
      item.charStart = Math.min(item.charStart, tlen) + docOffset
      item.charEnd = Math.min(item.charEnd, tlen) + docOffset
    }

    // scanned-PDF gate: an embedded image is content the TEXT layer can't see, so the detector is blind to
    // any PII inside it (a scanned page, OR a dense text page with a pasted ID-card / void-cheque image).
    // Probe EVERY page (not just sparse ones) and flag any image-bearing page -- over-warning is the safe
    // error. 'image-only' = essentially no machine-readable text (a pure scan); 'has-image' = text + image.
    const strChars = items.reduce((a, i) => a + i.str.length, 0)
    let hasImage = false
    try {
      const opList = await page.getOperatorList()
      hasImage = opList.fnArray.some(
        (fn) => fn === OPS.paintImageXObject || fn === OPS.paintInlineImageXObject || fn === OPS.paintImageMaskXObject,
      )
    } catch {
      /* ignore */
    }
    const status: PageStatus = hasImage ? (strChars < 8 ? 'image-only' : 'has-image') : 'text-clean'

    pages.push({ pageIndex: p - 1, rotation: page.rotate, viewBoxWidth, viewBoxHeight, items })
    assess.push({ pageIndex: p - 1, status, strChars, hasImage })
    pageTexts.push(trimmed)
    docOffset += tlen + 2 // the 2-char '\n\n' join between pages
    page.cleanup()
  }

  await pdf.destroy()
  return { text: pageTexts.join('\n\n'), pages, assess, bytes }
}

// Back-compat thin wrapper (kept so any text-only caller is unchanged).
export async function loadPdfText(file: File): Promise<string> {
  return (await loadPdfDoc(file)).text
}
