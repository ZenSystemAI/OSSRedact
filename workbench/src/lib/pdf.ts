// PDF text extraction + per-text-item geometry (in-browser, via Mozilla pdf.js). Lets the workbench LOAD a
// PDF, detect + redact its text, and export a TRUE redacted PDF: each page is rasterized to a canvas, black
// boxes are painted over the detected words, and the result is reassembled as an IMAGE-ONLY PDF (no text
// layer = nothing recoverable under the boxes). See pdfExport.ts for the render/paint/verify pipeline.
//
// INVARIANT: the flat text (offsets the detector uses) and the per-item geometry are built in ONE
// getTextContent() pass with the default normalization, so span char-offsets map provably onto item rects.

import * as pdfjsLib from 'pdfjs-dist'
import type { PDFDocumentProxy, PDFPageProxy } from 'pdfjs-dist'
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

export type LoadedPdf = {
  text: string
  pages: PageGeom[]
  assess: PageAssessment[]
  assessPromise?: Promise<PageAssessment[]>
  bytes: ArrayBuffer
}
function errorName(e: unknown): string | undefined {
  if (e && typeof e === 'object' && 'name' in e && typeof e.name === 'string') return e.name
  return undefined
}

function assessmentFor(pageIndex: number, strChars: number, hasImage: boolean): PageAssessment {
  const status: PageStatus = hasImage ? (strChars < 8 ? 'image-only' : 'has-image') : 'text-clean'
  return { pageIndex, status, strChars, hasImage }
}

function failSafeAssessment(pageIndex: number, strChars: number): PageAssessment {
  return assessmentFor(pageIndex, strChars, true)
}

async function assessPageImages(pdf: PDFDocumentProxy, pageNumber: number, strChars: number): Promise<PageAssessment> {
  let page: PDFPageProxy | null = null
  try {
    page = await pdf.getPage(pageNumber)
    const opList = await page.getOperatorList()
    const hasImage = opList.fnArray.some(
      (fn) => fn === OPS.paintImageXObject || fn === OPS.paintInlineImageXObject || fn === OPS.paintImageMaskXObject,
    )
    return assessmentFor(pageNumber - 1, strChars, hasImage)
  } catch {
    return failSafeAssessment(pageNumber - 1, strChars)
  } finally {
    page?.cleanup()
  }
}

async function assessPdfImages(bytes: ArrayBuffer, strCharsByPage: number[]): Promise<PageAssessment[]> {
  let pdf: PDFDocumentProxy | null = null
  try {
    pdf = await pdfjsLib.getDocument({ data: bytes.slice(0) }).promise
    const assess: PageAssessment[] = []
    for (let p = 1; p <= strCharsByPage.length; p++) {
      assess.push(await assessPageImages(pdf, p, strCharsByPage[p - 1]))
    }
    return assess
  } catch {
    return strCharsByPage.map((strChars, pageIndex) => failSafeAssessment(pageIndex, strChars))
  } finally {
    if (pdf) {
      try {
        await pdf.destroy()
      } catch {
        // Assessment has already produced a fail-safe result; do not turn worker cleanup failure into text-clean.
      }
    }
  }
}

export async function loadPdfDoc(file: File): Promise<LoadedPdf> {
  const bytes = await file.arrayBuffer()
  let pdf: PDFDocumentProxy | null = null
  try {
    // slice(0) -> a throwaway copy for the worker (getDocument detaches its buffer); keep `bytes` intact
    pdf = await pdfjsLib.getDocument({ data: bytes.slice(0) }).promise
  } catch (e) {
    if (errorName(e) === 'PasswordException') throw new Error('This PDF is password-protected. Unlock it first, then load it.')
    throw e
  }

  const pages: PageGeom[] = []
  const pageTexts: string[] = []
  const strCharsByPage: number[] = []
  let docOffset = 0

  try {
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

      const strChars = items.reduce((a, i) => a + i.str.length, 0)
      pages.push({ pageIndex: p - 1, rotation: page.rotate, viewBoxWidth, viewBoxHeight, items })
      pageTexts.push(trimmed)
      strCharsByPage.push(strChars)
      docOffset += tlen + 2 // the 2-char '\n\n' join between pages
      page.cleanup()
    }
  } finally {
    await pdf.destroy()
  }

  // Probe image operators in a separate pdf.js document after the text/geometry path has finished. The UI gets
  // the same assess array shape immediately, then swaps in this fail-safe result when it resolves.
  const assess = strCharsByPage.map((strChars, pageIndex) => assessmentFor(pageIndex, strChars, false))
  const assessPromise = assessPdfImages(bytes, strCharsByPage)
  return { text: pageTexts.join('\n\n'), pages, assess, assessPromise, bytes }
}

// Back-compat thin wrapper (kept so any text-only caller is unchanged).
export async function loadPdfText(file: File): Promise<string> {
  return (await loadPdfDoc(file)).text
}
