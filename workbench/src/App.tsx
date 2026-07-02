import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Header from './components/Header'
import Toolbar from './components/Toolbar'
import DocCanvas from './components/DocCanvas'
import LayoutCanvas, { layoutKind } from './components/LayoutCanvas'
import Inspector from './components/Inspector'
import Dropzone from './components/Dropzone'
import type { Span, RegionBox, EntityMap } from './lib/types'
import { tier0Spans } from './lib/tier0'
import { mergeSpans, toSpans, insertSpan, combineWithManual, buildEntityMap, redactedText, explain, newId, setLabelActive, setLabelsActive, newPlaceholderIndex } from './lib/redaction'
import { labelTier, type Tier } from './lib/labels'
import { DEEP_DEGRADED_WARNING, DEEP_DEGRADED_EXPORT_CONFIRM } from './lib/degrade'
import { modelOnDevice } from './lib/neural'
import { deepDetect, deepProviderLabel, gateHealth, prepareDeepDetect, type DeepProvider, type GateHealth } from './lib/gate'
import { verifyDocx, docxLeakParts } from './lib/docx'
import { verifyXlsx } from './lib/xlsx'
import { download, downloadBlob, findPlaceholders, survivingValues, type LoadedDoc } from './lib/formats'
import { putMap, sha256Hex, getRemember, type Fingerprint } from './lib/mapStore'
import { extOf, neutralName, assembleZip, redactedBatchText, replacementsForText, type BatchEntry, type ZipFile } from './lib/batch'
import { maskPlaceholdersForPrint } from './lib/printMask'

const MIME: Record<string, string> = { md: 'text/markdown', markdown: 'text/markdown', csv: 'text/csv', json: 'application/json', html: 'text/html' }
type ResolvedBatchEntry = { entry: BatchEntry; placeholderOf: Map<string, string> }
const PageView = lazy(() => import('./components/PageView'))

export default function App() {
  const [doc, setDoc] = useState<LoadedDoc | null>(null)
  const [spans, setSpans] = useState<Span[]>([])
  const [regions, setRegions] = useState<RegionBox[]>([])
  const [view, setView] = useState<'text' | 'layout' | 'pages'>('text')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [gate, setGate] = useState<GateHealth | null>(null)
  // Fail-closed deep-scan state for the active document:
  //   'clean'    - a deep (neural) scan ran successfully; names/orgs/addresses were scanned.
  //   'degraded' - a deep scan was ATTEMPTED but the model was unavailable -> Tier-0-only output that may leak
  //                names/orgs/addresses. The user thought they ran deep, so export requires an explicit confirm.
  //   'none'     - deep never ran (Tier-0 auto-detect baseline). A persistent banner informs the user, but the
  //                default structured-only export is not confirm-gated (they never requested a deep scan).
  // Reset to 'none' on a new doc, clear, or re-running Tier-0 auto-detect.
  const [deepStatus, setDeepStatus] = useState<'clean' | 'degraded' | 'none'>('none')
  // Browser-model download progress (0..100) while the one-time ~300 MB fetch is in flight; null otherwise.
  const [loadPct, setLoadPct] = useState<number | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  // Redaction-filter preference: labels the reviewer chose NOT to redact. Persists across re-detection so a
  // muted category does not silently come back active after Deep detect. Empty = redact every category.
  const [mutedLabels, setMutedLabels] = useState<Set<string>>(new Set())
  // Batch mode (finding 020): an ORDERED set of same-type files sharing ONE entity map, exported as one
  // .zip. Empty for the common single-file case (no rail, single-doc path byte-for-byte unchanged). When
  // populated, the ACTIVE entry's doc/spans/regions are mirrored into the single-doc state above, so the
  // existing DocCanvas/Inspector/Toolbar are reused verbatim; switching entries saves the live spans/regions
  // back into the outgoing entry first (see selectEntry).
  const [batch, setBatch] = useState<BatchEntry[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [batchProgress, setBatchProgress] = useState<{ done: number; total: number } | null>(null)
  const batchAbort = useRef<AbortController | null>(null)
  const inBatch = batch.length > 0

  // Open a document in the layout-preserving view when one is available (PDF geometry, or an xlsx/csv grid),
  // so page/table structure shows by default; plain text falls back to the flat view.
  const initialView = (d: LoadedDoc): 'text' | 'layout' | 'pages' => (layoutKind(d.kind, d.pages) ? 'layout' : 'text')

  const flash = useCallback((m: string) => {
    setToast(m)
    window.setTimeout(() => setToast((t) => (t === m ? null : t)), 2600)
  }, [])

  useEffect(() => {
    gateHealth().then(setGate)
  }, [])

  // Entity map for the ACTIVE document. In single-file mode this is the per-doc map (unchanged). In batch
  // mode it is derived from a SHARED placeholder index built over EVERY entry in order (the active entry
  // using its LIVE spans), so the same label+value resolves to the SAME placeholder across every file.
  const { map, placeholderOf } = useMemo(() => {
    if (!doc) return { map: {}, placeholderOf: new Map<string, string>() }
    if (!inBatch) return buildEntityMap(doc.text, spans)
    const idx = newPlaceholderIndex()
    let activePlaceholderOf = new Map<string, string>()
    for (const e of batch) {
      const isActive = e.id === activeId
      const eSpans = isActive ? spans : e.spans
      const eText = isActive ? doc.text : e.doc.text
      const { placeholderOf: po } = buildEntityMap(eText, eSpans, idx)
      if (isActive) activePlaceholderOf = po
    }
    return { map: idx.map, placeholderOf: activePlaceholderOf } // idx.map = the FULL shared batch map
  }, [doc, spans, inBatch, batch, activeId])
  const activeCount = useMemo(() => spans.filter((s) => s.active).length, [spans])
  const regionCount = useMemo(() => regions.filter((r) => r.active).length, [regions])
  const hasRedactions = activeCount > 0 || regionCount > 0
  const selected = useMemo(() => spans.find((s) => s.id === selectedId) ?? null, [spans, selectedId])

  function handleLoad(d: LoadedDoc) {
    setBatch([]) // single-file load leaves batch mode (no rail)
    setActiveId(null)
    setBatchProgress(null)
    setDoc(d)
    setSelectedId(null)
    setRegions([])
    setView(initialView(d))
    const fresh = toSpans(mergeSpans(tier0Spans(d.text)), 'auto', mutedLabels)
    setSpans(fresh)
    const imgPages = (d.assess ?? []).filter((a) => a.status !== 'text-clean').length
    if (imgPages > 0)
      flash(`${imgPages} page(s) contain images the text scan can’t read -- open “Pages” to draw redaction boxes over them.`)
  }

  // Load >1 same-type files as a batch. Each entry gets its own Tier-0 spans up front (cheap, in-memory);
  // the active entry's doc/spans/regions are mirrored into the single-doc state so the existing review UI
  // is reused verbatim. The shared entity map is computed across all entries (see the map useMemo above).
  function handleLoadBatch(docs: LoadedDoc[]) {
    const entries: BatchEntry[] = docs.map((d) => ({
      id: newId(),
      name: d.name,
      kind: extOf(d.name),
      doc: d,
      spans: toSpans(mergeSpans(tier0Spans(d.text)), 'auto', mutedLabels),
      regions: [],
      status: 'pending',
    }))
    setBatch(entries)
    setBatchProgress(null)
    const first = entries[0]
    setActiveId(first.id)
    setDoc(first.doc)
    setSpans(first.spans)
    setRegions(first.regions)
    setSelectedId(null)
    setView(initialView(first.doc))
    flash(`Batch loaded: ${entries.length} ${first.kind} files share one entity map. Review each, then export one .zip.`)
  }

  // Switch the active batch entry. Save the live spans/regions back into the OUTGOING entry first (so the
  // reviewer's work on it is not lost), then mirror the incoming entry into the single-doc state.
  const selectEntry = useCallback(
    (id: string) => {
      if (id === activeId) return
      setBatch((prev) => prev.map((e) => (e.id === activeId ? { ...e, spans, regions } : e)))
      const next = batch.find((e) => e.id === id)
      if (!next) return
      // Pull the freshest saved copy of the incoming entry (it may differ from `next` if it was the one
      // just saved above in the same render, but activeId !== id guarantees it is a different entry).
      setActiveId(id)
      setDoc(next.doc)
      setSpans(next.spans)
      setRegions(next.regions)
      setSelectedId(null)
      setView(initialView(next.doc))
    },
    [activeId, batch, spans, regions],
  )

  // Keep the active entry's saved spans/regions in sync with the live single-doc state while editing, so
  // export + the shared map + entry-switching always read the current work without an explicit save click.
  useEffect(() => {
    if (!inBatch || !activeId) return
    setBatch((prev) => prev.map((e) => (e.id === activeId ? { ...e, spans, regions } : e)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [spans, regions, activeId, inBatch])

  const addRegion = useCallback((r: Omit<RegionBox, 'id'>) => {
    setRegions((prev) => [...prev, { ...r, id: newId() }])
  }, [])
  const deleteRegion = useCallback((id: string) => {
    setRegions((prev) => prev.filter((r) => r.id !== id))
  }, [])

  const autoDetect = useCallback(() => {
    if (!doc) return
    const fresh = toSpans(mergeSpans(tier0Spans(doc.text)), 'auto', mutedLabels)
    setSpans((prev) => combineWithManual(prev, fresh))
    setDeepStatus('none') // re-running the Tier-0 baseline; a prior deep result no longer describes these spans
  }, [doc, mutedLabels])

  // Pick the deep-detect provider. On-prem installs use /gate when reachable; the hosted website demo
  // falls back to the in-browser model and surfaces the one-time model download as progress.
  const ensureDeepProvider = useCallback(async (signal?: AbortSignal): Promise<DeepProvider> => {
    let announcedBrowserLoad = false
    // Tell the truth about what the load costs: weights already in the origin cache load from
    // disk in seconds -- announcing a "~300 MB download" there reads as a re-download every visit.
    const cached = await modelOnDevice()
    try {
      return await prepareDeepDetect((p) => {
        if (!announcedBrowserLoad) {
          announcedBrowserLoad = true
          setLoadPct(0)
          flash(cached
            ? 'Loading the browser model from this device -- already downloaded, no network needed.'
            : 'Loading the browser model -- one-time ~300 MB download, then it runs offline.')
        }
        if (typeof p.progress === 'number') setLoadPct(Math.min(100, Math.round(p.progress)))
      }, signal)
    } finally {
      setLoadPct(null)
    }
  }, [flash])

  const runDeep = useCallback(async () => {
    if (!doc) return
    setBusy(true)
    try {
      const provider = await ensureDeepProvider()
      const raw = await deepDetect(doc.text, 0.5, undefined, provider)
      const fresh = toSpans(raw, 'neural', mutedLabels)
      setSpans((prev) => combineWithManual(prev, fresh))
      setGate((g) => ({ ...(g ?? {}), ok: true, provider }))
      setDeepStatus('clean')
      flash(`${deepProviderLabel(provider)} found ${fresh.length} spans (Tier-0 + neural)`)
    } catch (e) {
      setGate((g) => ({ ...(g ?? {}), ok: false }))
      setDeepStatus('degraded')
      flash(`Deep detect unavailable -- using local Tier-0 only. (${e instanceof Error ? e.message : e})`)
    } finally {
      setBusy(false)
    }
  }, [doc, ensureDeepProvider, flash, mutedLabels])

  // Batch "Deep detect all": iterate entries SEQUENTIALLY (never a parallel model/proxy flood) with a
  // cancellable AbortSignal and per-file progress. On provider failure for an entry, mark it Tier-0-only
  // and CONTINUE -- the batch never hard-fails because deep detect is down (mirrors runDeep's
  // single-file degrade). The live active entry's spans are flushed back into the batch first so its
  // existing manual work is preserved, then every entry is detected from its own saved spans.
  const runDeepAll = useCallback(async () => {
    if (!inBatch) return
    setBusy(true)
    const ac = new AbortController()
    batchAbort.current = ac
    // snapshot of entries with the live active entry's spans flushed in (so manual work on it is kept)
    const work = batch.map((e) => (e.id === activeId ? { ...e, spans, regions } : e))
    setBatchProgress({ done: 0, total: work.length })
    // Select the deep provider ONCE up front: local /gate for installs, browser model for the hosted demo.
    // If selection/load fails, every entry degrades to Tier-0 without retrying on every file.
    let provider: DeepProvider | null = null
    try {
      provider = await ensureDeepProvider(ac.signal)
    } catch {
      provider = null
    }
    let gateOk: boolean | null = null
    let degraded = 0
    const updated: BatchEntry[] = []
    for (let i = 0; i < work.length; i++) {
      if (ac.signal.aborted) break
      const e = work[i]
      try {
        if (!provider) throw new Error('deep detect unavailable')
        const raw = await deepDetect(e.doc.text, 0.5, ac.signal, provider)
        const fresh = toSpans(raw, 'neural', mutedLabels)
        updated.push({ ...e, spans: combineWithManual(e.spans, fresh), status: 'detected' })
        gateOk = true
      } catch (err) {
        if (ac.signal.aborted) break
        // deep provider unavailable for this entry: keep its Tier-0 spans, mark it, continue
        updated.push({ ...e, status: 'detected', error: 'Tier-0 only (deep detect unavailable)' })
        degraded++
        gateOk = gateOk ?? false
      }
      setBatchProgress({ done: i + 1, total: work.length })
    }
    // merge results back; entries not reached (aborted) keep their prior state
    setBatch((prev) => prev.map((p) => updated.find((u) => u.id === p.id) ?? p))
    // re-mirror the active entry's (possibly updated) spans into the live single-doc state
    const activeUpdated = updated.find((u) => u.id === activeId)
    if (activeUpdated) setSpans(activeUpdated.spans)
    if (gateOk) setGate((g) => ({ ...(g ?? {}), ok: true, ...(provider ? { provider } : {}) }))
    // Fail-closed: if ANY entry fell back to Tier-0, the shared-map export (zip) contains under-redacted
    // content, so treat the batch as degraded (export is confirm-gated); only an all-clean run is 'clean'.
    setDeepStatus(degraded > 0 ? 'degraded' : 'clean')
    if (degraded === work.length) {
      setGate((g) => ({ ...(g ?? {}), ok: false }))
      flash(`Deep detect unavailable -- all ${work.length} files use local Tier-0 only.`)
    } else if (degraded > 0) {
      flash(`Deep detect done: ${work.length - degraded} via ${provider ? deepProviderLabel(provider) : 'deep detect'}, ${degraded} fell back to Tier-0.`)
    } else if (!ac.signal.aborted) {
      flash(`Deep detect done across ${work.length} files (${provider ? deepProviderLabel(provider) : 'deep detect'}).`)
    }
    batchAbort.current = null
    setBatchProgress(null)
    setBusy(false)
  }, [inBatch, batch, activeId, spans, regions, mutedLabels, flash, ensureDeepProvider])

  const cancelBatch = useCallback(() => {
    batchAbort.current?.abort()
  }, [])

  // "Apply label decisions to all": propagate the reviewer's per-label active choices across every entry,
  // so policy is set once. Drives off the CURRENT mutedLabels set: a label muted here is set inactive on
  // every span of that label in every file; an unmuted label is set active everywhere.
  const applyLabelsToAll = useCallback(() => {
    if (!inBatch) return
    const allLabels = new Set<string>()
    for (const e of batch) for (const s of e.spans) allLabels.add(s.label)
    for (const s of spans) allLabels.add(s.label)
    const muted = new Set<string>([...mutedLabels].filter((l) => allLabels.has(l)))
    const active = new Set<string>([...allLabels].filter((l) => !mutedLabels.has(l)))
    const apply = (arr: typeof spans) => setLabelsActive(setLabelsActive(arr, muted, false), active, true)
    setBatch((prev) => prev.map((e) => ({ ...e, spans: apply(e.spans) })))
    setSpans((prev) => apply(prev))
    flash(`Applied label decisions to all ${batch.length} files.`)
  }, [inBatch, batch, spans, mutedLabels, flash])

  const addManual = useCallback((start: number, end: number) => {
    const id = newId()
    setSpans((prev) =>
      insertSpan(prev, { id, start, end, label: 'manual', tier: 0, conf: 1, rule: 'manual', source: 'manual', active: true }),
    )
    setSelectedId(id)
  }, [])

  const toggle = useCallback((id: string) => setSpans((prev) => prev.map((s) => (s.id === id ? { ...s, active: !s.active } : s))), [])
  // Per-label redaction filter: set every span of `label` active/inactive AND remember the preference so a
  // re-detection does not silently re-enable a muted category.
  const setLabel = useCallback((label: string, active: boolean) => {
    setSpans((prev) => setLabelActive(prev, label, active))
    setMutedLabels((prev) => {
      const next = new Set(prev)
      if (active) next.delete(label)
      else next.add(label)
      return next
    })
  }, [])
  // Tier-level quick action: redact/pass every label in a tier that is currently present in the doc.
  const setTier = useCallback(
    (tier: Tier, active: boolean) => {
      const labels = new Set(spans.filter((s) => labelTier(s.label) === tier).map((s) => s.label))
      setSpans((prev) => setLabelsActive(prev, labels, active))
      setMutedLabels((prev) => {
        const next = new Set(prev)
        for (const l of labels) {
          if (active) next.delete(l)
          else next.add(l)
        }
        return next
      })
    },
    [spans],
  )
  const relabel = useCallback((id: string, label: string) => setSpans((prev) => prev.map((s) => (s.id === id ? { ...s, label } : s))), [])
  const del = useCallback(
    (id: string) => {
      setSpans((prev) => prev.filter((s) => s.id !== id))
      setSelectedId((cur) => (cur === id ? null : cur))
    },
    [],
  )

  function exportName(prefix: string, ext: string) {
    // NEVER echo the upload filename into a redacted artifact: upload names routinely CONTAIN the very PII we
    // just redacted (e.g. "Marie Tremblay statement.pdf", "Alexandre Gosselin-TD.pdf") -- leaking the name in
    // the output filename even when the content is clean. Shareable outputs get a neutral name; the browser
    // de-dups repeats as "redacted (1).pdf".
    return `${prefix}.${ext}`
  }

  const redactedCurrentText = useCallback((): string | null => {
    if (!doc) return null
    if (!inBatch) return redactedText(doc.text, spans)
    return redactedBatchText(doc.text, spans, placeholderOf, map)
  }, [doc, inBatch, spans, placeholderOf, map])

  // Fail-closed export gate: when a deep scan was attempted but degraded to Tier-0, the output may leak
  // names/orgs/addresses. Require an explicit confirmation before it leaves the tool (copy/download/print).
  // Returns true to proceed. 'none' (deep never requested) is not gated -- the persistent banner informs the
  // user, who chose the structured-only baseline; only the "I ran deep but it silently fell back" case blocks.
  function confirmDegradedExport(): boolean {
    if (deepStatus !== 'degraded') return true
    return typeof window === 'undefined' || window.confirm(DEEP_DEGRADED_EXPORT_CONFIRM)
  }

  function copyRedacted() {
    if (!confirmDegradedExport()) return
    const redacted = redactedCurrentText()
    if (redacted == null) return
    navigator.clipboard.writeText(redacted).then(
      () => flash('Redacted text copied'),
      () => flash('Copy failed -- your browser blocked clipboard access'),
    )
  }
  // Remember the entity map on THIS device, keyed by the fingerprint of the REDACTED (placeholder-bearing)
  // body -- never the original text, never the upload filename. Lets a returned/own redacted file auto-match
  // its map with no separate .json upload. Gated behind the opt-in (default ON); OFF writes nothing. The map
  // (originals) goes ONLY to IndexedDB on this machine -- never into a shared/exported artifact.
  const persistMap = useCallback(async () => {
    if (!doc) return
    if (!getRemember()) return
    const redacted = redactedCurrentText()
    if (redacted == null) return
    const placeholders = findPlaceholders(redacted).filter((ph) => Object.prototype.hasOwnProperty.call(map, ph))
    if (!placeholders.length) return // nothing redacted -> nothing to remember
    const fpExact = await sha256Hex(redacted)
    const stamp = new Date().toISOString().slice(0, 10) // neutral date stamp -- no filename, no original text
    await putMap({
      id: fpExact, // idempotent under StrictMode double-invoke
      createdAt: Date.now(),
      neutralLabel: `redaction from ${stamp}`,
      fpExact,
      placeholders,
      map,
      fingerprints: [{ fpExact, placeholders }], // forward-compat for batch redaction (finding 020)
    })
  }, [doc, map, redactedCurrentText])

  const persistBatchMap = useCallback(async (sharedMap: EntityMap, fingerprints: Fingerprint[]) => {
    if (!getRemember()) return false
    const usable = fingerprints.filter((fp) => fp.placeholders.length)
    if (!usable.length || !Object.keys(sharedMap).length) return false
    const primary = usable[0]
    const stamp = new Date().toISOString().slice(0, 10)
    await putMap({
      id: primary.fpExact,
      createdAt: Date.now(),
      neutralLabel: `batch redaction from ${stamp}`,
      fpExact: primary.fpExact,
      placeholders: primary.placeholders,
      map: sharedMap,
      fingerprints: usable,
    })
    return true
  }, [])

  async function downloadRedacted() {
    if (!doc) return
    if (!confirmDegradedExport()) return
    // format-preserving office doc: rewrite the redacted slices inside the original zip and re-verify (fail-closed)
    const office = doc.rebuildDocx
      ? { rebuild: doc.rebuildDocx, verify: verifyDocx, ext: 'docx' }
      : doc.rebuildXlsx
        ? { rebuild: doc.rebuildXlsx, verify: verifyXlsx, ext: 'xlsx' }
        : null
    if (office) {
      const repls = replacementsForText(doc.text, spans, placeholderOf, map)
      const blob = await office.rebuild(repls)
      const leaked = await office.verify(blob, Object.values(map)) // block if any redacted value survives
      if (leaked.length) {
        // Name the part(s) still holding a leaked value so a blocked export points somewhere, not a dead end.
        const parts = office.ext === 'docx' ? await docxLeakParts(blob, leaked) : []
        const where = parts.length ? ` in ${parts.join(', ')}` : ''
        flash(`BLOCKED: ${leaked.length} redacted value(s) still present${where} in the .${office.ext}. Not saved.`)
        return
      }
      downloadBlob(exportName('redacted', office.ext), blob)
      await persistMap() // remember the map on-device (gated by opt-in) -- AFTER the fail-closed verify passed
      return
    }
    const ext = doc.kind === 'pdf' ? 'txt' : doc.kind || 'txt'
    const redacted = redactedCurrentText()
    if (redacted == null) return
    const leaked = survivingValues(redacted, Object.values(map))
    if (leaked.length) {
      flash(`BLOCKED: ${leaked.length} redacted value(s) still present in the .${ext}. Not saved.`)
      return
    }
    download(exportName('redacted', ext), redacted, MIME[ext] ?? 'text/plain')
    if (doc.kind === 'pdf') flash('Saved redacted text. For a redacted PDF, use “Redacted PDF” (print / Save as PDF).')
    else await persistMap() // text/office round-trip-capable export -> remember the map on-device (gated). PDF has no placeholders.
  }
  function downloadMap() {
    download(exportName('entity-map', 'json'), JSON.stringify(map, null, 2), 'application/json')
    flash('Entity map saved -- contains original values, keep it local')
    void persistMap() // also remember on-device so the .json is no longer required to restore (gated by opt-in)
  }
  function downloadAudit() {
    download(exportName('audit', 'json'), JSON.stringify(explain(spans), null, 2), 'application/json')
  }

  // --- batch export (finding 020) ---
  // Compute, over EVERY entry in order, the shared placeholder index AND each entry's placeholderOf, so the
  // same label+value resolves to the same placeholder across files. The active entry uses its LIVE spans.
  const resolveBatch = useCallback(() => {
    const idx = newPlaceholderIndex()
    const work = batch.map((e) => (e.id === activeId ? { ...e, spans, regions } : e))
    const perEntry = work.map((e) => {
      const { placeholderOf: po } = buildEntityMap(e.doc.text, e.spans, idx)
      return { entry: e, placeholderOf: po }
    })
    return { sharedMap: idx.map, perEntry }
  }, [batch, activeId, spans, regions])

  // "Download batch (.zip)": rebuild + fail-closed verify EACH entry, add the redacted blob under a NEUTRAL
  // name, and assemble one .zip. The shared entity map is offered as a SEPARATE local download and is NEVER
  // placed inside the zip (it holds originals). Phase 1 handles text/docx/xlsx (cheap in-memory rebuilds);
  // PDF entries are rasterized one-at-a-time (Phase 2) -- see exportEntryBlob.
  const downloadBatchZip = useCallback(async () => {
    if (!inBatch) return
    // Fail-closed: a batch where deep detect degraded on any file ships under-redacted content in the zip.
    if (deepStatus === 'degraded' && typeof window !== 'undefined' && !window.confirm(DEEP_DEGRADED_EXPORT_CONFIRM)) return
    setBusy(true)
    try {
      const { sharedMap, perEntry } = resolveBatch()
      const total = perEntry.length
      const zipFiles: ZipFile[] = []
      const audits: Record<string, unknown>[] = []
      const fingerprints = await buildBatchFingerprints(perEntry, sharedMap)
      setBatchProgress({ done: 0, total })
      for (let i = 0; i < perEntry.length; i++) {
        const { entry, placeholderOf: po } = perEntry[i]
        const built = await exportEntryBlob(entry, po, sharedMap)
        if (!built) {
          flash(`BLOCKED: file ${i + 1} of ${total} (${entry.kind}) leaked a redacted value or could not be redacted. Zip not saved.`)
          setBatch((prev) => prev.map((e) => (e.id === entry.id ? { ...e, status: 'error', error: 'verify failed -- blocked' } : e)))
          setBatchProgress(null)
          setBusy(false)
          return
        }
        zipFiles.push({ name: neutralName(i, total, built.ext), blob: built.blob })
        audits.push({ file: neutralName(i, total, built.ext), spans: explain(entry.spans) }) // values-free
        setBatchProgress({ done: i + 1, total })
      }
      const zip = await assembleZip(zipFiles, JSON.stringify(audits, null, 2))
      downloadBlob('redacted-batch.zip', zip)
      const remembered = await persistBatchMap(sharedMap, fingerprints)
      flash(`Batch zip saved: ${zipFiles.length} redacted files, all passed verify. ${remembered ? 'Shared map saved on this device; download it separately for cross-device restore.' : 'Download the shared map separately to restore.'}`)
    } catch (e) {
      flash('Batch export failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBatchProgress(null)
      setBusy(false)
    }
  }, [inBatch, resolveBatch, persistBatchMap, flash, deepStatus])

  // Rebuild one entry's redacted blob and run its FORMAT-SPECIFIC fail-closed verify. Returns null if the
  // verify leaks (caller blocks the whole zip). Office: rewrite slices + verifyDocx/verifyXlsx. Text: splice
  // placeholders. PDF: lazy rasterize + verifyNoText, freed before the next file (Phase 2).
  async function exportEntryBlob(
    entry: BatchEntry,
    po: Map<string, string>,
    sharedMap: EntityMap,
  ): Promise<{ blob: Blob; ext: string } | null> {
    const d = entry.doc
    const values = Object.values(sharedMap)
    const office = d.rebuildDocx
      ? { rebuild: d.rebuildDocx, verify: verifyDocx, ext: 'docx' }
      : d.rebuildXlsx
        ? { rebuild: d.rebuildXlsx, verify: verifyXlsx, ext: 'xlsx' }
        : null
    if (office) {
      const repls = replacementsForText(d.text, entry.spans, po, sharedMap)
      const blob = await office.rebuild(repls)
      const leaked = await office.verify(blob, values)
      if (leaked.length) return null
      return { blob, ext: office.ext }
    }
    if (d.kind === 'pdf' && d.pages && d.bytes) {
      // Phase 2: lazy per-file rasterization -- render, verify, return; the canvas is freed inside
      // renderRedactedPdf so only ONE rasterized PDF is held at a time.
      const { renderRedactedPdf, verifyNoText } = await import('./lib/pdfExport')
      const { blob, uncovered } = await renderRedactedPdf(d.bytes, d.pages, entry.spans.filter((s) => s.active), entry.regions.filter((r) => r.active))
      if (uncovered.length) return null
      const verdict = await verifyNoText(blob, values)
      if (!verdict.ok) return null
      return { blob, ext: 'pdf' }
    }
    // text-ish: splice placeholders, then sweep any duplicate occurrence of a detected value (Finding C),
    // consistent with the active batch preview and using the FULL shared map, so a value detected in file 1
    // is still masked if it appears in file 2 but detection missed that occurrence.
    const out = redactedBatchText(d.text, entry.spans, po, sharedMap)
    if (survivingValues(out, values).length) return null
    const ext = d.kind || 'txt'
    return { blob: new Blob([out], { type: (MIME[ext] ?? 'text/plain') + ';charset=utf-8' }), ext }
  }

  function fingerprintTextForEntry(entry: BatchEntry, po: Map<string, string>, sharedMap: EntityMap): string | null {
    const d = entry.doc
    if (d.kind === 'pdf') return null
    return redactedBatchText(d.text, entry.spans, po, sharedMap)
  }

  async function buildBatchFingerprints(perEntry: ResolvedBatchEntry[], sharedMap: EntityMap): Promise<Fingerprint[]> {
    const fingerprints: Fingerprint[] = []
    for (const { entry, placeholderOf: po } of perEntry) {
      const text = fingerprintTextForEntry(entry, po, sharedMap)
      if (!text) continue
      const placeholders = findPlaceholders(text)
      if (placeholders.length) fingerprints.push({ fpExact: await sha256Hex(text), placeholders })
    }
    return fingerprints
  }

  // The shared batch entity map -> a SEPARATE local .json download. Mirrors the single-file "keep it local"
  // warning; this file holds originals and must NEVER be shared or placed inside the zip.
  const downloadBatchMap = useCallback(async () => {
    const { sharedMap, perEntry } = resolveBatch()
    download('entity-map.json', JSON.stringify(sharedMap, null, 2), 'application/json')
    await persistBatchMap(sharedMap, await buildBatchFingerprints(perEntry, sharedMap))
    flash('Shared entity map saved -- contains original values for the whole batch, keep it local')
  }, [resolveBatch, persistBatchMap, flash])

  // "Redacted PDF": for a real PDF, image-flatten + paint boxes + verify (fail-closed); for txt/docx, the
  // print region renders fixed-width blocks from the swept redacted text via the browser's Save-as-PDF.
  const handleRedactedPdf = useCallback(async () => {
    if (!doc) return
    if (deepStatus === 'degraded' && typeof window !== 'undefined' && !window.confirm(DEEP_DEGRADED_EXPORT_CONFIRM)) return
    if (doc.kind !== 'pdf' || !doc.pages || !doc.bytes) {
      window.print()
      return
    }
    // image pages the text scan can't read. A page the reviewer has already drawn a box on counts as reviewed;
    // warn only about image pages that still have NO manual box.
    const uncovered = (doc.assess ?? [])
      .filter((a) => a.status !== 'text-clean')
      .filter((a) => !regions.some((r) => r.pageIndex === a.pageIndex && r.active))
      .map((a) => a.pageIndex + 1)
    if (uncovered.length) {
      const ok = window.confirm(
        `Page(s) ${uncovered.join(', ')} contain images (scanned pages, screenshots, or photos) with no manual ` +
          `redaction box. Automatic detection cannot read text inside an image, so any personal information there ` +
          `will NOT be redacted. Open “Pages” to draw boxes over it, or export anyway?`,
      )
      if (!ok) {
        setView('pages')
        return
      }
    }
    setBusy(true)
    try {
      const { renderRedactedPdf, verifyNoText } = await import('./lib/pdfExport')
      const { blob, uncovered } = await renderRedactedPdf(doc.bytes, doc.pages, spans.filter((s) => s.active), regions.filter((r) => r.active))
      if (uncovered.length) {
        flash(`BLOCKED: ${uncovered.length} detected value(s) could not be covered by a box (no matching position on the page). Not saved -- review in "Pages".`)
        setView('pages')
        return
      }
      const verdict = await verifyNoText(blob, Object.values(map))
      if (!verdict.ok) {
        flash(`BLOCKED: output still has recoverable text (${verdict.leaked.length} values, ${verdict.residualChars} chars). Not saved.`)
        return
      }
      downloadBlob(exportName('redacted', 'pdf'), blob)
      flash('Redacted PDF saved (flattened to image). Every detected value was matched to a box; visually confirm scanned/image regions.')
    } catch (e) {
      flash('PDF redaction failed: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setBusy(false)
    }
  }, [doc, spans, regions, map, flash, deepStatus])

  function maskedForPrint(): string {
    const redacted = redactedCurrentText()
    return redacted ? maskPlaceholdersForPrint(redacted, map) : ''
  }

  function reset() {
    batchAbort.current?.abort()
    batchAbort.current = null
    setBatch([])
    setActiveId(null)
    setBatchProgress(null)
    setDoc(null)
    setSpans([])
    setRegions([])
    setView('text')
    setSelectedId(null)
    setDeepStatus('none')
  }

  return (
    <div className="flex flex-col" style={{ height: '100vh' }}>
      <Header />
      {doc ? (
        <>
          <Toolbar
            docName={doc.name}
            activeCount={activeCount}
            totalCount={spans.length}
            regionCount={regionCount}
            hasRedactions={hasRedactions}
            isPdf={doc.kind === 'pdf'}
            hasLayout={!!layoutKind(doc.kind, doc.pages)}
            view={view}
            onView={setView}
            busy={busy}
            gate={gate}
            loadPct={loadPct}
            onAutoDetect={autoDetect}
            onDeepDetect={runDeep}
            onClearDetections={() => {
              setSpans([])
              setSelectedId(null)
              setDeepStatus('none')
            }}
            onCopyRedacted={copyRedacted}
            onDownloadRedacted={downloadRedacted}
            onDownloadMap={downloadMap}
            onDownloadAudit={downloadAudit}
            onPrint={handleRedactedPdf}
            onReset={reset}
          />
          {deepStatus !== 'clean' && hasRedactions && (
            <div
              role={deepStatus === 'degraded' ? 'alert' : 'status'}
              className="flex items-start gap-2 px-4 py-2 text-xs"
              style={{
                borderBottom: '1px solid var(--border)',
                background: deepStatus === 'degraded' ? 'rgba(220, 38, 38, 0.12)' : 'var(--color-surface)',
                color: deepStatus === 'degraded' ? 'var(--color-danger, #dc2626)' : 'var(--color-muted)',
              }}
            >
              <span aria-hidden style={{ lineHeight: '1.2' }}>{deepStatus === 'degraded' ? '⚠' : 'ℹ'}</span>
              <span>
                {deepStatus === 'degraded'
                  ? DEEP_DEGRADED_WARNING
                  : 'Structured data only (secrets, IDs, cards, emails, dates). Names, organizations, and addresses are NOT scanned until you run Deep detect.'}
              </span>
            </div>
          )}
          {inBatch && (
            <div
              className="flex items-center gap-2 flex-wrap px-4 py-2"
              style={{ borderBottom: '1px solid var(--border)', background: 'var(--color-surface)' }}
            >
              <span className="text-xs mono" style={{ color: 'var(--color-muted)' }}>
                Batch: {batch.length} {batch[0]?.kind} files · one shared map
              </span>
              <button className="btn btn-ghost" onClick={runDeepAll} disabled={busy}>
                {loadPct != null
                  ? loadPct > 0
                    ? `Loading model ${loadPct}%`
                    : 'Loading model…'
                  : batchProgress
                    ? `Detecting ${batchProgress.done}/${batchProgress.total}…`
                    : 'Deep detect all'}
              </button>
              {batchProgress && (
                <button className="btn btn-ghost" onClick={cancelBatch}>
                  Cancel
                </button>
              )}
              <button className="btn btn-ghost" onClick={applyLabelsToAll} disabled={busy} title="Apply this file's redact/keep label choices to every file in the batch">
                Apply label decisions to all
              </button>
              <div className="ml-auto flex items-center gap-2">
                <button className="btn btn-primary" onClick={downloadBatchZip} disabled={busy}>
                  Download batch (.zip)
                </button>
                <button
                  className="btn btn-ghost"
                  onClick={downloadBatchMap}
                  disabled={busy}
                  title="Shared entity map for the whole batch -- holds original values, stays on this device, NEVER goes in the zip"
                  style={{ color: 'var(--color-warning)' }}
                >
                  Download shared map (.json · local)
                </button>
              </div>
            </div>
          )}
          <div className="flex" style={{ flex: 1, minHeight: 0 }}>
          {inBatch && (
            <aside
              style={{ width: 220, flex: '0 0 220px', overflowY: 'auto', borderRight: '1px solid var(--border)', background: 'var(--color-black)' }}
            >
              <div className="eyebrow" style={{ padding: '10px 12px 6px' }}>
                Files ({batch.length})
              </div>
              {batch.map((e, i) => {
                const liveSpans = e.id === activeId ? spans : e.spans
                const redCount = liveSpans.filter((s) => s.active).length
                return (
                  <button
                    key={e.id}
                    onClick={() => selectEntry(e.id)}
                    className="w-full text-left"
                    style={{
                      display: 'block',
                      padding: '8px 12px',
                      fontSize: 12.5,
                      borderBottom: '1px solid var(--border)',
                      background: e.id === activeId ? 'var(--glass)' : 'transparent',
                      color: 'var(--color-text)',
                    }}
                  >
                    <div className="mono" style={{ color: 'var(--color-muted)', fontSize: 10.5 }}>
                      #{String(i + 1).padStart(2, '0')} · {e.status === 'error' ? 'blocked' : e.status}
                    </div>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={e.name}>
                      {e.name}
                    </div>
                    <div className="mono" style={{ color: 'var(--color-light)', fontSize: 10.5 }}>
                      {redCount} redacted
                    </div>
                  </button>
                )
              })}
            </aside>
          )}
          <div style={{ flex: 1, minWidth: 0, borderRight: '1px solid var(--border)' }}>
            {view === 'pages' && doc.kind === 'pdf' && doc.bytes && doc.pages ? (
              <Suspense fallback={<div className="panel" style={{ margin: 20, padding: 16 }}>Loading pages...</div>}>
                <PageView
                  bytes={doc.bytes}
                  pages={doc.pages}
                  assess={doc.assess ?? []}
                  spans={spans}
                  regions={regions}
                  selectedSpanId={selectedId}
                  onSelectSpan={setSelectedId}
                  onAddRegion={addRegion}
                  onDeleteRegion={deleteRegion}
                />
              </Suspense>
            ) : view === 'layout' && layoutKind(doc.kind, doc.pages) ? (
              <LayoutCanvas
                text={doc.text}
                spans={spans}
                placeholderOf={placeholderOf}
                selectedId={selectedId}
                onSelect={setSelectedId}
                onAddManual={addManual}
                pages={doc.pages}
                kind={doc.kind}
              />
            ) : (
              <DocCanvas
                text={doc.text}
                spans={spans}
                placeholderOf={placeholderOf}
                selectedId={selectedId}
                onSelect={setSelectedId}
                onAddManual={addManual}
              />
            )}
          </div>
          <aside style={{ width: 340, flex: '0 0 340px', overflowY: 'auto', background: 'var(--color-surface)' }}>
            <Inspector
              span={selected}
              text={doc.text}
              placeholder={selected ? placeholderOf.get(selected.id) : undefined}
              spans={spans}
              onToggle={toggle}
              onRelabel={relabel}
              onDelete={del}
              onSetLabel={setLabel}
              onSetTier={setTier}
            />
          </aside>
          </div>
        </>
      ) : (
        <div style={{ flex: 1, minHeight: 0 }}>
          <Dropzone onLoad={handleLoad} onLoadBatch={handleLoadBatch} />
        </div>
      )}

      <div id="print-region">{maskedForPrint()}</div>

      {toast && (
        <div
          className="panel"
          style={{
            position: 'fixed',
            bottom: 22,
            left: '50%',
            transform: 'translateX(-50%)',
            padding: '10px 18px',
            fontSize: 13.5,
            background: 'var(--color-card)',
            boxShadow: '0 12px 40px rgba(0,0,0,.5)',
            zIndex: 50,
            maxWidth: '80vw',
          }}
        >
          {toast}
        </div>
      )}
    </div>
  )
}
