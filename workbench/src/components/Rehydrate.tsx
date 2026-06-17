// Round-trip restore (spec C). After a redacted document comes back from a colleague (who edited it), this
// puts the original values back into the surviving placeholders while keeping the colleague's edits. Everything
// runs in-browser; files stay on the machine.
//
// DEFAULT path (no separate upload): if this device redacted the file, its entity map was saved locally
// (IndexedDB, keyed by the fingerprint of the REDACTED body -- see mapStore.ts). When the edited file is
// dropped, we scan its surviving placeholders + content fingerprint and AUTO-MATCH the stored map. The
// matched map (the originals) never leaves this device.
//
// FALLBACK path (kept forever): no stored map matches (different machine, cleared store, private browsing)
// -> the manual entity-map .json picker appears and the original two-file flow still works.

import { useRef, useState } from 'react'
import { rehydrateFile, downloadBlob, findPlaceholders } from '../lib/formats'
import { loadDocx } from '../lib/docx'
import { loadXlsx } from '../lib/xlsx'
import { sha256Hex, matchByFingerprint, type MapRecord } from '../lib/mapStore'
import type { EntityMap } from '../lib/types'

type Status = { kind: 'idle' | 'ok' | 'err'; msg: string }

// Read the file's body text exactly the way rehydrateFile does -- so the fingerprint + placeholder scan
// run over the SAME body that the round-trip restore will operate on. PDF has no placeholders (image-only
// redaction) and cannot round-trip.
async function readBody(file: File): Promise<string> {
  const ext = (file.name.split('.').pop() || '').toLowerCase()
  if (ext === 'pdf') throw new Error('pdf')
  if (ext === 'docx') return (await loadDocx(file)).text
  if (ext === 'xlsx') return (await loadXlsx(file)).text
  return file.text()
}

export default function Rehydrate() {
  const [docFile, setDocFile] = useState<File | null>(null)
  const [mapFile, setMapFile] = useState<File | null>(null)
  const [status, setStatus] = useState<Status>({ kind: 'idle', msg: '' })
  const [busy, setBusy] = useState(false)
  // Auto-match state. `matched` = a stored on-device map that resolves this file's survivors; `noMatch`
  // = we scanned and found none (reveal the manual upload fallback). Before a doc is scanned both are off.
  const [matched, setMatched] = useState<MapRecord | null>(null)
  const [noMatch, setNoMatch] = useState(false)
  const docRef = useRef<HTMLInputElement>(null)
  const mapRef = useRef<HTMLInputElement>(null)

  // On docFile pick: try to auto-match a locally-stored map. Hit -> one-click restore (no .json). Miss ->
  // reveal the manual map picker. PDF / unreadable -> reveal the manual picker too (it will error clearly).
  async function tryAutoMatch(file: File) {
    setMatched(null)
    setNoMatch(false)
    setStatus({ kind: 'idle', msg: '' })
    try {
      const body = await readBody(file)
      const present = findPlaceholders(body)
      const fpExact = await sha256Hex(body)
      const rec = await matchByFingerprint(fpExact, present)
      if (rec) setMatched(rec)
      else setNoMatch(true)
    } catch {
      // pdf or load failure: fall back to the manual path (the run() below surfaces the precise error)
      setNoMatch(true)
    }
  }

  // Restore using the auto-matched on-device map. ONE click, no .json upload.
  async function runFromDevice() {
    if (!docFile || !matched) return
    setBusy(true)
    setStatus({ kind: 'idle', msg: '' })
    try {
      // Cross-map collision guard: every surviving placeholder must be resolvable in the matched map.
      // matchByFingerprint already enforces this, but re-check here so a wrong-map restore can never slip
      // through (defence in depth -- do not partial-restore from the wrong map).
      const body = await readBody(docFile)
      const unresolvable = findPlaceholders(body).filter((ph) => !(ph in matched.map))
      if (unresolvable.length) {
        setMatched(null)
        setNoMatch(true)
        setStatus({ kind: 'err', msg: 'The saved map on this device does not resolve every placeholder. Upload the entity-map .json instead.' })
        return
      }
      const { blob, filename, restored, unknown } = await rehydrateFile(docFile, matched.map)
      downloadBlob(filename, blob)
      const warn = unknown.length
        ? ` ${unknown.length} placeholder(s) had no value in the map and were left as-is (${unknown.slice(0, 3).join(', ')}${unknown.length > 3 ? '…' : ''}).`
        : ''
      setStatus({
        kind: 'ok',
        msg: restored
          ? `Restored ${restored} value(s) from this device's saved map and saved ${filename}.${warn}`
          : `No placeholders matched the saved map -- nothing to restore.${warn}`,
      })
    } catch (e) {
      setStatus({ kind: 'err', msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setBusy(false)
    }
  }

  // Restore using a manually-uploaded entity-map .json (the cross-device fallback).
  async function run() {
    if (!docFile || !mapFile) return
    setBusy(true)
    setStatus({ kind: 'idle', msg: '' })
    try {
      const raw = await mapFile.text()
      let map: EntityMap
      try {
        map = JSON.parse(raw)
      } catch {
        throw new Error('The entity map is not valid JSON. Use the .json saved from “Download entity map”.')
      }
      if (!map || typeof map !== 'object' || Array.isArray(map))
        throw new Error('The entity map must be a JSON object of placeholder → value.')

      const { blob, filename, restored, unknown } = await rehydrateFile(docFile, map)
      downloadBlob(filename, blob)
      const warn = unknown.length
        ? ` ${unknown.length} placeholder(s) had no value in the map and were left as-is (${unknown.slice(0, 3).join(', ')}${unknown.length > 3 ? '…' : ''}).`
        : ''
      setStatus({
        kind: 'ok',
        msg: restored
          ? `Restored ${restored} value(s) from the uploaded map and saved ${filename}.${warn}`
          : `No placeholders matched the map -- nothing to restore.${warn}`,
      })
    } catch (e) {
      setStatus({ kind: 'err', msg: e instanceof Error ? e.message : String(e) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="w-full max-w-2xl flex flex-col gap-4">
      <p className="text-sm" style={{ color: 'var(--color-muted)', lineHeight: 1.6 }}>
        Got an edited copy back from a colleague? Drop the edited document. If you redacted it on this device,
        the saved map is matched automatically and the original values go back into the placeholders -- no
        separate file needed. If there is no saved map (another machine, cleared storage), upload the entity-map
        .json you saved when you redacted it. Every edit your colleague made is kept.
      </p>

      <FilePick
        label="Edited document"
        hint=".docx · .xlsx · .txt · .md · .csv"
        file={docFile}
        inputRef={docRef}
        accept=".docx,.xlsx,.txt,.md,.markdown,.csv,.tsv,.log,.json,.jsonl,.xml,.html,.htm,.yaml,.yml"
        onPick={(f) => {
          setDocFile(f)
          setMapFile(null)
          void tryAutoMatch(f)
        }}
      />

      {matched && (
        <>
          <div
            className="text-sm panel"
            style={{ padding: '10px 14px', color: 'var(--color-success)', background: 'var(--color-surface)' }}
          >
            Matched a redaction map saved on this device ({matched.neutralLabel}). No file upload needed.
          </div>
          <button className="btn btn-primary self-start" disabled={busy} onClick={runFromDevice}>
            {busy ? 'Restoring…' : 'Restore values'}
          </button>
        </>
      )}

      {noMatch && (
        <>
          <div className="text-sm" style={{ color: 'var(--color-muted)', lineHeight: 1.6 }}>
            No saved map for this file on this device -- upload the entity-map .json saved when you redacted it.
          </div>
          <FilePick
            label="Entity map"
            hint=".json -- holds the original values, keep it private"
            file={mapFile}
            inputRef={mapRef}
            accept=".json,application/json"
            onPick={(f) => {
              setMapFile(f)
              setStatus({ kind: 'idle', msg: '' })
            }}
          />
          <button className="btn btn-primary self-start" disabled={!docFile || !mapFile || busy} onClick={run}>
            {busy ? 'Restoring…' : 'Restore values'}
          </button>
        </>
      )}

      {status.msg && (
        <div
          className="text-sm panel"
          style={{
            padding: '10px 14px',
            color: status.kind === 'err' ? 'var(--color-warning)' : status.kind === 'ok' ? 'var(--color-success)' : 'var(--color-text)',
            background: 'var(--color-surface)',
          }}
        >
          {status.msg}
        </div>
      )}
    </div>
  )
}

function FilePick({
  label,
  hint,
  file,
  accept,
  inputRef,
  onPick,
}: {
  label: string
  hint: string
  file: File | null
  accept: string
  inputRef: React.RefObject<HTMLInputElement | null>
  onPick: (f: File) => void
}) {
  return (
    <div>
      <div className="eyebrow mb-2">{label}</div>
      <div
        onClick={() => inputRef.current?.click()}
        className="panel flex items-center justify-between gap-3 cursor-pointer"
        style={{ padding: '12px 14px', background: 'var(--color-surface)', borderStyle: 'dashed', borderColor: 'var(--border-mid)' }}
      >
        <span className="text-sm mono" style={{ color: file ? 'var(--color-text)' : 'var(--color-light)' }}>
          {file ? file.name : `Choose a file -- ${hint}`}
        </span>
        <span className="btn btn-ghost" style={{ pointerEvents: 'none', padding: '4px 12px' }}>
          Browse
        </span>
      </div>
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f) onPick(f)
        }}
      />
    </div>
  )
}
