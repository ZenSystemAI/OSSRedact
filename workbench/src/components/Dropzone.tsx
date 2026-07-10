import { useCallback, useEffect, useRef, useState, type DragEvent as ReactDragEvent } from 'react'
import { loadFile, type LoadedDoc } from '../lib/formats'
import { extOf, typeBucket, sameTypeError } from '../lib/batch'
import Rehydrate from './Rehydrate'
import { getRemember, setRemember, clearMaps } from '../lib/mapStore'


type IntakeState = {
  completed: number
  total: number
  label: string
}

function isFileDrag(dataTransfer: DataTransfer | null): boolean {
  if (!dataTransfer) return false
  return (dataTransfer.files?.length ?? 0) > 0 || Array.from(dataTransfer.types ?? []).includes('Files')
}
const SAMPLE = `Objet : Confirmation de virement Interac

Bonjour Marie Tremblay,

Votre paiement a ete recu. Details du dossier :
- NAS : 046 454 286
- Carte : 4539 1488 0343 6467
- Compte : 006-02761-1234567
- Courriel : marie.tremblay@videotron.ca
- Telephone : (514) 555-0188
- Adresse : 4567 boulevard Rene-Levesque, Montreal H3B 1A1
- Reference de transaction : 8841220755301
- Date : 21 mai 2026

Merci de votre confiance.
Service a la clientele`

export default function Dropzone({
  onLoad,
  onLoadBatch,
}: {
  onLoad: (d: LoadedDoc) => void
  onLoadBatch: (docs: LoadedDoc[]) => void
}) {
  const [mode, setMode] = useState<'redact' | 'restore'>('redact')
  const [drag, setDrag] = useState(false)
  const [paste, setPaste] = useState('')
  const [err, setErr] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const loadingRef = useRef(false)
  const [intake, setIntake] = useState<IntakeState | null>(null)
  const intakeText = intake
    ? intake.total === 1
      ? `Loading ${intake.label}...`
      : `Loading ${intake.completed}/${intake.total} files...`
    : ''

  // Load one or many files. A single file routes to the unchanged single-doc path; >1 SAME-TYPE files
  // route to the batch path. Same-type is enforced here (export/verify are format-specific): the FIRST
  // file sets the batch's type bucket; any mismatch is rejected with a message stating WHY, and the
  // matching files still load. Accepted batch files load in parallel and report coarse progress so PDF
  // intake/batches do not look stalled.
  const handleFiles = useCallback(
    async (files: File[]) => {
      setErr('')
      if (!files.length || loadingRef.current) return

      loadingRef.current = true
      const markDone = () => {
        setIntake((current) =>
          current ? { ...current, completed: Math.min(current.completed + 1, current.total) } : current,
        )
      }

      try {
        if (files.length === 1) {
          setIntake({ completed: 0, total: 1, label: files[0].name })
          try {
            const doc = await loadFile(files[0])
            markDone()
            onLoad(doc)
          } catch (e) {
            markDone()
            setErr(e instanceof Error ? e.message : String(e))
          }
          return
        }

        const bucket = typeBucket(extOf(files[0].name))
        const rejected: string[] = []
        const accepted: File[] = []
        for (const f of files) {
          if (sameTypeError(bucket, extOf(f.name))) rejected.push(f.name)
          else accepted.push(f)
        }

        setIntake({ completed: 0, total: accepted.length, label: `${accepted.length} files` })
        const results: { file: File; doc: LoadedDoc | null; error: string | null }[] = new Array(accepted.length)
        // Keep PDF batch intake responsive without recreating the old export memory risk: PDFs are heavy
        // worker parses, so bound them to two concurrent loads; lighter text/office formats can fan out a bit.
        const workerCount = Math.min(accepted.length, bucket === 'pdf' ? 2 : 4)
        let next = 0
        await Promise.all(
          Array.from({ length: workerCount }, async () => {
            while (next < accepted.length) {
              const index = next++
              const file = accepted[index]
              try {
                results[index] = { file, doc: await loadFile(file), error: null }
              } catch (e) {
                results[index] = { file, doc: null, error: e instanceof Error ? e.message : String(e) }
              } finally {
                markDone()
              }
            }
          }),
        )

        const docs: LoadedDoc[] = []
        for (const result of results) {
          if (result.doc) docs.push(result.doc)
          else rejected.push(`${result.file.name} (${result.error})`)
        }
        if (rejected.length) {
          const sample = sameTypeError(bucket, extOf(files.find((f) => sameTypeError(bucket, extOf(f.name)))?.name ?? '')) ?? ''
          setErr(`${rejected.length} file(s) skipped (different type or unreadable). ${sample}`.trim())
        }
        if (docs.length === 1) onLoad(docs[0])
        else if (docs.length > 1) onLoadBatch(docs)
      } finally {
        loadingRef.current = false
        setIntake(null)
      }
    },
    [onLoad, onLoadBatch],
  )

  const handleSurfaceDragEnter = (e: ReactDragEvent<HTMLElement>) => {
    if (mode !== 'redact' || !isFileDrag(e.dataTransfer)) return
    e.preventDefault()
    e.dataTransfer.dropEffect = 'copy'
    setDrag(true)
  }

  const handleSurfaceDragOver = (e: ReactDragEvent<HTMLElement>) => {
    if (mode !== 'redact' || !isFileDrag(e.dataTransfer)) return
    e.preventDefault()
    e.dataTransfer.dropEffect = 'copy'
    setDrag(true)
  }

  const handleSurfaceDragLeave = (e: ReactDragEvent<HTMLElement>) => {
    if (mode !== 'redact' || !isFileDrag(e.dataTransfer)) return
    if (!(e.relatedTarget instanceof Node) || !e.currentTarget.contains(e.relatedTarget)) setDrag(false)
  }

  const handleSurfaceDrop = (e: ReactDragEvent<HTMLElement>) => {
    if (mode !== 'redact' || !isFileDrag(e.dataTransfer)) return
    e.preventDefault()
    e.stopPropagation()
    setDrag(false)
    void handleFiles(Array.from(e.dataTransfer.files ?? []))
  }

  useEffect(() => {
    if (mode !== 'redact') {
      setDrag(false)
      return
    }

    const preventFileNavigation = (event: DragEvent) => {
      const dataTransfer = event.dataTransfer
      if (!dataTransfer || !isFileDrag(dataTransfer)) return
      event.preventDefault()
      dataTransfer.dropEffect = 'copy'
    }

    const handleDocumentDrop = (event: DragEvent) => {
      const dataTransfer = event.dataTransfer
      if (!dataTransfer || !isFileDrag(dataTransfer)) return
      event.preventDefault()
      setDrag(false)
      void handleFiles(Array.from(dataTransfer.files ?? []))
    }

    document.addEventListener('dragover', preventFileNavigation)
    document.addEventListener('drop', handleDocumentDrop)
    return () => {
      document.removeEventListener('dragover', preventFileNavigation)
      document.removeEventListener('drop', handleDocumentDrop)
    }
  }, [handleFiles, mode])

  return (
    <div
      className="flex flex-col items-center justify-center h-full gap-6 px-6"
      onDragEnter={handleSurfaceDragEnter}
      onDragOver={handleSurfaceDragOver}
      onDragLeave={handleSurfaceDragLeave}
      onDrop={handleSurfaceDrop}
    >
      <div className="flex rounded-lg" style={{ border: '1px solid var(--border)', overflow: 'hidden' }}>
        {(['redact', 'restore'] as const).map((m) => (
          <button
            key={m}
            onClick={() => {
              setMode(m)
              setErr('')
            }}
            style={{
              padding: '7px 20px',
              fontSize: 13.5,
              background: mode === m ? 'var(--color-teal)' : 'transparent',
              color: mode === m ? '#06231f' : 'var(--color-light)',
              fontWeight: mode === m ? 600 : 400,
            }}
          >
            {m === 'redact' ? 'Redact a document' : 'Restore values'}
          </button>
        ))}
      </div>

      {mode === 'restore' && (
        <div className="w-full max-w-2xl flex flex-col gap-4">
          <Rehydrate />
          <MapStoreControls />
        </div>
      )}
      {mode === 'redact' && (
        <>
      <div
        onClick={() => {
          if (!intake) inputRef.current?.click()
        }}
        className="panel w-full max-w-2xl flex flex-col items-center justify-center gap-3 cursor-pointer transition-colors"
        style={{
          padding: '48px 24px',
          borderStyle: 'dashed',
          borderColor: drag ? 'var(--color-teal)' : 'var(--border-mid)',
          background: drag ? 'rgba(78,205,184,.06)' : 'var(--color-surface)',
          cursor: intake ? 'wait' : 'pointer',
        }}
      >
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal)" strokeWidth="1.6" aria-hidden="true">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <path d="M14 2v6h6M12 18v-6M9 15l3-3 3 3" />
        </svg>
        <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 18, color: 'var(--color-heading)' }}>
          Drop a document, or click to choose
        </div>
        <div className="text-sm" style={{ color: 'var(--color-muted)' }}>
          .pdf · .docx · .xlsx · .txt · .md · .csv · .json
        </div>
        {intake ? (
          <div className="text-xs" role="status" aria-live="polite" style={{ color: 'var(--color-teal)' }}>
            {intakeText}
          </div>
        ) : (
          <div className="text-xs" style={{ color: 'var(--color-muted)' }}>
            Drop several same-type files to process them as a batch.
          </div>
        )}
        <input
          ref={inputRef}
          type="file"
          multiple
          accept=".pdf,.docx,.xlsx,.txt,.md,.markdown,.csv,.tsv,.log,.json,.jsonl,.xml,.html,.htm,.yaml,.yml"
          className="hidden"
          disabled={Boolean(intake)}
          onChange={async (e) => {
            const input = e.currentTarget
            const fs = Array.from(input.files ?? [])
            try {
              if (fs.length) await handleFiles(fs)
            } finally {
              input.value = ''
            }
          }}
        />
      </div>

      <div className="w-full max-w-2xl">
        <div className="eyebrow mb-2">or paste text</div>
        <textarea
          value={paste}
          onChange={(e) => setPaste(e.target.value)}
          placeholder="Paste any text here…"
          className="w-full panel mono"
          style={{ minHeight: 120, padding: 14, fontSize: 13, color: 'var(--color-text)', resize: 'vertical', background: 'var(--color-black)' }}
        />
        <div className="flex items-center gap-3 mt-3">
          <button
            className="btn btn-primary"
            disabled={!paste.trim()}
            onClick={() => onLoad({ name: 'pasted.txt', text: paste, kind: 'txt' })}
          >
            Load pasted text
          </button>
          <button className="btn btn-ghost" onClick={() => onLoad({ name: 'sample.txt', text: SAMPLE, kind: 'txt' })}>
            Try a sample
          </button>
        </div>
      </div>

          {err && (
            <div className="text-sm" style={{ color: 'var(--color-warning)', maxWidth: 640, textAlign: 'center' }}>
              {err}
            </div>
          )}
        </>
      )}
    </div>
  )
}

// On-device map store controls (Restore tab). Opt-in toggle (default ON) gates the redact-side write;
// "Clear stored maps" empties the IndexedDB store. The note states, in plain language, that maps stay on
// THIS device and hold the real values -- mirroring the existing "keep it local" wording.
function MapStoreControls() {
  const [remember, setRememberState] = useState<boolean>(() => getRemember())
  const [cleared, setCleared] = useState(false)

  return (
    <div className="panel flex flex-col gap-3" style={{ padding: '12px 14px', background: 'var(--color-surface)' }}>
      <label className="flex items-center gap-2 text-sm" style={{ color: 'var(--color-text)', cursor: 'pointer' }}>
        <input
          type="checkbox"
          checked={remember}
          onChange={(e) => {
            const on = e.target.checked
            setRemember(on)
            setRememberState(on)
            setCleared(false)
          }}
        />
        Remember redaction maps on this device
      </label>
      <div className="flex items-center gap-3">
        <button
          className="btn btn-ghost"
          style={{ padding: '4px 12px' }}
          onClick={async () => {
            await clearMaps()
            setCleared(true)
          }}
        >
          Clear stored maps
        </button>
        {cleared && (
          <span className="text-sm" style={{ color: 'var(--color-success)' }}>
            Stored maps cleared from this device.
          </span>
        )}
      </div>
      <p className="text-sm" style={{ color: 'var(--color-muted)', lineHeight: 1.6 }}>
        Maps stay on THIS device only and hold the real values -- never share them or the file alongside the
        redacted copy.
      </p>
    </div>
  )
}
