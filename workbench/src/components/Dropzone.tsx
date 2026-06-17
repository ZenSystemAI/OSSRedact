import { useRef, useState } from 'react'
import { loadFile, type LoadedDoc } from '../lib/formats'
import { extOf, typeBucket, sameTypeError } from '../lib/batch'
import Rehydrate from './Rehydrate'
import { getRemember, setRemember, clearMaps } from '../lib/mapStore'

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

  // Load one or many files. A single file routes to the unchanged single-doc path; >1 SAME-TYPE files
  // route to the batch path. Same-type is enforced here (export/verify are format-specific): the FIRST
  // file sets the batch's type bucket; any mismatch is rejected with a message stating WHY, and the
  // matching files still load.
  async function handleFiles(files: File[]) {
    setErr('')
    if (!files.length) return
    if (files.length === 1) {
      try {
        onLoad(await loadFile(files[0]))
      } catch (e) {
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
    const docs: LoadedDoc[] = []
    for (const f of accepted) {
      try {
        docs.push(await loadFile(f))
      } catch (e) {
        rejected.push(`${f.name} (${e instanceof Error ? e.message : String(e)})`)
      }
    }
    if (rejected.length) {
      const sample = sameTypeError(bucket, extOf(files.find((f) => sameTypeError(bucket, extOf(f.name)))?.name ?? '')) ?? ''
      setErr(`${rejected.length} file(s) skipped (different type or unreadable). ${sample}`.trim())
    }
    if (docs.length === 1) onLoad(docs[0])
    else if (docs.length > 1) onLoadBatch(docs)
  }

  return (
    <div className="flex flex-col items-center justify-center h-full gap-6 px-6">
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
        onDragOver={(e) => {
          e.preventDefault()
          setDrag(true)
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDrag(false)
          const fs = Array.from(e.dataTransfer.files ?? [])
          if (fs.length) handleFiles(fs)
        }}
        onClick={() => inputRef.current?.click()}
        className="panel w-full max-w-2xl flex flex-col items-center justify-center gap-3 cursor-pointer transition-colors"
        style={{
          padding: '48px 24px',
          borderStyle: 'dashed',
          borderColor: drag ? 'var(--color-teal)' : 'var(--border-mid)',
          background: drag ? 'rgba(78,205,184,.06)' : 'var(--color-surface)',
        }}
      >
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal)" strokeWidth="1.6" aria-hidden="true">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <path d="M14 2v6h6M12 18v-6M9 15l3-3 3 3" />
        </svg>
        <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 18, color: '#fff' }}>
          Drop a document, or click to choose
        </div>
        <div className="text-sm" style={{ color: 'var(--color-muted)' }}>
          .pdf · .docx · .xlsx · .txt · .md · .csv · .json
        </div>
        <div className="text-xs" style={{ color: 'var(--color-muted)' }}>
          Drop several same-type files to process them as a batch.
        </div>
        <input
          ref={inputRef}
          type="file"
          multiple
          accept=".pdf,.docx,.xlsx,.txt,.md,.markdown,.csv,.tsv,.log,.json,.jsonl,.xml,.html,.htm,.yaml,.yml"
          className="hidden"
          onChange={(e) => {
            const fs = Array.from(e.target.files ?? [])
            if (fs.length) handleFiles(fs)
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
