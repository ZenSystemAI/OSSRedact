import { useEffect, useMemo, useRef, useState } from 'react'
import { getDenylist, setDenylist, type AllowlistState } from '../lib/daemon'
import { normalizeAllowlist, diffAllowlist, normalizationSummary, describeSaveError } from './DictionaryPanel'

/**
 * The "Always redact" dictionary -- the INVERSE of the do-not-redact list. User-declared terms (project
 * codenames, client names, internal hostnames) that are ALWAYS redacted, even when the neural model never
 * flags them. It only ADDS redaction, so it can never weaken the firewall; the worst a stray entry does is
 * over-redact. Reuses the do-not-redact panel's pure list helpers (normalize/diff/summary/error) since the
 * editor mechanics are identical; the daemon side is /api/denylist (a term scanner, not a value filter).
 */
type Load = 'loading' | 'ready' | 'error'

export default function DenylistPanel() {
  const [meta, setMeta] = useState<AllowlistState | null>(null)
  const [baseline, setBaseline] = useState<string[]>([])
  const [draft, setDraft] = useState<string[]>([])
  const [entry, setEntry] = useState('')
  const [load, setLoad] = useState<Load>('loading')
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [saveErr, setSaveErr] = useState<string | null>(null)
  const [hint, setHint] = useState<string | null>(null)
  const entryRef = useRef<HTMLInputElement>(null)

  const fetchState = () => {
    setLoad('loading')
    setLoadErr(null)
    getDenylist()
      .then((s) => {
        setMeta(s)
        setBaseline(s.values)
        setDraft(s.values)
        setLoad('ready')
      })
      .catch((e) => {
        setLoadErr(describeSaveError(e))
        setLoad('error')
      })
  }

  useEffect(fetchState, [])

  const diff = useMemo(() => diffAllowlist(baseline, draft), [baseline, draft])
  const configCount = meta?.config_values ?? 0

  const addEntry = () => {
    const trimmed = entry.trim()
    if (trimmed === '') return
    if (trimmed.length < 2) {
      setHint(`"${trimmed}" is too short -- terms under 2 characters are ignored`)
      return
    }
    if (draft.some((v) => v.toLowerCase() === trimmed.toLowerCase())) {
      setHint(`"${trimmed}" is already in the always-redact list`)
      setEntry('')
      return
    }
    setDraft((d) => [...d, trimmed])
    setEntry('')
    setHint(null)
    entryRef.current?.focus()
  }

  const removeAt = (idx: number) => {
    setDraft((d) => d.filter((_, i) => i !== idx))
    setHint(null)
  }

  const revert = () => {
    setDraft(baseline)
    setEntry('')
    setSaveErr(null)
    setHint(null)
  }

  const save = async () => {
    setSaving(true)
    setSaveErr(null)
    const normalized = normalizeAllowlist(draft)
    try {
      const res = await setDenylist(normalized.values)
      setBaseline(res.values)
      setDraft(res.values)
      setMeta((m) => (m ? { ...m, values: res.values, active_total: res.active_total } : m))
      setHint(normalizationSummary(normalized))
    } catch (e) {
      setSaveErr(describeSaveError(e))
    } finally {
      setSaving(false)
    }
  }

  const heading = (
    <div className="mb-4">
      <h2 className="text-sm font-semibold text-gray-900 dark:text-neutral-100">Always-redact dictionary</h2>
      <p className="mt-1 text-xs leading-relaxed text-gray-500 dark:text-neutral-400">
        Terms listed here are <strong>always redacted</strong>, even when the model does not recognize them --
        internal codenames, client names, hostnames. Case-insensitive, whole-word. It only adds redaction, so
        a stray entry just over-redacts (safe).
      </p>
    </div>
  )

  if (load === 'loading') {
    return <div className="max-w-lg">{heading}<p className="py-10 text-center text-sm text-gray-400 dark:text-neutral-500">Loading the always-redact list…</p></div>
  }

  if (load === 'error') {
    return (
      <div className="max-w-lg">
        {heading}
        <div className="rounded-lg border border-red-200 dark:border-red-400/20 bg-red-50 dark:bg-red-400/10 p-3">
          <p className="text-sm text-red-700 dark:text-red-400">{loadErr ?? 'Could not load the always-redact list.'}</p>
          <button type="button" onClick={fetchState} className="mt-2 rounded-md border border-red-300 dark:border-red-400/20 px-2.5 py-1 text-xs font-medium text-red-700 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-400/15 focus:outline-none focus:ring-2 focus:ring-teal-500">
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-lg">
      {heading}

      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500 dark:text-neutral-400">
        <span><span className="font-mono text-gray-900 dark:text-neutral-100">{meta?.active_total ?? draft.length}</span> active</span>
        <span><span className="font-mono text-gray-900 dark:text-neutral-100">{draft.length}</span> editable</span>
        {configCount > 0 && (
          <span title="Contributed by gateway-config; read-only here.">
            <span className="font-mono text-gray-900 dark:text-neutral-100">{configCount}</span> from config (read-only)
          </span>
        )}
      </div>

      <div className="flex gap-2">
        <input
          ref={entryRef}
          value={entry}
          onChange={(e) => setEntry(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addEntry() } }}
          spellCheck={false}
          aria-label="Add a term to always redact"
          placeholder="e.g. Project Bluebird, Acme Robotics, prod-db-07"
          className="min-w-0 flex-1 rounded-lg border border-gray-300 dark:border-white/10 px-3 py-2 font-mono text-sm text-gray-900 dark:text-neutral-100 placeholder:text-gray-400 dark:placeholder:text-neutral-500 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500"
        />
        <button type="button" onClick={addEntry} disabled={entry.trim() === ''} className="flex-none rounded-lg bg-teal-600 px-3.5 py-2 text-sm font-medium text-white hover:bg-teal-700 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:ring-offset-1 disabled:opacity-40">
          Add
        </button>
      </div>

      {hint && <p className="mt-1.5 text-xs text-gray-400 dark:text-neutral-500" role="status">{hint}</p>}

      {draft.length === 0 ? (
        <p className="mt-3 rounded-lg border border-dashed border-gray-200 dark:border-white/10 py-8 text-center text-sm text-gray-400 dark:text-neutral-500">
          No always-redact terms yet. Add a codename or client name above to redact it everywhere it appears.
        </p>
      ) : (
        <ul className="mt-3 space-y-1.5" aria-label="Always-redact entries">
          {draft.map((value, idx) => (
            <li key={`${value}-${idx}`} className="flex items-center gap-2 rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-[#191919] py-1.5 pl-3 pr-1.5">
              <span className="min-w-0 flex-1 truncate font-mono text-sm text-gray-900 dark:text-neutral-100" title={value}>{value}</span>
              <button type="button" onClick={() => removeAt(idx)} aria-label={`Remove ${value} from the always-redact list`} className="flex-none rounded-md p-1.5 text-gray-400 dark:text-neutral-500 hover:bg-gray-100 dark:hover:bg-white/10 hover:text-gray-700 dark:hover:text-neutral-100 focus:outline-none focus:ring-2 focus:ring-teal-500">
                <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12" /></svg>
              </button>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-4 flex items-center justify-between border-t border-gray-100 dark:border-white/10 pt-3">
        <span className="text-xs text-gray-400 dark:text-neutral-500" aria-live="polite">
          {diff.dirty ? (
            <span className="inline-flex items-center gap-1.5 text-amber-600 dark:text-amber-300">
              <span className="inline-block h-2 w-2 rounded-full bg-amber-500" />
              Unsaved changes
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5"><span className="inline-block h-2 w-2 rounded-full bg-teal-500" />Saved</span>
          )}
        </span>
        <div className="flex gap-2">
          <button type="button" onClick={revert} disabled={!diff.dirty || saving} className="rounded-lg border border-gray-300 dark:border-white/10 px-3 py-2 text-sm font-medium text-gray-600 dark:text-neutral-300 hover:bg-gray-50 dark:hover:bg-white/5 focus:outline-none focus:ring-2 focus:ring-teal-500 disabled:opacity-40">
            Revert
          </button>
          <button type="button" onClick={save} disabled={!diff.dirty || saving} className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:ring-offset-1 disabled:opacity-40">
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>

      {saveErr && <p className="mt-2 text-xs text-red-600 dark:text-red-400" role="alert">{saveErr}</p>}
    </div>
  )
}
