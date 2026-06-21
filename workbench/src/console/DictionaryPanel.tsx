import { useEffect, useMemo, useRef, useState } from 'react'
import { getAllowlist, setAllowlist, DaemonError, type AllowlistState } from '../lib/daemon'

// =============================================================================
// Pure helpers (unit-tested in DictionaryPanel.test.tsx)
// =============================================================================

export interface NormalizeResult {
  /** The cleaned, deduped values to persist (first occurrence wins, original casing kept). */
  values: string[]
  /** Count of raw entries dropped because they were blank after trimming. */
  dropped: number
  /** Count of raw entries removed as case-insensitive duplicates of an earlier value. */
  deduped: number
}

/**
 * Clean an allowlist before saving: trim each entry, drop blanks, and remove
 * case-insensitive duplicates keeping the FIRST occurrence (and its original
 * casing). Returns the cleaned list plus how many were dropped/deduped so the
 * UI can tell the user what normalization happened.
 */
export function normalizeAllowlist(raw: string[]): NormalizeResult {
  const values: string[] = []
  const seen = new Set<string>()
  let dropped = 0
  let deduped = 0
  for (const entry of raw) {
    const trimmed = entry.trim()
    if (trimmed === '') {
      dropped++
      continue
    }
    const key = trimmed.toLowerCase()
    if (seen.has(key)) {
      deduped++
      continue
    }
    seen.add(key)
    values.push(trimmed)
  }
  return { values, dropped, deduped }
}

// Shannon entropy in bits-per-character. High entropy is the fingerprint of a
// random token (key/secret) versus a human-readable project noun.
function shannonEntropy(s: string): number {
  if (s.length === 0) return 0
  const counts = new Map<string, number>()
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let bits = 0
  for (const c of counts.values()) {
    const p = c / s.length
    bits -= p * Math.log2(p)
  }
  return bits
}

const SECRET_PREFIXES = [
  'sk-', 'sk_', 'pk-', 'pk_', 'rk_', 'ghp_', 'gho_', 'github_pat_', 'xoxb-', 'xoxp-',
  'aws_', 'akia', 'asia', 'ya29.', 'eyj', 'glpat-', 'shpat_', 'shpss_', 'whsec_', 'bearer ',
]

const IBAN_RE = /^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/

/**
 * Heuristic: does this value LOOK like a secret/credential? Used ONLY to warn
 * the user that the daemon will redact it server-side no matter what -- never to
 * silently filter the value. False positives are acceptable (a warning, not a block);
 * we err toward warning. Matches: known key prefixes (sk-..., AKIA..., ghp_..., JWTs),
 * IBAN shapes, 13-19 digit card-ish runs, and long high-entropy tokens.
 */
export function looksLikeSecret(value: string): boolean {
  const v = value.trim()
  if (v === '') return false
  const lower = v.toLowerCase()

  // Known credential prefixes (case-insensitive on the prefix).
  if (SECRET_PREFIXES.some((p) => lower.startsWith(p))) return true

  // IBAN-ish: 2 letters + 2 check digits + 10-30 alphanumerics.
  const compact = v.replace(/[\s-]/g, '')
  if (IBAN_RE.test(compact.toUpperCase())) return true

  // Card-ish: 13-19 digits, possibly grouped by spaces or dashes.
  const digitsOnly = v.replace(/[\s-]/g, '')
  if (/^\d{13,19}$/.test(digitsOnly)) return true

  // Long high-entropy token: alphanumeric (with -, _, .) runs that are long and
  // random-looking. Human project nouns are short and/or low-entropy.
  if (v.length >= 20 && /^[A-Za-z0-9_\-.+/=]+$/.test(v) && !v.includes(' ')) {
    const hasDigit = /\d/.test(v)
    const hasLetter = /[A-Za-z]/.test(v)
    if (hasDigit && hasLetter && shannonEntropy(v) >= 3.5) return true
  }

  return false
}

export interface AllowlistDiff {
  added: string[]
  removed: string[]
  dirty: boolean
}

/**
 * Compare the saved baseline against the current draft (case-insensitive on
 * membership, order-insensitive). Drives the dirty-state indicator and Save/Revert.
 */
export function diffAllowlist(baseline: string[], draft: string[]): AllowlistDiff {
  const norm = (arr: string[]) => new Set(normalizeAllowlist(arr).values.map((v) => v.toLowerCase()))
  const base = norm(baseline)
  const next = norm(draft)
  const added = [...next].filter((k) => !base.has(k))
  const removed = [...base].filter((k) => !next.has(k))
  return { added, removed, dirty: added.length > 0 || removed.length > 0 }
}

/** Human-readable summary of what normalization changed, or null if nothing changed. */
export function normalizationSummary(r: NormalizeResult): string | null {
  const parts: string[] = []
  if (r.deduped > 0) parts.push(`${r.deduped} duplicate${r.deduped === 1 ? '' : 's'} removed`)
  if (r.dropped > 0) parts.push(`${r.dropped} blank${r.dropped === 1 ? '' : 's'} dropped`)
  return parts.length ? parts.join(' · ') : null
}

/** Map a thrown daemon error to a user-facing message. */
export function describeSaveError(e: unknown): string {
  if (e instanceof DaemonError) {
    if (e.status === 403) return 'Save refused: the dictionary is editable only from the local machine (403).'
    if (e.status === 500) return 'Save failed: the daemon could not write the dictionary file (500).'
    if (e.status === 404) return 'Save failed: the daemon did not recognize the dictionary endpoint (404).'
    if (typeof e.status === 'number') return `Save failed (${e.status}).`
  }
  return `Save failed: ${(e as Error)?.message ?? String(e)}`
}

// =============================================================================
// Component
// =============================================================================

type Load = 'loading' | 'ready' | 'error'

export default function DictionaryPanel() {
  const [meta, setMeta] = useState<AllowlistState | null>(null)
  const [baseline, setBaseline] = useState<string[]>([]) // last-saved file values
  const [draft, setDraft] = useState<string[]>([]) // editable working set
  const [entry, setEntry] = useState('') // the add-input
  const [load, setLoad] = useState<Load>('loading')
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [saveErr, setSaveErr] = useState<string | null>(null)
  const [lastNormalization, setLastNormalization] = useState<string | null>(null)
  const entryRef = useRef<HTMLInputElement>(null)

  const fetchState = () => {
    setLoad('loading')
    setLoadErr(null)
    getAllowlist()
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

  // config_values are read-only entries contributed by gateway-config; the file
  // set is what we edit. active_total = config + file (minus overlap, daemon-computed).
  const configCount = meta?.config_values ?? 0

  const addEntry = () => {
    const raw = entry
    const trimmed = raw.trim()
    if (trimmed === '') return
    const dupe = draft.some((v) => v.toLowerCase() === trimmed.toLowerCase())
    if (dupe) {
      setLastNormalization(`"${trimmed}" is already in the dictionary`)
      setEntry('')
      return
    }
    setDraft((d) => [...d, trimmed])
    setEntry('')
    setLastNormalization(null)
    entryRef.current?.focus()
  }

  const removeAt = (idx: number) => {
    setDraft((d) => d.filter((_, i) => i !== idx))
    setLastNormalization(null)
  }

  const revert = () => {
    setDraft(baseline)
    setEntry('')
    setSaveErr(null)
    setLastNormalization(null)
  }

  const save = async () => {
    setSaving(true)
    setSaveErr(null)
    const normalized = normalizeAllowlist(draft)
    try {
      const res = await setAllowlist(normalized.values)
      setBaseline(res.values)
      setDraft(res.values)
      setMeta((m) => (m ? { ...m, values: res.values, active_total: res.active_total } : m))
      setLastNormalization(normalizationSummary(normalized))
    } catch (e) {
      setSaveErr(describeSaveError(e))
    } finally {
      setSaving(false)
    }
  }

  // --- header (title + intro) shared across states ---
  const heading = (
    <div className="mb-4">
      <h2 className="text-sm font-semibold text-gray-900 dark:text-neutral-100">Do-not-redact dictionary</h2>
      <p className="mt-1 text-xs leading-relaxed text-gray-500 dark:text-neutral-400">
        Values listed here pass through to the model verbatim -- project nouns, public brand and framework
        names you want a coding agent to see. Matching is case-insensitive.
      </p>
    </div>
  )

  // --- the non-dismissable secrets warning (always visible) ---
  const secretsNotice = (
    <div
      role="note"
      aria-label="Secrets are never exempt"
      className="mb-4 flex gap-2.5 rounded-lg border border-amber-300 dark:border-amber-400/20 bg-amber-50 dark:bg-amber-400/10 p-3"
    >
      <svg
        className="mt-0.5 h-4 w-4 flex-none text-amber-600 dark:text-amber-300"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        aria-hidden="true"
      >
        <path d="M12 9v4M12 17h.01M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.42 0z" />
      </svg>
      <p className="text-xs leading-relaxed text-amber-800 dark:text-amber-300">
        <span className="font-semibold">Secrets are never exempt.</span>{' '}
        API keys, passwords, payment cards, IBANs, and government IDs are always redacted, even if you list
        them here. The daemon enforces this server-side -- the dictionary cannot whitelist a credential.
      </p>
    </div>
  )

  if (load === 'loading') {
    return (
      <div className="max-w-lg">
        {heading}
        {secretsNotice}
        <p className="py-10 text-center text-sm text-gray-400 dark:text-neutral-500">Loading the dictionary…</p>
      </div>
    )
  }

  if (load === 'error') {
    return (
      <div className="max-w-lg">
        {heading}
        {secretsNotice}
        <div className="rounded-lg border border-red-200 dark:border-red-400/20 bg-red-50 dark:bg-red-400/10 p-3">
          <p className="text-sm text-red-700 dark:text-red-400">{loadErr ?? 'Could not load the dictionary.'}</p>
          <button type="button"
            onClick={fetchState}
            className="mt-2 rounded-md border border-red-300 dark:border-red-400/20 px-2.5 py-1 text-xs font-medium text-red-700 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-400/15 focus:outline-none focus:ring-2 focus:ring-teal-500"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-lg">
      {heading}
      {secretsNotice}

      {/* counts: editable file set vs read-only config contributions */}
      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500 dark:text-neutral-400">
        <span>
          <span className="font-mono text-gray-900 dark:text-neutral-100">{meta?.active_total ?? draft.length}</span> active
        </span>
        <span>
          <span className="font-mono text-gray-900 dark:text-neutral-100">{draft.length}</span> editable
        </span>
        {configCount > 0 && (
          <span title="Contributed by gateway-config; read-only here.">
            <span className="font-mono text-gray-900 dark:text-neutral-100">{configCount}</span> from config (read-only)
          </span>
        )}
      </div>

      {/* add field */}
      <div className="flex gap-2">
        <input
          ref={entryRef}
          value={entry}
          onChange={(e) => setEntry(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              addEntry()
            }
          }}
          spellCheck={false}
          aria-label="Add a value to the dictionary"
          placeholder="e.g. ProjectFalcon, PostgreSQL, Acme Corp"
          className="min-w-0 flex-1 rounded-lg border border-gray-300 dark:border-white/10 px-3 py-2 font-mono text-sm text-gray-900 dark:text-neutral-100 placeholder:text-gray-400 dark:placeholder:text-neutral-500 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500"
        />
        <button type="button"
          onClick={addEntry}
          disabled={entry.trim() === ''}
          className="flex-none rounded-lg bg-teal-600 px-3.5 py-2 text-sm font-medium text-white hover:bg-teal-700 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:ring-offset-1 disabled:opacity-40"
        >
          Add
        </button>
      </div>

      {/* per-add hint: dedupe / "already present" feedback */}
      {lastNormalization && (
        <p className="mt-1.5 text-xs text-gray-400 dark:text-neutral-500" role="status">
          {lastNormalization}
        </p>
      )}

      {/* the entries list */}
      {draft.length === 0 ? (
        <p className="mt-3 rounded-lg border border-dashed border-gray-200 dark:border-white/10 py-8 text-center text-sm text-gray-400 dark:text-neutral-500">
          The editable dictionary is empty. Add a value above to let it pass through to the model.
        </p>
      ) : (
        <ul className="mt-3 space-y-1.5" aria-label="Dictionary entries">
          {draft.map((value, idx) => {
            const secret = looksLikeSecret(value)
            return (
              <li
                key={`${value}-${idx}`}
                className="flex items-center gap-2 rounded-lg border border-gray-200 dark:border-white/10 bg-white dark:bg-[#191919] py-1.5 pl-3 pr-1.5"
              >
                <span className="min-w-0 flex-1 truncate font-mono text-sm text-gray-900 dark:text-neutral-100" title={value}>
                  {value}
                </span>
                {secret && (
                  <span
                    className="flex-none rounded bg-amber-100 dark:bg-amber-400/15 px-1.5 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-300"
                    title="This looks like a secret. The daemon will redact it anyway -- it cannot be allowlisted."
                  >
                    looks like a secret · still redacted
                  </span>
                )}
                <button type="button"
                  onClick={() => removeAt(idx)}
                  aria-label={`Remove ${value} from the dictionary`}
                  className="flex-none rounded-md p-1.5 text-gray-400 dark:text-neutral-500 hover:bg-gray-100 dark:hover:bg-white/10 hover:text-gray-700 dark:hover:text-neutral-100 focus:outline-none focus:ring-2 focus:ring-teal-500"
                >
                  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                    <path d="M18 6 6 18M6 6l12 12" />
                  </svg>
                </button>
              </li>
            )
          })}
        </ul>
      )}

      {/* dirty-state + actions */}
      <div className="mt-4 flex items-center justify-between border-t border-gray-100 dark:border-white/10 pt-3">
        <span className="text-xs text-gray-400 dark:text-neutral-500" aria-live="polite">
          {diff.dirty ? (
            <span className="inline-flex items-center gap-1.5 text-amber-600 dark:text-amber-300">
              <span className="inline-block h-2 w-2 rounded-full bg-amber-500" />
              Unsaved changes
              <span className="text-gray-400 dark:text-neutral-500">
                · {diff.added.length > 0 && `+${diff.added.length}`}
                {diff.added.length > 0 && diff.removed.length > 0 && ' '}
                {diff.removed.length > 0 && `−${diff.removed.length}`}
              </span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full bg-teal-500" />
              Saved
            </span>
          )}
        </span>
        <div className="flex gap-2">
          <button type="button"
            onClick={revert}
            disabled={!diff.dirty || saving}
            className="rounded-lg border border-gray-300 dark:border-white/10 px-3 py-2 text-sm font-medium text-gray-600 dark:text-neutral-300 hover:bg-gray-50 dark:hover:bg-white/5 focus:outline-none focus:ring-2 focus:ring-teal-500 disabled:opacity-40"
          >
            Revert
          </button>
          <button type="button"
            onClick={save}
            disabled={!diff.dirty || saving}
            className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-700 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:ring-offset-1 disabled:opacity-40"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>

      {saveErr && (
        <p className="mt-2 text-xs text-red-600 dark:text-red-400" role="alert">
          {saveErr}
        </p>
      )}
    </div>
  )
}
