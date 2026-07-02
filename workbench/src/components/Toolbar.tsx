import { useEffect, useRef, useState } from 'react'
import type { GateHealth } from '../lib/gate'

type Props = {
  docName: string
  activeCount: number
  totalCount: number
  regionCount: number
  hasRedactions: boolean
  isPdf: boolean
  hasLayout: boolean
  view: 'text' | 'layout' | 'pages'
  onView: (v: 'text' | 'layout' | 'pages') => void
  busy: boolean
  gate: GateHealth | null
  loadPct: number | null
  onAutoDetect: () => void
  onDeepDetect: () => void
  onClearDetections: () => void
  onCopyRedacted: () => void
  onDownloadRedacted: () => void
  onDownloadMap: () => void
  onDownloadAudit: () => void
  onPrint: () => void
  onReset: () => void
}

export default function Toolbar(p: Props) {
  const [menu, setMenu] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenu(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])

  return (
    <div className="flex items-center gap-2 flex-wrap px-4 py-2.5 border-b" style={{ borderColor: 'var(--border)' }}>
      <button className="btn btn-primary" onClick={p.onAutoDetect} disabled={p.busy}>
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
          <circle cx="11" cy="11" r="7" />
          <path d="m21 21-4.3-4.3" />
        </svg>
        Auto-detect
      </button>

      <button className="btn btn-ghost" onClick={p.onDeepDetect} disabled={p.busy} title="Run deep detect with the local gate when available, otherwise the browser model">
        <span
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: p.gate?.ok ? 'var(--color-success)' : 'var(--color-light)',
            boxShadow: p.gate?.ok ? '0 0 8px var(--color-success)' : 'none',
          }}
        />
        {p.loadPct != null
          ? p.loadPct > 0
            ? `Loading model ${p.loadPct}%`
            : 'Loading model…'
          : p.busy
            ? 'Detecting…'
            : 'Deep detect'}
      </button>

      <button className="btn btn-ghost" onClick={p.onClearDetections} disabled={p.busy || p.totalCount === 0}>
        Clear
      </button>

      {(p.isPdf || p.hasLayout) && (
        <div className="flex rounded-lg ml-1" style={{ border: '1px solid var(--border)', overflow: 'hidden' }}>
          {([
            ['text', 'Text'],
            ...(p.hasLayout ? [['layout', 'Layout'] as const] : []),
            ...(p.isPdf ? [['pages', 'Pages'] as const] : []),
          ] as const).map(([v, label]) => (
            <button
              key={v}
              onClick={() => p.onView(v)}
              className="text-xs"
              title={v === 'layout' ? 'Preserve the page/table layout (columns + rows aligned)' : undefined}
              style={{
                padding: '5px 11px',
                background: p.view === v ? 'var(--color-teal)' : 'transparent',
                color: p.view === v ? '#06231f' : 'var(--color-light)',
                fontWeight: p.view === v ? 600 : 400,
              }}
            >
              {label}
            </button>
          ))}
        </div>
      )}

      <div className="text-xs mono ml-1" style={{ color: 'var(--color-muted)' }}>
        {p.activeCount} redacted{p.totalCount > p.activeCount ? ` · ${p.totalCount - p.activeCount} kept` : ''}
        {p.regionCount > 0 ? ` · ${p.regionCount} box${p.regionCount > 1 ? 'es' : ''}` : ''}
      </div>

      <div className="ml-auto flex items-center gap-2">
        <div className="relative" ref={menuRef}>
          <button className="btn btn-ghost" onClick={() => setMenu((m) => !m)} disabled={!p.hasRedactions}>
            Export
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" aria-hidden="true">
              <path d="m6 9 6 6 6-6" />
            </svg>
          </button>
          {menu && (
            <div
              className="panel absolute right-0 mt-1 z-20"
              style={{ minWidth: 240, padding: 6, background: 'var(--color-card)', boxShadow: '0 12px 40px rgba(0,0,0,.5)' }}
            >
              <MenuItem label="Copy redacted text" hint="placeholders" onClick={() => { p.onCopyRedacted(); setMenu(false) }} />
              <MenuItem label="Download redacted file" hint=".txt / .md / .csv" onClick={() => { p.onDownloadRedacted(); setMenu(false) }} />
              <MenuItem label="Download entity map" hint=".json · sensitive · local" warn onClick={() => { p.onDownloadMap(); setMenu(false) }} />
              <MenuItem label="Download audit trail" hint=".json · no values" onClick={() => { p.onDownloadAudit(); setMenu(false) }} />
            </div>
          )}
        </div>

        <button
          className="btn btn-ghost"
          onClick={p.onPrint}
          disabled={!p.hasRedactions}
          title={p.isPdf ? 'Export the redacted document as a PDF' : 'Open the print dialog for the redacted view (Print or Save as PDF)'}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v8H6z" />
          </svg>
          {p.isPdf ? 'Redacted PDF' : 'Print'}
        </button>

        <button className="btn btn-ghost" onClick={p.onReset} title="Close this document">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <path d="M18 6 6 18M6 6l12 12" />
          </svg>
        </button>
      </div>
    </div>
  )
}

function MenuItem({ label, hint, warn, onClick }: { label: string; hint: string; warn?: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left flex items-center justify-between gap-3 rounded-lg"
      style={{ padding: '8px 10px', fontSize: 13.5, color: 'var(--color-text)', background: 'transparent' }}
      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--glass)')}
      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
    >
      <span>{label}</span>
      <span className="mono" style={{ fontSize: 10.5, color: warn ? 'var(--color-warning)' : 'var(--color-light)' }}>
        {hint}
      </span>
    </button>
  )
}
