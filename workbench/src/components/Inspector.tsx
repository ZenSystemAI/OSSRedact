import type * as React from 'react'
import type { Span } from '../lib/types'
import { labelMeta, labelTier, MANUAL_LABELS, type Tier } from '../lib/labels'
import { labelActivity } from '../lib/redaction'

type Props = {
  span: Span | null
  text: string
  placeholder?: string
  spans: Span[]
  onToggle: (id: string) => void
  onRelabel: (id: string, label: string) => void
  onDelete: (id: string) => void
  onSetLabel: (label: string, active: boolean) => void
  onSetTier: (tier: Tier, active: boolean) => void
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1 text-sm">
      <span style={{ color: 'var(--color-light)' }}>{k}</span>
      <span className="mono text-right" style={{ color: 'var(--color-text)' }}>
        {v}
      </span>
    </div>
  )
}

export default function Inspector({ span, text, placeholder, spans, onToggle, onRelabel, onDelete, onSetLabel, onSetTier }: Props) {
  if (!span) {
    // Per-label REDACTION FILTER (fine-grained control): every detected category is a toggle. Unchecking a
    // category leaves it detected but visible (not masked); checking redacts all of its spans. Grouped by tier
    // so the catastrophic set (irreversible-harm PII) reads as the redact-by-default block.
    const activity = labelActivity(spans)
    const TIERS: { tier: Tier; title: string; hint: string }[] = [
      { tier: 'catastrophic', title: 'Catastrophic', hint: 'irreversible-harm PII' },
      { tier: 'operational', title: 'Operational', hint: 'lower-harm, optional' },
    ]
    return (
      <div style={{ padding: 18 }}>
        <div className="eyebrow mb-1">Redaction filter</div>
        {activity.length === 0 ? (
          <p className="text-sm" style={{ color: 'var(--color-muted)', marginTop: 10 }}>
            No detections yet. Run <b style={{ color: 'var(--color-teal)' }}>Auto-detect</b> or{' '}
            <b style={{ color: 'var(--color-teal)' }}>Deep detect</b>, or select any text in the document to redact it manually.
          </p>
        ) : (
          <>
            <p className="text-xs mb-3" style={{ color: 'var(--color-light)', lineHeight: 1.6 }}>
              Choose which categories to redact. Unchecked categories are still detected but left visible.
            </p>
            {TIERS.map(({ tier, title, hint }) => {
              const rows = activity.filter((a) => labelTier(a.label) === tier)
              if (!rows.length) return null
              const anyOff = rows.some((r) => r.active < r.total)
              return (
                <div key={tier} className="mb-4">
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="eyebrow" style={{ fontSize: 10, color: tier === 'catastrophic' ? 'var(--color-warning)' : 'var(--color-light)' }}>
                      {title}
                    </span>
                    <span className="text-xs" style={{ color: 'var(--color-muted)' }}>{hint}</span>
                    <button
                      className="btn btn-ghost ml-auto"
                      style={{ padding: '2px 9px', fontSize: 11 }}
                      onClick={() => onSetTier(tier, anyOff)}
                      title={anyOff ? `Redact every ${title.toLowerCase()} category` : `Stop redacting every ${title.toLowerCase()} category`}
                    >
                      {anyOff ? 'Redact all' : 'None'}
                    </button>
                  </div>
                  <div className="flex flex-col gap-0.5">
                    {rows.map(({ label, total, active }) => {
                      const m = labelMeta(label)
                      const on = active === total // fully redacted
                      const partial = active > 0 && active < total
                      return (
                        <button
                          key={label}
                          aria-pressed={on}
                          onClick={() => onSetLabel(label, active < total)} // any off -> redact all; all on -> pass all
                          className="flex items-center gap-2.5 text-sm"
                          title={partial ? `${active} of ${total} redacted (some toggled individually). Click to redact all.` : on ? 'Redacting all. Click to pass through.' : 'Passing through. Click to redact all.'}
                          style={{ background: 'transparent', border: 'none', padding: '3px 2px', cursor: 'pointer', textAlign: 'left', width: '100%' }}
                        >
                          <span
                            aria-hidden
                            style={{
                              width: 14, height: 14, borderRadius: 4, border: `1.5px solid ${m.color}`,
                              background: on ? m.color : partial ? `${m.color}55` : 'transparent',
                              flex: '0 0 auto', display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                            }}
                          >
                            {on && (
                              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#0b0b0b" strokeWidth="3.5">
                                <path d="M20 6L9 17l-5-5" />
                              </svg>
                            )}
                          </span>
                          <span style={{ color: on || partial ? 'var(--color-text)' : 'var(--color-muted)' }}>{m.en}</span>
                          <span className="mono ml-auto" style={{ color: 'var(--color-muted)' }}>{partial ? `${active}/${total}` : total}</span>
                        </button>
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </>
        )}
        <div className="mt-2 pt-4 text-xs" style={{ borderTop: '1px solid var(--border)', color: 'var(--color-light)', lineHeight: 1.7 }}>
          Click a highlight in the document to inspect one detection. Select text to add a redaction.
        </div>
      </div>
    )
  }

  const meta = labelMeta(span.label)
  const value = text.slice(span.start, span.end)
  return (
    <div style={{ padding: 18 }}>
      <div className="flex items-center gap-2.5 mb-1">
        <span style={{ width: 12, height: 12, borderRadius: 3, background: meta.color }} />
        <select
          value={span.label}
          onChange={(e) => onRelabel(span.id, e.target.value)}
          className="mono"
          style={{
            background: 'var(--color-black)',
            color: 'var(--color-text)',
            border: '1px solid var(--border-mid)',
            borderRadius: 7,
            padding: '4px 8px',
            fontSize: 13,
          }}
        >
          {[...new Set([span.label, ...MANUAL_LABELS])].map((l) => (
            <option key={l} value={l}>
              {labelMeta(l).en}
            </option>
          ))}
        </select>
      </div>
      {placeholder && (
        <div className="mono mb-3" style={{ color: 'var(--color-teal)', fontSize: 12 }}>
          {placeholder}
        </div>
      )}

      <div className="panel" style={{ padding: 12, background: 'var(--color-black)', marginBottom: 14 }}>
        <div className="eyebrow mb-1.5" style={{ fontSize: 10 }}>
          Original value (local only)
        </div>
        <div className="mono" style={{ fontSize: 13, color: '#fff', wordBreak: 'break-word', whiteSpace: 'pre-wrap' }}>
          {value}
        </div>
      </div>

      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 8 }}>
        <Row k="source" v={span.source} />
        <Row k="rule" v={span.rule} />
        <Row k="tier" v={`T${span.tier}`} />
        <Row
          k="confidence"
          v={
            <span className="inline-flex items-center gap-2">
              <span style={{ display: 'inline-block', width: 60, height: 5, borderRadius: 3, background: 'var(--border-mid)' }}>
                <span style={{ display: 'block', width: `${Math.round(span.conf * 100)}%`, height: '100%', borderRadius: 3, background: meta.color }} />
              </span>
              {span.conf.toFixed(2)}
            </span>
          }
        />
        {span.validator && <Row k="validator" v={<span style={{ color: span.validator === 'luhn_ok' ? 'var(--color-success)' : 'var(--color-warning)' }}>{span.validator}</span>} />}
        {span.cue && <Row k="cue" v={`“${span.cue}”`} />}
        {span.subtype && <Row k="subtype" v={span.subtype} />}
        {span.members && span.members > 1 && <Row k="merged" v={`${span.members} spans`} />}
      </div>

      <div className="flex items-center gap-2 mt-4">
        <button className={span.active ? 'btn btn-ghost' : 'btn btn-primary'} style={{ flex: 1 }} onClick={() => onToggle(span.id)}>
          {span.active ? 'Unredact (keep visible)' : 'Redact this'}
        </button>
        <button
          className="btn btn-ghost"
          onClick={() => onDelete(span.id)}
          title="Remove this detection entirely"
          style={{ padding: '9px 12px' }}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m2 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
          </svg>
        </button>
      </div>
    </div>
  )
}
