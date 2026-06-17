export default function Header() {
  return (
    <header className="flex items-center justify-between px-5 py-3 border-b" style={{ borderColor: 'var(--border)' }}>
      <div className="flex items-center gap-2.5">
        <span
          className="grid place-items-center"
          style={{
            width: 28,
            height: 28,
            borderRadius: 7,
            background: 'linear-gradient(135deg,var(--color-teal),var(--color-teal-dim))',
            boxShadow: '0 0 20px rgba(78,205,184,.4)',
          }}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="#04201b" aria-hidden="true">
            <path d="M13 2 3 14h7l-1 8 11-12h-7z" />
          </svg>
        </span>
        <div className="leading-none">
          <div style={{ fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: 17, color: '#fff', letterSpacing: '-.02em' }}>
            ossredact Workbench
          </div>
        </div>
      </div>
      <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--color-muted)' }}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
          <rect x="3" y="11" width="18" height="11" rx="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
        <span>
          100% local <span style={{ color: 'var(--color-light)' }}>·</span> the document never leaves this machine
        </span>
      </div>
    </header>
  )
}
