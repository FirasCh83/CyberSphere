import { useState } from 'react'

const DOT = {
  running: 'var(--gold)',
  done: 'var(--ok)',
  error: 'var(--crit)',
}

const navItems = [
  { icon: '＋', label: 'New session', kbd: 'Ctrl N', view: 'chat' },
  { icon: '⚙', label: 'Toolchain' },
  { icon: '◈', label: 'Knowledge base' },
  { icon: '▤', label: 'Reports', view: 'report' },
]

export default function Sidebar({ sessions, activeSession, setActiveSession, view, setView }) {
  const [query, setQuery] = useState('')

  const visible = sessions.filter(s =>
    s.name.toLowerCase().includes(query.trim().toLowerCase())
  )

  return (
    <aside className="sidebar">
      <div className="sb-tabs">
        <button className="sb-tab on">SESSIONS</button>
        <button className="sb-tab">AGENTS</button>
      </div>

      <div className="sb-nav">
        {navItems.map(item => (
          <button
            className={`sb-item${item.view && view === item.view ? ' on' : ''}`}
            key={item.label}
            onClick={() => item.view && setView?.(item.view)}
          >
            <span className="ic">{item.icon}</span>
            {item.label}
            {item.kbd && <span className="kbd">{item.kbd}</span>}
          </button>
        ))}
      </div>

      <div className="sb-search">
        <span>⌕</span>
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search sessions…"
        />
      </div>

      <div className="sb-group">SESSIONS</div>
      <div className="sb-sessions">
        {visible.length === 0 && (
          <div className="sb-empty">
            {sessions.length === 0 ? 'No sessions yet' : 'No matches'}
          </div>
        )}
        {visible.map(s => (
          <button
            key={s.id}
            className={`sess${activeSession?.id === s.id ? ' on' : ''}`}
            onClick={() => setActiveSession(s)}
          >
            <span className="dot" style={{ background: DOT[s.status] || 'var(--dim)' }} />
            <span className="nm">{s.name}</span>
            <span className="ago">{s.time}</span>
          </button>
        ))}
      </div>

      <div className="sb-foot">
        <div className="badge">CS</div>
        <div className="st">
          backend ready
          <small>recon → vuln → report</small>
        </div>
        <span className="pulse" style={{ marginLeft: 'auto' }} />
      </div>
    </aside>
  )
}
