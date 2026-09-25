export default function TitleBar({ backendOnline = false }) {
  const wc = window.windowControls

  return (
    <div className="titlebar drag-region">
      <div className="tb-left no-drag">
        <span className="tb-mark">◆</span>
        <span className="tb-title">CYBERSPHERE</span>
        <span className="tb-sub">// agent-driven pentest suite</span>
        <span
          className="tb-badge"
          style={{
            color: backendOnline ? 'var(--ok)' : 'var(--crit)',
            borderColor: backendOnline ? 'var(--ok)' : 'var(--crit)',
          }}
        >
          {backendOnline ? 'BACKEND · ONLINE' : 'BACKEND · OFFLINE'}
        </span>
      </div>
      <div className="tb-right no-drag">
        <button className="tb-btn" onClick={() => wc?.minimize()}>─</button>
        <button className="tb-btn" onClick={() => wc?.maximize()}>□</button>
        <button className="tb-btn close" onClick={() => wc?.close()}>✕</button>
      </div>
    </div>
  )
}
