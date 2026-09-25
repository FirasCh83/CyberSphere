import { useState, useEffect, useRef, useCallback } from 'react'

const SEV_COLOR = {
  critical: 'var(--crit)',
  high: 'var(--high)',
  medium: 'var(--med)',
  low: 'var(--low)',
  info: 'var(--dim)',
}

const CSEVENT = '[[CSEVENT]]'
const ERROR_RE = /^\s*\[ERROR\]|Traceback \(most recent call last\)|pipeline FAILED|^\s*[\w.]+(Error|Exception):|^\s*File "/

function fmt(total) {
  const m = String(Math.floor(total / 60)).padStart(2, '0')
  const s = String(total % 60).padStart(2, '0')
  return `${m}:${s}`
}

// Command card — ticks a live client-side timer while running, then shows the
// backend-measured elapsed once the tool finishes.
function Command({ tool, line, result, running, elapsed, ok }) {
  const [t, setT] = useState(0)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    if (!running) return
    const start = performance.now()
    const iv = setInterval(() => setT((performance.now() - start) / 1000), 100)
    return () => clearInterval(iv)
  }, [running])

  const cls = `cmd fade-in${running ? '' : ok ? ' done' : ' err'}`
  const bodyShown = result && (open || !running)

  return (
    <div className={cls}>
      <div
        className="cmd-head"
        style={{ cursor: result ? 'pointer' : 'default' }}
        onClick={() => result && setOpen(o => !o)}
      >
        <span className="cmd-tool">{tool}</span>
        <span className="cmd-line">{line}</span>
        {running ? (
          <span className="cmd-timer"><span className="spinner" /><span>{t.toFixed(1)}s</span></span>
        ) : (
          <span className="cmd-timer">
            <span className="check" style={{ color: ok ? 'var(--ok)' : 'var(--crit)' }}>{ok ? '✓' : '✕'}</span>
            <span>{Number(elapsed).toFixed(1)}s</span>
          </span>
        )}
      </div>
      {bodyShown && <div className="cmd-body">{result}</div>}
    </div>
  )
}

export default function MainPanel({ activeSession, onCreateSession, onSessionStatus, apiBase, view }) {
  const [input, setInput] = useState('')
  const [events, setEvents] = useState([])
  const [status, setStatus] = useState('idle')
  const [elapsed, setElapsed] = useState(0)
  const [findings, setFindings] = useState({ open_ports: [], severity_counts: {}, findings: [], advisory: [] })
  const [report, setReport] = useState(null)

  const endRef = useRef(null)
  const esRef = useRef(null)
  const pollRef = useRef(null)
  const doneRef = useRef(false)
  const traceRef = useRef(false)   // true while a python traceback is streaming

  const refreshFindings = useCallback((id) => {
    fetch(`${apiBase}/api/session/${id}/findings`)
      .then(r => r.json())
      .then(d => { if (!d.error) setFindings(d) })
      .catch(() => {})
  }, [apiBase])

  // dispatch one parsed [[CSEVENT]] object into the transcript
  const dispatch = useCallback((ev) => {
    if (ev.type === 'report') { setReport(ev.data); return }
    setEvents(prev => {
      if (ev.type === 'phase') return [...prev, { kind: 'phase', name: ev.name, sub: ev.sub }]
      if (ev.type === 'thought') return [...prev, { kind: 'thought', who: ev.who || 'reasoning', text: ev.text }]
      if (ev.type === 'handoff')
        return [...prev, { kind: 'handoff', from: ev.from, to: ev.to, ports: ev.ports || [], findings: ev.findings || 0 }]
      if (ev.type === 'rag_inspection')
        return [...prev, { kind: 'rag', rows: ev.rows || [] }]
      if (ev.type === 'tool_start')
        return [...prev, { kind: 'command', id: ev.id, tool: ev.tool, line: ev.line, running: true, result: '', elapsed: 0, ok: true }]
      if (ev.type === 'tool_end')
        return prev.map(b => (b.kind === 'command' && b.id === ev.id)
          ? { ...b, running: false, elapsed: ev.elapsed, result: ev.result, ok: ev.ok } : b)
      if (ev.type === 'done') return [...prev, { kind: 'done', text: ev.text }]
      return prev
    })
  }, [])

  // append an error/traceback line, merging consecutive ones into one block
  const pushError = useCallback((text) => {
    setEvents(prev => {
      const last = prev[prev.length - 1]
      if (last && last.kind === 'error')
        return [...prev.slice(0, -1), { ...last, text: `${last.text}\n${text}` }]
      return [...prev, { kind: 'error', text }]
    })
  }, [])

  const handleLine = useCallback((line) => {
    if (typeof line !== 'string') return
    if (line.startsWith(CSEVENT)) {
      traceRef.current = false
      try { dispatch(JSON.parse(line.slice(CSEVENT.length))) } catch { /* ignore malformed */ }
      return
    }
    // Once a traceback starts, capture EVERY following raw line (stack frames +
    // the real exception) until the FAILED marker. Otherwise the middle lines
    // that don't match ERROR_RE get dropped and the actual error is never shown.
    if (/Traceback \(most recent call last\)/.test(line)) {
      traceRef.current = true
      pushError(line)
      return
    }
    if (traceRef.current || ERROR_RE.test(line)) {
      pushError(line)
      if (/pipeline FAILED/.test(line)) traceRef.current = false
    }
  }, [dispatch, pushError])

  // connect to the session's SSE stream whenever the active session changes
  useEffect(() => {
    esRef.current?.close()
    clearInterval(pollRef.current)

    if (!activeSession) {
      setEvents([]); setStatus('idle'); setElapsed(0)
      setFindings({ open_ports: [], severity_counts: {}, findings: [], advisory: [] })
      setReport(null)
      return
    }

    doneRef.current = false
    setEvents([{ kind: 'user', text: activeSession.name }])
    setStatus('running')
    setElapsed(0)
    setFindings({ open_ports: [], severity_counts: {}, findings: [] })
    setReport(null)

    const finish = (st) => {
      if (doneRef.current) return
      doneRef.current = true
      setStatus(st)
      onSessionStatus?.(activeSession.id, st)
      refreshFindings(activeSession.id)
      esRef.current?.close()
    }

    const es = new EventSource(`${apiBase}/api/session/${activeSession.id}/stream`)
    esRef.current = es
    es.onmessage = (e) => {
      let data
      try { data = JSON.parse(e.data) } catch { return }
      if (data.log !== undefined) handleLine(data.log)
      if (data.status === 'done') finish('done')
      else if (data.status === 'error') finish('error')
      else if (data.error) finish('error')
    }
    es.onerror = () => { if (!doneRef.current) finish('error') }

    pollRef.current = setInterval(() => refreshFindings(activeSession.id), 2500)
    return () => { es.close(); clearInterval(pollRef.current) }
  }, [activeSession?.id, apiBase, handleLine, refreshFindings, onSessionStatus])

  // elapsed clock — runs while a scan is active
  useEffect(() => {
    if (status !== 'running') return
    const iv = setInterval(() => setElapsed(e => e + 1), 1000)
    return () => clearInterval(iv)
  }, [status])

  useEffect(() => { endRef.current?.scrollIntoView({ block: 'end' }) }, [events])

  const handleSubmit = async () => {
    const target = input.trim()
    if (!target) return
    setInput('')
    await onCreateSession(target)
  }

  // group the flat event list into conversation turns
  const turns = []
  let cur = null
  for (const ev of events) {
    if (ev.kind === 'user') { turns.push({ type: 'user', text: ev.text }); cur = null; continue }
    if (ev.kind === 'phase') { cur = { type: 'agent', name: ev.name, sub: ev.sub, blocks: [] }; turns.push(cur); continue }
    if (!cur) { cur = { type: 'agent', name: 'Agent', sub: '', blocks: [] }; turns.push(cur) }
    cur.blocks.push(ev)
  }

  const sc = findings.severity_counts || {}
  const pill = status === 'running' ? 'SCANNING' : status === 'done' ? 'COMPLETE' : status === 'error' ? 'FAILED' : ''
  const pillColor = status === 'done' ? 'var(--ok)' : status === 'error' ? 'var(--crit)' : 'var(--gold)'
  const dotStyle = status === 'running'
    ? {}
    : { background: pillColor, animation: 'none', boxShadow: 'none' }

  const renderBlock = (b, i) => {
    if (b.kind === 'thought' || b.kind === 'done')
      return (
        <div className="thought fade-in" key={i}>
          <span className="who">{b.kind === 'done' ? 'summary' : b.who}</span>
          {b.text}
        </div>
      )
    if (b.kind === 'command')
      return <Command key={i} {...b} />
    if (b.kind === 'handoff')
      return (
        <div className="handoff fade-in" key={i}>
          <div className="handoff-flow">
            <span className="handoff-agent">{b.from}</span>
            <span className="handoff-arrow">→</span>
            <span className="handoff-agent">{b.to}</span>
            <span className="handoff-meta">{b.ports.length} open ports · {b.findings} recon findings</span>
          </div>
          {b.ports.length > 0 && (
            <div className="handoff-ports">
              {b.ports.map((p, j) => (
                <span className="port" key={j}>{p.port}{p.service ? `/${p.service}` : ''}</span>
              ))}
            </div>
          )}
        </div>
      )
    if (b.kind === 'rag') {
      if (!b.rows.length)
        return <div className="rag-empty fade-in" key={i}>No candidates matched the knowledge base.</div>
      return (
        <div className="rag-table fade-in" key={i}>
          <div className="rag-row rag-head">
            <span className="rag-cve">CVE</span>
            <span className="rag-loc">port</span>
            <span className="rag-score">score</span>
            <span className="rag-route">route</span>
          </div>
          {b.rows.map((r, j) => (
            <div className="rag-row" key={j}>
              <span className="rag-cve">{r.cve}</span>
              <span className="rag-loc">{r.port}{r.service ? `/${r.service}` : ''}</span>
              <span className="rag-score" title={`semantic ${r.semantic} · evidence ${r.evidence}`}>{r.combined}</span>
              <span className={`rag-route ${r.decision === 'validate' ? 'is-validate' : 'is-advisory'}`}>
                {r.decision === 'validate' ? 'validate' : 'advisory'}
                {!r.has_module && ' · no module'}
              </span>
            </div>
          ))}
        </div>
      )
    }
    if (b.kind === 'error')
      return <div className="errblock fade-in" key={i}>{b.text}</div>
    return null
  }

  const buildMarkdown = (r) => {
    if (!r) return ''
    const L = []
    L.push(`# CyberSphere Assessment — ${r.target}`, '')
    L.push(`- Generated: ${r.generated_at || ''}`)
    if (r.os_guess) L.push(`- OS guess: ${r.os_guess}`)
    const c = r.counts || {}
    L.push(`- Confirmed ${c.confirmed || 0} · Probable ${c.probable || 0} · Unconfirmed ${c.unconfirmed || 0} · Exploitable ${c.exploitable || 0}`, '')
    L.push('## Summary', r.summary || '', '')
    L.push('## Open ports')
    ;(r.open_ports || []).forEach(p => L.push(`- ${p.port}${p.service ? `/${p.service}` : ''}${p.version ? ` (${p.version})` : ''}`))
    const sec = (title, arr) => {
      if (!arr || !arr.length) return
      L.push('', `## ${title}`)
      arr.forEach(v => {
        L.push(`### ${v.cve_id || v.name} — ${v.severity} (CVSS ${v.cvss_score})`)
        L.push(`- Port ${v.port}/${v.service} · version ${v.version || 'n/a'}`)
        if (v.metasploit_module) L.push(`- Metasploit: \`${v.metasploit_module}\``)
        if (v.description) L.push(`- ${v.description}`)
        if (v.validation_output) L.push(`- Validation: ${v.validation_output}`)
      })
    }
    sec('Confirmed', r.confirmed)
    sec('Probable', r.probable)
    sec('Unconfirmed', r.unconfirmed)
    sec('Advisory (no exploit module — manual review)', r.advisory)
    return L.join('\n')
  }

  const copyReport = () => {
    navigator.clipboard?.writeText(buildMarkdown(report)).catch(() => {})
  }

  const vulnCard = (v, i) => (
    <div className="rep-vuln" key={i}>
      <div className="rep-vuln-head">
        <span className="sd" style={{ background: SEV_COLOR[v.severity] || 'var(--dim)' }} />
        <span className="rep-cve">{v.cve_id || v.name}</span>
        <span className="rep-sev" style={{ color: SEV_COLOR[v.severity] || 'var(--dim)' }}>{v.severity}</span>
        {v.cvss_score ? <span className="rep-cvss">CVSS {v.cvss_score}</span> : null}
        <span className="rep-loc">{v.port}{v.service ? `/${v.service}` : ''}</span>
      </div>
      {v.version && <div className="rep-meta">version {v.version}{v.requires_auth ? ' · auth required' : ''}</div>}
      {v.metasploit_module && <div className="rep-msf">msf: {v.metasploit_module}</div>}
      {v.description && <div className="rep-desc">{v.description}</div>}
      {v.validation_output && <div className="rep-val">{v.validation_output}</div>}
    </div>
  )

  const renderReport = () => {
    if (!activeSession)
      return (
        <div className="report">
          <div className="rep-empty">Select a session to view its report.</div>
        </div>
      )
    if (!report)
      return (
        <div className="report">
          <div className="rep-empty">
            {status === 'running' ? 'Assessment in progress — the report appears when the scan finishes.' : 'No report yet for this session.'}
          </div>
        </div>
      )
    const r = report
    const c = r.counts || {}
    return (
      <div className="report">
        <div className="rep-doc">
          <div className="rep-top">
            <div>
              <div className="rep-title">CyberSphere Assessment</div>
              <div className="rep-target">{r.target}</div>
              <div className="rep-sub">
                {r.generated_at ? new Date(r.generated_at).toLocaleString() : ''}
                {r.os_guess ? ` · ${r.os_guess}` : ''}
              </div>
            </div>
            <button className="rep-copy" onClick={copyReport}>Copy Markdown</button>
          </div>

          <div className="rep-stats">
            {[['confirmed', 'var(--ok)'], ['probable', 'var(--gold)'], ['unconfirmed', 'var(--dim)'], ['exploitable', 'var(--crit)']].map(([k, col]) => (
              <div className="rep-stat" key={k}>
                <div className="rep-count" style={{ color: col }}>{c[k] || 0}</div>
                <div className="rep-stat-l">{k}</div>
              </div>
            ))}
          </div>

          <div className="rep-h2">Summary</div>
          <div className="rep-summary">{r.summary || '—'}</div>

          <div className="rep-h2">Open ports</div>
          <div className="ports">
            {(r.open_ports || []).length === 0
              ? <span className="empty">none</span>
              : r.open_ports.map((p, i) => (
                  <span className="port" key={i}>{p.port}{p.service ? `/${p.service}` : ''}</span>
                ))}
          </div>

          {[['Confirmed', r.confirmed], ['Probable', r.probable], ['Unconfirmed', r.unconfirmed], ['Advisory', r.advisory]].map(([title, arr]) =>
            (arr && arr.length) ? (
              <div key={title}>
                <div className="rep-h2">{title}{title === 'Advisory' ? ' — no exploit module, manual review' : ''}</div>
                {arr.map(vulnCard)}
              </div>
            ) : null
          )}
        </div>
      </div>
    )
  }

  return (
    <main className="main">
      {activeSession && (
        <div className="statusbar">
          <div className="status-l">
            <span className="pulse" style={dotStyle} />
            <span className="pill" style={{ color: pillColor }}>{pill}</span>
          </div>
          <div className="status-r">
            TARGET&nbsp; <b>{activeSession.name}</b> &nbsp;·&nbsp; elapsed <b>{fmt(elapsed)}</b>
          </div>
        </div>
      )}

      {view === 'report' ? renderReport() : (
      <div className="convo">
        <div className="chat">
          {!activeSession ? (
            <div className="hero">
              <div className="wordmark">CYBERSPHERE</div>
              <p className="tagline">
                Point me at a target — an IP, domain, or host. I'll drive recon, match
                findings against known CVEs, and validate what's real. You just read the report.
              </p>
              <div className="chips">
                {['NMAP', 'NUCLEI', 'KATANA', 'WHATWEB', 'METASPLOIT'].map(c => (
                  <span className="chip" key={c}>{c}</span>
                ))}
              </div>
            </div>
          ) : (
            <div className="chat-inner">
              {turns.map((turn, i) =>
                turn.type === 'user' ? (
                  <div className="msg user fade-in" key={i}>
                    <div className="msg-row">
                      <div className="bubble">
                        <span className="lead">target</span>
                        Run a full assessment on <b>{turn.text}</b>.
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="msg agent fade-in" key={i}>
                    <div className="msg-row">
                      <div className="avatar">CS</div>
                      <div className="agent-body">
                        <div className="agent-name">
                          {turn.name}{turn.sub && <small>{turn.sub}</small>}
                        </div>
                        {turn.blocks.map(renderBlock)}
                      </div>
                    </div>
                  </div>
                )
              )}
              <div ref={endRef} />
            </div>
          )}
        </div>

        {activeSession && (
          <aside className="findings">
            <div className="f-title">Live findings</div>
            <div className="f-sub" style={{ margin: '0 0 8px' }}>Validated severity</div>
            <div className="sev-grid">
              {['critical', 'high', 'medium', 'low'].map(sev => (
                <div className="sev" key={sev}>
                  <div className="n" style={{ color: SEV_COLOR[sev] }}>{sc[sev] || 0}</div>
                  <div className="l">{sev.slice(0, 4)}</div>
                </div>
              ))}
            </div>

            <div className="f-sub">Open ports</div>
            <div className="ports">
              {findings.open_ports.length === 0
                ? <span className="empty">none yet</span>
                : findings.open_ports.map((p, i) => <span className="port" key={i}>{p.port}</span>)}
            </div>

            <div className="f-sub">Vulnerabilities</div>
            <div>
              {findings.findings.length === 0
                ? <span className="empty">{status === 'running' ? 'scanning…' : 'none validated'}</span>
                : findings.findings.map((f, i) => (
                    <div className="vuln fade-in" key={i}>
                      <div className="top">
                        <span className="sd" style={{ background: SEV_COLOR[f.severity] || 'var(--dim)' }} />
                        <span className="cve">{f.cve}</span>
                        {f.location && <span className="loc">{f.location}</span>}
                      </div>
                      {f.detail && <div className="desc">{f.detail}</div>}
                    </div>
                  ))}
            </div>

            {(findings.advisory || []).length > 0 && (
              <>
                <div className="f-sub">Advisory <span className="adv-count">{findings.advisory.length}</span></div>
                <div className="adv-note">Potential exposure — no exploit module, not validated.</div>
                <div>
                  {findings.advisory.map((f, i) => (
                    <div className="vuln advisory fade-in" key={i}>
                      <div className="top">
                        <span className="sd" style={{ background: SEV_COLOR[f.severity] || 'var(--dim)' }} />
                        <span className="cve">{f.cve}</span>
                        {f.location && <span className="loc">{f.location}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </aside>
        )}
      </div>
      )}

      <div className="composer">
        <div className="composer-inner">
          <span className="plus">＋</span>
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            placeholder={activeSession ? 'Launch another target…' : 'Enter a target IP, domain, or hostname…'}
          />
          <span className="model">recon-agent · vuln-agent</span>
          <button className="launch" onClick={handleSubmit} disabled={!input.trim()}>Launch →</button>
        </div>
      </div>
    </main>
  )
}



