import { useState, useEffect, useCallback } from 'react'
import Sidebar from './components/Sidebar.jsx'
import TitleBar from './components/TitleBar.jsx'
import MainPanel from './components/MainPanel.jsx'

const API = 'http://localhost:8000'

export default function App() {
  const [sessions, setSessions] = useState([])
  const [activeSession, setActiveSession] = useState(null)
  const [backendOnline, setBackendOnline] = useState(false)
  const [view, setView] = useState('chat')   // 'chat' | 'report'

  // poll backend health so the UI can reflect connectivity
  useEffect(() => {
    const check = async () => {
      try {
        const r = await fetch(`${API}/api/health`)
        setBackendOnline(r.ok)
      } catch {
        setBackendOnline(false)
      }
    }
    check()
    const id = setInterval(check, 5000)
    return () => clearInterval(id)
  }, [])

  const createSession = async (target) => {
    const res = await fetch(`${API}/api/session/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    })
    const data = await res.json()
    const now = new Date()
    const newSession = {
      id: data.session_id,
      name: target,
      time: `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`,
      status: 'running',
    }
    setSessions(prev => {
      const next = [newSession, ...prev]
      // reflect terminal status back onto the session entry
      setActiveSession(s => (s?.id === newSession.id ? { ...s, ...newSession } : s))
      return next
    })
    setActiveSession(newSession)
    setView('chat')   // watch the run live; the Reports tab shows it once done
    return data.session_id
  }

  // keep the session list's status in sync with the active session's lifecycle.
  // memoized so its identity is stable across renders — MainPanel's SSE effect
  // depends on it, and a fresh identity each render would tear down + re-seed
  // the stream (wiping the transcript) every time this fires. That was the glitch.
  const onSessionStatus = useCallback((id, status) => {
    setSessions(prev => prev.map(s => (s.id === id ? { ...s, status } : s)))
  }, [])

  return (
    <div className="app-bg flex flex-col h-screen w-screen select-none overflow-hidden">
      <TitleBar backendOnline={backendOnline} />
      <div className="body">
        <Sidebar
          sessions={sessions}
          activeSession={activeSession}
          setActiveSession={s => { setActiveSession(s); setView('chat') }}
          view={view}
          setView={setView}
        />
        <MainPanel
          activeSession={activeSession}
          onCreateSession={createSession}
          onSessionStatus={onSessionStatus}
          apiBase={API}
          view={view}
          setView={setView}
        />
      </div>
    </div>
  )
}
