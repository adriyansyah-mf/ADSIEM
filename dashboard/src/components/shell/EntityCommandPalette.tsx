import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search } from 'lucide-react'
import { api } from '@/api/client'

interface SearchResults {
  alerts: { id: string; title: string; severity: string }[]
  cases: { id: string; title: string; status: string }[]
  agents: { id: string; name: string; hostname: string; status: string }[]
}

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/
const HASH_RE = /^[a-f0-9]{32,64}$/i

/** Global entity command palette (Ironwatch spec 3, "Shell anatomy"): accepts
 * IP, hostname, user, hash, agent, alert, and case identifiers and routes to
 * the matching detail workspace. Opens via the topbar trigger or Ctrl/Cmd+K. */
export function EntityCommandPalette() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SearchResults | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen(true)
      } else if (e.key === 'Escape' && open) {
        setOpen(false)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 10)
    else { setQuery(''); setResults(null) }
  }, [open])

  useEffect(() => {
    if (query.length < 2) { setResults(null); return }
    const t = setTimeout(async () => {
      try {
        const r = await api.get('/api/search', { params: { q: query, limit: 6 } })
        setResults(r.data)
      } catch { setResults(null) }
    }, 200)
    return () => clearTimeout(t)
  }, [query])

  const go = (to: string) => { navigate(to); setOpen(false) }

  const isEntityLookup = IP_RE.test(query.trim()) || HASH_RE.test(query.trim())
  const hasResults = results && (results.alerts.length > 0 || results.cases.length > 0 || results.agents.length > 0)

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="global-search"
        aria-label="Search alerts, cases, agents, and indicators"
        style={{
          flex: '1 1 auto', minWidth: 0, maxWidth: 360, margin: '0 16px', display: 'flex', alignItems: 'center', gap: 6,
          background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 6,
          padding: '6px 10px', color: 'var(--text-muted)', fontSize: 12, cursor: 'pointer', textAlign: 'left', overflow: 'hidden',
        }}
      >
        <Search size={14} aria-hidden="true" style={{ flexShrink: 0 }} />
        <span style={{ flex: '1 1 auto', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>Search alerts, cases, agents, IPs…</span>
        <kbd className="search-kbd-hint" style={{ flexShrink: 0, fontFamily: 'var(--font-mono)', fontSize: 10, border: '1px solid var(--border)', borderRadius: 3, padding: '1px 5px', color: 'var(--text-muted)' }}>⌘K</kbd>
      </button>

      {open && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Command palette"
          style={{ position: 'fixed', inset: 0, zIndex: 1200, display: 'flex', alignItems: 'flex-start', justifyContent: 'center', paddingTop: '12vh' }}
        >
          <div onClick={() => setOpen(false)} style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.6)' }} />
          <div style={{
            position: 'relative', width: '100%', maxWidth: 560, background: 'var(--bg-hover)',
            border: '1px solid var(--border)', borderRadius: 8, boxShadow: '0 12px 32px rgba(0,0,0,0.6)', overflow: 'hidden',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
              <Search size={16} color="var(--text-muted)" aria-hidden="true" />
              <input
                ref={inputRef}
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="IP, hostname, user, hash, agent, alert, or case…"
                aria-label="Command palette search"
                style={{ flex: 1, background: 'none', border: 'none', color: 'var(--text-primary)', fontSize: 14 }}
              />
              <kbd style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>ESC</kbd>
            </div>

            <div style={{ maxHeight: 360, overflowY: 'auto' }}>
              {query.length < 2 && (
                <div style={{ padding: '24px 16px', textAlign: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
                  Type at least 2 characters to search.
                </div>
              )}
              {query.length >= 2 && !hasResults && !isEntityLookup && (
                <div style={{ padding: '24px 16px', textAlign: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
                  No matches for &ldquo;{query}&rdquo;.
                </div>
              )}
              {isEntityLookup && (
                <button
                  onClick={() => go(`/ueba?entity=${encodeURIComponent(query.trim())}`)}
                  style={{ display: 'flex', width: '100%', gap: 8, alignItems: 'center', padding: '10px 14px', border: 'none', borderBottom: '1px solid var(--border)', background: 'transparent', color: 'var(--text-primary)', cursor: 'pointer', textAlign: 'left', fontSize: 13 }}
                >
                  <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: 'rgba(44,110,142,0.15)', color: 'var(--accent-blue)', fontWeight: 700, textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>entity</span>
                  View risk & history for <span className="mono">{query.trim()}</span>
                </button>
              )}
              {results?.agents.map(a => (
                <button key={a.id} onClick={() => go(`/agents?highlight=${a.id}`)} style={resultRowStyle}>
                  <span style={{ ...badgeStyle, background: a.status === 'online' ? 'rgba(79,143,99,0.15)' : 'rgba(104,113,126,0.15)', color: a.status === 'online' ? 'var(--accent-green)' : 'var(--text-muted)' }}>agent</span>
                  <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.name || a.hostname}</span>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{a.status}</span>
                </button>
              ))}
              {results?.alerts.map(a => (
                <button key={a.id} onClick={() => go(`/alerts?open=${a.id}`)} style={resultRowStyle}>
                  <span style={{ ...badgeStyle, background: 'rgba(216,57,63,0.15)', color: 'var(--accent-red)' }}>{a.severity}</span>
                  <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</span>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>alert</span>
                </button>
              ))}
              {results?.cases.map(c => (
                <button key={c.id} onClick={() => go(`/cases/${c.id}`)} style={resultRowStyle}>
                  <span style={{ ...badgeStyle, background: 'rgba(44,110,142,0.15)', color: 'var(--accent-blue)' }}>{c.status}</span>
                  <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</span>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>case</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  )
}

const resultRowStyle: React.CSSProperties = {
  display: 'flex', width: '100%', gap: 8, alignItems: 'center', padding: '9px 14px',
  border: 'none', borderBottom: '1px solid var(--border)', background: 'transparent',
  color: 'var(--text-primary)', cursor: 'pointer', textAlign: 'left', fontSize: 13,
}
const badgeStyle: React.CSSProperties = {
  fontSize: 10, padding: '1px 6px', borderRadius: 3, fontWeight: 700, textTransform: 'uppercase',
  fontFamily: 'var(--font-mono)', flexShrink: 0, whiteSpace: 'nowrap',
}
