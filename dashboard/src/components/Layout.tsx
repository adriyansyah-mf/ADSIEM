import { useState, useEffect } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: '⚡', minRole: 'viewer' },
  { to: '/agents', label: 'Agents', icon: '🖥', minRole: 'viewer' },
  { to: '/logs', label: 'Logs', icon: '📋', minRole: 'viewer' },
  { to: '/events', label: 'Events', icon: '🔍', minRole: 'viewer' },
  { to: '/alerts', label: 'Alerts', icon: '🚨', minRole: 'viewer' },
  { to: '/cases', label: 'Cases', icon: '🎫', minRole: 'viewer' },
  { to: '/rules', label: 'Rules', icon: '📏', minRole: 'viewer' },
  { to: '/decoders', label: 'Decoders', icon: '🔧', minRole: 'viewer' },
  { to: '/users', label: 'Users', icon: '👥', minRole: 'superadmin' },
]

type OpMode = 'MANUAL' | 'OBSERVER' | 'OPERATOR'

export default function Layout() {
  const { pathname } = useLocation()
  const { user, logout, hasRole } = useAuthStore()
  const [opMode, setOpMode] = useState<OpMode>('OBSERVER')
  const [clock, setClock] = useState(new Date())

  const { data: agentsData } = useQuery({
    queryKey: ['agents-health'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 100 } }).then(r => r.data),
    refetchInterval: 30_000,
  })

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const agents = agentsData?.items ?? []
  const onlineCount = agents.filter((a: { status: string }) => a.status === 'online').length
  const totalCount = agentsData?.total ?? 0

  const modeColors: Record<OpMode, string> = {
    MANUAL: 'var(--accent-yellow)',
    OBSERVER: 'var(--accent-cyan)',
    OPERATOR: 'var(--accent-green)',
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden', background: 'var(--bg-base)' }}>
      {/* Top Navigation Bar */}
      <header style={{
        height: '50px',
        flexShrink: 0,
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '0 16px',
        background: 'var(--bg-panel)',
        borderBottom: '1px solid var(--border)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
      }}>
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginRight: '8px', flexShrink: 0 }}>
          <span style={{ fontSize: '18px' }}>🛡</span>
          <span style={{
            fontFamily: 'Rajdhani, sans-serif',
            fontWeight: 700,
            fontSize: '15px',
            color: 'var(--accent-cyan)',
            letterSpacing: '2px',
            textTransform: 'uppercase',
            whiteSpace: 'nowrap',
          }}>AD-AGENTIC SIEM</span>
        </div>

        <div style={{ width: '1px', height: '30px', background: 'var(--border)', flexShrink: 0 }} />

        {/* Nav tabs */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: '2px', flex: 1, overflow: 'hidden' }}>
          {NAV_ITEMS.filter(item => hasRole(item.minRole)).map(item => {
            const isActive = item.to === '/' ? pathname === '/' : pathname.startsWith(item.to)
            return (
              <Link
                key={item.to}
                to={item.to}
                title={item.label}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  padding: '4px 10px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontFamily: 'Rajdhani, sans-serif',
                  fontWeight: 600,
                  letterSpacing: '0.5px',
                  textDecoration: 'none',
                  whiteSpace: 'nowrap',
                  color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  background: isActive ? 'rgba(0,212,255,0.1)' : 'transparent',
                  borderBottom: isActive ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                  transition: 'all 0.15s',
                }}
              >
                <span style={{ fontSize: '14px' }}>{item.icon}</span>
                <span>{item.label.toUpperCase()}</span>
              </Link>
            )
          })}
        </nav>

        <div style={{ width: '1px', height: '30px', background: 'var(--border)', flexShrink: 0 }} />

        {/* System health */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          flexShrink: 0,
          fontFamily: 'Share Tech Mono, monospace',
          fontSize: '11px',
          color: onlineCount > 0 ? 'var(--accent-green)' : 'var(--text-secondary)',
        }}>
          <span style={{
            width: '6px', height: '6px', borderRadius: '50%',
            background: onlineCount > 0 ? 'var(--accent-green)' : 'var(--text-muted)',
            boxShadow: onlineCount > 0 ? '0 0 6px var(--accent-green)' : 'none',
          }} />
          <span>{onlineCount}/{totalCount} AGENTS</span>
        </div>

        <div style={{ width: '1px', height: '30px', background: 'var(--border)', flexShrink: 0 }} />

        {/* Op Mode buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexShrink: 0 }}>
          {(['MANUAL', 'OBSERVER', 'OPERATOR'] as OpMode[]).map(mode => (
            <button
              key={mode}
              onClick={() => setOpMode(mode)}
              style={{
                padding: '3px 8px',
                borderRadius: '3px',
                border: `1px solid ${opMode === mode ? modeColors[mode] : 'var(--border)'}`,
                background: opMode === mode ? `${modeColors[mode]}22` : 'transparent',
                color: opMode === mode ? modeColors[mode] : 'var(--text-muted)',
                fontFamily: 'Rajdhani, sans-serif',
                fontWeight: 700,
                fontSize: '10px',
                letterSpacing: '1px',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              {mode}
            </button>
          ))}
        </div>

        <div style={{ width: '1px', height: '30px', background: 'var(--border)', flexShrink: 0 }} />

        {/* User info + clock */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 600, fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.2 }}>
              {user?.username ?? '—'}
            </div>
            <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-secondary)', lineHeight: 1.2 }}>
              {clock.toLocaleTimeString('en-US', { hour12: false })}
            </div>
          </div>
          <button
            onClick={logout}
            style={{
              padding: '4px 8px',
              borderRadius: '3px',
              border: '1px solid var(--border)',
              background: 'transparent',
              color: 'var(--accent-red)',
              fontFamily: 'Rajdhani, sans-serif',
              fontWeight: 700,
              fontSize: '10px',
              letterSpacing: '1px',
              cursor: 'pointer',
            }}
          >
            EXIT
          </button>
        </div>
      </header>

      {/* Main content */}
      <main style={{ flex: 1, overflow: 'auto', padding: '16px' }}>
        <Outlet />
      </main>
    </div>
  )
}
