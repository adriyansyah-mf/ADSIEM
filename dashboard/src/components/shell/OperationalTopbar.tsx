import { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { ChevronDown } from 'lucide-react'
import { ALL_NAV_ITEMS } from './navGroups'
import { EntityCommandPalette } from './EntityCommandPalette'

const ADMIN_ITEMS = ALL_NAV_ITEMS.filter(i => i.minRole === 'admin' || i.minRole === 'superadmin')

interface OperationalTopbarProps {
  wsConnected: boolean
}

export function OperationalTopbar({ wsConnected }: OperationalTopbarProps) {
  const { pathname } = useLocation()
  const { user, logout, hasRole } = useAuthStore()
  const [clock, setClock] = useState(new Date())
  const [adminMenuOpen, setAdminMenuOpen] = useState(false)

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const isActive = (to: string) => (to === '/' ? pathname === '/' : pathname.startsWith(to))
  const currentLabel = ALL_NAV_ITEMS.find(i => isActive(i.to))?.label ?? 'AD-SIEM'
  const visibleAdminItems = ADMIN_ITEMS.filter(i => hasRole(i.minRole ?? 'viewer'))

  return (
    <header className="app-topbar" style={{
      height: 52, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 16, padding: '0 20px',
      background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)',
    }}>
      <span style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
        <span style={{ fontFamily: 'var(--font-display)', fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>
          {currentLabel}
        </span>
        {wsConnected && (
          <span
            title="Live feed connected"
            role="status"
            aria-label="Live alert feed connected"
            style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-green)', flexShrink: 0, display: 'inline-block' }}
          />
        )}
      </span>

      <EntityCommandPalette />

      <div style={{ width: 1, height: 24, background: 'var(--border)' }} />

      <div className="user-controls" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.2 }}>
            {user?.username ?? '—'}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.2, fontVariantNumeric: 'tabular-nums', fontFamily: 'var(--font-mono)' }}>
            {clock.toLocaleTimeString('en-US', { hour12: false })}
          </div>
        </div>
        {visibleAdminItems.length > 0 && (
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setAdminMenuOpen(o => !o)}
              aria-expanded={adminMenuOpen}
              onBlur={() => setTimeout(() => setAdminMenuOpen(false), 150)}
              style={{
                display: 'flex', alignItems: 'center', gap: 4, padding: '5px 12px', borderRadius: 6,
                border: '1px solid var(--border)', background: adminMenuOpen ? 'rgba(44,110,142,0.1)' : 'transparent',
                color: 'var(--text-secondary)', fontSize: 12, fontWeight: 500, cursor: 'pointer',
              }}
            >
              Governance <ChevronDown size={13} />
            </button>
            {adminMenuOpen && (
              <div style={{
                position: 'absolute', top: '100%', right: 0, marginTop: 4,
                background: 'var(--bg-hover)', border: '1px solid var(--border)', borderRadius: 6,
                zIndex: 1000, overflow: 'hidden', minWidth: 160, boxShadow: '0 12px 32px rgba(0,0,0,0.6)',
              }}>
                {visibleAdminItems.map(item => {
                  const Icon = item.icon
                  const active = isActive(item.to)
                  return (
                    <Link
                      key={item.to}
                      to={item.to}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px', textDecoration: 'none',
                        background: active ? 'rgba(44,110,142,0.12)' : 'transparent',
                        color: active ? 'var(--accent-blue)' : 'var(--text-primary)', fontSize: 12.5,
                      }}
                    >
                      <Icon size={14} strokeWidth={active ? 2 : 1.75} />
                      {item.label}
                    </Link>
                  )
                })}
              </div>
            )}
          </div>
        )}
        <button
          onClick={logout}
          className="sign-out-btn"
          style={{
            padding: '5px 12px', borderRadius: 6, border: '1px solid var(--border)',
            background: 'transparent', color: 'var(--text-muted)', fontSize: 12, fontWeight: 500, cursor: 'pointer',
          }}
        >
          Sign out
        </button>
      </div>
    </header>
  )
}
