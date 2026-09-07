import { useState, useEffect } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import {
  LayoutDashboard, FileText, Activity, Bell, FolderOpen,
  Brain, HeartPulse, Lock, ScanLine, Crosshair,
  Terminal, Server, BookOpen, Wrench, Shield, Bot,
  Users, Settings, PanelLeftClose, PanelLeftOpen,
  Webhook, ClipboardList, FileBarChart, Grid3x3, ChevronDown,
  type LucideIcon,
} from 'lucide-react'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  minRole?: string
}

const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: 'Monitor',
    items: [
      { to: '/', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/logs', label: 'Logs', icon: FileText },
      { to: '/events', label: 'Events', icon: Activity },
      { to: '/alerts', label: 'Alerts', icon: Bell },
      { to: '/cases', label: 'Cases', icon: FolderOpen },
      { to: '/assistant', label: 'SOC Assistant', icon: Bot },
    ],
  },
  {
    label: 'Analytics',
    items: [
      { to: '/ueba', label: 'UEBA', icon: Brain },
      { to: '/hygiene', label: 'Hygiene', icon: HeartPulse },
      { to: '/fim', label: 'FIM', icon: Lock },
      { to: '/yara', label: 'YARA', icon: ScanLine },
      { to: '/hunts', label: 'Threat Hunt', icon: Crosshair },
      { to: '/mitre-heatmap', label: 'MITRE Heatmap', icon: Grid3x3 },
      { to: '/reports', label: 'Reports', icon: FileBarChart },
    ],
  },
  {
    label: 'Response',
    items: [
      { to: '/live-response', label: 'Live Response', icon: Terminal },
    ],
  },
  {
    label: 'Configuration',
    items: [
      { to: '/agents', label: 'Agents', icon: Server },
      { to: '/rules', label: 'Rules', icon: BookOpen },
      { to: '/decoders', label: 'Decoders', icon: Wrench },
      { to: '/soar', label: 'SOAR', icon: Shield },
    ],
  },
]

const ADMIN_ITEMS: NavItem[] = [
  { to: '/webhooks', label: 'Webhooks', icon: Webhook, minRole: 'admin' },
  { to: '/audit-logs', label: 'Audit Log', icon: ClipboardList, minRole: 'admin' },
  { to: '/settings', label: 'Settings', icon: Settings, minRole: 'admin' },
  { to: '/users', label: 'Users', icon: Users, minRole: 'superadmin' },
]

export default function Layout() {
  const { pathname } = useLocation()
  const { user, logout, hasRole, accessToken } = useAuthStore()
  const queryClient = useQueryClient()
  const [clock, setClock] = useState(new Date())
  const [collapsed, setCollapsed] = useState(false)
  const [wsConnected, setWsConnected] = useState(false)

  const { data: agentsData } = useQuery({
    queryKey: ['agents-health'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 100 } }).then(r => r.data),
    refetchInterval: 30_000,
  })

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    if (!accessToken) return
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/api/ws/alerts?token=${accessToken}`)
    ws.onopen = () => setWsConnected(true)
    ws.onclose = () => setWsConnected(false)
    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        if (data.type === 'new_alert') {
          queryClient.invalidateQueries({ queryKey: ['alerts-recent'] })
          queryClient.invalidateQueries({ queryKey: ['alerts-dashboard'] })
        }
      } catch {}
    }
    const ping = setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping') }, 30000)
    return () => { clearInterval(ping); ws.close() }
  }, [accessToken, queryClient])

  const onlineCount = (agentsData?.items ?? []).filter((a: { status: string }) => a.status === 'online').length
  const totalCount = agentsData?.total ?? 0

  const navigate = useNavigate()
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<{ alerts: any[]; cases: any[] } | null>(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const [adminMenuOpen, setAdminMenuOpen] = useState(false)

  const handleSearch = async (q: string) => {
    if (q.length < 2) { setSearchResults(null); return }
    try {
      const r = await api.get('/api/search', { params: { q, limit: 5 } })
      setSearchResults(r.data)
    } catch {
      setSearchResults(null)
    }
  }

  const isActive = (to: string) => to === '/' ? pathname === '/' : pathname.startsWith(to)

  const allItems = [...NAV_GROUPS.flatMap(g => g.items), ...ADMIN_ITEMS]
  const currentLabel = allItems.find(i => isActive(i.to))?.label ?? 'AD-SIEM'

  const sidebarW = collapsed ? 56 : 216

  return (
    <div className="app-shell" style={{ display: 'flex', height: '100dvh', overflow: 'hidden', background: 'transparent' }}>
      <a className="skip-link" href="#main-content">Skip to main content</a>

      {/* ── Sidebar ── */}
      <aside className="app-sidebar" style={{
        width: sidebarW,
        minWidth: sidebarW,
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--glass-bg)',
        backdropFilter: 'var(--glass-blur-chrome)',
        WebkitBackdropFilter: 'var(--glass-blur-chrome)',
        borderRight: '1px solid var(--glass-border)',
        transition: 'background var(--motion-standard)',
        overflow: 'hidden',
      }}>

        {/* Logo */}
        <div style={{
          height: 52,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '0 16px',
          borderBottom: '1px solid var(--glass-border)',
          flexShrink: 0,
        }}>
          <img
            src="/favicon.jpeg"
            alt="AD-SIEM"
            style={{
              width: 28, height: 28, borderRadius: 6,
              objectFit: 'cover', flexShrink: 0,
            }}
          />
          {!collapsed && (
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em', lineHeight: 1.1 }}>
                AD-SIEM
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.02em' }}>
                Security Operations
              </div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '8px 0' }}>
          {NAV_GROUPS.map((group, gi) => {
            const visibleItems = group.items.filter(i => hasRole(i.minRole ?? 'viewer'))
            if (visibleItems.length === 0) return null
            return (
            <div key={group.label} style={{ marginBottom: 4 }}>
              {!collapsed && (
                <div style={{
                  padding: gi === 0 ? '8px 16px 4px' : '12px 16px 4px',
                  fontSize: 10,
                  fontWeight: 600,
                  letterSpacing: '0.08em',
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                }}>
                  {group.label}
                </div>
              )}
              {collapsed && gi > 0 && <div style={{ height: 1, background: 'var(--glass-border)', margin: '6px 10px' }} />}
              {visibleItems.map(item => {
                const active = isActive(item.to)
                const Icon = item.icon
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    title={collapsed ? item.label : undefined}
                    aria-current={active ? 'page' : undefined}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: collapsed ? '8px 0' : '7px 16px',
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      textDecoration: 'none',
                      background: active ? 'rgba(44,110,142,0.12)' : 'transparent',
                      borderLeft: active ? '2px solid var(--accent-blue)' : '2px solid transparent',
                      color: active ? 'var(--accent-blue)' : 'var(--text-muted)',
                      boxShadow: active ? 'inset 12px 0 24px -24px var(--accent-blue)' : 'none',
                      transition: 'color var(--motion-micro), background var(--motion-micro)',
                    }}
                  >
                    <Icon size={15} strokeWidth={active ? 2 : 1.75} style={{ flexShrink: 0 }} />
                    {!collapsed && (
                      <span style={{
                        fontSize: 13,
                        fontWeight: active ? 500 : 400,
                        color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                        whiteSpace: 'nowrap',
                        letterSpacing: '0.01em',
                      }}>
                        {item.label}
                      </span>
                    )}
                  </Link>
                )
              })}
            </div>
            )
          })}

          {/* Admin */}
          {ADMIN_ITEMS.filter(i => hasRole(i.minRole ?? 'viewer')).length > 0 && (
            <div style={{ marginTop: 4 }}>
              {!collapsed && (
                <div style={{
                  padding: '12px 16px 4px',
                  fontSize: 10,
                  fontWeight: 600,
                  letterSpacing: '0.08em',
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                }}>
                  Administration
                </div>
              )}
              {collapsed && <div style={{ height: 1, background: 'var(--glass-border)', margin: '6px 10px' }} />}
              {ADMIN_ITEMS.filter(i => hasRole(i.minRole ?? 'viewer')).map(item => {
                const active = isActive(item.to)
                const Icon = item.icon
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    title={collapsed ? item.label : undefined}
                    aria-current={active ? 'page' : undefined}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: collapsed ? '8px 0' : '7px 16px',
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      textDecoration: 'none',
                      background: active ? 'rgba(44,110,142,0.12)' : 'transparent',
                      borderLeft: active ? '2px solid var(--accent-blue)' : '2px solid transparent',
                      color: active ? 'var(--accent-blue)' : 'var(--text-muted)',
                      boxShadow: active ? 'inset 12px 0 24px -24px var(--accent-blue)' : 'none',
                      transition: 'color var(--motion-micro), background var(--motion-micro)',
                    }}
                  >
                    <Icon size={15} strokeWidth={active ? 2 : 1.75} style={{ flexShrink: 0 }} />
                    {!collapsed && (
                      <span style={{
                        fontSize: 13,
                        fontWeight: active ? 500 : 400,
                        color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                        whiteSpace: 'nowrap',
                        letterSpacing: '0.01em',
                      }}>
                        {item.label}
                      </span>
                    )}
                  </Link>
                )
              })}
            </div>
          )}
        </nav>

        {/* Bottom: agent count + collapse */}
        <div style={{ borderTop: '1px solid var(--glass-border)', flexShrink: 0 }}>
          {!collapsed ? (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '10px 16px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                <span style={{
                  width: 7, height: 7, borderRadius: '50%',
                  background: onlineCount > 0 ? 'var(--accent-green)' : 'var(--text-muted)',
                  boxShadow: onlineCount > 0 ? '0 0 6px color-mix(in srgb, var(--accent-green) 55%, transparent)' : 'none',
                  flexShrink: 0,
                }} />
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  <span style={{ color: onlineCount > 0 ? 'var(--accent-green)' : 'var(--text-muted)', fontWeight: 500 }}>{onlineCount}</span>
                  <span> / {totalCount} agents</span>
                </span>
              </div>
              <button
                onClick={() => setCollapsed(true)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', padding: '8px', borderRadius: 4 }}
                title="Collapse sidebar"
              >
                <PanelLeftClose size={14} />
              </button>
            </div>
          ) : (
            <button
              onClick={() => setCollapsed(false)}
              title="Expand sidebar"
              style={{
                width: '100%', background: 'none', border: 'none',
                cursor: 'pointer', color: 'var(--text-muted)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                padding: '14px 0',
              }}
            >
              <PanelLeftOpen size={14} />
            </button>
          )}
        </div>
      </aside>

      {/* ── Right side ── */}
      <div className="app-workspace" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>

        {/* Topbar */}
        <header className="app-topbar" style={{
          height: 52,
          flexShrink: 0,
          display: 'flex',
          alignItems: 'center',
          gap: 16,
          padding: '0 20px',
          background: 'var(--glass-bg)',
          backdropFilter: 'var(--glass-blur-chrome)',
          WebkitBackdropFilter: 'var(--glass-blur-chrome)',
          borderBottom: '1px solid var(--glass-border)',
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              {currentLabel}
            </span>
            {wsConnected && (
              <span
                title="Live feed connected"
                role="status"
                aria-label="Live alert feed connected"
                style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-green)', boxShadow: '0 0 6px var(--accent-green)', animation: 'pulse 2s infinite', flexShrink: 0, display: 'inline-block' }}
              />
            )}
          </span>

          {/* Global Search */}
          <div className="global-search" style={{ flex: 1, maxWidth: 360, position: 'relative', margin: '0 16px' }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'rgba(7,17,29,0.66)', border: '1px solid var(--glass-border)',
              borderRadius: 8, padding: '6px 10px',
            }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
              </svg>
              <input
                value={searchQuery}
                onChange={e => { setSearchQuery(e.target.value); setSearchOpen(true); handleSearch(e.target.value) }}
                onFocus={() => setSearchOpen(true)}
                onBlur={() => setTimeout(() => setSearchOpen(false), 200)}
                placeholder="Search alerts, cases, IPs…"
                aria-label="Search alerts, cases, and indicators"
                style={{
                  background: 'none', border: 'none', outline: 'none',
                  color: 'var(--text-primary)', fontSize: 12, width: '100%',
                }}
              />
            </div>
            {searchOpen && searchResults && (searchResults.alerts.length > 0 || searchResults.cases.length > 0) && (
              <div style={{
                position: 'absolute', top: '100%', left: 0, right: 0, marginTop: 4,
                background: 'var(--glass-bg-strong)', border: '1px solid var(--glass-border)', borderRadius: 8,
                backdropFilter: 'var(--glass-blur)', WebkitBackdropFilter: 'var(--glass-blur)',
                zIndex: 1000, overflow: 'hidden', boxShadow: '0 18px 48px rgba(0,0,0,0.34)',
              }}>
                {searchResults.alerts.map((a: any) => (
                  <div
                    key={a.id}
                    onMouseDown={() => { navigate(`/alerts?open=${a.id}`); setSearchOpen(false); setSearchQuery('') }}
                    style={{ padding: '8px 14px', cursor: 'pointer', borderBottom: '1px solid var(--glass-border)', display: 'flex', gap: 8, alignItems: 'center' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(44,110,142,0.08)' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                  >
                    <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 4, background: 'rgba(255,59,92,0.15)', color: 'var(--accent-red)', fontWeight: 600, textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      {a.severity}
                    </span>
                    <span style={{ fontSize: 12, color: 'var(--text-primary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.title}
                    </span>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>alert</span>
                  </div>
                ))}
                {searchResults.cases.map((c: any) => (
                  <div
                    key={c.id}
                    onMouseDown={() => { navigate(`/cases/${c.id}`); setSearchOpen(false); setSearchQuery('') }}
                    style={{ padding: '8px 14px', cursor: 'pointer', borderBottom: '1px solid var(--glass-border)', display: 'flex', gap: 8, alignItems: 'center' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(44,110,142,0.08)' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                  >
                    <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 4, background: 'rgba(44,110,142,0.12)', color: 'var(--accent-blue)', fontWeight: 600, textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      {c.status}
                    </span>
                    <span style={{ fontSize: 12, color: 'var(--text-primary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {c.title}
                    </span>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>case</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ width: 1, height: 24, background: 'var(--glass-border)' }} />

          {/* User */}
          <div className="user-controls" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.2 }}>
                {user?.username ?? '—'}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.2, fontVariantNumeric: 'tabular-nums' }}>
                {clock.toLocaleTimeString('en-US', { hour12: false })}
              </div>
            </div>
            {ADMIN_ITEMS.filter(i => hasRole(i.minRole ?? 'viewer')).length > 0 && (
              <div style={{ position: 'relative' }}>
                <button
                  onClick={() => setAdminMenuOpen(o => !o)}
                  aria-expanded={adminMenuOpen}
                  onBlur={() => setTimeout(() => setAdminMenuOpen(false), 150)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    padding: '5px 12px',
                    borderRadius: 7,
                    border: '1px solid var(--glass-border)',
                    background: adminMenuOpen ? 'rgba(44,110,142,0.1)' : 'transparent',
                    color: 'var(--text-secondary)',
                    fontSize: 12,
                    fontWeight: 500,
                    cursor: 'pointer',
                  }}
                >
                  Admin <ChevronDown size={13} />
                </button>
                {adminMenuOpen && (
                  <div style={{
                    position: 'absolute', top: '100%', right: 0, marginTop: 4,
                    background: 'var(--glass-bg-strong)', border: '1px solid var(--glass-border)', borderRadius: 8,
                    backdropFilter: 'var(--glass-blur)', WebkitBackdropFilter: 'var(--glass-blur)',
                    zIndex: 1000, overflow: 'hidden', minWidth: 160,
                    boxShadow: '0 18px 48px rgba(0,0,0,0.34)',
                  }}>
                    {ADMIN_ITEMS.filter(i => hasRole(i.minRole ?? 'viewer')).map(item => {
                      const Icon = item.icon
                      const active = isActive(item.to)
                      return (
                        <Link
                          key={item.to}
                          to={item.to}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 8,
                            padding: '8px 14px',
                            textDecoration: 'none',
                            background: active ? 'rgba(44,110,142,0.12)' : 'transparent',
                            color: active ? 'var(--accent-blue)' : 'var(--text-primary)',
                            fontSize: 12.5,
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
                padding: '5px 12px',
                borderRadius: 7,
                border: '1px solid var(--glass-border)',
                background: 'transparent',
                color: 'var(--text-muted)',
                fontSize: 12,
                fontWeight: 500,
                cursor: 'pointer',
              }}
            >
              Sign out
            </button>
          </div>
        </header>

        {/* Content */}
        <main id="main-content" tabIndex={-1} style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: 20 }}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
