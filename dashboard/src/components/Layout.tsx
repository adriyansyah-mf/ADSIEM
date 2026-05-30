import { useState, useEffect } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import {
  LayoutDashboard, FileText, Activity, Bell, FolderOpen,
  Brain, HeartPulse, Lock, ScanLine, Crosshair,
  Terminal, Package, Server, BookOpen, Wrench, Shield,
  Users, Settings, PanelLeftClose, PanelLeftOpen,
  GitMerge, Webhook, ClipboardList,
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
    ],
  },
  {
    label: 'Response',
    items: [
      { to: '/live-response', label: 'Live Response', icon: Terminal },
      { to: '/artifacts', label: 'Artifacts', icon: Package },
    ],
  },
  {
    label: 'Configuration',
    items: [
      { to: '/agents', label: 'Agents', icon: Server },
      { to: '/rules', label: 'Rules', icon: BookOpen },
      { to: '/decoders', label: 'Decoders', icon: Wrench },
      { to: '/correlation', label: 'Correlation', icon: GitMerge },
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

type OpMode = 'MANUAL' | 'OBSERVER' | 'OPERATOR'

const MODE_COLOR: Record<OpMode, string> = {
  MANUAL:   '#f59e0b',
  OBSERVER: '#38bdf8',
  OPERATOR: '#34d399',
}

export default function Layout() {
  const { pathname } = useLocation()
  const { user, logout, hasRole, accessToken } = useAuthStore()
  const queryClient = useQueryClient()
  const [opMode, setOpMode] = useState<OpMode>('OBSERVER')
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
  const currentLabel = allItems.find(i => isActive(i.to))?.label ?? 'SIEM'

  const sidebarW = collapsed ? 56 : 216

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: '#0d0f14' }}>

      {/* ── Sidebar ── */}
      <aside style={{
        width: sidebarW,
        minWidth: sidebarW,
        display: 'flex',
        flexDirection: 'column',
        background: '#111318',
        borderRight: '1px solid #1e2028',
        transition: 'width 0.2s ease, min-width 0.2s ease',
        overflow: 'hidden',
      }}>

        {/* Logo */}
        <div style={{
          height: 52,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '0 16px',
          borderBottom: '1px solid #1e2028',
          flexShrink: 0,
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: 6,
            background: 'linear-gradient(135deg, #1d4ed8, #7c3aed)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          {!collapsed && (
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#f1f5f9', letterSpacing: '0.02em', lineHeight: 1.1 }}>
                SIEM Platform
              </div>
              <div style={{ fontSize: 10, color: '#64748b', letterSpacing: '0.04em' }}>
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
                  color: '#64748b',
                  textTransform: 'uppercase',
                }}>
                  {group.label}
                </div>
              )}
              {collapsed && gi > 0 && <div style={{ height: 1, background: '#1e2028', margin: '6px 10px' }} />}
              {visibleItems.map(item => {
                const active = isActive(item.to)
                const Icon = item.icon
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    title={collapsed ? item.label : undefined}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: collapsed ? '8px 0' : '7px 16px',
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      textDecoration: 'none',
                      background: active ? 'rgba(59,130,246,0.1)' : 'transparent',
                      borderLeft: active ? '2px solid #3b82f6' : '2px solid transparent',
                      color: active ? '#93c5fd' : '#64748b',
                      transition: 'color 0.12s, background 0.12s',
                    }}
                  >
                    <Icon size={15} strokeWidth={active ? 2 : 1.75} style={{ flexShrink: 0 }} />
                    {!collapsed && (
                      <span style={{
                        fontSize: 13,
                        fontWeight: active ? 500 : 400,
                        color: active ? '#e2e8f0' : '#94a3b8',
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
                  color: '#64748b',
                  textTransform: 'uppercase',
                }}>
                  Administration
                </div>
              )}
              {collapsed && <div style={{ height: 1, background: '#1e2028', margin: '6px 10px' }} />}
              {ADMIN_ITEMS.filter(i => hasRole(i.minRole ?? 'viewer')).map(item => {
                const active = isActive(item.to)
                const Icon = item.icon
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    title={collapsed ? item.label : undefined}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: collapsed ? '8px 0' : '7px 16px',
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      textDecoration: 'none',
                      background: active ? 'rgba(59,130,246,0.1)' : 'transparent',
                      borderLeft: active ? '2px solid #3b82f6' : '2px solid transparent',
                      color: active ? '#93c5fd' : '#64748b',
                      transition: 'color 0.12s, background 0.12s',
                    }}
                  >
                    <Icon size={15} strokeWidth={active ? 2 : 1.75} style={{ flexShrink: 0 }} />
                    {!collapsed && (
                      <span style={{
                        fontSize: 13,
                        fontWeight: active ? 500 : 400,
                        color: active ? '#e2e8f0' : '#94a3b8',
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
        <div style={{ borderTop: '1px solid #1e2028', flexShrink: 0 }}>
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
                  background: onlineCount > 0 ? '#34d399' : '#374151',
                  boxShadow: onlineCount > 0 ? '0 0 5px #34d399' : 'none',
                  flexShrink: 0,
                }} />
                <span style={{ fontSize: 12, color: '#64748b' }}>
                  <span style={{ color: onlineCount > 0 ? '#34d399' : '#64748b', fontWeight: 500 }}>{onlineCount}</span>
                  <span> / {totalCount} agents</span>
                </span>
              </div>
              <button
                onClick={() => setCollapsed(true)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748b', display: 'flex', padding: '8px', borderRadius: 4 }}
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
                cursor: 'pointer', color: '#64748b',
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
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>

        {/* Topbar */}
        <header style={{
          height: 52,
          flexShrink: 0,
          display: 'flex',
          alignItems: 'center',
          gap: 16,
          padding: '0 20px',
          background: '#111318',
          borderBottom: '1px solid #1e2028',
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <span style={{ fontSize: 15, fontWeight: 600, color: '#e2e8f0', letterSpacing: '0.01em' }}>
              {currentLabel}
            </span>
            {wsConnected && (
              <span
                title="Live feed connected"
                style={{ width: 6, height: 6, borderRadius: '50%', background: '#34d399', boxShadow: '0 0 6px #34d399', animation: 'pulse 2s infinite', flexShrink: 0, display: 'inline-block' }}
              />
            )}
          </span>

          {/* Global Search */}
          <div style={{ flex: 1, maxWidth: 320, position: 'relative', margin: '0 16px' }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: '#0d0f14', border: '1px solid #1e2028',
              borderRadius: 6, padding: '4px 10px',
            }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#475569" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
              </svg>
              <input
                value={searchQuery}
                onChange={e => { setSearchQuery(e.target.value); setSearchOpen(true); handleSearch(e.target.value) }}
                onFocus={() => setSearchOpen(true)}
                onBlur={() => setTimeout(() => setSearchOpen(false), 200)}
                placeholder="Search alerts, cases, IPs…"
                style={{
                  background: 'none', border: 'none', outline: 'none',
                  color: '#94a3b8', fontSize: 12, width: '100%',
                }}
              />
            </div>
            {searchOpen && searchResults && (searchResults.alerts.length > 0 || searchResults.cases.length > 0) && (
              <div style={{
                position: 'absolute', top: '100%', left: 0, right: 0, marginTop: 4,
                background: '#111318', border: '1px solid #1e2028', borderRadius: 6,
                zIndex: 1000, overflow: 'hidden', boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
              }}>
                {searchResults.alerts.map((a: any) => (
                  <div
                    key={a.id}
                    onMouseDown={() => { navigate('/alerts'); setSearchOpen(false); setSearchQuery('') }}
                    style={{ padding: '8px 14px', cursor: 'pointer', borderBottom: '1px solid #1e2028', display: 'flex', gap: 8, alignItems: 'center' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#1e2028' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                  >
                    <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(255,34,68,0.15)', color: '#ff2244', fontFamily: 'Share Tech Mono, monospace', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      {a.severity}
                    </span>
                    <span style={{ fontSize: 12, color: '#e2e8f0', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.title}
                    </span>
                    <span style={{ fontSize: 10, color: '#475569', whiteSpace: 'nowrap' }}>alert</span>
                  </div>
                ))}
                {searchResults.cases.map((c: any) => (
                  <div
                    key={c.id}
                    onMouseDown={() => { navigate(`/cases/${c.id}`); setSearchOpen(false); setSearchQuery('') }}
                    style={{ padding: '8px 14px', cursor: 'pointer', borderBottom: '1px solid #1e2028', display: 'flex', gap: 8, alignItems: 'center' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#1e2028' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent' }}
                  >
                    <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(0,212,255,0.1)', color: '#00d4ff', fontFamily: 'Share Tech Mono, monospace', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      {c.status}
                    </span>
                    <span style={{ fontSize: 12, color: '#e2e8f0', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {c.title}
                    </span>
                    <span style={{ fontSize: 10, color: '#475569', whiteSpace: 'nowrap' }}>case</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Op mode */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 1, background: '#0d0f14', borderRadius: 6, padding: 2 }}>
            {(['MANUAL', 'OBSERVER', 'OPERATOR'] as OpMode[]).map(mode => (
              <button
                key={mode}
                onClick={() => setOpMode(mode)}
                title={
                  mode === 'MANUAL'   ? 'Manual: all AI automation disabled — analyst drives everything' :
                  mode === 'OBSERVER' ? 'Observer: AI monitors and annotates, no automatic actions' :
                                       'Operator: AI-assisted response — automation rules execute automatically'
                }
                style={{
                  padding: '8px 12px',
                  borderRadius: 4,
                  border: 'none',
                  minHeight: 32,
                  background: opMode === mode ? '#1e2028' : 'transparent',
                  color: opMode === mode ? MODE_COLOR[mode] : '#475569',
                  fontSize: 11,
                  fontWeight: 600,
                  letterSpacing: '0.04em',
                  cursor: 'pointer',
                  transition: 'all 0.12s',
                }}
              >
                {mode}
              </button>
            ))}
          </div>

          <div style={{ width: 1, height: 24, background: '#1e2028' }} />

          {/* User */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 13, fontWeight: 500, color: '#cbd5e1', lineHeight: 1.2 }}>
                {user?.username ?? '—'}
              </div>
              <div style={{ fontSize: 11, color: '#475569', lineHeight: 1.2, fontVariantNumeric: 'tabular-nums' }}>
                {clock.toLocaleTimeString('en-US', { hour12: false })}
              </div>
            </div>
            <button
              onClick={logout}
              className="sign-out-btn"
              style={{
                padding: '5px 12px',
                borderRadius: 5,
                border: '1px solid #1e2028',
                background: 'transparent',
                color: '#64748b',
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
        <main style={{ flex: 1, overflow: 'auto', padding: 20 }}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
