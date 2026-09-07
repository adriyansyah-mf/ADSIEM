import { Link, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { COMMAND_CENTER, NAV_GROUPS, type NavItem } from './navGroups'

interface WorkflowSidebarProps {
  collapsed: boolean
  onToggleCollapse: () => void
  onlineCount: number
  totalCount: number
}

function NavLink({ item, collapsed, active }: { item: NavItem; collapsed: boolean; active: boolean }) {
  const Icon = item.icon
  return (
    <Link
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
        transition: 'color var(--motion-micro), background var(--motion-micro)',
      }}
    >
      <Icon size={15} strokeWidth={active ? 2 : 1.75} color={active ? 'var(--accent-blue)' : 'var(--text-muted)'} style={{ flexShrink: 0 }} />
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
}

export function WorkflowSidebar({ collapsed, onToggleCollapse, onlineCount, totalCount }: WorkflowSidebarProps) {
  const { pathname } = useLocation()
  const { hasRole } = useAuthStore()
  const isActive = (to: string) => (to === '/' ? pathname === '/' : pathname.startsWith(to))
  const sidebarW = collapsed ? 56 : 216

  return (
    <aside className="app-sidebar" style={{
      width: sidebarW,
      minWidth: sidebarW,
      display: 'flex',
      flexDirection: 'column',
      background: 'var(--bg-panel)',
      borderRight: '1px solid var(--border)',
      transition: 'width var(--motion-standard)',
      overflow: 'hidden',
    }}>
      {/* Logo */}
      <div style={{
        height: 52, display: 'flex', alignItems: 'center', gap: 10, padding: '0 16px',
        borderBottom: '1px solid var(--border)', flexShrink: 0,
      }}>
        <img src="/favicon.jpeg" alt="AD-SIEM" style={{ width: 28, height: 28, borderRadius: 4, objectFit: 'cover', flexShrink: 0 }} />
        {!collapsed && (
          <div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.1 }}>AD-SIEM</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.02em' }}>Security Operations</div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '8px 0' }}>
        <div style={{ marginBottom: 4 }}>
          <NavLink item={COMMAND_CENTER} collapsed={collapsed} active={isActive(COMMAND_CENTER.to)} />
        </div>
        {NAV_GROUPS.map((group, gi) => {
          const visibleItems = group.items.filter(i => hasRole(i.minRole ?? 'viewer'))
          if (visibleItems.length === 0) return null
          return (
            <div key={group.label} style={{ marginBottom: 4 }}>
              {!collapsed && (
                <div style={{
                  padding: gi === 0 ? '10px 16px 4px' : '12px 16px 4px',
                  fontSize: 10, fontWeight: 600, letterSpacing: '0.08em',
                  color: 'var(--text-muted)', textTransform: 'uppercase',
                }}>
                  {group.label}
                </div>
              )}
              {collapsed && <div style={{ height: 1, background: 'var(--border)', margin: '6px 10px' }} />}
              {visibleItems.map(item => (
                <NavLink key={item.to} item={item} collapsed={collapsed} active={isActive(item.to)} />
              ))}
            </div>
          )
        })}
      </nav>

      {/* Bottom: agent count + collapse */}
      <div style={{ borderTop: '1px solid var(--border)', flexShrink: 0 }}>
        {!collapsed ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
              <span style={{
                width: 7, height: 7, borderRadius: '50%',
                background: onlineCount > 0 ? 'var(--accent-green)' : 'var(--text-muted)',
                flexShrink: 0,
              }} />
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                <span style={{ color: onlineCount > 0 ? 'var(--accent-green)' : 'var(--text-muted)', fontWeight: 500 }}>{onlineCount}</span>
                <span> / {totalCount} agents</span>
              </span>
            </div>
            <button
              onClick={onToggleCollapse}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', padding: '8px', borderRadius: 4 }}
              title="Collapse sidebar"
            >
              <PanelLeftClose size={14} />
            </button>
          </div>
        ) : (
          <button
            onClick={onToggleCollapse}
            title="Expand sidebar"
            style={{
              width: '100%', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '14px 0',
            }}
          >
            <PanelLeftOpen size={14} />
          </button>
        )}
      </div>
    </aside>
  )
}
