import { NavLink } from 'react-router-dom'
import { Activity, Ban, Bell, BookOpen, Brain, ClipboardList, Crosshair, FileBarChart, FileText,
  FolderOpen, Grid3x3, HeartPulse, LayoutDashboard, Lock, LogOut, PanelLeftClose,
  PanelLeftOpen, Radio, ScanLine, Server, Settings, Shield, Terminal, Users, Webhook, Wrench, X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'

interface NavigationItem {
  readonly to: string
  readonly label: string
  readonly icon: LucideIcon
  readonly minRole?: string
}

export const NAVIGATION: readonly { readonly label: string; readonly items: readonly NavigationItem[] }[] = [
  { label: 'Operations', items: [
    { to: '/', label: 'Overview', icon: LayoutDashboard },
    { to: '/alerts', label: 'Alerts', icon: Bell },
    { to: '/cases', label: 'Cases', icon: FolderOpen },
    { to: '/handover', label: 'Shift handover', icon: ClipboardList },
  ] },
  { label: 'Investigation', items: [
    { to: '/logs', label: 'Log search', icon: FileText },
    { to: '/events', label: 'Events', icon: Activity },
    { to: '/live-events', label: 'Live events', icon: Radio },
    { to: '/hunts', label: 'Threat hunting', icon: Crosshair },
    { to: '/ueba', label: 'Behavior analytics', icon: Brain },
    { to: '/mitre-heatmap', label: 'MITRE coverage', icon: Grid3x3 },
  ] },
  { label: 'Response', items: [
    { to: '/live-response', label: 'Live response', icon: Terminal },
    { to: '/soar', label: 'SOAR workflows', icon: Shield, minRole: 'analyst' },
    { to: '/sop', label: 'Playbooks & SOPs', icon: BookOpen },
    { to: '/knowledge', label: 'Knowledge base', icon: BookOpen },
  ] },
  { label: 'Environment', items: [
    { to: '/agents', label: 'Agents', icon: Server },
    { to: '/hygiene', label: 'Security posture', icon: HeartPulse },
    { to: '/fim', label: 'File integrity', icon: Lock },
    { to: '/yara', label: 'YARA', icon: ScanLine },
    { to: '/prevention', label: 'Prevention', icon: Ban },
    { to: '/reports', label: 'Reports', icon: FileBarChart },
  ] },
  { label: 'Administration', items: [
    { to: '/rules', label: 'Detection rules', icon: BookOpen },
    { to: '/decoders', label: 'Decoders', icon: Wrench },
    { to: '/webhooks', label: 'Integrations', icon: Webhook, minRole: 'admin' },
    { to: '/audit-logs', label: 'Audit log', icon: ClipboardList, minRole: 'admin' },
    { to: '/users', label: 'Users', icon: Users, minRole: 'superadmin' },
    { to: '/settings', label: 'Settings', icon: Settings, minRole: 'admin' },
  ] },
]

export function pageLabel(pathname: string): string {
  if (/^\/alerts\/[^/]+/.test(pathname)) return 'Alert detail'
  if (/^\/cases\/[^/]+/.test(pathname)) return 'Case detail'
  return NAVIGATION.flatMap(group => group.items).find(item =>
    item.to === '/' ? pathname === '/' : pathname.startsWith(item.to))?.label ?? 'Workspace'
}

export function AppSidebar({ collapsed = false, onCollapse, onNavigate, onClose }: {
  readonly collapsed?: boolean
  readonly onCollapse?: () => void
  readonly onNavigate?: () => void
  readonly onClose?: () => void
}) {
  const { user, hasRole, logout } = useAuthStore()
  return (
    <aside className={`app-sidebar ${collapsed ? 'app-sidebar--collapsed' : ''}`}>
      <div className="app-brand">
        <img src="/logo.png" width={28} height={28} alt="" />
        <div className="sidebar-label"><strong>AD-SIEM</strong><span>Security operations</span></div>
        {onClose && <button className="ui-icon-button" onClick={onClose} aria-label="Close navigation"><X size={18} /></button>}
      </div>
      <nav className="app-navigation" aria-label="Main navigation">
        {NAVIGATION.map(group => {
          const items = group.items.filter(item => hasRole(item.minRole ?? 'viewer'))
          return items.length > 0 && (
            <div className="nav-group" key={group.label}>
              <div className="nav-group__label sidebar-label">{group.label}</div>
              {items.map(({ to, label, icon: Icon }) => (
                <NavLink key={to} to={to} end={to === '/'} title={label} onClick={onNavigate}
                  className={({ isActive }) => `nav-link ${isActive ? 'nav-link--active' : ''}`}>
                  <Icon size={17} strokeWidth={1.75} aria-hidden="true" />
                  <span className="sidebar-label">{label}</span>
                </NavLink>
              ))}
            </div>
          )
        })}
      </nav>
      <div className="sidebar-footer">
        <div className="sidebar-user sidebar-label">
          <span className="sidebar-avatar" aria-hidden="true">{user?.username.slice(0, 2).toUpperCase()}</span>
          <div><strong>{user?.username}</strong><span>{user?.role}</span></div>
        </div>
        <div className="control-cluster">
          <button className="ui-icon-button sign-out-btn" onClick={logout} title="Sign out" aria-label="Sign out"><LogOut size={16} /></button>
          {onCollapse && <button className="ui-icon-button sidebar-collapse" onClick={onCollapse}
            title={collapsed ? 'Expand navigation' : 'Collapse navigation'} aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}>
            {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          </button>}
        </div>
      </div>
    </aside>
  )
}
