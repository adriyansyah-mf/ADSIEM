import { NavLink, matchPath, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Activity, Bell, BookOpen, ChartColumn, ClipboardList, CodeXml, Crosshair, FolderOpen, Hash, House,
  LayoutGrid, LogOut, Monitor, PanelLeftClose, PanelLeftOpen, Search, Settings, ShieldCheck, Terminal, Users,
  Workflow, X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

export interface NavPage {
  readonly to: string
  readonly label: string
  readonly minRole?: string
}

export interface NavSection {
  readonly key: string
  readonly label: string
  readonly icon: LucideIcon
  /** Every route this entry owns. The first visible one is where the entry links to;
   *  the rest show as tabs above the page, so nothing from the old 40-item menu is lost. */
  readonly pages: readonly NavPage[]
  readonly badge?: 'alerts' | 'cases'
}

// 18 entries, as in the redesign canvas. Pages that used to be top-level items now
// live under the entry they belong to.
export const NAVIGATION: readonly { readonly label: string | null; readonly items: readonly NavSection[] }[] = [
  { label: null, items: [
    { key: 'home', label: 'Home', icon: House, pages: [
      { to: '/', label: 'Overview' },
      { to: '/command-center', label: 'Command center' },
    ] },
  ] },
  { label: 'Triage', items: [
    { key: 'alerts', label: 'Alerts', icon: Bell, badge: 'alerts', pages: [{ to: '/alerts', label: 'Alerts' }] },
    { key: 'cases', label: 'Cases', icon: FolderOpen, badge: 'cases', pages: [{ to: '/cases', label: 'Cases' }] },
    { key: 'handover', label: 'Shift handover', icon: ClipboardList, pages: [{ to: '/handover', label: 'Shift handover' }] },
  ] },
  { label: 'Investigate', items: [
    { key: 'search', label: 'Search', icon: Search, pages: [
      { to: '/logs', label: 'Log search' },
      { to: '/events', label: 'Events' },
      { to: '/live-events', label: 'Live events' },
    ] },
    { key: 'hunts', label: 'Hunts', icon: Crosshair, pages: [
      { to: '/hunts', label: 'Threat hunting' },
      { to: '/retro-hunt', label: 'Retro-hunt' },
    ] },
    { key: 'entities', label: 'Entities & risk', icon: Users, pages: [
      { to: '/entity-risk', label: 'Entity risk' },
      { to: '/ueba', label: 'Behavior analytics' },
      { to: '/lateral', label: 'Lateral movement' },
    ] },
    { key: 'intel', label: 'Threat intel', icon: Hash, pages: [
      { to: '/threat-iocs', label: 'Threat IoCs' },
      { to: '/mitre-heatmap', label: 'MITRE coverage' },
    ] },
    { key: 'dashboards', label: 'Dashboards', icon: LayoutGrid, pages: [{ to: '/dashboards', label: 'Dashboards' }] },
  ] },
  { label: 'Respond', items: [
    { key: 'response', label: 'Live response', icon: Terminal, pages: [{ to: '/live-response', label: 'Live response' }] },
    { key: 'soar', label: 'Automations', icon: Workflow, pages: [{ to: '/soar', label: 'SOAR workflows', minRole: 'analyst' }] },
    { key: 'playbooks', label: 'Playbooks & knowledge', icon: BookOpen, pages: [
      { to: '/sop', label: 'Playbooks & SOPs' },
      { to: '/knowledge', label: 'Knowledge base' },
      { to: '/ai-skills', label: 'AI skills' },
    ] },
  ] },
  { label: 'Environment', items: [
    { key: 'endpoints', label: 'Endpoints', icon: Monitor, pages: [
      { to: '/agents', label: 'Agents' },
      { to: '/syslog', label: 'Syslog devices' },
      { to: '/agent-updates', label: 'Agent updates' },
    ] },
    { key: 'posture', label: 'Posture', icon: Activity, pages: [
      { to: '/hygiene', label: 'Security posture' },
      { to: '/vulnerabilities', label: 'Vulnerabilities' },
      { to: '/fim', label: 'File integrity' },
    ] },
    { key: 'protection', label: 'Protection', icon: ShieldCheck, pages: [
      { to: '/prevention', label: 'Prevention' },
      { to: '/policies', label: 'Policies' },
      { to: '/yara', label: 'YARA' },
      { to: '/malware-hashes', label: 'Malware hashes' },
      { to: '/web-protection', label: 'Web protection', minRole: 'analyst' },
      { to: '/ip-blocklist', label: 'IP blocklist', minRole: 'analyst' },
    ] },
    { key: 'rules', label: 'Detection rules', icon: CodeXml, pages: [
      { to: '/rules', label: 'Detection rules' },
      { to: '/rule-quality', label: 'Rule quality' },
      { to: '/decoders', label: 'Decoders' },
    ] },
    { key: 'reports', label: 'Reports', icon: ChartColumn, pages: [{ to: '/reports', label: 'Reports' }] },
  ] },
]

export const SETTINGS_SECTION: NavSection = {
  key: 'settings', label: 'Admin & settings', icon: Settings, pages: [
    { to: '/settings', label: 'Settings', minRole: 'admin' },
    { to: '/users', label: 'Users', minRole: 'superadmin' },
    { to: '/webhooks', label: 'Integrations', minRole: 'admin' },
    { to: '/audit-logs', label: 'Audit log', minRole: 'admin' },
  ],
}

export const ALL_SECTIONS: readonly NavSection[] = [...NAVIGATION.flatMap(group => group.items), SETTINGS_SECTION]

function pageMatches(page: NavPage, pathname: string): boolean {
  return page.to === '/' ? pathname === '/' : matchPath({ path: page.to, end: false }, pathname) !== null
}

export function sectionFor(pathname: string): NavSection | undefined {
  if (/^\/alerts\/[^/]+/.test(pathname)) return ALL_SECTIONS.find(section => section.key === 'alerts')
  if (/^\/cases\/[^/]+/.test(pathname)) return ALL_SECTIONS.find(section => section.key === 'cases')
  return ALL_SECTIONS.find(section => section.pages.some(page => pageMatches(page, pathname)))
}

export function pageLabel(pathname: string): string {
  if (/^\/alerts\/[^/]+/.test(pathname)) return 'Alert detail'
  if (/^\/cases\/[^/]+/.test(pathname)) return 'Case detail'
  return ALL_SECTIONS.flatMap(section => section.pages).find(page => pageMatches(page, pathname))?.label ?? 'Workspace'
}

export function useVisiblePages() {
  const hasRole = useAuthStore(state => state.hasRole)
  return (section: NavSection) => section.pages.filter(page => hasRole(page.minRole ?? 'viewer'))
}

/** Sibling pages of the current entry, shown as tabs in the top bar. */
export function SectionTabs() {
  const { pathname } = useLocation()
  const visible = useVisiblePages()
  const section = sectionFor(pathname)
  const pages = section ? visible(section) : []
  if (!section || pages.length < 2 || /^\/(alerts|cases)\/[^/]+/.test(pathname)) return null
  return (
    <nav className="section-tabs" aria-label={`${section.label} sections`}>
      {pages.map(page => (
        <NavLink key={page.to} to={page.to} end={page.to === '/'}
          className={({ isActive }) => `section-tabs__link ${isActive ? 'section-tabs__link--active' : ''}`}>
          {page.label}
        </NavLink>
      ))}
    </nav>
  )
}

function useCount(kind: 'alerts' | 'cases', enabled: boolean) {
  const url = kind === 'alerts' ? '/api/alerts' : '/api/cases'
  const status = kind === 'alerts' ? 'new' : 'open'
  return useQuery<number>({
    queryKey: [kind, 'nav-count', status],
    queryFn: () => api.get(url, { params: { status, page: 1, page_size: 1 } }).then(response => Number(response.data.total) || 0),
    enabled,
    refetchInterval: 60_000,
    staleTime: 30_000,
  })
}

export function AppSidebar({ collapsed = false, onCollapse, onNavigate, onClose, onOpenSearch }: {
  readonly collapsed?: boolean
  readonly onCollapse?: () => void
  readonly onNavigate?: () => void
  readonly onClose?: () => void
  readonly onOpenSearch?: () => void
}) {
  const { pathname } = useLocation()
  const { user, logout } = useAuthStore()
  const visible = useVisiblePages()
  const active = sectionFor(pathname)
  const alerts = useCount('alerts', Boolean(user))
  const cases = useCount('cases', Boolean(user))
  const counts = { alerts: alerts.data, cases: cases.data }

  const renderItem = (section: NavSection) => {
    const pages = visible(section)
    if (pages.length === 0) return null
    const Icon = section.icon
    const isActive = active?.key === section.key
    const count = section.badge ? counts[section.badge] : undefined
    return (
      <NavLink key={section.key} to={pages[0].to} end={pages[0].to === '/'} title={section.label} onClick={onNavigate}
        aria-current={isActive ? 'page' : undefined}
        className={`nav-link ${isActive ? 'nav-link--active' : ''}`}>
        <Icon size={18} strokeWidth={1.75} aria-hidden="true" />
        <span className="sidebar-label nav-link__text">{section.label}</span>
        {count !== undefined && count > 0 && (
          <span className={`nav-badge sidebar-label ${section.badge === 'alerts' ? 'nav-badge--alert' : ''}`}
            aria-label={`${count} ${section.badge === 'alerts' ? 'new alerts' : 'open cases'}`}>
            {count > 999 ? '999+' : count}
          </span>
        )}
      </NavLink>
    )
  }

  return (
    <aside className={`app-sidebar ${collapsed ? 'app-sidebar--collapsed' : ''}`}>
      <div className="app-brand">
        <span className="app-brand__mark" aria-hidden="true">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3 4 6v6c0 4.4 3.4 7.9 8 9 4.6-1.1 8-4.6 8-9V6z" /></svg>
        </span>
        <div className="sidebar-label"><strong>AD-SIEM</strong><span>Security operations</span></div>
        {onClose && <button className="ui-icon-button" onClick={onClose} aria-label="Close navigation"><X size={18} /></button>}
      </div>
      <div className="sidebar-scope sidebar-label">
        <span className="sidebar-scope__label">Scope</span>
        <span className="sidebar-scope__value">{user?.role === 'superadmin' ? 'All groups' : (user?.group_id ?? 'default')}</span>
      </div>
      {onOpenSearch && (
        <button type="button" className="sidebar-search" onClick={onOpenSearch} title="Search or jump to (Ctrl K)">
          <Search size={16} strokeWidth={1.75} aria-hidden="true" />
          <span className="sidebar-label">Search or jump to</span>
          <kbd className="sidebar-label">Ctrl K</kbd>
        </button>
      )}
      <nav className="app-navigation" aria-label="Main navigation">
        {NAVIGATION.map(group => {
          const items = group.items.filter(section => visible(section).length > 0)
          return items.length > 0 && (
            <div className="nav-group" key={group.label ?? 'top'}>
              {group.label && <div className="nav-group__label sidebar-label">{group.label}</div>}
              {items.map(renderItem)}
            </div>
          )
        })}
        <div className="nav-spacer" />
        {renderItem(SETTINGS_SECTION)}
      </nav>
      <div className="sidebar-footer">
        <div className="sidebar-user">
          <span className="sidebar-avatar" aria-hidden="true">{user?.username.slice(0, 2).toUpperCase()}</span>
          <div className="sidebar-label"><strong>{user?.username}</strong><span>{user?.role}</span></div>
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
