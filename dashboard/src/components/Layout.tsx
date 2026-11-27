import { Suspense, useEffect, useRef, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { Menu } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import AssistantWidget from '@/components/AssistantWidget'
import { QueryState } from '@/components/Workspace'
import { AppSidebar, SectionTabs, pageLabel, sectionFor } from '@/components/AppSidebar'
import CommandPalette, { type CommandPaletteHandle } from '@/components/CommandPalette'

export default function Layout() {
  const { pathname } = useLocation()
  const { accessToken } = useAuthStore()
  const queryClient = useQueryClient()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('sidebar-collapsed') === '1')
  const [wsConnected, setWsConnected] = useState(false)
  const mobileNav = useRef<HTMLDialogElement>(null)
  const palette = useRef<CommandPaletteHandle>(null)

  useEffect(() => { localStorage.setItem('sidebar-collapsed', collapsed ? '1' : '0') }, [collapsed])
  useEffect(() => { mobileNav.current?.close() }, [pathname])
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        palette.current?.open()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
  useEffect(() => {
    const onResize = () => { if (window.innerWidth >= 768) mobileNav.current?.close() }
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  useEffect(() => {
    if (!accessToken) return
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${protocol}://${window.location.host}/api/ws/alerts?token=${accessToken}`)
    ws.onopen = () => setWsConnected(true)
    ws.onclose = () => setWsConnected(false)
    ws.onmessage = event => {
      try {
        const data: unknown = JSON.parse(event.data)
        if (data && typeof data === 'object' && 'type' in data && data.type === 'new_alert') {
          for (const key of ['alerts-recent', 'alerts-dashboard', 'alerts', 'metrics']) {
            void queryClient.invalidateQueries({ queryKey: [key] })
          }
        }
      } catch (error) {
        if (!(error instanceof SyntaxError)) throw error
      }
    }
    const ping = window.setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping') }, 30_000)
    return () => { window.clearInterval(ping); ws.close() }
  }, [accessToken, queryClient])

  const section = sectionFor(pathname)
  const currentLabel = pageLabel(pathname)
  const openSearch = () => { mobileNav.current?.close(); palette.current?.open() }

  return (
    <div className="app-shell">
      <a className="skip-link ui-button ui-button--primary" href="#workspace-content">Skip to content</a>
      <div className="desktop-navigation">
        <AppSidebar collapsed={collapsed} onCollapse={() => setCollapsed(value => !value)} onOpenSearch={openSearch} />
      </div>
      <dialog className="mobile-navigation" ref={mobileNav} aria-label="Navigation">
        <AppSidebar onNavigate={() => mobileNav.current?.close()} onClose={() => mobileNav.current?.close()} onOpenSearch={openSearch} />
      </dialog>
      <div className="app-main">
        <header className="app-header">
          <button className="ui-icon-button mobile-menu" onClick={() => mobileNav.current?.showModal()} aria-label="Open navigation"><Menu size={18} /></button>
          <div className="app-header__location">
            <SectionTabs />
            <span className="app-header__crumb">
              {section && section.label !== currentLabel && <span className="app-header__crumb-root">{section.label} / </span>}
              <strong>{currentLabel}</strong>
            </span>
          </div>
          <div className="workspace-scope">
            <span className={`connection-state ${wsConnected ? 'connection-state--live' : ''}`}
              title={wsConnected ? 'Live alert updates connected' : 'Live updates disconnected; lists still refresh automatically'}>
              <span className="connection-state__dot" aria-hidden="true" />
              {wsConnected ? 'Live' : 'Polling'}
            </span>
          </div>
        </header>
        <main id="workspace-content" className="app-content" tabIndex={-1}>
          <Suspense fallback={<QueryState kind="loading" title="Loading…" description="Fetching this page." />}><Outlet /></Suspense>
        </main>
      </div>
      <CommandPalette ref={palette} />
      <AssistantWidget />
    </div>
  )
}
