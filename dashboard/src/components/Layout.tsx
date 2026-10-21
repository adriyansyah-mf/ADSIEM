import { useEffect, useRef, useState } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronRight, Menu, Search, Wifi, WifiOff } from 'lucide-react'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import AssistantWidget from '@/components/AssistantWidget'
import { AppSidebar, pageLabel } from '@/components/AppSidebar'
import type { Alert, Case } from '@/types'

interface SearchResults {
  readonly alerts: readonly Pick<Alert, 'id' | 'title'>[]
  readonly cases: readonly Pick<Case, 'id' | 'title'>[]
}

export default function Layout() {
  const { pathname } = useLocation()
  const { accessToken, user } = useAuthStore()
  const queryClient = useQueryClient()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('sidebar-collapsed') === '1')
  const [wsConnected, setWsConnected] = useState(false)
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const mobileNav = useRef<HTMLDialogElement>(null)
  const searchRegion = useRef<HTMLDivElement>(null)
  const searchInput = useRef<HTMLInputElement>(null)

  useEffect(() => { localStorage.setItem('sidebar-collapsed', collapsed ? '1' : '0') }, [collapsed])
  useEffect(() => {
    mobileNav.current?.close()
    setSearchOpen(false)
  }, [pathname])
  useEffect(() => {
    const timer = window.setTimeout(() => setQuery(search.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [search])
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        searchInput.current?.focus()
      }
      if (event.key === 'Escape') setSearchOpen(false)
    }
    const onPointer = (event: PointerEvent) => {
      if (event.target instanceof Node && !searchRegion.current?.contains(event.target)) setSearchOpen(false)
    }
    window.addEventListener('keydown', onKey)
    window.addEventListener('pointerdown', onPointer)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('pointerdown', onPointer)
    }
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

  const results = useQuery<SearchResults>({
    queryKey: ['global-search', query],
    queryFn: () => api.get('/api/search', { params: { q: query, limit: 5 } }).then(response => response.data),
    enabled: query.length >= 2,
  })
  const visibleResults = searchOpen && search.trim().length >= 2
  const currentLabel = pageLabel(pathname)

  return (
    <div className="app-shell">
      <a className="skip-link ui-button ui-button--primary" href="#workspace-content">Skip to content</a>
      <div className="desktop-navigation"><AppSidebar collapsed={collapsed} onCollapse={() => setCollapsed(value => !value)} /></div>
      <dialog className="mobile-navigation" ref={mobileNav} aria-label="Navigation">
        <AppSidebar onNavigate={() => mobileNav.current?.close()} onClose={() => mobileNav.current?.close()} />
      </dialog>
      <div className="app-main">
        <header className="app-header">
          <div className="app-header__location">
            <button className="ui-icon-button mobile-menu" onClick={() => mobileNav.current?.showModal()} aria-label="Open navigation"><Menu size={18} /></button>
            <span className="breadcrumb-root">Workspace</span><ChevronRight size={14} aria-hidden="true" />
            <span>{currentLabel}</span>
          </div>
          <div className="global-search" ref={searchRegion}>
            <Search size={16} aria-hidden="true" />
            <input ref={searchInput} id="global-search-input" aria-label="Search alerts and cases"
              value={search} placeholder="Search alerts and cases…" onChange={event => { setSearch(event.target.value); setSearchOpen(true) }}
              onFocus={() => setSearchOpen(true)} aria-expanded={visibleResults} aria-controls="global-search-results" />
            <kbd>⌘ / Ctrl K</kbd>
            {visibleResults && (
              <div className="global-search__results" id="global-search-results" aria-label="Search results">
                {query !== search.trim() || results.isPending ? <p role="status">Searching alerts and cases…</p>
                  : results.isError ? <p role="alert">Search is unavailable. Try again in a moment.</p>
                  : results.data && (
                    <>
                      {(['alerts', 'cases'] as const).map(type => (
                        <div key={type}>
                          <h2>{type === 'alerts' ? 'Alerts' : 'Cases'}</h2>
                          {results.data[type].map(item => <Link key={item.id} to={`/${type}/${item.id}`}>{item.title}</Link>)}
                        </div>
                      ))}
                      {results.data.alerts.length + results.data.cases.length === 0 && <p>No matching alerts or cases.</p>}
                    </>
                  )}
              </div>
            )}
          </div>
          <div className="workspace-scope" title={user?.group_id}>
            <span className="connection-state" title={wsConnected ? 'Live alert updates connected' : 'Live updates disconnected; lists still refresh automatically'}>
              {wsConnected ? <Wifi size={15} /> : <WifiOff size={15} />}
              <span>{wsConnected ? 'Live' : 'Polling'}</span>
            </span>
            <span className="workspace-scope__group">{user?.role === 'superadmin' ? 'All groups' : user?.group_id}</span>
          </div>
        </header>
        <main id="workspace-content" className="app-content" tabIndex={-1}><Outlet /></main>
      </div>
      <AssistantWidget />
    </div>
  )
}
