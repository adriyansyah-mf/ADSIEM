import { useState, useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { WorkflowSidebar } from './WorkflowSidebar'
import { OperationalTopbar } from './OperationalTopbar'

/** Orchestrates the three-zone shell (Ironwatch spec 3, "Shell anatomy"):
 * navigation, primary workspace, and — per-page — a context rail. Owns only
 * cross-cutting state (sidebar collapse, the live-alert WebSocket); everything
 * page-identity-specific lives in OperationalTopbar/WorkflowSidebar themselves. */
export default function AppShell() {
  const { accessToken } = useAuthStore()
  const queryClient = useQueryClient()
  const [collapsed, setCollapsed] = useState(false)
  const [wsConnected, setWsConnected] = useState(false)

  const { data: agentsData } = useQuery({
    queryKey: ['agents-health'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 100 } }).then(r => r.data),
    refetchInterval: 30_000,
  })

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
          queryClient.invalidateQueries({ queryKey: ['command-center'] })
        }
      } catch { /* non-JSON or unrecognized message, ignore */ }
    }
    const ping = setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping') }, 30000)
    return () => { clearInterval(ping); ws.close() }
  }, [accessToken, queryClient])

  const onlineCount = (agentsData?.items ?? []).filter((a: { status: string }) => a.status === 'online').length
  const totalCount = agentsData?.total ?? 0

  return (
    <div className="app-shell" style={{ display: 'flex', height: '100dvh', overflow: 'hidden', background: 'var(--bg-base)' }}>
      <a className="skip-link" href="#main-content">Skip to main content</a>

      <WorkflowSidebar
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed(c => !c)}
        onlineCount={onlineCount}
        totalCount={totalCount}
      />

      <div className="app-workspace" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        <OperationalTopbar wsConnected={wsConnected} />
        <main id="main-content" tabIndex={-1} style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: 20 }}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
