import { Component, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight, Crosshair, Download, RefreshCw, Search, X } from 'lucide-react'
import { format, formatDistanceToNowStrict } from 'date-fns'
import { api } from '@/api/client'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import ProcessTree from '@/components/ProcessTree'
import { AlertSuppressions } from '@/components/AlertSuppressions'
import { AgentResponseDialog } from '@/components/AgentActions'
import { QueryState } from '@/components/Workspace'
import { AssetTierChip } from '@/components/AssetTier'
import { useUpdateAlert } from '@/hooks/useAlerts'
import { useAlertCases, useCreateCase } from '@/hooks/useCases'
import { useStartHunt } from '@/hooks/useHunts'
import { emitToast } from '@/hooks/useToast'
import { useAuthStore } from '@/stores/auth'
import { assetTierLabel } from '@/lib/assetTier'
import type { Alert, AlertDetail, PaginatedResponse } from '@/types'

const OPEN = 'new,acknowledged,in_progress'
const SEVERITY_RANK: Readonly<Record<Alert['severity'], number>> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const BULK_ACTIONS: readonly { readonly status: Alert['status']; readonly label: string }[] = [
  { status: 'acknowledged', label: 'Acknowledge' },
  { status: 'in_progress', label: 'In progress' },
  { status: 'false_positive', label: 'False positive' },
  { status: 'resolved', label: 'Resolve' },
]
const WINDOWS: readonly { readonly value: string; readonly label: string; readonly hours: number }[] = [
  { value: '1h', label: 'Last hour', hours: 1 },
  { value: '24h', label: 'Last 24h', hours: 24 },
  { value: '7d', label: 'Last 7 days', hours: 168 },
  { value: '30d', label: 'Last 30 days', hours: 720 },
  { value: '', label: 'All time', hours: 0 },
]

type View = 'mine' | 'unassigned' | 'critical' | 'open' | 'all' | 'suppressed'
type GroupBy = 'none' | 'title' | 'hostname'

interface ViewDef { readonly key: View; readonly label: string; readonly params: (userId?: string) => Record<string, string | boolean | undefined> }
const VIEWS: readonly ViewDef[] = [
  { key: 'mine', label: 'My queue', params: id => ({ status: OPEN, assignee_id: id }) },
  { key: 'unassigned', label: 'Unassigned', params: () => ({ status: OPEN, unassigned: true }) },
  { key: 'critical', label: 'Critical & high', params: () => ({ status: OPEN, severity: 'critical,high' }) },
  { key: 'open', label: 'All open', params: () => ({ status: OPEN }) },
  { key: 'all', label: 'All statuses', params: () => ({}) },
  { key: 'suppressed', label: 'Suppressed', params: () => ({ status: 'below_threshold' }) },
]

const age = (iso: string) => formatDistanceToNowStrict(new Date(iso)).replace(/ (\w)\w*$/, '$1').replace(' ', '')
const shortId = (id: string) => `ALR-${id.replace(/-/g, '').slice(0, 6).toUpperCase()}`

function useWideLayout(query = '(min-width: 1180px)') {
  const [wide, setWide] = useState(() => typeof window !== 'undefined' && window.matchMedia(query).matches)
  useEffect(() => {
    const media = window.matchMedia(query)
    const onChange = () => setWide(media.matches)
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [query])
  return wide
}

function useAlertQueue(page: number, pageSize: number, params: Record<string, unknown>, enabled = true) {
  return useQuery<PaginatedResponse<Alert>>({
    queryKey: ['alerts', 'queue', page, pageSize, params],
    queryFn: () => api.get('/api/alerts', { params: { page, page_size: pageSize, sort: 'priority', ...params } }).then(r => r.data),
    refetchInterval: 15_000,
    enabled,
  })
}

function useViewCount(params: Record<string, unknown>, enabled: boolean) {
  return useQuery<number>({
    queryKey: ['alerts', 'view-count', params],
    queryFn: () => api.get('/api/alerts', { params: { page: 1, page_size: 1, ...params } }).then(r => Number(r.data.total) || 0),
    refetchInterval: 30_000,
    enabled,
  })
}

function HuntButton({ alert }: { readonly alert: Alert }) {
  const navigate = useNavigate()
  const hunt = useStartHunt()
  const ioc = alert.source_ip || alert.hostname
  if (!ioc) return null
  return <button type="button" className="aq-btn" title={`Hunt ${ioc}`} disabled={hunt.isPending}
    onClick={() => hunt.mutate({ ioc_type: alert.source_ip ? 'ip' : 'hostname', ioc_value: ioc }, { onSuccess: () => navigate('/hunts') })}>
    <Crosshair size={14} aria-hidden="true" /> Hunt
  </button>
}

/** Keeps one broken panel (an unexpected process-tree payload) from blanking the whole queue. */
class PanelBoundary extends Component<{ readonly children: ReactNode }, { readonly failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  render() { return this.state.failed ? <p className="aq-muted">This panel could not be shown. Open the full detail instead.</p> : this.props.children }
}

function field(detail: AlertDetail | undefined, ...names: string[]): string | undefined {
  const data = detail?.event?.data ?? {}
  for (const name of names) {
    const value = data[name]
    if (value !== undefined && value !== null && value !== '') return String(value)
  }
  return undefined
}

function AlertPane({ alert, canTriage }: { readonly alert: Alert; readonly canTriage: boolean }) {
  const navigate = useNavigate()
  const user = useAuthStore(state => state.user)
  const update = useUpdateAlert()
  const createCase = useCreateCase()
  const linked = useAlertCases(alert.id)
  const [isolating, setIsolating] = useState(false)
  const detailQuery = useQuery<AlertDetail>({
    queryKey: ['alert-detail', alert.id],
    queryFn: () => api.get(`/api/alerts/${alert.id}`).then(r => r.data),
  })
  const detail = detailQuery.data
  const current = detail ?? alert
  const caseId = linked.data?.items[0]?.id
  const hostQuery = current.hostname ? `host.name:"${current.hostname}"` : current.source_ip ? `source.ip:"${current.source_ip}"` : ''
  const user_ = field(detail, 'user.name', 'user.target', 'winlog.event_data.TargetUserName')
  const process = field(detail, 'process.name', 'process.executable')
  const command = field(detail, 'process.command_line')
  const narrative = detail?.ueba?.ai_narrative ?? detail?.rule?.description ?? null
  const setStatus = (status: Alert['status']) => update.mutate({ id: alert.id, data: { status } })

  const escalate = () => {
    if (caseId) { navigate(`/cases/${caseId}`); return }
    createCase.mutate(
      { title: current.title, severity: current.severity, alert_id: current.id,
        description: `Escalated from alert ${shortId(current.id)} on ${current.hostname ?? 'an unknown host'}.` },
      { onSuccess: created => navigate(`/cases/${created.id}`) },
    )
  }

  return (
    <section className="aq-pane" aria-label="Alert detail">
      <div className="aq-pane__head">
        <div className="aq-pane__meta">
          <SeverityBadge severity={current.severity} />
          <span className="aq-mono">{shortId(current.id)} · first seen {age(current.created_at)} ago</span>
          <StatusBadge status={current.status} />
        </div>
        <h2>{current.title}</h2>
        {canTriage && (
          <div className="aq-pane__actions" role="group" aria-label="Triage actions">
            {current.status === 'new' && <button type="button" className="aq-btn aq-btn--primary" disabled={update.isPending}
              onClick={() => setStatus('acknowledged')}>Acknowledge</button>}
            <button type="button" className="aq-btn" onClick={escalate} disabled={createCase.isPending || linked.isPending}>
              {caseId ? 'Open case' : createCase.isPending ? 'Creating case…' : 'Escalate to case'}
            </button>
            {user && current.assignee_id !== user.id && <button type="button" className="aq-btn" disabled={update.isPending}
              onClick={() => update.mutate({ id: alert.id, data: { assignee_id: user.id } })}>Assign to me</button>}
            <label className="aq-status">
              <span className="sr-only">Set status</span>
              <select value="" onChange={event => { if (event.target.value) setStatus(event.target.value as Alert['status']) }} disabled={update.isPending}>
                <option value="">Set status…</option>
                {BULK_ACTIONS.filter(action => action.status !== current.status).map(action => <option key={action.status} value={action.status}>{action.label}</option>)}
              </select>
            </label>
            <HuntButton alert={current} />
            {detail?.agent && <button type="button" className="aq-btn aq-btn--danger" onClick={() => setIsolating(true)}>Isolate host</button>}
          </div>
        )}
      </div>

      <div className="aq-pane__body">
        <div className="aq-ai">
          <div className="aq-ai__top">
            <span className="aq-ai__label">AI triage assessment</span>
            <span>Verdict: <strong>{current.ai_verdict ? current.ai_verdict.replace(/_/g, ' ') : 'not assessed'}</strong></span>
          </div>
          <p>{narrative ?? (detailQuery.isPending ? 'Loading the detection context…' : 'No narrative was recorded for this alert. The full detail has the raw event and rule.')}</p>
          <div className="aq-ai__links"><Link to={`/alerts/${alert.id}`}>Open full detail</Link><Link to={`/alerts/${alert.id}#feedback`}>Report incorrect verdict</Link></div>
        </div>

        <div className="aq-facts">
          <div>
            <p className="aq-facts__label">Host</p>
            <p className="aq-facts__value">{current.hostname ?? '—'}</p>
            <p className="aq-facts__sub">
              {(current.asset_tier != null || current.asset_role) && <AssetTierChip tier={current.asset_tier} role={current.asset_role} />}
              {detail?.agent ? `agent ${detail.agent.status}` : current.source_ip ?? ''}
            </p>
          </div>
          <div>
            <p className="aq-facts__label">User</p>
            <p className="aq-facts__value">{user_ ?? '—'}</p>
            <p className="aq-facts__sub">{current.source_ip ? `from ${current.source_ip}${current.source_ip_country ? ` · ${current.source_ip_country}` : ''}` : ''}</p>
          </div>
          <div>
            <p className="aq-facts__label">Process</p>
            <p className="aq-facts__value">{process ?? '—'}</p>
            <p className="aq-facts__sub aq-mono" title={command}>{command ?? ''}</p>
          </div>
        </div>

        <div className="aq-split">
          <div className="aq-block aq-block--wide">
            <h3>Process tree</h3>
            <div className="aq-tree"><PanelBoundary><ProcessTree alertId={alert.id} /></PanelBoundary></div>
          </div>
          <div className="aq-block">
            <h3>Detection</h3>
            <dl className="aq-dl">
              <dt>Rule</dt><dd>{detail?.rule?.title ?? current.title}</dd>
              <dt>ATT&amp;CK</dt><dd className="aq-mono aq-accent">{(detail?.mitre.map(m => m.id) ?? current.mitre_techniques ?? []).join(' · ') || '—'}</dd>
              <dt>Source</dt><dd>{detail?.event?.log_type ?? detail?.event?.decoder ?? '—'}</dd>
              <dt>Grouped</dt><dd>{(current.duplicate_count ?? 0) + 1} event{current.duplicate_count ? 's' : ''}</dd>
              <dt>Rule, 24h</dt><dd>{detail ? `${detail.rule_fired_24h} firings` : '…'}</dd>
              {(current.asset_tier != null || current.asset_role) && <><dt>Asset</dt><dd>{assetTierLabel(current.asset_tier, current.asset_role)}</dd></>}
            </dl>
          </div>
        </div>

        <div className="aq-block">
          <h3>Related alerts on this host or address, 24h</h3>
          {!detail ? <p className="aq-muted">Loading…</p> : detail.related.length === 0 ? <p className="aq-muted">No other alerts from this host or address in the last 24 hours.</p> : (
            <div className="aq-related">
              <table>
                <thead><tr><th>Time</th><th>Alert</th><th>Severity</th><th>Status</th></tr></thead>
                <tbody>
                  {detail.related.slice(0, 8).map(item => (
                    <tr key={item.id} onClick={() => navigate(`/alerts?alert=${item.id}`)}>
                      <td className="aq-mono">{format(new Date(item.created_at), 'HH:mm:ss')}</td>
                      <td><Link to={`/alerts/${item.id}`}>{item.title}</Link></td>
                      <td><SeverityBadge severity={item.severity} /></td>
                      <td><StatusBadge status={item.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {hostQuery && <Link className="aq-link" to={`/logs?q=${encodeURIComponent(hostQuery)}`}>Open in Search with this {current.hostname ? 'host' : 'address'}</Link>}
        </div>
      </div>
      {isolating && detail?.agent && <AgentResponseDialog action="isolate" onClose={() => setIsolating(false)}
        agent={{ id: detail.agent.id, hostname: detail.agent.hostname, name: detail.agent.name, group_id: current.group_id }} />}
    </section>
  )
}

interface AlertGroup { readonly key: string; readonly items: readonly Alert[]; readonly top: Alert['severity']; readonly hosts: number; readonly latest: string }

function groupAlerts(items: readonly Alert[], by: Exclude<GroupBy, 'none'>): readonly AlertGroup[] {
  const map = new Map<string, Alert[]>()
  for (const alert of items) {
    const key = (by === 'title' ? alert.title : alert.hostname) || '(none)'
    map.set(key, [...(map.get(key) ?? []), alert])
  }
  return [...map.entries()].map(([key, group]) => ({
    key, items: group,
    top: group.reduce((best, alert) => SEVERITY_RANK[alert.severity] > SEVERITY_RANK[best] ? alert.severity : best, group[0].severity),
    hosts: new Set(group.map(alert => alert.hostname).filter(Boolean)).size,
    latest: group.reduce((last, alert) => alert.created_at > last ? alert.created_at : last, group[0].created_at),
  })).sort((a, b) => SEVERITY_RANK[b.top] - SEVERITY_RANK[a.top] || b.items.length - a.items.length)
}

export default function AlertsPage() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { user, hasRole } = useAuthStore()
  const canTriage = hasRole('analyst')
  const wide = useWideLayout()
  const listRef = useRef<HTMLDivElement>(null)
  const [page, setPage] = useState(1)
  const pageSize = 50
  const [checked, setChecked] = useState<ReadonlySet<string>>(new Set())

  // Explicit filters from links elsewhere (status/severity/hostname/source_ip/search/start_time) win over the saved view.
  const legacy = ['status', 'severity', 'hostname', 'source_ip', 'search', 'start_time', 'end_time'].some(key => params.get(key))
  const view = (VIEWS.some(v => v.key === params.get('view')) ? params.get('view') : legacy ? 'all' : 'open') as View
  const groupBy = (['title', 'hostname'].includes(params.get('group') ?? '') ? params.get('group') : 'none') as GroupBy
  const window_ = params.get('window') ?? ''
  const q = params.get('q') ?? ''
  const [qInput, setQInput] = useState(q)
  const severityFilter = params.get('severity') ?? ''
  const selectedId = params.get('alert') ?? undefined

  const set = (values: Readonly<Record<string, string>>) => {
    setParams(current => {
      const next = new URLSearchParams(current)
      for (const [key, value] of Object.entries(values)) { if (value) next.set(key, value); else next.delete(key) }
      return next
    }, { replace: true })
    if (!('alert' in values)) setPage(1)
  }
  useEffect(() => { setQInput(q) }, [q])
  useEffect(() => {
    const timer = window.setTimeout(() => { if (qInput.trim() !== q) set({ q: qInput.trim() }) }, 350)
    return () => window.clearTimeout(timer)
  }) // eslint-disable-line react-hooks/exhaustive-deps

  const openId = params.get('open')
  useEffect(() => { if (openId) set({ open: '', alert: openId }) }, [openId]) // eslint-disable-line react-hooks/exhaustive-deps

  const since = useMemo(() => {
    const hours = WINDOWS.find(w => w.value === window_)?.hours ?? 0
    return hours ? new Date(Math.floor(Date.now() / 60_000) * 60_000 - hours * 3_600_000).toISOString() : undefined
  }, [window_])

  const viewDef = VIEWS.find(v => v.key === view) ?? VIEWS[3]
  const queryParams = useMemo(() => {
    const base: Record<string, unknown> = { ...viewDef.params(user?.id) }
    for (const key of ['status', 'hostname', 'source_ip', 'search', 'start_time', 'end_time']) {
      const value = params.get(key)
      if (value) base[key] = value
    }
    if (severityFilter) base.severity = severityFilter
    if (q) base.q = q
    if (since && !base.start_time) base.start_time = since
    return base
  }, [viewDef, user?.id, params, severityFilter, q, since])

  const alerts = useAlertQueue(page, pageSize, queryParams)
  const items = useMemo(() => alerts.data?.items ?? [], [alerts.data])
  const selected = items.find(alert => alert.id === selectedId) ?? (wide && groupBy === 'none' ? items[0] : undefined)
  useEffect(() => { setChecked(new Set()) }, [page, queryParams])

  const counts = {
    mine: useViewCount(VIEWS[0].params(user?.id), Boolean(user)),
    unassigned: useViewCount(VIEWS[1].params(), true),
    critical: useViewCount(VIEWS[2].params(), true),
    open: useViewCount(VIEWS[3].params(), true),
  }
  const criticalOpen = useViewCount({ status: OPEN, severity: 'critical' }, true)

  const exportAll = useMutation({
    mutationFn: () => api.get('/api/export/alerts/csv', { responseType: 'blob' }),
    onSuccess: response => {
      const url = URL.createObjectURL(response.data)
      const link = document.createElement('a')
      link.href = url; link.download = 'all-alerts.csv'; link.click()
      URL.revokeObjectURL(url)
    },
    onError: () => emitToast('Could not export alerts. Please try again.', 'error'),
  })
  const bulkUpdate = useMutation({
    mutationFn: (nextStatus: Alert['status']) =>
      api.post<{ updated: number; not_found: string[] }>('/api/alerts/bulk-update', { ids: [...checked], status: nextStatus }).then(r => r.data),
    onSuccess: ({ updated, not_found }) => {
      void queryClient.invalidateQueries({ queryKey: ['alerts'] })
      setChecked(new Set())
      emitToast(not_found.length ? `Updated ${updated} alerts, ${not_found.length} no longer available` : `Updated ${updated} alerts`, not_found.length ? 'error' : 'success')
    },
    onError: () => emitToast('Could not update the selected alerts', 'error'),
  })
  const update = useUpdateAlert()

  const pick = (alert: Alert) => { if (wide) set({ alert: alert.id }); else navigate(`/alerts/${alert.id}`) }
  const toggle = (id: string) => setChecked(current => {
    const next = new Set(current)
    if (next.has(id)) next.delete(id); else next.add(id)
    return next
  })
  const allChecked = items.length > 0 && items.every(alert => checked.has(alert.id))

  // J/K move through the queue, A acknowledges the selected alert.
  useEffect(() => {
    if (!wide || groupBy !== 'none') return
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement
      if (event.ctrlKey || event.metaKey || event.altKey || target.closest('input, textarea, select, [contenteditable="true"], dialog')) return
      const index = selected ? items.findIndex(alert => alert.id === selected.id) : -1
      const key = event.key.toLowerCase()
      if (key === 'j' || key === 'k') {
        const next = items[Math.min(items.length - 1, Math.max(0, index + (key === 'j' ? 1 : -1)))]
        if (next) { event.preventDefault(); set({ alert: next.id }); listRef.current?.querySelector(`[data-id="${next.id}"]`)?.scrollIntoView({ block: 'nearest' }) }
      }
      if (key === 'a' && canTriage && selected && selected.status === 'new') { event.preventDefault(); update.mutate({ id: selected.id, data: { status: 'acknowledged' } }) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }) // eslint-disable-line react-hooks/exhaustive-deps

  const chips = (['status', 'hostname', 'source_ip', 'search', 'start_time'] as const).filter(key => params.get(key))
  const groups = groupBy === 'none' ? [] : groupAlerts(items, groupBy)
  const total = alerts.data?.total ?? 0
  const from = total ? (page - 1) * pageSize + 1 : 0
  const to = Math.min(total, page * pageSize)

  const list = alerts.isError ? <QueryState kind="error" title="Could not load alerts" description="Your filters are preserved. Try again." onRetry={() => { void alerts.refetch() }} />
    : alerts.isPending ? <QueryState kind="loading" title="Loading the queue…" />
    : items.length === 0 ? <QueryState kind="empty" title={view === 'mine' ? 'Nothing assigned to you' : 'No alerts in this view'}
      description={q || severityFilter || window_ || chips.length ? 'Clear the filters to widen the view.' : 'New detections will appear here as events are processed.'} />
    : groupBy !== 'none' ? (
      <ul className="aq-groups">
        {groups.map(group => <li key={group.key}>
          <button type="button" className="aq-group" onClick={() => set(groupBy === 'title'
            ? { q: group.key === '(none)' ? '' : group.key, group: '' }
            : { q: group.key === '(none)' ? '' : group.key, group: '' })}>
            <SeverityBadge severity={group.top} />
            <span className="aq-group__name">{group.key}</span>
            <span className="aq-muted">{group.items.length} alerts{groupBy === 'title' ? ` · ${group.hosts} hosts` : ''} · latest {age(group.latest)} ago</span>
          </button>
        </li>)}
      </ul>
    ) : (
      <div className="aq-rows" ref={listRef}>
        {items.map(alert => {
          const on = selected?.id === alert.id
          return (
            <div key={alert.id} data-id={alert.id} className={`aq-row ${on ? 'aq-row--on' : ''}`}>
              {canTriage && <input type="checkbox" className="aq-check" checked={checked.has(alert.id)} aria-label={`Select ${alert.title}`} onChange={() => toggle(alert.id)} />}
              <button type="button" className="aq-row__main" aria-pressed={on} onClick={() => pick(alert)}>
                <span className={`aq-sev severity-chip severity-chip--${alert.severity}`}>{alert.severity}</span>
                <span className="aq-row__text">
                  <span className="aq-row__title">{alert.title}</span>
                  <span className="aq-mono">{alert.hostname ?? alert.source_ip ?? 'Unknown host'}{alert.mitre_techniques?.length ? ` · ${alert.mitre_techniques[0]}` : ''}</span>
                  <span className="aq-row__meta">
                    {shortId(alert.id)} · {alert.assignee_id ? (alert.assignee_id === user?.id ? 'You' : 'Assigned') : 'Unassigned'} · {(alert.duplicate_count ?? 0) + 1} event{alert.duplicate_count ? 's' : ''}
                    {alert.status !== 'new' && <> · {alert.status.replace(/_/g, ' ')}</>}
                    {alert.asset_tier != null && <> · <AssetTierChip tier={alert.asset_tier} role={alert.asset_role} /></>}
                  </span>
                </span>
                <span className="aq-row__age">{age(alert.created_at)}</span>
              </button>
            </div>
          )
        })}
      </div>
    )

  return (
    <div className="aq">
      <header className="aq-head">
        <nav aria-label="Breadcrumb" className="aq-crumb">Triage / <span>Alerts</span></nav>
        <div className="aq-head__row">
          <div className="aq-head__title">
            <h1>Alert queue</h1>
            <span>{counts.open.data?.toLocaleString() ?? '—'} open · {criticalOpen.data?.toLocaleString() ?? '—'} critical</span>
          </div>
          <div className="aq-head__actions">
            <span className="aq-muted">Group by</span>
            <div role="group" aria-label="Group by" className="aq-seg">
              <button type="button" aria-pressed={groupBy === 'none'} onClick={() => set({ group: '' })}>Alert</button>
              <button type="button" aria-pressed={groupBy === 'title'} onClick={() => set({ group: 'title' })}>Detection</button>
              <button type="button" aria-pressed={groupBy === 'hostname'} onClick={() => set({ group: 'hostname' })}>Host</button>
            </div>
            <button type="button" className="aq-btn aq-btn--icon" onClick={() => { void alerts.refetch() }} disabled={alerts.isFetching} aria-label="Refresh" title="Refresh"><RefreshCw size={14} /></button>
            <button type="button" className="aq-btn" onClick={() => exportAll.mutate()} disabled={exportAll.isPending}
              title="Exports all alerts you can access, regardless of the filters"><Download size={14} aria-hidden="true" /> {exportAll.isPending ? 'Exporting…' : 'Export CSV'}</button>
          </div>
        </div>
        <nav aria-label="Saved views" className="aq-views">
          {VIEWS.map(v => {
            const count = v.key in counts ? counts[v.key as keyof typeof counts].data : undefined
            return (
              <button key={v.key} type="button" aria-current={view === v.key && !legacy ? 'true' : undefined}
                onClick={() => setParams(current => {
                  const next = new URLSearchParams()
                  for (const keep of ['group', 'window', 'q']) { const value = current.get(keep); if (value) next.set(keep, value) }
                  next.set('view', v.key)
                  return next
                }, { replace: true })}>
                {v.label}{count !== undefined && <span>{count.toLocaleString()}</span>}
              </button>
            )
          })}
        </nav>
      </header>

      <div className={`aq-body ${wide && groupBy === 'none' ? 'aq-body--split' : ''}`}>
        <section className="aq-list" aria-label="Alert list">
          <div className="aq-filters">
            <label className="aq-search">
              <Search size={15} aria-hidden="true" />
              <span className="sr-only">Filter alerts</span>
              <input type="search" value={qInput} onChange={event => setQInput(event.target.value)} placeholder="Filter: title, host or IP" />
            </label>
            <label className="aq-select"><span className="sr-only">Severity</span>
              <select value={severityFilter} onChange={event => set({ severity: event.target.value })}>
                <option value="">Severity: all</option>
                {['critical', 'high', 'medium', 'low', 'info'].map(value => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
              </select>
            </label>
            <label className="aq-select"><span className="sr-only">Time window</span>
              <select value={window_} onChange={event => set({ window: event.target.value })}>
                {WINDOWS.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
              </select>
            </label>
          </div>
          {chips.length > 0 && (
            <div className="aq-chips">
              {chips.map(key => <button type="button" key={key} className="aq-chip" onClick={() => set({ [key]: '' })}>
                {key.replace('_', ' ')}: {key === 'start_time' ? format(new Date(params.get(key) as string), 'dd MMM HH:mm') : params.get(key)} <X size={12} />
              </button>)}
            </div>
          )}
          {groupBy === 'none' && items.length > 0 && (
            <div className="aq-listbar">
              {canTriage && <label className="aq-listbar__all"><input type="checkbox" className="aq-check" checked={allChecked}
                onChange={() => setChecked(allChecked ? new Set() : new Set(items.map(alert => alert.id)))} />{checked.size ? `${checked.size} selected` : 'Select all'}</label>}
              {checked.size > 0 ? <div className="aq-listbar__bulk" role="group" aria-label="Bulk actions">
                {BULK_ACTIONS.map(action => <button type="button" key={action.status} className="aq-btn aq-btn--sm" disabled={bulkUpdate.isPending}
                  onClick={() => bulkUpdate.mutate(action.status)}>{action.label}</button>)}
              </div> : <>
                <span className="aq-listbar__hint">Sorted by priority, then age</span>
                {wide && <span className="aq-mono">J/K{canTriage ? ' · A ack' : ''}</span>}
              </>}
            </div>
          )}
          <div className="aq-list__scroll">{list}</div>
          {total > pageSize && (
            <div className="aq-pager">
              <span>{from}–{to} of {total.toLocaleString()}</span>
              <button type="button" className="aq-btn aq-btn--icon" aria-label="Previous page" disabled={page === 1} onClick={() => setPage(p => p - 1)}><ChevronLeft size={14} /></button>
              <button type="button" className="aq-btn aq-btn--icon" aria-label="Next page" disabled={to >= total} onClick={() => setPage(p => p + 1)}><ChevronRight size={14} /></button>
            </div>
          )}
        </section>

        {wide && groupBy === 'none' && (selected
          ? <AlertPane key={selected.id} alert={selected} canTriage={canTriage} />
          : <div className="aq-pane aq-pane--empty"><QueryState kind="empty" title="Select an alert" description="Its context, process tree and actions open here." /></div>)}
      </div>
      {(!wide || view === 'suppressed' || groupBy !== 'none') && <div className="aq-suppressions"><AlertSuppressions /></div>}
    </div>
  )
}
