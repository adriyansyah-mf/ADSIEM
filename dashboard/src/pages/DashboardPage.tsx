import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { format, formatDistanceToNowStrict } from 'date-fns'
import { api } from '@/api/client'
import { QueryState } from '@/components/Workspace'
import { AnalystWorkload, RecentActivity, ThreatLookup } from '@/components/DashboardWidgets'
import { SeverityBars, TopSourcesChart, MttrTrendChart } from '@/components/MetricsCharts'
import SeverityBadge from '@/components/SeverityBadge'
import { useAlerts, useUpdateAlert } from '@/hooks/useAlerts'
import { useAgents } from '@/hooks/useAgents'
import { useSocMetrics, useSocTimeseries, useTopSources, useMttrTrend } from '@/hooks/useMetrics'
import type { TimeseriesPoint } from '@/hooks/useMetrics'
import { useAuthStore } from '@/stores/auth'
import type { Agent, Alert } from '@/types'

const WINDOWS = [{ days: 1, label: '24h' }, { days: 7, label: '7d' }, { days: 30, label: '30d' }] as const
const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const SEVERITY_FILL: Record<string, string> = { critical: '#FF5D6C', high: '#FF9F43', medium: '#F2D45C', low: '#4F6FB8' }

const number = (value?: number) => value === undefined ? '—' : value.toLocaleString()
const minutes = (value?: number | null) => value == null ? '—' : value >= 60 ? `${(value / 60).toFixed(1)}h` : `${Math.round(value)}m`
const age = (iso: string) => formatDistanceToNowStrict(new Date(iso)).replace(/ (\w)\w*$/, '$1').replace(' ', '')

interface MitreHeatmap { readonly tactics?: readonly { readonly techniques: readonly MitreCell[] }[]; readonly by_tactic?: Record<string, readonly MitreCell[]> }
interface MitreCell { readonly technique_id: string; readonly technique_name: string; readonly count: number }
interface AuditEntry { readonly id: string; readonly actor_name?: string | null; readonly action: string; readonly resource_type?: string | null; readonly created_at: string | null }

/** Buckets the hourly server series into at most ~30 stacked bars for the window. */
function bucketSeries(points: readonly TimeseriesPoint[], days: number) {
  const hours = days === 1 ? 1 : days === 7 ? 6 : 24
  const span = hours * 3_600_000
  const end = Math.ceil(Date.now() / 3_600_000) * 3_600_000
  const count = Math.ceil((days * 24) / hours)
  const start = end - count * span
  const bars = Array.from({ length: count }, (_, index) => ({ t: start + index * span, critical: 0, high: 0, medium: 0, low: 0, total: 0 }))
  for (const point of points) {
    const index = Math.floor((new Date(point.t).getTime() - start) / span)
    const bar = bars[index]
    if (!bar) continue
    const record = point as unknown as Record<string, number>
    for (const severity of SEVERITIES) bar[severity] += record[severity] ?? 0
    bar.total += point.total
  }
  return bars
}

function useMitreTop(days: number) {
  return useQuery<MitreCell[]>({
    queryKey: ['metrics', 'mitre-top', days],
    queryFn: () => api.get<MitreHeatmap>('/api/mitre/heatmap', { params: { days } }).then(({ data }) => {
      const cells = data.by_tactic ? Object.values(data.by_tactic).flat() : (data.tactics ?? []).flatMap(tactic => tactic.techniques)
      const merged = new Map<string, MitreCell>()
      for (const cell of cells) {
        const seen = merged.get(cell.technique_id)
        if (!seen || seen.count < cell.count) merged.set(cell.technique_id, cell)
      }
      return [...merged.values()].sort((a, b) => b.count - a.count).slice(0, 5)
    }),
    staleTime: 60_000,
  })
}

function useAuditTrail(enabled: boolean) {
  return useQuery<AuditEntry[]>({
    queryKey: ['audit-logs', 'overview'],
    queryFn: () => api.get('/api/audit-logs', { params: { limit: 5 } }).then(response => response.data),
    enabled,
    refetchInterval: 60_000,
  })
}

function initials(name?: string | null) {
  return (name ?? 'SY').replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase() || 'SY'
}

export default function DashboardPage() {
  const { user, hasRole } = useAuthStore()
  const [days, setDays] = useState(1)
  const since = useMemo(() => new Date(Date.now() - days * 86_400_000).toISOString(), [days])
  const metrics = useSocMetrics(days)
  const timeseries = useSocTimeseries(days)
  const sources = useTopSources(days)
  const mttr = useMttrTrend(Math.max(days, 7))
  const queue = useAlerts(1, 50, { status: 'new', start_time: since })
  const agents = useAgents(1, 500)
  const mitre = useMitreTop(Math.max(days, 7))
  const isAdmin = hasRole('admin')
  const audit = useAuditTrail(isAdmin)
  const updateAlert = useUpdateAlert()
  const canTriage = hasRole('analyst')
  const windowLabel = days === 1 ? 'last 24 hours' : `last ${days} days`
  const reviewUrl = `/alerts?status=new&start_time=${encodeURIComponent(since)}`

  const refresh = () => {
    for (const query of [metrics, timeseries, sources, mttr, queue, agents, mitre]) void query.refetch()
    if (isAdmin) void audit.refetch()
  }

  const priority = useMemo(() => [...(queue.data?.items ?? [])]
    .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || b.created_at.localeCompare(a.created_at))
    .slice(0, 6), [queue.data])
  const ownerless = useMemo(() => (queue.data?.items ?? []).filter(alert => alert.severity === 'critical' && !alert.assignee_id), [queue.data])
  const bars = useMemo(() => bucketSeries(timeseries.data?.points ?? [], days), [timeseries.data, days])
  const peak = Math.max(1, ...bars.map(bar => bar.total))

  const fleet = useMemo(() => {
    const items: readonly Agent[] = agents.data?.items ?? []
    const offline = items.filter(agent => agent.status !== 'online')
    const degraded = items.filter(agent => agent.status === 'online' && (agent.is_isolated
      || (agent.evidence && ['blocked', 'backlogged', 'degraded'].includes(agent.evidence.status))))
    const versions = new Map<string, number>()
    for (const agent of items) if (agent.version) versions.set(agent.version, (versions.get(agent.version) ?? 0) + 1)
    const newest = [...versions.keys()].sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))[0]
    return {
      total: agents.data?.total ?? items.length, online: items.length - offline.length,
      healthy: items.length - offline.length - degraded.length, degraded, offline,
      newest, onNewest: newest ? versions.get(newest) ?? 0 : 0,
      blocked: items.filter(agent => agent.evidence?.status === 'blocked'),
    }
  }, [agents.data])

  const openAlerts = metrics.data ? ['new', 'acknowledged', 'in_progress'].reduce((sum, key) => sum + (metrics.data.by_status[key] ?? 0), 0) : undefined
  const criticals = metrics.data?.by_severity.critical
  const assignAll = () => {
    if (!user) return
    for (const alert of ownerless.slice(0, 20)) updateAlert.mutate({ id: alert.id, data: { assignee_id: user.id, status: 'acknowledged' } })
  }

  const attention: { key: string; tone: 'critical' | 'warn' | 'info'; chip: string; meta: string; title: string; body: string; actions: React.ReactNode }[] = []
  if (ownerless.length > 0) attention.push({
    key: 'ownerless', tone: 'critical', chip: 'Critical', meta: `unassigned · ${age(ownerless[ownerless.length - 1].created_at)}`,
    title: `${ownerless.length} critical alert${ownerless.length === 1 ? ' has' : 's have'} no owner`,
    body: ownerless.slice(0, 2).map(alert => `${alert.title}${alert.hostname ? ` on ${alert.hostname}` : ''}`).join(' · '),
    actions: <>
      {canTriage && <button type="button" className="ov-btn ov-btn--primary" onClick={assignAll} disabled={updateAlert.isPending}>Assign to me</button>}
      <Link className="ov-btn" to={`/alerts?status=new&severity=critical`}>Review</Link>
    </>,
  })
  if (fleet.offline.length > 0) attention.push({
    key: 'offline', tone: 'warn', chip: 'Endpoints', meta: `${fleet.offline.length} of ${fleet.total}`,
    title: `${fleet.offline.length} endpoint${fleet.offline.length === 1 ? ' is' : 's are'} not reporting`,
    body: fleet.offline.slice(0, 3).map(agent => agent.hostname).join(', ') + (fleet.offline.length > 3 ? ` and ${fleet.offline.length - 3} more` : ''),
    actions: <Link className="ov-btn" to="/agents?status=offline">See endpoints</Link>,
  })
  if (fleet.blocked.length > 0) attention.push({
    key: 'evidence', tone: 'info', chip: 'Platform', meta: 'evidence delivery',
    title: `Evidence delivery is blocked on ${fleet.blocked.length === 1 ? fleet.blocked[0].hostname : `${fleet.blocked.length} endpoints`}`,
    body: fleet.blocked[0].evidence?.reason ?? 'The group evidence budget may be full. New evidence is rejected until space frees up.',
    actions: <Link className="ov-btn" to="/settings">Check storage</Link>,
  })

  return <div className="ov">
    <div className="ov-head">
      <div>
        <nav aria-label="Breadcrumb" className="ov-crumb">Home / <span>Overview</span></nav>
        <h1>Security operations overview</h1>
        <p className="ov-sub">
          {metrics.dataUpdatedAt ? `Data as of ${format(new Date(metrics.dataUpdatedAt), 'HH:mm:ss')}` : 'Loading…'} · {windowLabel} · refreshes automatically
        </p>
      </div>
      <div className="ov-head__actions">
        <div role="group" aria-label="Time window" className="ov-seg">
          {WINDOWS.map(option => (
            <button key={option.days} type="button" aria-pressed={days === option.days} onClick={() => setDays(option.days)}>{option.label}</button>
          ))}
        </div>
        <button type="button" className="ov-btn ov-btn--icon" onClick={refresh} aria-label="Refresh overview" title="Refresh overview" disabled={metrics.isFetching}><RefreshCw size={15} /></button>
        <Link to="/reports" className="ov-btn">Schedule report</Link>
        <Link to={reviewUrl} className="ov-btn ov-btn--primary">Review new alerts</Link>
      </div>
    </div>

    {metrics.isError && <section className="panel"><QueryState kind="error" title="Overview metrics are unavailable"
      description="Totals will appear after a successful refresh." onRetry={() => { void metrics.refetch() }} /></section>}

    {attention.length > 0 && (
      <section aria-label="Needs attention" className="ov-attention">
        {attention.map(item => (
          <article key={item.key} className={`ov-card ov-attn ov-attn--${item.tone}`}>
            <div className="ov-attn__meta"><span className={`ov-chip ov-chip--${item.tone}`}>{item.chip}</span><span>{item.meta}</span></div>
            <p className="ov-attn__title">{item.title}</p>
            <p className="ov-attn__body">{item.body}</p>
            <div className="ov-attn__actions">{item.actions}</div>
          </article>
        ))}
      </section>
    )}

    <section aria-label="Key metrics" className="ov-kpis" aria-busy={metrics.isPending}>
      <Link className="ov-card ov-kpi" to="/alerts?status=new">
        <p className="ov-kpi__label">Open alerts</p><p className="ov-kpi__value">{number(openAlerts)}</p>
        <p className="ov-kpi__detail">{number(metrics.data?.by_status.new)} new · {windowLabel}</p>
      </Link>
      <Link className="ov-card ov-kpi" to={`/alerts?severity=critical&start_time=${encodeURIComponent(since)}`}>
        <p className="ov-kpi__label">Critical, {days === 1 ? 'last 24h' : `last ${days}d`}</p><p className="ov-kpi__value">{number(criticals)}</p>
        <p className={`ov-kpi__detail ${ownerless.length ? 'is-warn' : ''}`}>{ownerless.length ? `${ownerless.length} new and unassigned` : 'none waiting without an owner'}</p>
      </Link>
      <div className="ov-card ov-kpi">
        <p className="ov-kpi__label">Mean time to acknowledge</p><p className="ov-kpi__value">{minutes(metrics.data?.avg_ack_minutes)}</p>
        <p className="ov-kpi__detail">resolve: {minutes(metrics.data?.avg_mttr_minutes)}</p>
      </div>
      <Link className="ov-card ov-kpi" to="/agents">
        <p className="ov-kpi__label">Endpoints reporting</p>
        <p className="ov-kpi__value">{agents.data ? fleet.online : '—'}<span> / {agents.data ? fleet.total : '—'}</span></p>
        <p className={`ov-kpi__detail ${fleet.offline.length ? 'is-warn' : ''}`}>{fleet.offline.length ? `${fleet.offline.length} offline` : 'all online'}</p>
      </Link>
    </section>

    <div className="ov-row">
      <section aria-labelledby="ov-volume" className="ov-card ov-panel ov-panel--wide">
        <div className="ov-panel__head">
          <h2 id="ov-volume">Detections per {days === 1 ? 'hour' : days === 7 ? '6 hours' : 'day'}</h2>
          <div className="ov-legend">{SEVERITIES.map(severity => <span key={severity}><i style={{ background: SEVERITY_FILL[severity] }} />{severity[0].toUpperCase() + severity.slice(1)}</span>)}</div>
        </div>
        {timeseries.isPending ? <QueryState kind="loading" title="Loading detection trend…" />
          : timeseries.isError ? <QueryState kind="error" title="Trend unavailable" onRetry={() => { void timeseries.refetch() }} />
          : <>
            <div className="ov-bars" role="img" aria-label={`Stacked bar chart of detections over the ${windowLabel}, peak ${peak} in one bar`}>
              {bars.map(bar => (
                <div key={bar.t} className="ov-bar" title={`${format(new Date(bar.t), days === 30 ? 'dd MMM' : 'dd MMM HH:mm')} · ${bar.total} detections`}>
                  {SEVERITIES.map(severity => bar[severity] > 0 && (
                    <div key={severity} style={{ height: `${(bar[severity] / peak) * 100}%`, background: SEVERITY_FILL[severity] }} />
                  ))}
                </div>
              ))}
            </div>
            <div className="ov-axis">
              {[0, 0.25, 0.5, 0.75].map(fraction => {
                const bar = bars[Math.floor(fraction * bars.length)]
                return <span key={fraction}>{bar ? format(new Date(bar.t), days === 1 ? 'HH:mm' : 'dd MMM') : ''}</span>
              })}
              <span>now</span>
            </div>
          </>}
      </section>

      <section aria-labelledby="ov-queue" className="ov-card ov-panel ov-panel--side">
        <div className="ov-panel__head"><h2 id="ov-queue">Priority queue</h2><Link to={reviewUrl}>All {number(queue.data?.total)}</Link></div>
        {queue.isPending ? <QueryState kind="loading" title="Loading queue…" />
          : queue.isError ? <QueryState kind="error" title="Could not load the queue" onRetry={() => { void queue.refetch() }} />
          : priority.length === 0 ? <QueryState kind="empty" title="The new-alert queue is clear" description={`No new alerts in the ${windowLabel}.`} />
          : priority.map((alert: Alert) => (
            <Link key={alert.id} to={`/alerts?open=${alert.id}`} className="ov-queue__row">
              <SeverityBadge severity={alert.severity} />
              <span className="ov-queue__text"><span>{alert.title}</span><span className="ov-mono">{alert.hostname ?? 'Unknown host'}</span></span>
              <span className="ov-queue__age">{age(alert.created_at)}</span>
            </Link>
          ))}
      </section>
    </div>

    <div className="ov-row ov-row--thirds">
      <section aria-labelledby="ov-mitre" className="ov-card ov-panel">
        <div className="ov-panel__head"><h2 id="ov-mitre">Top ATT&amp;CK techniques</h2><Link to="/mitre-heatmap">Coverage</Link></div>
        {mitre.isPending ? <QueryState kind="loading" title="Loading techniques…" />
          : mitre.isError ? <QueryState kind="error" title="Techniques unavailable" onRetry={() => { void mitre.refetch() }} />
          : mitre.data.length === 0 ? <QueryState kind="empty" title="No mapped techniques" description="Alerts in this window carry no ATT&CK mapping." />
          : mitre.data.map(cell => (
            <div key={cell.technique_id} className="ov-mitre">
              <div className="ov-mitre__line"><span><span className="ov-mono ov-accent">{cell.technique_id}</span> {cell.technique_name}</span><span>{cell.count.toLocaleString()}</span></div>
              <div className="ov-meter"><div style={{ width: `${(cell.count / mitre.data[0].count) * 100}%` }} /></div>
            </div>
          ))}
      </section>

      <section aria-labelledby="ov-fleet" className="ov-card ov-panel">
        <div className="ov-panel__head"><h2 id="ov-fleet">Fleet health</h2><Link to="/agents">Endpoints</Link></div>
        {agents.isPending ? <QueryState kind="loading" title="Loading endpoints…" />
          : agents.isError ? <QueryState kind="error" title="Endpoints unavailable" onRetry={() => { void agents.refetch() }} />
          : <>
            <div className="ov-stack" aria-hidden="true">
              <div style={{ flex: fleet.healthy, background: '#4CC38A' }} />
              <div style={{ flex: fleet.degraded.length, background: '#FF9F43' }} />
              <div style={{ flex: fleet.offline.length, background: '#5A6273' }} />
            </div>
            <ul className="ov-fleet">
              <li><span><i style={{ background: '#4CC38A' }} />Healthy</span><span>{fleet.healthy}</span></li>
              <li><span><i style={{ background: '#FF9F43' }} />Degraded (isolated or evidence held back)</span><span>{fleet.degraded.length}</span></li>
              <li><span><i style={{ background: '#5A6273' }} />Offline</span><span>{fleet.offline.length}</span></li>
              {fleet.newest && <li className="ov-fleet__foot"><span>On agent v{fleet.newest}</span><span>{fleet.onNewest} of {fleet.total}</span></li>}
            </ul>
          </>}
      </section>

      {isAdmin ? (
        <section aria-labelledby="ov-audit" className="ov-card ov-panel">
          <div className="ov-panel__head"><h2 id="ov-audit">Audit trail</h2><Link to="/audit-logs">All</Link></div>
          {audit.isPending ? <QueryState kind="loading" title="Loading audit trail…" />
            : audit.isError ? <QueryState kind="error" title="Audit trail unavailable" onRetry={() => { void audit.refetch() }} />
            : audit.data.length === 0 ? <QueryState kind="empty" title="No recorded activity" />
            : audit.data.map(entry => {
              const who = entry.actor_name ?? 'system'
              return (
                <div key={entry.id} className="ov-audit">
                  <span className="ov-avatar" title={who}>{initials(who)}</span>
                  <span className="ov-audit__text">{who} · {entry.action.replace(/[._]/g, ' ')}{entry.resource_type ? ` ${entry.resource_type}` : ''}</span>
                  <span className="ov-audit__at">{entry.created_at ? format(new Date(entry.created_at), 'HH:mm') : ''}</span>
                </div>
              )
            })}
        </section>
      ) : <RecentActivity />}
    </div>

    <h2 className="ov-section-title">More analytics</h2>
    <div className="ov-row ov-row--thirds">
      <section className="ov-card ov-panel" aria-labelledby="ov-sev">
        <div className="ov-panel__head"><h2 id="ov-sev">Severity distribution</h2></div>
        {metrics.isPending ? <QueryState kind="loading" title="Loading severity totals…" />
          : metrics.isError ? <QueryState kind="error" title="Severity totals unavailable" onRetry={() => { void metrics.refetch() }} />
          : <SeverityBars bySeverity={metrics.data.by_severity} height={200} />}
      </section>
      <section className="ov-card ov-panel" aria-labelledby="ov-mttr">
        <div className="ov-panel__head"><h2 id="ov-mttr">Response trend</h2></div>
        {mttr.isPending ? <QueryState kind="loading" title="Loading response trend…" />
          : mttr.isError ? <QueryState kind="error" title="Response trend unavailable" onRetry={() => { void mttr.refetch() }} />
          : <MttrTrendChart points={mttr.data.points} height={200} />}
      </section>
      <section className="ov-card ov-panel" aria-labelledby="ov-src">
        <div className="ov-panel__head"><h2 id="ov-src">Top source addresses</h2></div>
        {sources.isPending ? <QueryState kind="loading" title="Loading source addresses…" />
          : sources.isError ? <QueryState kind="error" title="Source addresses unavailable" onRetry={() => { void sources.refetch() }} />
          : <TopSourcesChart sources={sources.data.sources} height={200} />}
      </section>
    </div>
    <div className="ov-row ov-row--thirds">
      <AnalystWorkload />
      {isAdmin && <RecentActivity />}
      <ThreatLookup />
    </div>
  </div>
}
