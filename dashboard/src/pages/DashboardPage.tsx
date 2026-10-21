import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowRight, RefreshCw } from 'lucide-react'
import { format } from 'date-fns'
import { PageHeader, Panel, QueryState } from '@/components/Workspace'
import { AnalystWorkload, MetricCard, RecentActivity, ThreatLookup } from '@/components/DashboardWidgets'
import { AlertsOverTimeChart, SeverityBars, TopSourcesChart, MttrTrendChart } from '@/components/MetricsCharts'
import DataTable from '@/components/DataTable'
import type { Column } from '@/components/DataTable'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import { useAlerts } from '@/hooks/useAlerts'
import { useSocMetrics, useSocTimeseries, useTopSources, useMttrTrend } from '@/hooks/useMetrics'
import type { Alert } from '@/types'

const number = (value?: number) => value === undefined ? '—' : value.toLocaleString()
const minutes = (value?: number | null) => value == null ? '—' : value >= 60 ? `${(value / 60).toFixed(1)}h` : `${value.toFixed(1)}m`

export default function DashboardPage() {
  const navigate = useNavigate()
  const [days, setDays] = useState(7)
  const [since, setSince] = useState(() => new Date(Date.now() - 7 * 86_400_000).toISOString())
  const metrics = useSocMetrics(days)
  const timeseries = useSocTimeseries(days)
  const sources = useTopSources(days)
  const mttr = useMttrTrend(days)
  const queue = useAlerts(1, 8, { status: 'new', start_time: since })
  const reviewUrl = `/alerts?status=new&start_time=${encodeURIComponent(since)}`
  const refresh = () => { void metrics.refetch(); void timeseries.refetch(); void sources.refetch(); void mttr.refetch(); void queue.refetch() }
  const columns: readonly Column<Alert>[] = [
    { key: 'severity', header: 'Severity', render: row => <SeverityBadge severity={row.severity} /> },
    { key: 'title', header: 'Detection', render: row => <div className="table-primary">{row.title}
      <div className="table-secondary">{row.hostname ?? 'Unknown host'}{row.source_ip ? ` · ${row.source_ip}` : ''}</div></div> },
    { key: 'status', header: 'Status', render: row => <StatusBadge status={row.status} /> },
    { key: 'created_at', header: 'Detected', render: row => <time className="whitespace-nowrap" dateTime={row.created_at}>{format(new Date(row.created_at), 'dd MMM, HH:mm')}</time> },
  ]

  return <div className="workspace">
    <PageHeader eyebrow="Security operations" title="Operations overview"
      description="Your detection queue, response workload, and security trends in one workspace."
      actions={<>
        <select aria-label="Dashboard time window" className="ui-input w-auto" value={days}
          onChange={event => { const value = Number(event.target.value); setDays(value); setSince(new Date(Date.now() - value * 86_400_000).toISOString()) }}>
          <option value={1}>Last 24 hours</option><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option>
        </select>
        <button className="ui-icon-button" onClick={refresh} title="Refresh overview" aria-label="Refresh overview" disabled={metrics.isFetching}><RefreshCw size={16} /></button>
        <Link to={reviewUrl} className="ui-button ui-button--primary">Review new alerts <ArrowRight size={14} /></Link>
      </>} />
    <div className="state-banner">
      <span>{metrics.isFetching ? 'Updating overview…' : metrics.dataUpdatedAt ? `Updated ${format(new Date(metrics.dataUpdatedAt), 'HH:mm:ss')}` : 'Loading overview…'}</span>
      <span>· Server totals · Last {days === 1 ? '24 hours' : `${days} days`}</span>
    </div>
    {metrics.isError && <section className="panel"><QueryState kind="error" title="Overview metrics are unavailable"
      description={metrics.data ? 'The last successful totals are retained below. They may be out of date.' : 'Totals will appear after a successful refresh.'}
      onRetry={() => { void metrics.refetch() }} /></section>}
    <div className="metric-grid" aria-busy={metrics.isPending}>
      <MetricCard title="New alerts" value={metrics.data ? number(metrics.data.by_status.new ?? 0) : '—'} detail="Awaiting triage · selected window" to={reviewUrl} />
      <MetricCard title="Critical detections" value={metrics.data ? number(metrics.data.by_severity.critical ?? 0) : '—'} detail="All statuses · selected window" to={`/alerts?severity=critical&start_time=${encodeURIComponent(since)}`} />
      <MetricCard title="Active cases" value={number(metrics.data?.open_cases)} detail="Created in selected window" to="/cases" />
      <MetricCard title="Avg. acknowledgment" value={minutes(metrics.data?.avg_ack_minutes)} detail="Detected → acknowledged" />
    </div>
    <div className="dashboard-columns">
      <div className="dashboard-stack">
        <Panel title="Needs your team's attention" description={queue.data ? `Showing the latest ${queue.data.items.length} of ${queue.data.total.toLocaleString()} new alerts in this window` : 'Latest new alerts in the selected window'}
          actions={<Link className="ui-button ui-button--quiet" to={reviewUrl}>View queue <ArrowRight size={14} /></Link>}>
          {queue.isPending ? <QueryState kind="loading" title="Loading investigation queue…" />
            : queue.isError ? <QueryState kind="error" title="Could not load the queue" onRetry={() => { void queue.refetch() }} />
            : <DataTable columns={columns} data={queue.data.items} total={queue.data.total} page={1} pageSize={8}
              onPageChange={() => navigate(reviewUrl)} onRowClick={alert => navigate(`/alerts/${alert.id}`)}
              showToolbar={false} showPagination={false}
              exportFilename="new-alerts-preview.csv" emptyTitle="The new-alert queue is clear"
              emptyDescription="There are no new alerts in this time window. Open Alerts to review other statuses." />}
        </Panel>
        <Panel title="Detection volume" description={`Hourly alerts over the last ${days === 1 ? '24 hours' : `${days} days`}`}>
          {timeseries.isPending ? <QueryState kind="loading" title="Loading detection trend…" />
            : timeseries.isError ? <QueryState kind="error" title="Trend unavailable" onRetry={() => { void timeseries.refetch() }} />
            : <AlertsOverTimeChart points={timeseries.data.points} height={220} />}
        </Panel>
        <div className="dashboard-charts">
          <Panel title="Severity distribution" description="All detections in the selected window">
            {metrics.isPending ? <QueryState kind="loading" title="Loading severity totals…" />
              : metrics.isError ? <QueryState kind="error" title="Severity totals unavailable" onRetry={() => { void metrics.refetch() }} />
              : <SeverityBars bySeverity={metrics.data.by_severity} height={200} />}
          </Panel>
          <Panel title="Response trend" description="Daily acknowledgment and resolution times">
            {mttr.isPending ? <QueryState kind="loading" title="Loading response trend…" />
              : mttr.isError ? <QueryState kind="error" title="Response trend unavailable" onRetry={() => { void mttr.refetch() }} />
              : <MttrTrendChart points={mttr.data.points} height={200} />}
          </Panel>
        </div>
        <Panel title="Top source addresses" description="Server-ranked by detection count in the selected window">
          {sources.isPending ? <QueryState kind="loading" title="Loading source addresses…" />
            : sources.isError ? <QueryState kind="error" title="Source addresses unavailable" onRetry={() => { void sources.refetch() }} />
            : <TopSourcesChart sources={sources.data.sources} height={200} />}
        </Panel>
      </div>
      <div className="dashboard-stack"><AnalystWorkload /><RecentActivity /><ThreatLookup /></div>
    </div>
  </div>
}
