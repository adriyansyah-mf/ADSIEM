import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowUpRight, Search } from 'lucide-react'
import { format } from 'date-fns'
import { Panel, QueryState } from '@/components/Workspace'
import { useAnalystWorkload, useQuickThreatLookup, useRecentEvents } from '@/hooks/useMetrics'

export function MetricCard({ title, value, detail, to }: {
  readonly title: string
  readonly value: string
  readonly detail: string
  readonly to?: string
}) {
  const content = <><span className="metric-card__label">{title}</span>
    <strong className="metric-card__value">{value}</strong><span className="metric-card__detail">{detail}</span></>
  return to ? <Link className="panel metric-card" to={to}>{content}</Link> : <div className="panel metric-card">{content}</div>
}

export function AnalystWorkload() {
  const query = useAnalystWorkload()
  const pool = query.data?.find(item => item.user_id === 'unassigned')
  const analysts = query.data?.filter(item => item.user_id !== 'unassigned').slice(0, 5) ?? []
  return <Panel title="Analyst workload" description="Current open assignments · all time"
    actions={<Link className="ui-button ui-button--quiet" to="/handover" aria-label="Open shift handover"><ArrowUpRight size={16} /></Link>}>
    {query.isPending ? <QueryState kind="loading" title="Loading workload…" />
      : query.isError ? <QueryState kind="error" title="Workload unavailable" onRetry={() => { void query.refetch() }} />
      : <>
        <div className="workload-row">
          <div><strong>Unassigned</strong><div className="workload-row__meta">{pool?.open_alerts ?? 0} alerts · {pool?.open_cases ?? 0} cases</div></div>
          <strong className="tabular-nums">{pool?.total ?? 0}</strong>
        </div>
        {analysts.map(item => <div className="workload-row" key={item.user_id}>
          <div className="workload-row__name">{item.username}<div className="workload-row__meta">{item.open_alerts} alerts · {item.open_cases} cases</div></div>
          <span className="tabular-nums">{item.total}</span>
        </div>)}
        {analysts.length === 0 && <p className="text-muted-foreground mt-3 mb-0">No active analysts in this workspace.</p>}
        {analysts.length > 0 && <p className="text-muted-foreground text-xs mt-3 mb-0">Up to five analysts, ordered by open workload.</p>}
      </>}
  </Panel>
}

export function RecentActivity() {
  const query = useRecentEvents()
  return <Panel title="Recent activity" description="Latest five decoded events" actions={<Link to="/events" className="ui-button ui-button--quiet">View events</Link>}>
    {query.isPending ? <QueryState kind="loading" title="Loading events…" />
      : query.isError ? <QueryState kind="error" title="Events unavailable" onRetry={() => { void query.refetch() }} />
      : query.data.items.length === 0 ? <QueryState kind="empty" title="No events received" description="Check agent connectivity and configured log sources." />
      : query.data.items.map(item => <div key={item.id} className="workload-row">
        <div className="min-w-0"><div className="break-words">{item.event_action ?? item.event_category ?? 'Decoded event'}</div>
          <div className="workload-row__meta font-mono">{item.source_ip ?? item.user_name ?? 'System'}</div></div>
        <time className="text-muted-foreground text-xs whitespace-nowrap" dateTime={item.created_at}>{format(new Date(item.created_at), 'HH:mm:ss')}</time>
      </div>)}
  </Panel>
}

export function ThreatLookup() {
  const [ioc, setIoc] = useState('')
  const [type, setType] = useState('ip')
  const query = useQuickThreatLookup()
  return <Panel title="Threat intelligence" description="Look up an indicator in configured providers">
    <form className="space-y-3" onSubmit={event => { event.preventDefault(); if (ioc.trim()) query.mutate({ ioc: ioc.trim(), ioc_type: type }) }}>
      <label className="field"><span>Indicator type</span><select className="ui-input" value={type} onChange={event => setType(event.target.value)}>
        <option value="ip">IP address</option><option value="hash">File hash</option><option value="domain">Domain</option><option value="url">URL</option>
      </select></label>
      <label className="field"><span>Indicator</span><input className="ui-input font-mono" value={ioc} onChange={event => setIoc(event.target.value)} required placeholder="For example, 203.0.113.9" /></label>
      <button className="ui-button" disabled={query.isPending || !ioc.trim()}><Search size={14} /> {query.isPending ? 'Looking up…' : 'Look up indicator'}</button>
    </form>
    {query.isError && <p role="alert" className="text-destructive mt-3">Lookup failed. Check your connection and try again.</p>}
    {query.data && <div className="mt-4">
      {query.data.status === 'worker_unreachable' ? <p role="alert" className="text-muted-foreground">Threat intelligence worker is unavailable. Try again later.</p>
        : <pre className="text-xs whitespace-pre-wrap break-all bg-background rounded p-3">{JSON.stringify(query.data, null, 2)}</pre>}
    </div>}
  </Panel>
}
