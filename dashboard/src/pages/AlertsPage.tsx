import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Crosshair, Download, ExternalLink, Layers, List, RefreshCw, X } from 'lucide-react'
import { format, formatDistanceToNowStrict } from 'date-fns'
import { api } from '@/api/client'
import DataTable from '@/components/DataTable'
import type { Column } from '@/components/DataTable'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import { AlertSuppressions } from '@/components/AlertSuppressions'
import { PageHeader, QueryState } from '@/components/Workspace'
import { TimeRangeFilter } from '@/components/TimeRangeSelect'
import { useAlerts, useUpdateAlert } from '@/hooks/useAlerts'
import { useStartHunt } from '@/hooks/useHunts'
import { emitToast } from '@/hooks/useToast'
import { useAuthStore } from '@/stores/auth'
import type { Alert } from '@/types'

const SEVERITY_RANK: Readonly<Record<Alert['severity'], number>> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const TRIAGE_ACTIONS: readonly { readonly status: Alert['status']; readonly label: string }[] = [
  { status: 'acknowledged', label: 'Acknowledge' },
  { status: 'in_progress', label: 'In progress' },
  { status: 'false_positive', label: 'False positive' },
  { status: 'resolved', label: 'Resolve' },
]
type GroupBy = 'none' | 'title' | 'hostname'

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

function HuntButton({ alert }: { readonly alert: Alert }) {
  const navigate = useNavigate()
  const hunt = useStartHunt()
  const ioc = alert.source_ip || alert.hostname
  if (!ioc) return null
  return <button className="ui-button" title={`Hunt ${ioc}`} disabled={hunt.isPending}
    onClick={event => {
      event.stopPropagation()
      hunt.mutate({ ioc_type: alert.source_ip ? 'ip' : 'hostname', ioc_value: ioc }, { onSuccess: () => navigate('/hunts') })
    }}><Crosshair size={14} aria-hidden="true" /> Hunt</button>
}

function AlertPreview({ alert, canTriage, onClose }: {
  readonly alert: Alert
  readonly canTriage: boolean
  readonly onClose: () => void
}) {
  const update = useUpdateAlert()
  const detected = new Date(alert.created_at)
  const facts: readonly [string, string | null | undefined][] = [
    ['Host', alert.hostname],
    ['Source IP', alert.source_ip ? `${alert.source_ip}${alert.source_ip_country ? ` · ${alert.source_ip_country}` : ''}` : null],
    ['Detected', `${format(detected, 'dd MMM yyyy, HH:mm:ss')} · ${formatDistanceToNowStrict(detected)} ago`],
    ['Kill chain', alert.kill_chain_stage],
    ['Repeats', alert.duplicate_count ? `${alert.duplicate_count} duplicates merged` : null],
    ['Correlation', alert.context?.correlation_hit_count ? `${alert.context.correlation_hit_count} hits${alert.context.correlation_group ? ` by ${alert.context.correlation_group}` : ''}` : null],
  ]
  return (
    <aside className="alert-preview panel" aria-label="Alert preview">
      <div className="alert-preview__head">
        <div className="control-cluster"><SeverityBadge severity={alert.severity} /><StatusBadge status={alert.status} /></div>
        <button className="ui-icon-button" onClick={onClose} aria-label="Close preview"><X size={16} /></button>
      </div>
      <h2 className="alert-preview__title">{alert.title}</h2>
      {alert.mitre_techniques?.length ? <div className="alert-preview__tags">{alert.mitre_techniques.map(technique =>
        <span key={technique} className="font-mono">{technique}</span>)}</div> : null}
      {alert.ai_verdict && <div className="alert-preview__ai">
        <span className="alert-preview__label">AI triage assessment</span>
        <strong>{alert.ai_verdict.replace(/_/g, ' ')}</strong>
        <span className="table-secondary">Open the full detail to see the reasoning and give feedback.</span>
      </div>}
      <dl className="alert-preview__facts">
        {facts.filter(([, value]) => value).map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}
      </dl>
      {alert.context?.tags?.length ? <div className="alert-preview__tags">{alert.context.tags.slice(0, 8).map(tag => <span key={tag}>{tag}</span>)}</div> : null}
      {canTriage && <div className="alert-preview__actions" role="group" aria-label="Triage">
        {TRIAGE_ACTIONS.map(action => <button key={action.status} className="ui-button"
          disabled={update.isPending || alert.status === action.status}
          onClick={() => update.mutate({ id: alert.id, data: { status: action.status } })}>{action.label}</button>)}
      </div>}
      <div className="control-cluster">
        <Link className="ui-button ui-button--primary" to={`/alerts/${alert.id}`}><ExternalLink size={14} aria-hidden="true" /> Open full detail</Link>
        <HuntButton alert={alert} />
      </div>
    </aside>
  )
}

interface AlertGroup {
  readonly key: string
  readonly items: readonly Alert[]
  readonly top: Alert['severity']
  readonly hosts: number
  readonly latest: string
}

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
  const hasRole = useAuthStore(state => state.hasRole)
  const canTriage = hasRole('analyst')
  const wide = useWideLayout()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [searchInput, setSearchInput] = useState(params.get('search') ?? '')
  const [selectedId, setSelectedId] = useState<string>()
  const [checked, setChecked] = useState<ReadonlySet<string>>(new Set())
  const status = params.get('status') ?? ''
  const severity = params.get('severity') ?? ''
  const hostname = params.get('hostname') ?? ''
  const sourceIp = params.get('source_ip') ?? ''
  const search = params.get('search') ?? ''
  const start = params.get('start_time') ?? ''
  const end = params.get('end_time') ?? ''
  const groupBy = (['title', 'hostname'].includes(params.get('group') ?? '') ? params.get('group') : 'none') as GroupBy

  useEffect(() => { setSearchInput(search) }, [search])

  const updateFilters = (values: Readonly<Record<string, string>>) => {
    setParams(current => {
      const next = new URLSearchParams(current)
      for (const [key, value] of Object.entries(values)) {
        if (value) next.set(key, value)
        else next.delete(key)
      }
      return next
    })
    setPage(1)
  }
  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (searchInput !== search) {
        setParams(current => {
          const next = new URLSearchParams(current)
          if (searchInput.trim()) next.set('search', searchInput.trim())
          else next.delete('search')
          return next
        })
        setPage(1)
      }
    }, 400)
    return () => window.clearTimeout(timer)
  }, [searchInput, search, setParams])
  const openId = params.get('open')
  useEffect(() => { if (openId) navigate(`/alerts/${openId}`, { replace: true }) }, [openId, navigate])

  const alerts = useAlerts(page, pageSize, {
    status: status || undefined, severity: severity || undefined,
    hostname: hostname || undefined, source_ip: sourceIp || undefined, search: search || undefined,
    start_time: start || undefined, end_time: end || undefined,
  })
  const items = useMemo(() => alerts.data?.items ?? [], [alerts.data])
  const selected = items.find(alert => alert.id === selectedId)
  useEffect(() => { setChecked(new Set()) }, [page, pageSize, status, severity, hostname, sourceIp, search, start, end])

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
    mutationFn: async (nextStatus: Alert['status']) => {
      const results = await Promise.allSettled([...checked].map(id => api.put(`/api/alerts/${id}`, { status: nextStatus })))
      return { ok: results.filter(result => result.status === 'fulfilled').length, failed: results.filter(result => result.status === 'rejected').length }
    },
    onSuccess: ({ ok, failed }) => {
      void queryClient.invalidateQueries({ queryKey: ['alerts'] })
      setChecked(new Set())
      emitToast(failed ? `Updated ${ok} alerts, ${failed} failed` : `Updated ${ok} alerts`, failed ? 'error' : 'success')
    },
  })

  const toggle = (id: string) => setChecked(current => {
    const next = new Set(current)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    return next
  })
  const allChecked = items.length > 0 && items.every(alert => checked.has(alert.id))

  const columns: readonly Column<Alert>[] = [
    ...(canTriage ? [{ key: 'select', header: '', render: (row: Alert) => <input type="checkbox" className="alert-check"
      checked={checked.has(row.id)} aria-label={`Select ${row.title}`}
      onClick={event => event.stopPropagation()} onChange={() => toggle(row.id)} /> }] : []),
    { key: 'severity', header: 'Severity', render: row => <SeverityBadge severity={row.severity} /> },
    { key: 'title', header: 'Detection', render: row => <div className="table-primary">{row.title}
      {row.mitre_techniques?.length ? <div className="table-secondary">{row.mitre_techniques.join(' · ')}</div> : null}
    </div> },
    { key: 'status', header: 'Status', render: row => <StatusBadge status={row.status} /> },
    { key: 'hostname', header: 'Host', render: row => <span className="font-mono">{row.hostname ?? '—'}</span> },
    { key: 'source_ip', header: 'Source IP', render: row => <div className="font-mono">{row.source_ip ?? '—'}
      {row.source_ip_country && <div className="table-secondary">{row.source_ip_country}</div>}</div> },
    { key: 'created_at', header: 'Detected', render: row => <time className="whitespace-nowrap" dateTime={row.created_at}
      title={new Date(row.created_at).toLocaleString()}>{format(new Date(row.created_at), 'dd MMM, HH:mm:ss')}</time>,
      exportValue: row => row.created_at },
    { key: 'country', header: 'Country', hiddenByDefault: true, render: row => row.source_ip_country ?? '—', exportValue: row => row.source_ip_country ?? '' },
    { key: 'hunt', header: '', render: row => <HuntButton alert={row} /> },
  ]
  const activeFilters = Boolean(search || hostname || sourceIp || severity || status || start || end)
  const clearFilters = () => { setSearchInput(''); setParams({}); setPage(1) }
  const groups = groupBy === 'none' ? [] : groupAlerts(items, groupBy)

  const body = alerts.isError ? <section className="panel"><QueryState kind="error" title="Could not load alerts"
    description="Your filters are preserved. Check your connection and try again." onRetry={() => { void alerts.refetch() }} /></section>
    : alerts.isPending ? <section className="panel"><QueryState kind="loading" title="Loading detections…"
      description="Fetching alerts for this workspace." /></section>
    : groupBy !== 'none' ? (
      <section className="panel alert-groups" aria-label={`Alerts grouped by ${groupBy === 'title' ? 'detection' : 'host'}`}>
        <p className="table-secondary alert-groups__note">Grouping the {items.length} alerts on this page. Choose a group to filter the list to it.</p>
        {groups.length === 0 ? <QueryState kind="empty" title="No alerts to group" description="Widen the filters to see groups." />
          : <ul>{groups.map(group => <li key={group.key}>
            <button className="alert-group" onClick={() => updateFilters(groupBy === 'title'
              ? { search: group.key === '(none)' ? '' : group.key, group: '' }
              : { hostname: group.key === '(none)' ? '' : group.key, group: '' })}>
              <SeverityBadge severity={group.top} />
              <span className="alert-group__name">{group.key}</span>
              <span className="table-secondary">{group.items.length} alerts{groupBy === 'title' ? ` · ${group.hosts} hosts` : ''} · latest {formatDistanceToNowStrict(new Date(group.latest))} ago</span>
            </button>
          </li>)}</ul>}
      </section>
    ) : (
      <DataTable columns={columns} data={items} total={alerts.data.total} page={page} pageSize={pageSize}
        onPageChange={setPage} onPageSizeChange={setPageSize}
        onRowClick={alert => wide ? setSelectedId(current => current === alert.id ? undefined : alert.id) : navigate(`/alerts/${alert.id}`)}
        exportFilename="alerts-page.csv" emptyTitle="No alerts match this view"
        emptyDescription={activeFilters ? 'Try a wider time window or clear the filters above.' : 'New detections will appear here as events are processed.'} />
    )

  return (
    <div className="workspace">
      <PageHeader eyebrow="Triage" title="Alerts"
        description="Triage detections, investigate the evidence, and track response."
        actions={<>
          <button className="ui-button" onClick={() => { void alerts.refetch() }} disabled={alerts.isFetching}>
            <RefreshCw size={14} aria-hidden="true" /> Refresh
          </button>
          <button className="ui-button" onClick={() => exportAll.mutate()} disabled={exportAll.isPending}
            title="Exports all alerts you can access, regardless of the filters below">
            <Download size={14} aria-hidden="true" /> {exportAll.isPending ? 'Exporting…' : 'Export all alerts'}
          </button>
        </>} />
      <section className="panel" aria-label="Alert filters">
        <div className="filter-bar">
          <label className="field"><span>Search detections</span><input className="ui-input" value={searchInput}
            placeholder="Search by title…" onChange={event => setSearchInput(event.target.value)} /></label>
          <label className="field"><span>Hostname</span><input className="ui-input" value={hostname} placeholder="Any hostname"
            onChange={event => updateFilters({ hostname: event.target.value })} /></label>
          <label className="field"><span>Severity</span><select className="ui-input" value={severity}
            onChange={event => updateFilters({ severity: event.target.value })}>
            <option value="">All severities</option>{['critical', 'high', 'medium', 'low', 'info'].map(value => <option key={value} value={value}>{value.charAt(0).toUpperCase() + value.slice(1)}</option>)}
          </select></label>
          <label className="field"><span>Status</span><select className="ui-input" value={status}
            onChange={event => updateFilters({ status: event.target.value })}>
            <option value="">All statuses</option><option value="new">New</option><option value="in_progress">In progress</option>
            <option value="acknowledged">Acknowledged</option><option value="below_threshold">Below threshold</option>
            <option value="resolved">Resolved</option><option value="false_positive">False positive</option>
          </select></label>
          <div className="field"><span id="alert-time-label">Time window</span>
            <TimeRangeFilter value={{ start_time: start || undefined, end_time: end || undefined }}
              onChange={range => updateFilters({ start_time: range.start_time ?? '', end_time: range.end_time ?? '' })}
              selectClassName="ui-input" inputClassName="ui-input" />
          </div>
        </div>
        <div className="filter-footer">
          <span>{alerts.isFetching ? 'Updating results…' : alerts.dataUpdatedAt ? `Updated ${format(new Date(alerts.dataUpdatedAt), 'HH:mm:ss')} · refreshes every 15 seconds` : 'Waiting for detections'}</span>
          <div className="control-cluster">
            {sourceIp && <button className="ui-button" onClick={() => updateFilters({ source_ip: '' })}>Source: {sourceIp} <X size={14} /></button>}
            {activeFilters && <button className="ui-button ui-button--quiet" onClick={clearFilters}>Clear filters</button>}
          </div>
        </div>
      </section>

      <div className="alert-toolbar">
        <div className="segmented" role="group" aria-label="Group alerts">
          <button aria-pressed={groupBy === 'none'} onClick={() => updateFilters({ group: '' })}><List size={14} aria-hidden="true" /> List</button>
          <button aria-pressed={groupBy === 'title'} onClick={() => updateFilters({ group: 'title' })}><Layers size={14} aria-hidden="true" /> By detection</button>
          <button aria-pressed={groupBy === 'hostname'} onClick={() => updateFilters({ group: 'hostname' })}><Layers size={14} aria-hidden="true" /> By host</button>
        </div>
        {canTriage && groupBy === 'none' && items.length > 0 && <div className="control-cluster alert-bulk" role="group" aria-label="Bulk actions">
          <label className="alert-bulk__all"><input type="checkbox" className="alert-check" checked={allChecked}
            onChange={() => setChecked(allChecked ? new Set() : new Set(items.map(alert => alert.id)))} /> {checked.size ? `${checked.size} selected` : 'Select page'}</label>
          {checked.size > 0 && <>
            {TRIAGE_ACTIONS.map(action => <button key={action.status} className="ui-button" disabled={bulkUpdate.isPending}
              onClick={() => bulkUpdate.mutate(action.status)}>{action.label}</button>)}
            <button className="ui-button ui-button--quiet" onClick={() => setChecked(new Set())}>Clear</button>
          </>}
        </div>}
      </div>

      <div className={`alert-split ${wide && selected && groupBy === 'none' ? 'alert-split--open' : ''}`}>
        <div className="alert-split__list">{body}</div>
        {wide && selected && groupBy === 'none' && <AlertPreview alert={selected} canTriage={canTriage} onClose={() => setSelectedId(undefined)} />}
      </div>
      <AlertSuppressions />
    </div>
  )
}
