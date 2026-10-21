import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { Crosshair, Download, RefreshCw, X } from 'lucide-react'
import { format } from 'date-fns'
import { api } from '@/api/client'
import DataTable from '@/components/DataTable'
import type { Column } from '@/components/DataTable'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import { AlertSuppressions } from '@/components/AlertSuppressions'
import { PageHeader, QueryState } from '@/components/Workspace'
import { TimeRangeFilter } from '@/components/TimeRangeSelect'
import { useAlerts } from '@/hooks/useAlerts'
import { useStartHunt } from '@/hooks/useHunts'
import { emitToast } from '@/hooks/useToast'
import type { Alert } from '@/types'

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

export default function AlertsPage() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [searchInput, setSearchInput] = useState(params.get('search') ?? '')
  const status = params.get('status') ?? ''
  const severity = params.get('severity') ?? ''
  const hostname = params.get('hostname') ?? ''
  const sourceIp = params.get('source_ip') ?? ''
  const search = params.get('search') ?? ''
  const start = params.get('start_time') ?? ''
  const end = params.get('end_time') ?? ''

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
  const columns: readonly Column<Alert>[] = [
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

  return (
    <div className="workspace">
      <PageHeader eyebrow="Security operations" title="Alerts"
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
      {alerts.isError ? <section className="panel"><QueryState kind="error" title="Could not load alerts"
        description="Your filters are preserved. Check your connection and try again." onRetry={() => { void alerts.refetch() }} /></section>
        : alerts.isPending ? <section className="panel"><QueryState kind="loading" title="Loading detections…"
          description="Fetching alerts for this workspace." /></section>
        : <DataTable columns={columns} data={alerts.data.items} total={alerts.data.total} page={page} pageSize={pageSize}
          onPageChange={setPage} onPageSizeChange={setPageSize} onRowClick={alert => navigate(`/alerts/${alert.id}`)}
          exportFilename="alerts-page.csv" emptyTitle="No alerts match this view"
          emptyDescription={activeFilters ? 'Try a wider time window or clear the filters above.' : 'New detections will appear here as events are processed.'} />}
      <AlertSuppressions />
    </div>
  )
}
