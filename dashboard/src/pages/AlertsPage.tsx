import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import DataTable from '@/components/DataTable'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import AlertDetailModal from '@/components/AlertDetailModal'
import { useAlerts } from '@/hooks/useAlerts'
import { useStartHunt } from '@/hooks/useHunts'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { format } from 'date-fns'
import { Crosshair, Download, Search, ShieldOff, X } from 'lucide-react'
import { TimeRangeFilter, type TimeRange } from '@/components/TimeRangeSelect'
import type { Alert } from '@/types'

interface Suppression { id: string; entity_type: string; entity_value: string; reason: string | null; is_active: boolean }

function SuppressionPanel() {
  const qc = useQueryClient()
  const [form, setForm] = useState({ entity_type: 'ip', entity_value: '', reason: '' })
  const { data: list = [] } = useQuery<Suppression[]>({
    queryKey: ['suppressions'],
    queryFn: () => api.get('/api/suppressions').then(r => r.data),
  })
  const add = useMutation({
    mutationFn: (body: typeof form) => api.post('/api/suppressions', body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['suppressions'] }); setForm(f => ({ ...f, entity_value: '', reason: '' })) },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/suppressions/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['suppressions'] }),
  })

  return (
    <details className="mb-4 rounded border border-border">
      <summary className="flex items-center gap-2 px-4 py-2 cursor-pointer text-sm font-semibold hover:bg-muted/30 select-none">
        <ShieldOff size={14} /> Alert Suppressions ({list.length})
      </summary>
      <div className="px-4 pb-4 pt-2 space-y-3">
        <div className="flex flex-wrap gap-2 items-end">
          <select value={form.entity_type} onChange={e => setForm(f => ({ ...f, entity_type: e.target.value }))}
            className="px-2 py-1.5 rounded border border-border bg-background text-sm">
            <option value="ip">IP</option>
            <option value="hostname">Hostname</option>
            <option value="user">User</option>
            <option value="rule_title">Rule Title</option>
          </select>
          <input value={form.entity_value} onChange={e => setForm(f => ({ ...f, entity_value: e.target.value }))}
            placeholder="Value to suppress…" className="px-2 py-1.5 rounded border border-border bg-background text-sm w-52 font-mono" />
          <input value={form.reason} onChange={e => setForm(f => ({ ...f, reason: e.target.value }))}
            placeholder="Reason (optional)" className="px-2 py-1.5 rounded border border-border bg-background text-sm w-44" />
          <button onClick={() => add.mutate(form)} disabled={!form.entity_value || add.isPending}
            className="px-3 py-1.5 rounded border border-border text-sm hover:bg-muted disabled:opacity-50">
            Add
          </button>
        </div>
        {list.length > 0 && (
          <table className="w-full text-xs">
            <thead><tr className="border-b border-border text-muted-foreground">
              <th className="text-left py-1 pr-3">Type</th><th className="text-left py-1 pr-3">Value</th>
              <th className="text-left py-1 pr-3">Reason</th><th className="text-left py-1"></th>
            </tr></thead>
            <tbody>{list.map(s => (
              <tr key={s.id} className="border-b border-border/40">
                <td className="py-1 pr-3 font-mono uppercase text-xs text-muted-foreground">{s.entity_type}</td>
                <td className="py-1 pr-3 font-mono">{s.entity_value}</td>
                <td className="py-1 pr-3 text-muted-foreground">{s.reason ?? '—'}</td>
                <td className="py-1"><button onClick={() => remove.mutate(s.id)}
                  className="text-destructive hover:text-destructive/80"><X size={12} /></button></td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </div>
    </details>
  )
}

async function downloadFile(url: string, filename: string) {
  let href: string | null = null
  try {
    const res = await import('@/api/client').then(m => m.api.get(url, { responseType: 'blob' }))
    href = URL.createObjectURL(res.data)
    const a = document.createElement('a')
    a.href = href
    a.download = filename
    a.click()
  } catch {
    alert('Export failed. Please try again.')
  } finally {
    if (href) URL.revokeObjectURL(href)
  }
}

function HuntButton({ alert }: { alert: Alert }) {
  const navigate = useNavigate()
  const startHunt = useStartHunt()
  const ioc = alert.source_ip || alert.hostname
  const iocType = alert.source_ip ? 'ip' : 'hostname'
  if (!ioc) return null

  return (
    <button
      onClick={e => {
        e.stopPropagation()
        startHunt.mutate(
          { ioc_type: iocType, ioc_value: ioc },
          { onSuccess: () => navigate('/hunts') }
        )
      }}
      disabled={startHunt.isPending}
      title={`Hunt ${iocType}: ${ioc}`}
      className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-border hover:border-primary hover:text-primary transition-colors disabled:opacity-50"
    >
      <Crosshair size={10} />
      Hunt
    </button>
  )
}

export default function AlertsPage() {
  const [searchParams] = useSearchParams()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [selected, setSelected] = useState<Alert | null>(null)
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState(() => searchParams.get('severity') ?? '')
  const [hostnameFilter, setHostnameFilter] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [searchFilter, setSearchFilter] = useState('')
  const [timeFilter, setTimeFilter] = useState<TimeRange>({})

  // Sync URL params on first mount (e.g. from dashboard severity clicks)
  useEffect(() => {
    const sv = searchParams.get('severity')
    if (sv) setSeverityFilter(sv)
  }, [])

  // Debounce the free-text search box so we don't refetch on every keystroke
  useEffect(() => {
    const t = setTimeout(() => { setSearchFilter(searchInput); setPage(1) }, 400)
    return () => clearTimeout(t)
  }, [searchInput])

  const { data, isLoading } = useAlerts(page, pageSize, {
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    hostname: hostnameFilter || undefined,
    search: searchFilter || undefined,
    start_time: timeFilter.start_time,
    end_time: timeFilter.end_time,
  })

  // Deep link from the global search dropdown (?open=<alert_id>) — fetched
  // directly rather than found in the current page's rows, since the
  // matching alert may not be on whatever page/filter is currently shown.
  const openId = searchParams.get('open')
  const { data: deepLinkedAlert } = useQuery<Alert>({
    queryKey: ['alert', openId],
    queryFn: () => api.get(`/api/alerts/${openId}`).then(r => r.data),
    enabled: !!openId,
  })
  useEffect(() => {
    if (deepLinkedAlert) setSelected(deepLinkedAlert)
  }, [deepLinkedAlert])

  const columns = [
    { key: 'severity', header: 'Severity', render: (r: Alert) => <SeverityBadge severity={r.severity} /> },
    { key: 'title', header: 'Title', render: (r: Alert) => <span className="font-medium">{r.title}</span> },
    { key: 'status', header: 'Status', render: (r: Alert) => <StatusBadge status={r.status} /> },
    { key: 'source_ip', header: 'Source IP', render: (r: Alert) => r.source_ip ?? '—' },
    { key: 'country', header: 'Country', render: (r: Alert) => r.source_ip_country ?? '—' },
    { key: 'hostname', header: 'Hostname', render: (r: Alert) => r.hostname ?? '—' },
    { key: 'time', header: 'Time', render: (r: Alert) => format(new Date(r.created_at), 'yyyy-MM-dd HH:mm:ss') },
    { key: 'hunt', header: '', render: (r: Alert) => <HuntButton alert={r} /> },
  ]

  return (
    <div>
      <SuppressionPanel />
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-bold">Alerts</h1>
        <button onClick={() => downloadFile('/api/export/alerts/csv', 'alerts.csv')}
          className="flex items-center gap-1 px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">
          <Download size={13} /> CSV
        </button>
      </div>
      <div className="flex flex-wrap items-center gap-2 mb-6">
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input value={searchInput} onChange={e => setSearchInput(e.target.value)}
            placeholder="Search title…"
            className="pl-8 pr-3 py-1.5 rounded border border-border bg-background text-sm w-48" />
        </div>
        <input value={hostnameFilter} onChange={e => { setHostnameFilter(e.target.value); setPage(1) }}
          placeholder="Hostname…"
          className="px-3 py-1.5 rounded border border-border bg-background text-sm w-36" />
        <select value={severityFilter} onChange={(e) => { setSeverityFilter(e.target.value); setPage(1) }}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm">
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1) }}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm">
          <option value="">All statuses</option>
          <option value="new">New</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
        <TimeRangeFilter
          value={timeFilter}
          onChange={r => { setTimeFilter(r); setPage(1) }}
          selectClassName="px-3 py-1.5 rounded border border-border bg-background text-sm"
          inputClassName="px-2 py-1 rounded border border-border bg-background text-xs"
        />
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={pageSize} onPageChange={setPage}
          onPageSizeChange={(s) => { setPageSize(s); setPage(1) }}
          onRowClick={setSelected} />
      )}
      {selected && <AlertDetailModal alert={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
