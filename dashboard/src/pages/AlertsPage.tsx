import { useState } from 'react'
import DataTable from '@/components/DataTable'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import AlertDetailModal from '@/components/AlertDetailModal'
import { useAlerts } from '@/hooks/useAlerts'
import { format } from 'date-fns'
import type { Alert } from '@/types'

export default function AlertsPage() {
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<Alert | null>(null)
  const [statusFilter, setStatusFilter] = useState('')
  const { data, isLoading } = useAlerts(page, 25, statusFilter || undefined)

  const columns = [
    { key: 'severity', header: 'Severity', render: (r: Alert) => <SeverityBadge severity={r.severity} /> },
    { key: 'title', header: 'Title', render: (r: Alert) => <span className="font-medium">{r.title}</span> },
    { key: 'status', header: 'Status', render: (r: Alert) => <StatusBadge status={r.status} /> },
    { key: 'source_ip', header: 'Source IP', render: (r: Alert) => r.source_ip ?? '—' },
    { key: 'hostname', header: 'Hostname', render: (r: Alert) => r.hostname ?? '—' },
    { key: 'time', header: 'Time', render: (r: Alert) => format(new Date(r.created_at), 'yyyy-MM-dd HH:mm:ss') },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Alerts</h1>
        <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1) }}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm">
          <option value="">All statuses</option>
          <option value="new">New</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} onRowClick={setSelected} />
      )}
      {selected && <AlertDetailModal alert={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
