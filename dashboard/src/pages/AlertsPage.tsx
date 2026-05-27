import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import DataTable from '@/components/DataTable'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import AlertDetailModal from '@/components/AlertDetailModal'
import { useAlerts } from '@/hooks/useAlerts'
import { useStartHunt } from '@/hooks/useHunts'
import { format } from 'date-fns'
import { Crosshair, Download } from 'lucide-react'
import type { Alert } from '@/types'

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
    { key: 'hunt', header: '', render: (r: Alert) => <HuntButton alert={r} /> },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Alerts</h1>
        <div className="flex items-center gap-2">
          <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1) }}
            className="px-3 py-1.5 rounded border border-border bg-background text-sm">
            <option value="">All statuses</option>
            <option value="new">New</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
          <button onClick={() => downloadFile('/api/export/alerts/csv', 'alerts.csv')}
            className="flex items-center gap-1 px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">
            <Download size={13} /> CSV
          </button>
          <button onClick={() => downloadFile('/api/export/alerts/pdf', 'alerts.pdf')}
            className="flex items-center gap-1 px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">
            <Download size={13} /> PDF
          </button>
        </div>
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} onRowClick={setSelected} />
      )}
      {selected && <AlertDetailModal alert={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
