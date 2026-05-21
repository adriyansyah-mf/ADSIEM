import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'

export default function DashboardPage() {
  const { data: alertsNew } = useQuery({
    queryKey: ['alerts-summary', 'new'],
    queryFn: () => api.get('/api/alerts', { params: { status: 'new', page_size: 1 } }).then(r => r.data.total),
    refetchInterval: 30_000,
  })
  const { data: alertsHigh } = useQuery({
    queryKey: ['alerts-summary', 'high'],
    queryFn: () => api.get('/api/alerts', { params: { severity: 'high', page_size: 1 } }).then(r => r.data.total),
    refetchInterval: 30_000,
  })
  const { data: agentsTotal } = useQuery({
    queryKey: ['agents-summary'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 1 } }).then(r => r.data.total),
    refetchInterval: 30_000,
  })
  const { data: logsTotal } = useQuery({
    queryKey: ['logs-summary'],
    queryFn: () => api.get('/api/logs', { params: { page_size: 1 } }).then(r => r.data.total),
    refetchInterval: 30_000,
  })

  const cards = [
    { label: 'New Alerts', value: alertsNew ?? '—', color: 'text-blue-400' },
    { label: 'High Severity', value: alertsHigh ?? '—', color: 'text-orange-400' },
    { label: 'Total Agents', value: agentsTotal ?? '—', color: 'text-green-400' },
    { label: 'Total Logs', value: logsTotal ?? '—', color: 'text-purple-400' },
  ]

  return (
    <div>
      <h1 className="text-xl font-bold mb-6">Dashboard</h1>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((c) => (
          <div key={c.label} className="rounded-lg border border-border bg-card p-5">
            <div className={`text-3xl font-bold ${c.color}`}>{c.value}</div>
            <div className="text-sm text-muted-foreground mt-1">{c.label}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
