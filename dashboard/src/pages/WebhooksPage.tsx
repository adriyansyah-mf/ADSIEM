import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import DataTable from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { PageHeader } from '@/components/ui/PageHeader'
import { useWebhooks, useCreateWebhook, useDeleteWebhook } from '@/hooks/useWebhooks'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import { Plus, Trash2, RotateCcw, XCircle } from 'lucide-react'
import type { Webhook } from '@/types'

interface FailedDelivery {
  id: string
  alert_id: string
  webhook_config_id: string
  group_id: string | null
  status: string
  attempts: number
  last_error: string | null
  error_class: string | null
  first_failed_at: string | null
  last_attempted_at: string | null
  created_at: string
}

interface QueueMetrics {
  webhook_deliveries: { pending: number; failed: number; oldest_pending_age_seconds: number | null }
  ingestion_dlq: { depth: number; oldest_age_seconds: number | null }
  ingestion_dead_letter: { depth: number; oldest_age_seconds: number | null }
}

function FailedDeliveriesPanel() {
  const qc = useQueryClient()
  const { data: metrics } = useQuery<QueueMetrics>({
    queryKey: ['queue-metrics'],
    queryFn: () => api.get('/api/queues/metrics').then(r => r.data),
    refetchInterval: 30000,
  })
  const { data: deliveries, isLoading } = useQuery<FailedDelivery[]>({
    queryKey: ['failed-webhook-deliveries'],
    queryFn: () => api.get('/api/queues/webhook-deliveries', { params: { status: 'failed' } }).then(r => r.data),
    refetchInterval: 30000,
  })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['failed-webhook-deliveries'] })
    qc.invalidateQueries({ queryKey: ['queue-metrics'] })
  }
  const retry = useMutation({
    mutationFn: (id: string) => api.post(`/api/queues/webhook-deliveries/${id}/retry`),
    onSuccess: () => { invalidate(); emitToast('Delivery queued for retry', 'success') },
    onError: () => emitToast('Failed to retry delivery', 'error'),
  })
  const discard = useMutation({
    mutationFn: (id: string) => api.post(`/api/queues/webhook-deliveries/${id}/discard`),
    onSuccess: () => { invalidate(); emitToast('Delivery discarded', 'success') },
    onError: () => emitToast('Failed to discard delivery', 'error'),
  })

  if (!metrics && !deliveries?.length) return null

  return (
    <div className="mb-6 enterprise-panel rounded border border-border bg-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold">Dead-letter queue</span>
        <span className="text-xs text-muted-foreground">
          {metrics && (
            <>
              webhook: {metrics.webhook_deliveries.failed} failed / {metrics.webhook_deliveries.pending} pending
              {' · '}ingestion DLQ: {metrics.ingestion_dlq.depth}
              {' · '}dead-lettered: {metrics.ingestion_dead_letter.depth}
            </>
          )}
        </span>
      </div>
      {isLoading ? (
        <div className="text-xs text-muted-foreground">Loading...</div>
      ) : !deliveries?.length ? (
        <div className="text-xs text-muted-foreground">No failed webhook deliveries.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-muted-foreground">
              <tr>
                <th className="text-left px-2 py-1">Attempts</th>
                <th className="text-left px-2 py-1">Error</th>
                <th className="text-left px-2 py-1">First failed</th>
                <th className="text-left px-2 py-1"></th>
              </tr>
            </thead>
            <tbody>
              {deliveries.map(d => (
                <tr key={d.id} className="border-t border-border">
                  <td className="px-2 py-1">{d.attempts}</td>
                  <td className="px-2 py-1 max-w-xs truncate" title={d.last_error ?? ''}>
                    {d.error_class}: {d.last_error}
                  </td>
                  <td className="px-2 py-1 whitespace-nowrap">
                    {d.first_failed_at ? new Date(d.first_failed_at).toLocaleString() : '—'}
                  </td>
                  <td className="px-2 py-1 whitespace-nowrap">
                    <button onClick={() => retry.mutate(d.id)} title="Retry"
                      className="mr-2 text-primary hover:opacity-70 inline-flex items-center gap-1">
                      <RotateCcw size={12} /> Retry
                    </button>
                    <button onClick={() => discard.mutate(d.id)} title="Discard"
                      className="text-destructive hover:opacity-70 inline-flex items-center gap-1">
                      <XCircle size={12} /> Discard
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default function WebhooksPage() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const { data, isLoading } = useWebhooks(page, pageSize)
  const createWebhook = useCreateWebhook()
  const deleteWebhook = useDeleteWebhook()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', url: '' })

  const columns = [
    { key: 'name', header: 'Name', render: (r: Webhook) => r.name },
    { key: 'url', header: 'URL', render: (r: Webhook) => <span className="font-mono text-xs truncate max-w-xs block">{r.url}</span> },
    { key: 'enabled', header: 'Enabled', render: (r: Webhook) => <StatusBadge status={r.is_enabled ? 'online' : 'offline'} /> },
    { key: 'actions', header: '', render: (r: Webhook) => (
      <button onClick={() => deleteWebhook.mutate(r.id)} className="text-destructive hover:opacity-70">
        <Trash2 size={14} /></button>
    )},
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <PageHeader title="Webhooks" className="!mb-0" />
        <button onClick={() => setShowForm(true)}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={14} /> New Webhook
        </button>
      </div>
      <FailedDeliveriesPanel />
      {showForm && (
        <div className="mb-4 p-4 enterprise-panel rounded border border-border bg-card space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs mb-1">Name</label>
              <input value={form.name} onChange={(e) => setForm(p => ({ ...p, name: e.target.value }))}
                className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm" />
            </div>
            <div>
              <label className="block text-xs mb-1">URL</label>
              <input value={form.url} onChange={(e) => setForm(p => ({ ...p, url: e.target.value }))}
                placeholder="https://hooks.example.com/..."
                className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm" />
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={() => { createWebhook.mutate(form); setShowForm(false); setForm({ name: '', url: '' }) }}
              className="px-4 py-1.5 rounded bg-primary text-primary-foreground text-sm">Create</button>
            <button onClick={() => setShowForm(false)} className="px-4 py-1.5 rounded border border-border text-sm">Cancel</button>
          </div>
        </div>
      )}
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={pageSize} onPageChange={setPage}
          onPageSizeChange={(s) => { setPageSize(s); setPage(1) }} />
      )}
    </div>
  )
}
