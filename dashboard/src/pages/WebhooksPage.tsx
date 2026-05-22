import { useState } from 'react'
import DataTable from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { useWebhooks, useCreateWebhook, useDeleteWebhook } from '@/hooks/useWebhooks'
import { Plus, Trash2 } from 'lucide-react'
import type { Webhook } from '@/types'

export default function WebhooksPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useWebhooks(page)
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
        <h1 className="text-xl font-bold">Webhooks</h1>
        <button onClick={() => setShowForm(true)}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={14} /> New Webhook
        </button>
      </div>
      {showForm && (
        <div className="mb-4 p-4 rounded border border-border bg-card space-y-3">
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
          page={page} pageSize={25} onPageChange={setPage} />
      )}
    </div>
  )
}
