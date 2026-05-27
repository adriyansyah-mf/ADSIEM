import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Plus, Trash2 } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'

interface CorrelationRule {
  id: string
  title: string
  description: string | null
  match_field: string
  min_count: number
  timewindow: number
  severity_filter: string | null
  output_severity: string
  output_title: string
  is_enabled: boolean
  group_id: string | null
  created_at: string
}

const EMPTY: Partial<CorrelationRule> = {
  title: '', match_field: 'source_ip', min_count: 5, timewindow: 300,
  severity_filter: '', output_severity: 'high',
  output_title: '[Correlated] {count} alerts from {match_value}',
  is_enabled: true,
}

export default function CorrelationPage() {
  const qc = useQueryClient()
  const { hasRole } = useAuthStore()
  const isAdmin = hasRole('admin')
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState<Partial<CorrelationRule>>(EMPTY)

  const { data: rules = [], isLoading } = useQuery<CorrelationRule[]>({
    queryKey: ['correlation-rules'],
    queryFn: () => api.get('/api/correlation-rules').then(r => r.data),
  })

  const create = useMutation({
    mutationFn: (body: Partial<CorrelationRule>) =>
      api.post('/api/correlation-rules', {
        ...body,
        severity_filter: body.severity_filter || null,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['correlation-rules'] })
      setShowForm(false)
      setForm(EMPTY)
    },
  })

  const del = useMutation({
    mutationFn: (id: string) => api.delete(`/api/correlation-rules/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['correlation-rules'] }),
  })

  const toggle = useMutation({
    mutationFn: ({ id, is_enabled }: { id: string; is_enabled: boolean }) =>
      api.put(`/api/correlation-rules/${id}`, { is_enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['correlation-rules'] }),
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Correlation Rules</h1>
        {isAdmin && (
          <button
            onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded text-sm hover:opacity-90"
          >
            <Plus size={14} /> New Rule
          </button>
        )}
      </div>

      {showForm && (
        <div className="mb-6 p-4 border border-border rounded bg-card space-y-3">
          <h2 className="font-semibold text-sm">New Correlation Rule</h2>
          <div className="grid grid-cols-2 gap-3">
            <input
              placeholder="Rule title"
              value={form.title || ''}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              className="col-span-2 px-3 py-2 rounded border border-border bg-background text-sm"
            />
            <select
              value={form.match_field}
              onChange={e => setForm(f => ({ ...f, match_field: e.target.value }))}
              className="px-3 py-2 rounded border border-border bg-background text-sm"
            >
              <option value="source_ip">source_ip</option>
              <option value="hostname">hostname</option>
              <option value="group_id">group_id</option>
            </select>
            <input
              type="number"
              placeholder="Min count"
              value={form.min_count || 5}
              onChange={e => setForm(f => ({ ...f, min_count: Number(e.target.value) }))}
              className="px-3 py-2 rounded border border-border bg-background text-sm"
            />
            <input
              type="number"
              placeholder="Time window (seconds)"
              value={form.timewindow || 300}
              onChange={e => setForm(f => ({ ...f, timewindow: Number(e.target.value) }))}
              className="px-3 py-2 rounded border border-border bg-background text-sm"
            />
            <select
              value={form.output_severity}
              onChange={e => setForm(f => ({ ...f, output_severity: e.target.value }))}
              className="px-3 py-2 rounded border border-border bg-background text-sm"
            >
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
            </select>
            <input
              placeholder="Output title — use {count} and {match_value}"
              value={form.output_title || ''}
              onChange={e => setForm(f => ({ ...f, output_title: e.target.value }))}
              className="col-span-2 px-3 py-2 rounded border border-border bg-background text-sm"
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => { if (!form.title?.trim()) return; create.mutate(form); }}
              disabled={create.isPending}
              className="px-4 py-1.5 bg-primary text-primary-foreground rounded text-sm hover:opacity-90 disabled:opacity-50"
            >
              {create.isPending ? 'Saving…' : 'Save'}
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="px-4 py-1.5 rounded border border-border text-sm hover:bg-muted"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {isLoading ? (
        <p className="text-muted-foreground text-sm">Loading…</p>
      ) : (
        <div className="space-y-2">
          {rules.map(r => (
            <div
              key={r.id}
              className="flex items-start justify-between p-4 rounded border border-border bg-card"
            >
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-medium text-sm">{r.title}</span>
                  <span
                    className={`text-xs px-1.5 py-0.5 rounded ${
                      r.is_enabled
                        ? 'bg-green-500/20 text-green-400'
                        : 'bg-muted text-muted-foreground'
                    }`}
                  >
                    {r.is_enabled ? 'enabled' : 'disabled'}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {r.min_count}+ alerts on{' '}
                  <code className="bg-muted px-1 rounded">{r.match_field}</code> within{' '}
                  {r.timewindow}s →{' '}
                  <span className="font-medium">{r.output_severity}</span>
                </p>
                <p className="text-xs text-muted-foreground">{r.output_title}</p>
              </div>
              {isAdmin && (
                <div className="flex gap-2 ml-4 flex-shrink-0">
                  <button
                    onClick={() => toggle.mutate({ id: r.id, is_enabled: !r.is_enabled })}
                    className="text-xs px-2 py-1 rounded border border-border hover:bg-muted"
                  >
                    {r.is_enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button
                    onClick={() => del.mutate(r.id)}
                    className="text-xs px-2 py-1 rounded border border-destructive text-destructive hover:bg-destructive/10"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              )}
            </div>
          ))}
          {rules.length === 0 && (
            <p className="text-muted-foreground text-sm">No correlation rules defined.</p>
          )}
        </div>
      )}
    </div>
  )
}
