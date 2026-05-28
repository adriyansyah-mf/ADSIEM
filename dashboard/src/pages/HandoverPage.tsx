import { useState } from 'react'
import { format } from 'date-fns'
import { ArrowRightLeft, AlertCircle, Briefcase, TrendingUp, Loader2 } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'

interface Handover {
  id: string
  group_id: string
  shift_label: string
  summary: string
  open_alerts: number
  open_cases: number
  escalations: number
  created_at: string | null
}

const SHIFT_LABELS = [
  { value: 'day', label: 'Day Shift' },
  { value: 'night', label: 'Night Shift' },
  { value: 'weekend', label: 'Weekend' },
]

export default function HandoverPage() {
  const qc = useQueryClient()
  const [form, setForm] = useState({ shift_label: 'day', summary: '', notes: '' })
  const [showForm, setShowForm] = useState(false)

  const { data: handovers = [], isLoading } = useQuery<Handover[]>({
    queryKey: ['handovers'],
    queryFn: () => api.get('/api/handover', { params: { limit: 20 } }).then(r => r.data),
    refetchInterval: 60_000,
  })

  const create = useMutation({
    mutationFn: (body: typeof form) => api.post('/api/handover', body).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['handovers'] })
      setForm({ shift_label: 'day', summary: '', notes: '' })
      setShowForm(false)
    },
  })

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ArrowRightLeft size={20} />
          <h1 className="text-xl font-bold">Shift Handover</h1>
        </div>
        <button
          onClick={() => setShowForm(x => !x)}
          className="flex items-center gap-2 px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium"
        >
          {showForm ? 'Cancel' : '+ New Handover'}
        </button>
      </div>

      {showForm && (
        <div className="rounded-lg border border-border bg-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Create Handover</h2>
          <p className="text-xs text-muted-foreground">
            Open alert/case counts are captured automatically at submission time.
          </p>

          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium mb-1">Shift</label>
              <select value={form.shift_label} onChange={e => setForm(f => ({ ...f, shift_label: e.target.value }))}
                className="px-3 py-2 rounded border border-border bg-background text-sm">
                {SHIFT_LABELS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Summary <span className="text-destructive">*</span></label>
              <textarea value={form.summary} onChange={e => setForm(f => ({ ...f, summary: e.target.value }))}
                rows={4} placeholder="Key incidents, ongoing investigations, actions taken…"
                className="w-full px-3 py-2 rounded border border-border bg-background text-sm resize-none" />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Additional Notes</label>
              <textarea value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
                rows={2} placeholder="Pending tasks, recommendations for incoming shift…"
                className="w-full px-3 py-2 rounded border border-border bg-background text-sm resize-none" />
            </div>

            <button
              onClick={() => create.mutate(form)}
              disabled={!form.summary.trim() || create.isPending}
              className="flex items-center gap-2 px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50"
            >
              {create.isPending && <Loader2 size={14} className="animate-spin" />}
              Submit Handover
            </button>
          </div>
        </div>
      )}

      {isLoading && <div className="text-muted-foreground text-sm">Loading…</div>}

      {!isLoading && handovers.length === 0 && (
        <div className="rounded-lg border border-border bg-card p-8 text-center text-muted-foreground text-sm">
          No handover records yet.
        </div>
      )}

      <div className="space-y-4">
        {handovers.map(h => (
          <div key={h.id} className="rounded-lg border border-border bg-card p-5 space-y-3">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider px-2 py-0.5 rounded bg-muted text-muted-foreground">
                  {h.shift_label}
                </span>
                {h.created_at && (
                  <span className="ml-2 text-xs text-muted-foreground font-mono">
                    {format(new Date(h.created_at), 'yyyy-MM-dd HH:mm')}
                  </span>
                )}
              </div>
              <div className="flex gap-4 text-xs">
                <span className="flex items-center gap-1 text-orange-400">
                  <AlertCircle size={12} /> {h.open_alerts} alerts
                </span>
                <span className="flex items-center gap-1 text-cyan-400">
                  <Briefcase size={12} /> {h.open_cases} cases
                </span>
                {h.escalations > 0 && (
                  <span className="flex items-center gap-1 text-red-400">
                    <TrendingUp size={12} /> {h.escalations} escalated
                  </span>
                )}
              </div>
            </div>
            <div className="text-sm leading-relaxed whitespace-pre-wrap border-t border-border pt-3">
              {h.summary}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
