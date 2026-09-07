import { useState } from 'react'
import { format } from 'date-fns'
import { CalendarClock, Loader2, Pause, Play, Trash2 } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'

interface HuntSchedule {
  id: string; name: string; ioc_type: string; ioc_value: string
  interval_hours: number; group_id: string; is_enabled: boolean
  last_run_at: string | null; created_at: string | null
}

export function ScheduledHuntsPanel() {
  const qc = useQueryClient()
  const [form, setForm] = useState({ name: '', ioc_type: 'ip', ioc_value: '', interval_hours: 24 })
  const [formErr, setFormErr] = useState('')

  const { data: schedules = [] } = useQuery<HuntSchedule[]>({
    queryKey: ['hunt-schedules'],
    queryFn: () => api.get('/api/hunt-schedules').then(r => r.data),
    refetchInterval: 30_000,
  })

  const create = useMutation({
    mutationFn: (body: typeof form) => api.post('/api/hunt-schedules', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hunt-schedules'] })
      setForm({ name: '', ioc_type: 'ip', ioc_value: '', interval_hours: 24 })
      setFormErr('')
    },
    onError: (e: any) => setFormErr(e?.response?.data?.detail ?? 'Failed'),
  })

  const toggle = useMutation({
    mutationFn: (id: string) => api.patch(`/api/hunt-schedules/${id}/toggle`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt-schedules'] }),
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/hunt-schedules/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt-schedules'] }),
  })

  return (
    <div className="enterprise-panel rounded-lg border border-border bg-card p-5 space-y-4">
      <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide flex items-center gap-2">
        <CalendarClock size={15} /> Scheduled Hunts
      </h2>

      {/* Create form */}
      <div className="flex flex-wrap gap-2 items-end">
        <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
          placeholder="Schedule name…"
          className="bg-muted border border-border rounded px-3 py-2 text-sm w-36 focus:outline-none focus:ring-1 focus:ring-primary" />
        <select value={form.ioc_type} onChange={e => setForm(f => ({ ...f, ioc_type: e.target.value }))}
          className="bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary">
          <option value="ip">IP</option>
          <option value="hostname">Hostname</option>
          <option value="user">User</option>
          <option value="hash">Hash</option>
        </select>
        <input value={form.ioc_value} onChange={e => setForm(f => ({ ...f, ioc_value: e.target.value }))}
          placeholder="IoC value…"
          className="bg-muted border border-border rounded px-3 py-2 text-sm font-mono w-44 focus:outline-none focus:ring-1 focus:ring-primary" />
        <div className="flex items-center gap-1">
          <input type="number" min={1} max={168} value={form.interval_hours}
            onChange={e => setForm(f => ({ ...f, interval_hours: parseInt(e.target.value) || 24 }))}
            className="bg-muted border border-border rounded px-2 py-2 text-sm w-16 focus:outline-none focus:ring-1 focus:ring-primary" />
          <span className="text-xs text-muted-foreground">h</span>
        </div>
        <button onClick={() => create.mutate(form)} disabled={!form.name || !form.ioc_value || create.isPending}
          className="flex items-center gap-1 px-3 py-2 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50">
          {create.isPending ? <Loader2 size={13} className="animate-spin" /> : null} Add
        </button>
      </div>
      {formErr && <p className="text-xs text-destructive">{formErr}</p>}

      {/* Schedule list */}
      {schedules.length === 0 ? (
        <p className="text-sm text-muted-foreground">No scheduled hunts yet.</p>
      ) : (
        <div className="overflow-x-auto" aria-label="Scheduled hunts table">
        <table className="w-full min-w-[640px] text-xs">
          <thead><tr className="border-b border-border text-muted-foreground">
            <th className="text-left py-1 pr-3">Name</th>
            <th className="text-left py-1 pr-3">IoC</th>
            <th className="text-left py-1 pr-3">Every</th>
            <th className="text-left py-1 pr-3">Last Run</th>
            <th className="text-left py-1"></th>
          </tr></thead>
          <tbody>
            {schedules.map(s => (
              <tr key={s.id} className={`border-b border-border/40 ${!s.is_enabled ? 'opacity-50' : ''}`}>
                <td className="py-1.5 pr-3 font-medium">{s.name}</td>
                <td className="py-1.5 pr-3 font-mono text-primary">{s.ioc_type}: {s.ioc_value}</td>
                <td className="py-1.5 pr-3 text-muted-foreground">{s.interval_hours}h</td>
                <td className="py-1.5 pr-3 text-muted-foreground">
                  {s.last_run_at ? format(new Date(s.last_run_at), 'MM-dd HH:mm') : 'Never'}
                </td>
                <td className="py-1.5 flex items-center gap-2">
                  <button onClick={() => toggle.mutate(s.id)} title={s.is_enabled ? 'Disable' : 'Enable'}
                    className="min-h-11 min-w-11 inline-flex items-center justify-center rounded text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">
                    {s.is_enabled ? <Pause size={13} /> : <Play size={13} />}
                  </button>
                  <button onClick={() => remove.mutate(s.id)} title="Delete"
                    className="min-h-11 min-w-11 inline-flex items-center justify-center rounded text-destructive hover:text-destructive/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">
                    <Trash2 size={13} />
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
