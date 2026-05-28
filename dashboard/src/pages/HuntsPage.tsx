import { useState } from 'react'
import { format } from 'date-fns'
import { Search, Crosshair, Clock, CheckCircle, XCircle, Loader2, ChevronDown, ChevronRight, CalendarClock, Pause, Play, Trash2 } from 'lucide-react'
import { useHunts, useStartHunt } from '@/hooks/useHunts'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { ThreatHunt } from '@/types'

interface HuntSchedule {
  id: string; name: string; ioc_type: string; ioc_value: string
  interval_hours: number; group_id: string; is_enabled: boolean
  last_run_at: string | null; created_at: string | null
}

function ScheduledHuntsPanel() {
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
    <div className="rounded-lg border border-border bg-card p-5 space-y-4">
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
        <table className="w-full text-xs">
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
                    className="text-muted-foreground hover:text-foreground">
                    {s.is_enabled ? <Pause size={13} /> : <Play size={13} />}
                  </button>
                  <button onClick={() => remove.mutate(s.id)} title="Delete"
                    className="text-destructive hover:text-destructive/80">
                    <Trash2 size={13} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

const IOC_TYPES = [
  { value: 'ip', label: 'IP Address' },
  { value: 'hostname', label: 'Hostname' },
  { value: 'user', label: 'Username' },
  { value: 'hash', label: 'File Hash (SHA256)' },
]

const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/30 border-red-700',
  high:     'text-orange-400 bg-orange-900/30 border-orange-700',
  medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-700',
  low:      'text-blue-400 bg-blue-900/30 border-blue-700',
  unknown:  'text-muted-foreground bg-muted/20 border-border',
}

function StatusIcon({ status }: { status: string }) {
  if (status === 'done') return <CheckCircle size={14} className="text-emerald-400" />
  if (status === 'failed') return <XCircle size={14} className="text-red-400" />
  if (status === 'running') return <Loader2 size={14} className="text-blue-400 animate-spin" />
  return <Clock size={14} className="text-muted-foreground" />
}

export default function HuntsPage() {
  const { data: hunts = [], isLoading } = useHunts()
  const startHunt = useStartHunt()
  const [iocType, setIocType] = useState('ip')
  const [iocValue, setIocValue] = useState('')
  const [error, setError] = useState('')

  const handleHunt = () => {
    const val = iocValue.trim()
    if (!val) { setError('Enter an IoC value'); return }
    setError('')
    startHunt.mutate({ ioc_type: iocType, ioc_value: val }, {
      onSuccess: () => setIocValue(''),
      onError: (e: any) => setError(e?.response?.data?.detail ?? 'Failed to start hunt'),
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Crosshair size={20} />
        <h1 className="text-xl font-bold">Threat Hunt</h1>
      </div>

      {/* Hunt form */}
      <div className="rounded-lg border border-border bg-card p-5 space-y-4">
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">New Hunt</h2>
        <div className="flex gap-3 flex-wrap">
          <select
            value={iocType}
            onChange={e => setIocType(e.target.value)}
            className="bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {IOC_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
          <input
            value={iocValue}
            onChange={e => setIocValue(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleHunt()}
            placeholder={iocType === 'ip' ? '192.168.1.1' : iocType === 'hostname' ? 'server-01' : iocType === 'user' ? 'john.doe' : 'sha256hash...'}
            className="flex-1 min-w-[240px] bg-muted border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <button
            onClick={handleHunt}
            disabled={startHunt.isPending}
            className="flex items-center gap-2 px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50"
          >
            {startHunt.isPending ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
            Hunt
          </button>
        </div>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <p className="text-xs text-muted-foreground">
          AI akan menelusuri seluruh riwayat alerts dan events yang terkait IoC ini, lalu menganalisa pola serangan.
        </p>
      </div>

      <ScheduledHuntsPanel />

      {/* Hunt results */}
      <div className="space-y-3">
        {isLoading && <div className="text-muted-foreground text-sm">Loading…</div>}
        {!isLoading && hunts.length === 0 && (
          <div className="rounded-lg border border-border bg-card p-8 text-center text-muted-foreground text-sm">
            Belum ada hunt. Masukkan IoC di atas untuk memulai.
          </div>
        )}
        {hunts.map(h => <HuntCard key={h.id} hunt={h} />)}
      </div>
    </div>
  )
}

function HuntCard({ hunt }: { hunt: ThreatHunt }) {
  const [expanded, setExpanded] = useState(hunt.status === 'done' && (hunt.alert_count ?? 0) > 0)
  const analysis = (() => {
    try { return hunt.analysis ? JSON.parse(hunt.analysis) : null } catch { return null }
  })()

  const riskClass = RISK_COLORS[hunt.risk_level ?? 'unknown'] ?? RISK_COLORS.unknown

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      {/* Header */}
      <button
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors text-left"
        onClick={() => setExpanded(x => !x)}
      >
        <StatusIcon status={hunt.status} />
        <span className="font-mono text-sm font-medium">{hunt.ioc_type.toUpperCase()}</span>
        <span className="font-mono text-sm text-primary">{hunt.ioc_value}</span>
        {hunt.risk_level && hunt.risk_level !== 'unknown' && (
          <span className={`text-xs px-2 py-0.5 rounded border font-medium ${riskClass}`}>
            {hunt.risk_level.toUpperCase()}
          </span>
        )}
        <div className="flex items-center gap-3 ml-auto text-xs text-muted-foreground">
          {hunt.status === 'done' && (
            <>
              <span>{hunt.alert_count} alerts</span>
              <span>{hunt.event_count} events</span>
            </>
          )}
          <span>{format(new Date(hunt.created_at), 'MM-dd HH:mm')}</span>
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-border px-4 py-4 space-y-4">
          {hunt.status === 'pending' || hunt.status === 'running' ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 size={14} className="animate-spin" />
              {hunt.status === 'pending' ? 'Menunggu giliran…' : 'AI sedang menelusuri…'}
            </div>
          ) : hunt.status === 'failed' ? (
            <p className="text-sm text-destructive">{analysis?.attack_narrative ?? 'Hunt gagal.'}</p>
          ) : (
            <>
              {/* AI Narrative */}
              {analysis?.attack_narrative && (
                <div className="rounded bg-muted/30 border border-border p-3 space-y-1">
                  <p className="text-xs text-muted-foreground uppercase font-medium">Analisa AI</p>
                  <p className="text-sm leading-relaxed">{analysis.attack_narrative}</p>
                </div>
              )}

              {/* MITRE + Kill Chain */}
              <div className="flex flex-wrap gap-4 text-xs">
                {analysis?.mitre_techniques?.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">MITRE: </span>
                    {analysis.mitre_techniques.map((t: string) => (
                      <span key={t} className="mr-1 px-1.5 py-0.5 bg-muted rounded font-mono">{t}</span>
                    ))}
                  </div>
                )}
                {analysis?.kill_chain_phase && (
                  <div>
                    <span className="text-muted-foreground">Kill Chain: </span>
                    <span className="font-medium">{analysis.kill_chain_phase.replace('_', ' ')}</span>
                  </div>
                )}
                {analysis?.campaign_assessment && (
                  <div>
                    <span className="text-muted-foreground">Campaign: </span>
                    <span className="font-medium">{analysis.campaign_assessment.replace('_', ' ')}</span>
                  </div>
                )}
              </div>

              {/* Recommended actions */}
              {analysis?.recommended_actions?.length > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground uppercase font-medium mb-1">Rekomendasi</p>
                  <ul className="text-sm space-y-0.5">
                    {analysis.recommended_actions.map((a: string, i: number) => (
                      <li key={i} className="flex gap-2"><span className="text-muted-foreground">•</span>{a}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Timeline */}
              {hunt.timeline && hunt.timeline.length > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground uppercase font-medium mb-2">Timeline ({hunt.timeline.length} entries)</p>
                  <div className="space-y-1 max-h-60 overflow-y-auto">
                    {hunt.timeline.map((e, i) => (
                      <div key={i} className="flex gap-2 text-xs font-mono">
                        <span className="text-muted-foreground whitespace-nowrap">{(e.time ?? '').slice(0, 16)}</span>
                        <span className={`px-1.5 rounded ${e.type === 'alert' ? 'bg-red-900/30 text-red-400' : 'bg-blue-900/30 text-blue-400'}`}>
                          {e.type.toUpperCase()}
                        </span>
                        {e.type === 'alert' ? (
                          <span className="truncate">[{e.severity?.toUpperCase()}] {e.title}</span>
                        ) : (
                          <span className="truncate">{e.category}/{e.action} user={e.user ?? '—'}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(hunt.alert_count === 0 && hunt.event_count === 0) && (
                <p className="text-sm text-muted-foreground">Tidak ditemukan riwayat IoC ini di alerts/events.</p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
