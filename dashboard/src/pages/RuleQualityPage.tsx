import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { Gauge, Loader2 } from 'lucide-react'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import SeverityBadge from '@/components/SeverityBadge'

// Which rules make noise, which ones analysts keep closing as false positives,
// how much suppressions hide (server-api/app/api/routes/rule_quality.py).

interface Item {
  rule_id: string
  title: string
  level: string
  level_override: string | null
  is_enabled: boolean
  source: string
  alerts: number
  alerts_per_day: number
  duplicates: number
  false_positives: number
  resolved: number
  untriaged: number
  fp_rate: number | null
  last_alert_at: string | null
  suppressed_hits: number
  advice: string[]
}

interface Quality {
  days: number
  rules_enabled: number
  rules_alerting: number
  alerts: number
  false_positives: number
  items: Item[]
}

const LEVELS = ['informational', 'low', 'medium', 'high', 'critical']

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-border bg-card px-4 py-3 min-w-[140px]">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-xl font-semibold tabular-nums">{typeof value === 'number' ? value.toLocaleString() : value}</div>
    </div>
  )
}

function FpBar({ rate }: { rate: number | null }) {
  if (rate === null) return <span className="text-xs text-muted-foreground">not triaged</span>
  const pct = Math.round(rate * 100)
  const tone = pct >= 80 ? 'bg-red-500' : pct >= 50 ? 'bg-amber-500' : 'bg-emerald-500'
  return (
    <div className="flex items-center gap-2 min-w-[110px]">
      <div className="h-1.5 flex-1 rounded bg-muted overflow-hidden"><div className={`h-full ${tone}`} style={{ width: `${pct}%` }} /></div>
      <span className="text-xs tabular-nums w-9 text-right">{pct}%</span>
    </div>
  )
}

export default function RuleQualityPage() {
  const qc = useQueryClient()
  const canTune = useAuthStore(s => s.hasRole('analyst'))
  const [days, setDays] = useState(30)
  const [onlyAdvice, setOnlyAdvice] = useState(false)
  const quality = useQuery<Quality>({
    queryKey: ['rule-quality', days],
    queryFn: () => api.get('/api/rule-quality', { params: { days } }).then(r => r.data),
  })
  const override = useMutation({
    mutationFn: ({ id, level }: { id: string; level: string | null }) =>
      api.put(`/api/rule-quality/${id}/level`, { level_override: level }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rule-quality'] }),
  })
  const items = (quality.data?.items ?? []).filter(i => !onlyAdvice || i.advice.length > 0)
  const fpShare = quality.data && quality.data.alerts ? Math.round(quality.data.false_positives / quality.data.alerts * 100) : 0

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <Gauge size={18} />
        <h1 className="text-xl font-bold">Rule quality</h1>
        <div className="flex-1" />
        <label className="flex items-center gap-1.5 text-sm cursor-pointer select-none">
          <input type="checkbox" checked={onlyAdvice} onChange={e => setOnlyAdvice(e.target.checked)} /> Needs tuning only
        </label>
        <select aria-label="Period" value={days} onChange={e => setDays(Number(e.target.value))}
          className="bg-muted border border-border rounded px-3 py-1.5 text-sm">
          {[7, 30, 90].map(d => <option key={d} value={d}>Last {d} days</option>)}
        </select>
      </div>
      <p className="text-xs text-muted-foreground max-w-3xl">
        False-positive rate is alerts closed as false positive out of all triaged alerts. A level override changes the
        severity of new alerts from the rule (the worker picks it up on its next rule reload) without editing the rule,
        so an imported rule still updates.
      </p>

      {quality.isLoading ? <Loader2 size={16} className="animate-spin" />
        : quality.isError ? <p className="text-sm text-destructive">Could not load rule quality.</p>
        : quality.data && <>
          <div className="flex flex-wrap gap-3">
            <Stat label="Enabled rules" value={quality.data.rules_enabled} />
            <Stat label={`Rules that alerted (${days}d)`} value={quality.data.rules_alerting} />
            <Stat label="Alerts" value={quality.data.alerts} />
            <Stat label="Closed as false positive" value={`${quality.data.false_positives.toLocaleString()} (${fpShare}%)`} />
          </div>
          {override.isError && <p className="text-xs text-destructive">Could not change the level. Changing it needs permission to edit rules.</p>}
          {!items.length ? <p className="text-sm text-muted-foreground">{onlyAdvice ? 'No rule needs tuning.' : 'No rule raised an alert in this period.'}</p> : (
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead className="text-xs text-muted-foreground text-left">
                  <tr className="border-b border-border">
                    {['Rule', 'Level', 'Alerts', 'Per day', 'False positive', 'Untriaged', 'Suppressed', 'Last alert'].map(h =>
                      <th key={h} className="px-3 py-2 font-medium whitespace-nowrap">{h}</th>)}
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {items.map(i => (
                    <tr key={i.rule_id} className="align-top">
                      <td className="px-3 py-2 min-w-[240px]">
                        <div className="font-medium">{i.title}{!i.is_enabled && <span className="ml-2 text-xs text-muted-foreground">(disabled)</span>}</div>
                        {i.advice.map(a => <div key={a} className="text-xs text-amber-500 mt-0.5">{a}</div>)}
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        {canTune ? (
                          <select aria-label={`Level for ${i.title}`} value={i.level_override ?? i.level} disabled={override.isPending}
                            onChange={e => override.mutate({ id: i.rule_id, level: e.target.value === i.level ? null : e.target.value })}
                            className="bg-muted border border-border rounded px-2 py-1 text-xs">
                            {LEVELS.map(l => <option key={l} value={l}>{l}{l === i.level ? ' (rule)' : ''}</option>)}
                          </select>
                        ) : <SeverityBadge severity={i.level_override ?? i.level} />}
                        {i.level_override && <div className="text-[11px] text-muted-foreground mt-0.5">rule says {i.level}</div>}
                      </td>
                      <td className="px-3 py-2 tabular-nums">{i.alerts.toLocaleString()}{i.duplicates > 0 &&
                        <div className="text-[11px] text-muted-foreground">+{i.duplicates.toLocaleString()} dup</div>}</td>
                      <td className="px-3 py-2 tabular-nums">{i.alerts_per_day}</td>
                      <td className="px-3 py-2"><FpBar rate={i.fp_rate} />
                        <div className="text-[11px] text-muted-foreground">{i.false_positives} FP · {i.resolved} real</div></td>
                      <td className="px-3 py-2 tabular-nums">{i.untriaged.toLocaleString()}</td>
                      <td className="px-3 py-2 tabular-nums">{i.suppressed_hits ? i.suppressed_hits.toLocaleString() : '—'}</td>
                      <td className="px-3 py-2 whitespace-nowrap text-xs text-muted-foreground">
                        {i.last_alert_at ? formatDistanceToNow(new Date(i.last_alert_at), { addSuffix: true }) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>}
    </div>
  )
}
