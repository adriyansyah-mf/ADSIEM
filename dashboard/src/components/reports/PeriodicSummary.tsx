import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { endOfMonth, format, startOfMonth, subDays, subMonths } from 'date-fns'
import { ArrowDown, ArrowUp, Download, Loader2 } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '@/api/client'
import { apiError } from './types'

// Period summary (server-api/app/api/routes/reports.py): numbers on the page,
// the PDF with an AI executive summary, and the PDFs generated before.

interface Named { name: string; count: number }
interface Summary {
  period: { from: string; to: string; days: number; tz: string }
  alerts: {
    total: number; previous: number; change_pct: number | null; by_severity: Record<string, number>
    by_day: { day: string; total: number; critical: number; high: number }[]
    top_rules: Named[]; top_hosts: Named[]; top_sources: Named[]; ai_verdicts: Record<string, number>
    mtta_minutes: number | null; mttr_minutes: number | null; resolved: number
  }
  cases: { opened: number; previous_opened: number; change_pct: number | null; closed: number; open_now: number
    notable: { id: string; title: string; severity: string; status: string; created_at: string }[] }
  mitre: { technique: string; count: number }[]
  agents: { total: number; online: number }
  vulnerabilities: { open: number; kev_open: number; critical_open: number; hosts_with_kev: number
    top_kev: { cve_id: string; name: string | null; hosts: number }[] }
  incident_reports: { number: string; title: string }[]
}
interface Run { id: string; period_from: string; period_to: string; language: string; ai: boolean
  created_by_name: string | null; created_at: string; alerts: number | null; cases: number | null }

const tz = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone } catch { return 'UTC' } })()
const ymd = (d: Date) => format(d, 'yyyy-MM-dd')
const PRESETS: [string, () => [string, string]][] = [
  ['Last 7 days', () => [ymd(subDays(new Date(), 6)), ymd(new Date())]],
  ['Last 30 days', () => [ymd(subDays(new Date(), 29)), ymd(new Date())]],
  ['This month', () => [ymd(startOfMonth(new Date())), ymd(new Date())]],
  ['Last month', () => { const m = subMonths(new Date(), 1); return [ymd(startOfMonth(m)), ymd(endOfMonth(m))] }],
]
const SEV = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLOR: Record<string, string> = { critical: 'var(--accent-red)', high: 'var(--accent-orange)', medium: 'var(--accent-yellow)', low: 'var(--accent-cyan)', info: 'var(--text-muted)' }

function duration(min: number | null) {
  if (min == null) return '—'
  return min < 120 ? `${Math.round(min)} min` : `${(min / 60).toFixed(1)} h`
}

function Kpi({ label, value, change, note, upIsBad = true }: {
  readonly label: string; readonly value: string; readonly change?: number | null; readonly note?: string; readonly upIsBad?: boolean
}) {
  const bad = change != null && (upIsBad ? change > 0 : change < 0)
  return (
    <div className="rounded border border-border bg-card p-3 space-y-1 min-w-0">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      {change != null && (
        <div className="text-xs flex items-center gap-1" style={{ color: bad ? 'var(--accent-orange)' : 'var(--accent-green)' }}>
          {change > 0 ? <ArrowUp size={12} /> : <ArrowDown size={12} />}{Math.abs(change)}% <span className="text-muted-foreground">vs the period before</span>
        </div>
      )}
      {note && <div className="text-xs text-muted-foreground">{note}</div>}
    </div>
  )
}

function Ranked({ title, items }: { readonly title: string; readonly items: Named[] }) {
  const max = Math.max(1, ...items.map(i => i.count))
  return (
    <section className="rounded border border-border bg-card p-3 space-y-2 min-w-0">
      <h3 className="text-sm font-semibold">{title}</h3>
      {!items.length ? <p className="text-xs text-muted-foreground">None.</p> : (
        <ul className="space-y-1 text-xs">
          {items.map(i => (
            <li key={i.name} className="grid grid-cols-[minmax(0,1fr)_auto] gap-2 items-center">
              <div className="relative h-5 rounded bg-muted overflow-hidden">
                <div className="absolute inset-y-0 left-0 bg-primary/30" style={{ width: `${(i.count / max) * 100}%` }} />
                <span className="relative px-1.5 font-mono truncate block leading-5">{i.name}</span>
              </div>
              <span className="tabular-nums">{i.count.toLocaleString()}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

export default function PeriodicSummary() {
  const qc = useQueryClient()
  const [[from, to], setRange] = useState<[string, string]>(PRESETS[0][1]())
  const [language, setLanguage] = useState<'id' | 'en'>('id')
  const [useAi, setUseAi] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState('')
  const valid = from && to && from <= to
  const summary = useQuery<Summary>({
    queryKey: ['report-summary', from, to],
    queryFn: () => api.get('/api/reports/summary', { params: { date_from: from, date_to: to, tz } }).then(r => r.data),
    enabled: !!valid,
  })
  const history = useQuery<Run[]>({ queryKey: ['report-history'], queryFn: () => api.get('/api/reports/history').then(r => r.data) })

  const save = (blob: Blob, name: string) => {
    const href = URL.createObjectURL(blob)
    try { const a = document.createElement('a'); a.href = href; a.download = name; a.click() } finally { URL.revokeObjectURL(href) }
  }
  const generate = async () => {
    setError(''); setGenerating(true)
    try {
      const res = await api.post('/api/reports/generate', { date_from: from, date_to: to, language, tz, use_ai: useAi }, { responseType: 'blob' })
      save(res.data, `security-report-${from}-to-${to}.pdf`)
      void qc.invalidateQueries({ queryKey: ['report-history'] })
    } catch (e) {
      setError(apiError(e, 'Could not generate the report.'))
    } finally {
      setGenerating(false)
    }
  }
  const s = summary.data

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end gap-2">
        <div className="control-cluster flex-wrap">
          {PRESETS.map(([label, fn]) => {
            const [f, t] = fn()
            return <button key={label} type="button" onClick={() => setRange([f, t])}
              className={`ui-button ${f === from && t === to ? 'ui-button--primary' : 'ui-button--quiet'}`}>{label}</button>
          })}
        </div>
        <label className="field"><span>From</span><input type="date" className="ui-input" value={from} onChange={e => setRange([e.target.value, to])} /></label>
        <label className="field"><span>To</span><input type="date" className="ui-input" value={to} onChange={e => setRange([from, e.target.value])} /></label>
      </div>
      {!valid && <p className="text-xs text-destructive">The start date must be on or before the end date.</p>}

      {summary.isLoading ? <Loader2 size={16} className="animate-spin" />
        : summary.isError ? <p className="text-sm text-destructive">{apiError(summary.error, 'Could not load the numbers.')}</p>
        : s && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <Kpi label="Alerts" value={s.alerts.total.toLocaleString()} change={s.alerts.change_pct} />
              <Kpi label="Cases opened" value={s.cases.opened.toLocaleString()} change={s.cases.change_pct}
                note={`${s.cases.closed} closed · ${s.cases.open_now} still open`} />
              <Kpi label="Mean time to acknowledge / resolve" value={`${duration(s.alerts.mtta_minutes)} / ${duration(s.alerts.mttr_minutes)}`}
                note={`${s.alerts.resolved.toLocaleString()} alerts resolved`} />
              <Kpi label="Exploited vulnerabilities open (KEV)" value={s.vulnerabilities.kev_open.toLocaleString()}
                note={`on ${s.vulnerabilities.hosts_with_kev} hosts · agents online ${s.agents.online}/${s.agents.total}`} />
            </div>

            <section className="rounded border border-border bg-card p-3 space-y-2">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h3 className="text-sm font-semibold">Alerts per day</h3>
                <div className="flex flex-wrap gap-2 text-xs">
                  {SEV.filter(k => s.alerts.by_severity[k]).map(k => (
                    <span key={k} className="flex items-center gap-1"><span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: SEV_COLOR[k] }} />
                      {k} {s.alerts.by_severity[k].toLocaleString()}</span>
                  ))}
                </div>
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={s.alerts.by_day.map(d => ({ day: d.day.slice(5), critical: d.critical, high: d.high, other: d.total - d.critical - d.high }))}
                  margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid stroke="var(--border-default)" strokeOpacity={0.5} vertical={false} />
                  <XAxis dataKey="day" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} minTickGap={12} />
                  <YAxis allowDecimals={false} width={40} tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-default)', fontSize: 12 }} />
                  <Bar dataKey="other" stackId="a" fill="var(--text-muted)" isAnimationActive={false} />
                  <Bar dataKey="high" stackId="a" fill="var(--accent-orange)" isAnimationActive={false} />
                  <Bar dataKey="critical" stackId="a" fill="var(--accent-red)" isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </section>

            <div className="grid md:grid-cols-3 gap-3">
              <Ranked title="Most frequent rules" items={s.alerts.top_rules} />
              <Ranked title="Hosts with most alerts" items={s.alerts.top_hosts} />
              <Ranked title="Top source IPs" items={s.alerts.top_sources} />
              <Ranked title="MITRE ATT&CK techniques" items={s.mitre.map(m => ({ name: m.technique, count: m.count }))} />
              <Ranked title="AI triage outcome" items={Object.entries(s.alerts.ai_verdicts).map(([name, count]) => ({ name: name.replace('_', ' '), count })).sort((a, b) => b.count - a.count)} />
              <section className="rounded border border-border bg-card p-3 space-y-2 min-w-0">
                <h3 className="text-sm font-semibold">Exploited vulnerabilities still open</h3>
                {!s.vulnerabilities.top_kev.length ? <p className="text-xs text-muted-foreground">None.</p> : (
                  <ul className="text-xs space-y-1">{s.vulnerabilities.top_kev.map(v => (
                    <li key={v.cve_id}><Link className="font-mono underline" to="/vulnerabilities">{v.cve_id}</Link> · {v.name} · {v.hosts} host{v.hosts > 1 ? 's' : ''}</li>
                  ))}</ul>
                )}
              </section>
            </div>

            <section className="rounded border border-border bg-card p-3 space-y-2">
              <h3 className="text-sm font-semibold">Notable cases (high and critical)</h3>
              {!s.cases.notable.length ? <p className="text-xs text-muted-foreground">None in this period.</p> : (
                <ul className="text-sm space-y-1">{s.cases.notable.map(c => (
                  <li key={c.id} className="flex flex-wrap gap-2 items-baseline">
                    <span className="text-xs text-muted-foreground tabular-nums">{format(new Date(c.created_at), 'yyyy-MM-dd')}</span>
                    <span className="text-xs uppercase" style={{ color: SEV_COLOR[c.severity] }}>{c.severity}</span>
                    <Link className="hover:underline" to={`/cases/${c.id}`}>{c.title}</Link>
                    <span className="text-xs text-muted-foreground">{c.status}</span>
                  </li>
                ))}</ul>
              )}
              {s.incident_reports.length > 0 && <p className="text-xs text-muted-foreground">Incident reports finalized: {s.incident_reports.map(r => r.number).join(', ')}</p>}
            </section>
          </>
        )}

      <section className="rounded border border-border bg-card p-4 space-y-3">
        <h3 className="text-sm font-semibold">Download as PDF</h3>
        <div className="flex flex-wrap items-end gap-3">
          <label className="field"><span>Language</span>
            <select className="ui-input w-auto" value={language} onChange={e => setLanguage(e.target.value as 'id' | 'en')}>
              <option value="id">Bahasa Indonesia</option><option value="en">English</option></select></label>
          <label className="flex items-center gap-2 text-sm cursor-pointer pb-2">
            <input type="checkbox" checked={useAi} onChange={e => setUseAi(e.target.checked)} /> AI executive summary</label>
          <button type="button" className="ui-button ui-button--primary" disabled={!valid || generating} onClick={() => void generate()}>
            {generating ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />} {generating ? 'Generating…' : 'Generate PDF'}</button>
        </div>
        <p className="text-xs text-muted-foreground">The PDF has these numbers with a chart and tables, and is kept below so it can be downloaded again.
          The organization name on it is set under Settings.</p>
        {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-semibold">Generated before</h3>
        {history.isLoading ? <Loader2 size={14} className="animate-spin" /> : !history.data?.length ? (
          <p className="text-xs text-muted-foreground">No PDFs yet.</p>
        ) : (
          <div className="rounded border border-border bg-card overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted text-muted-foreground">
                <tr className="text-left text-[11px] uppercase tracking-wider">
                  <th className="px-3 py-2">Period</th><th className="px-3 py-2">Alerts</th><th className="px-3 py-2">Cases</th>
                  <th className="px-3 py-2">Language</th><th className="px-3 py-2">By</th><th className="px-3 py-2">Created</th><th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>{history.data.map(r => (
                <tr key={r.id} className="border-t border-border">
                  <td className="px-3 py-2 tabular-nums whitespace-nowrap">{format(new Date(r.period_from), 'yyyy-MM-dd')} – {format(new Date(new Date(r.period_to).getTime() - 1000), 'yyyy-MM-dd')}</td>
                  <td className="px-3 py-2 tabular-nums">{r.alerts?.toLocaleString() ?? '—'}</td>
                  <td className="px-3 py-2 tabular-nums">{r.cases ?? '—'}</td>
                  <td className="px-3 py-2 uppercase text-xs">{r.language}{r.ai ? ' · AI' : ''}</td>
                  <td className="px-3 py-2">{r.created_by_name ?? '—'}</td>
                  <td className="px-3 py-2 text-muted-foreground tabular-nums whitespace-nowrap">{format(new Date(r.created_at), 'yyyy-MM-dd HH:mm')}</td>
                  <td className="px-3 py-2"><button type="button" className="ui-button ui-button--quiet text-xs"
                    onClick={async () => save((await api.get(`/api/reports/history/${r.id}/pdf`, { responseType: 'blob' })).data, `security-report-${r.period_from.slice(0, 10)}.pdf`)}>
                    <Download size={12} /> PDF</button></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
