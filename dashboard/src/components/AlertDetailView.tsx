import { useMemo, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import type { Alert, AlertDetail } from '@/types'
import SeverityBadge from './SeverityBadge'
import StatusBadge from './StatusBadge'
import { useUpdateAlert, useAddAlertNote, useAlertFeedback, useSubmitAlertFeedback } from '@/hooks/useAlerts'
import { useAlertCases, useCreateCase } from '@/hooks/useCases'
import { format, formatDistanceStrict } from 'date-fns'
import {
  X, ShieldOff, CheckCircle, Copy, Search, Server, Activity, Link2, FileText, Target, LayoutList, Braces, Info,
  ArrowLeft, Maximize2, FolderPlus, Briefcase,
} from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import MarkdownNote from './MarkdownNote'
import AiFeedbackWidget from './AiFeedbackWidget'

interface Props {
  alertId: string
  summary?: Alert            // row data to render while the full detail loads
  variant: 'page' | 'modal'
  onClose?: () => void       // modal only
}

type Tab = 'overview' | 'table' | 'json'
type DocValue = string | number | boolean | null | undefined | string[]

const STATUS_OPTIONS = ['new', 'in_progress', 'resolved', 'false_positive']

// Wazuh-style numeric level next to our severity, so analysts used to Wazuh read it at a glance.
const LEVEL: Record<string, number> = { info: 3, low: 5, medium: 8, high: 12, critical: 15 }

/** The alert as one flat, Wazuh-like document: what the Table and JSON tabs show. */
function buildDocument(a: Alert, d?: AlertDetail): Record<string, DocValue> {
  const ctx = a.context ?? {}
  const doc: Record<string, DocValue> = {
    timestamp: d?.event?.timestamp ?? a.created_at,
    id: a.id,
    'agent.id': d?.agent?.id ?? a.agent_id,
    'agent.name': d?.agent?.hostname ?? a.hostname,
    'agent.version': d?.agent?.version,
    'agent.status': d?.agent?.status,
    'rule.id': ctx.rule_ref ?? d?.rule?.id,
    'rule.level': LEVEL[a.severity] ?? null,
    'rule.severity': a.severity,
    'rule.description': d?.rule?.title ?? a.title,
    'rule.groups': (ctx.tags ?? d?.rule?.tags ?? []).filter(t => !/^attack\.t\d/i.test(t)).map(t => t.replace(/^attack\./, '')),
    'rule.firedtimes': d?.rule_fired_24h,
    'rule.mitre.id': d?.mitre.map(m => m.id),
    'rule.mitre.technique': d?.mitre.map(m => m.name ?? m.id),
    'rule.mitre.tactic': d ? [...new Set(d.mitre.map(m => m.tactic).filter(Boolean) as string[])] : undefined,
    'decoder.name': d?.event?.decoder,
    location: d?.event?.location,
    'log.type': d?.event?.log_type,
    full_log: d?.event?.full_log,
    'alert.status': a.status,
    'alert.occurrences': (a.duplicate_count ?? 0) + 1,
    'alert.kill_chain_stage': a.kill_chain_stage,
    'alert.ai_verdict': a.ai_verdict,
    'source.ip': a.source_ip,
    'source.geo.country': a.source_ip_country,
  }
  if (ctx.correlation_hit_count != null) {
    doc['threshold.hits'] = ctx.correlation_hit_count
    doc['threshold.window_seconds'] = ctx.correlation_window
    doc['threshold.group_by'] = ctx.correlation_group_by
    doc['threshold.group'] = ctx.correlation_group
    if (ctx.correlation_type) doc['correlation.type'] = ctx.correlation_type
    if (ctx.correlation_rules?.length) doc['correlation.rules'] = ctx.correlation_rules
  }
  for (const [k, v] of Object.entries(d?.event?.data ?? {})) {
    doc[`data.${k}`] = typeof v === 'object' && v !== null ? JSON.stringify(v) : (v as DocValue)
  }
  if (d?.ueba) {
    doc['ueba.entity'] = `${d.ueba.entity_type}:${d.ueba.entity_value}`
    doc['ueba.risk_score'] = Math.round(d.ueba.risk_score)
    doc['ueba.anomaly_score'] = Number(d.ueba.anomaly_score.toFixed(4))
    doc['ueba.reasons'] = d.ueba.reasons.map(r => r.text)
    for (const [k, v] of Object.entries(d.ueba.features)) doc[`ueba.features.${k}`] = v
  }
  return Object.fromEntries(Object.entries(doc).filter(([, v]) =>
    v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && v.length === 0)))
}

/** Lucene query for "find more events like this field" on the Logs page. */
function pivotQuery(field: string, value: DocValue): string | null {
  if (value === null || value === undefined || Array.isArray(value)) return null
  const v = String(value).replace(/"/g, '\\"')
  if (field.startsWith('data.')) return `decoded_fields.${field.slice(5)}:"${v}"`
  const direct: Record<string, string> = {
    location: 'location', 'decoder.name': 'decoder', 'log.type': 'log_type', 'agent.id': 'agent_id', 'source.ip': 'source_ip',
  }
  return direct[field] ? `${direct[field]}:"${v}"` : null
}

function copy(text: string) {
  navigator.clipboard?.writeText(text).catch(() => undefined)
}

function renderValue(v: DocValue): string {
  return Array.isArray(v) ? v.join(', ') : String(v)
}

// ─── Building blocks ─────────────────────────────────────────────

function Card({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="rounded border border-border bg-muted/20 px-3 py-2" title={hint}>
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-0.5 text-sm font-semibold">{children}</div>
    </div>
  )
}

function Section({ icon, title, children, right }: { icon: ReactNode; title: string; children: ReactNode; right?: ReactNode }) {
  return (
    <section className="rounded-lg border border-border">
      <header className="flex items-center gap-1.5 border-b border-border bg-muted/20 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {icon} {title}<span className="ml-auto normal-case tracking-normal">{right}</span>
      </header>
      <div className="p-3">{children}</div>
    </section>
  )
}

function KeyValues({ rows }: { rows: Array<[string, ReactNode]> }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  )
}

function DocumentTable({ doc, onPivot }: { doc: Record<string, DocValue>; onPivot: (q: string) => void }) {
  const [filter, setFilter] = useState('')
  const rows = Object.entries(doc).filter(([k, v]) =>
    !filter || k.toLowerCase().includes(filter.toLowerCase()) || renderValue(v).toLowerCase().includes(filter.toLowerCase()))
  return (
    <div className="space-y-2">
      <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter fields…"
        className="w-full rounded border border-border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary" />
      <div className="max-h-[60vh] overflow-auto rounded border border-border">
        <table className="w-full text-xs">
          <tbody>
            {rows.map(([k, v]) => {
              const q = pivotQuery(k, v)
              return (
                <tr key={k} className="group border-b border-border/40 align-top hover:bg-muted/20">
                  <td className="w-8 py-1 pl-2">
                    <div className="flex gap-1 opacity-0 group-hover:opacity-100">
                      <button title="Copy value" onClick={() => copy(renderValue(v))} className="text-muted-foreground hover:text-foreground"><Copy size={12} /></button>
                      {q && <button title={`Search logs: ${q}`} onClick={() => onPivot(q)} className="text-muted-foreground hover:text-primary"><Search size={12} /></button>}
                    </div>
                  </td>
                  <td className="whitespace-nowrap py-1 pr-4 font-mono text-muted-foreground">{k}</td>
                  <td className={`py-1 pr-2 font-mono break-all ${k === 'full_log' ? 'whitespace-pre-wrap' : ''}`}>{renderValue(v)}</td>
                </tr>
              )
            })}
            {rows.length === 0 && <tr><td className="p-3 text-muted-foreground" colSpan={3}>No field matches.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Overview ────────────────────────────────────────────────────

function Overview({ a, d, onPivot, wide }: { a: Alert; d?: AlertDetail; onPivot: (q: string) => void; wide?: boolean }) {
  const ctx = a.context ?? {}
  const data = d?.event?.data ?? {}
  const keyFields = ['source.ip', 'user.name', 'user.target', 'http.request.method', 'url.path', 'http.response.status_code',
    'user_agent.original', 'event.action', 'process.command_line', 'process.name', 'destination.ip', 'destination.port']
    .filter(k => data[k] !== undefined && data[k] !== null && data[k] !== '')
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Card label="Level" hint="Wazuh-style level derived from severity">
          {LEVEL[a.severity] ?? '—'} <span className="text-xs font-normal text-muted-foreground">({a.severity})</span>
        </Card>
        <Card label="Rule fired (24h)">{d ? d.rule_fired_24h || '—' : '…'}</Card>
        <Card label="Occurrences">
          {(a.duplicate_count ?? 0) + 1}
          {(a.duplicate_count ?? 0) > 0 && (
            <span className="block text-[11px] font-normal text-muted-foreground">last {formatDistanceStrict(new Date(a.updated_at), new Date())} ago</span>
          )}
        </Card>
        <Card label="Agent">
          {d?.agent ? (
            <span className="inline-flex items-center gap-1"><Server size={12} />{d.agent.hostname}
              <span className={`text-[11px] font-normal ${d.agent.status === 'online' ? 'text-emerald-400' : 'text-muted-foreground'}`}>{d.agent.status}</span>
            </span>
          ) : <span className="font-normal text-muted-foreground">{a.hostname ?? '—'}</span>}
        </Card>
      </div>

      {/* on the full page, rule and event sit side by side */}
      <div className={wide ? 'grid gap-3 xl:grid-cols-2 [&>*]:min-w-0' : 'space-y-3'}>
      <Section icon={<Target size={13} />} title="Rule" right={d?.rule && <span className="font-mono text-[11px]">{ctx.rule_ref ?? ''}</span>}>
        <div className="space-y-2">
          <div className="text-sm font-medium">{d?.rule?.title ?? (d?.ueba ? 'UEBA behavioural anomaly' : a.title)}</div>
          {d?.rule?.description && <p className="whitespace-pre-line text-xs text-muted-foreground">{d.rule.description}</p>}
          {ctx.correlation_hit_count != null && (
            <div className="rounded bg-muted/30 px-2 py-1 text-xs">
              Fired after <b>{ctx.correlation_hit_count}</b> {ctx.correlation_type ? ctx.correlation_type.replace('_', ' ') : 'matching events'}
              {ctx.correlation_window ? <> within <b>{ctx.correlation_window}s</b></> : null}
              {ctx.correlation_group && ctx.correlation_group !== '_all'
                ? <> for <span className="font-mono">{ctx.correlation_group_by ?? 'group'} = {ctx.correlation_group}</span></> : null}
            </div>
          )}
          {d && d.mitre.length > 0 && (
            <table className="w-full text-xs">
              <thead><tr className="text-left text-muted-foreground"><th className="py-0.5 pr-3 font-medium">MITRE ID</th><th className="py-0.5 pr-3 font-medium">Technique</th><th className="py-0.5 font-medium">Tactic</th></tr></thead>
              <tbody>
                {d.mitre.map(m => (
                  <tr key={m.id} className="border-t border-border/40">
                    <td className="py-0.5 pr-3 font-mono">{m.url ? <a href={m.url} target="_blank" rel="noreferrer" className="text-primary hover:underline">{m.id}</a> : m.id}</td>
                    <td className="py-0.5 pr-3">{m.name ?? '—'}</td>
                    <td className="py-0.5">{m.tactic ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {d?.rule && (
            <details className="text-xs">
              <summary className="cursor-pointer select-none text-muted-foreground hover:text-foreground">Rule definition</summary>
              <pre className="mt-2 max-h-60 overflow-auto whitespace-pre-wrap rounded bg-muted/20 p-2 font-mono text-xs">{d.rule.content}</pre>
            </details>
          )}
        </div>
      </Section>

      {d?.event && (
        <Section icon={<FileText size={13} />} title="Event"
          right={<span className="font-mono text-[11px]">{d.event.location ?? d.event.log_type}</span>}>
          <div className="space-y-2">
            <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-muted/20 p-2 font-mono text-xs">{d.event.full_log}</pre>
            <KeyValues rows={[
              ['Log type', <span className="font-mono">{d.event.log_type ?? '—'}</span>],
              ['Location', <span className="font-mono">{d.event.location ?? '— (agent < 1.4)'}</span>],
              ['Decoder', <span className="font-mono">{d.event.decoder ?? 'none matched'}</span>],
              ...keyFields.map(k => [k, (
                <span className="inline-flex items-center gap-1 font-mono">
                  {String(data[k])}
                  <button title="Search logs for this value" onClick={() => onPivot(`decoded_fields.${k}:"${String(data[k]).replace(/"/g, '\\"')}"`)}
                    className="text-muted-foreground hover:text-primary"><Search size={11} /></button>
                </span>
              )] as [string, ReactNode]),
            ]} />
          </div>
        </Section>
      )}

      </div>

      {d?.ueba && (
        <Section icon={<Activity size={13} />} title="Behavioural anomaly (UEBA)"
          right={<span className="font-mono text-[11px]">risk {d.ueba.risk_score.toFixed(0)}/100</span>}>
          <div className="space-y-2 text-xs">
            <div className="font-mono">{d.ueba.entity_type} {d.ueba.entity_value}</div>
            <ul className="list-disc space-y-0.5 pl-5">{d.ueba.reasons.map((r, i) => <li key={i}>{r.text}</li>)}</ul>
            {d.ueba.ai_narrative && <div className="rounded bg-muted/30 p-2"><b>AI ({d.ueba.ai_action}):</b> {d.ueba.ai_narrative}</div>}
          </div>
        </Section>
      )}

      {d && d.related.length > 0 && (
        <Section icon={<Link2 size={13} />} title={`Related alerts (same IP/host, ±24h)`} right={<span>{d.related.length}</span>}>
          <div className="max-h-44 divide-y divide-border/40 overflow-auto text-xs">
            {d.related.map(r => (
              <div key={r.id} className="flex items-center gap-2 py-1">
                <SeverityBadge severity={r.severity} />
                <span className="flex-1 truncate" title={r.title}>{r.title}</span>
                {r.duplicate_count > 0 && <span className="text-muted-foreground">×{r.duplicate_count + 1}</span>}
                <span className="whitespace-nowrap text-muted-foreground">{format(new Date(r.created_at), 'MM-dd HH:mm')}</span>
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  )
}

// ─── Case ────────────────────────────────────────────────────────

const CASE_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

/** What the analyst would otherwise retype: where, when, and what fired. */
function caseDescription(a: Alert): string {
  const lines = [
    `Opened from alert "${a.title}" (${a.severity}) at ${format(new Date(a.created_at), 'yyyy-MM-dd HH:mm:ss')}.`,
    a.hostname && `Host: ${a.hostname}`,
    a.source_ip && `Source IP: ${a.source_ip}${a.source_ip_country ? ` (${a.source_ip_country})` : ''}`,
    a.mitre_techniques?.length && `MITRE: ${a.mitre_techniques.join(', ')}`,
  ]
  return lines.filter(Boolean).join('\n')
}

/** Linked cases for this alert, and a form to open one by hand. */
function AlertCasePanel({ alert, onOpenCase }: { alert: Alert; onOpenCase: (id: string) => void }) {
  const { data: linked } = useAlertCases(alert.id)
  const createCase = useCreateCase()
  const [open, setOpen] = useState(false)
  const [title, setTitle] = useState(alert.title)
  const [severity, setSeverity] = useState<(typeof CASE_SEVERITIES)[number]>(
    (CASE_SEVERITIES as readonly string[]).includes(alert.severity) ? alert.severity as (typeof CASE_SEVERITIES)[number] : 'medium')
  const [description, setDescription] = useState(() => caseDescription(alert))
  const cases = linked?.items ?? []

  const submit = () => createCase.mutate(
    { title: title.trim(), severity, description: description.trim() || undefined, alert_id: alert.id },
    { onSuccess: (c) => { setOpen(false); onOpenCase(c.id) } },
  )

  return (
    <div className="space-y-2">
      <label className="block text-xs font-medium text-muted-foreground">Case</label>
      {cases.map((c) => (
        <button key={c.id} onClick={() => onOpenCase(c.id)}
          className="flex w-full items-start gap-1.5 rounded border border-border px-2 py-1.5 text-left text-xs hover:bg-muted">
          <Briefcase size={13} className="mt-0.5 shrink-0 text-primary" />
          <span className="min-w-0 flex-1 break-words">{c.title}</span>
          <StatusBadge status={c.status} />
        </button>
      ))}
      {!open && (
        <button onClick={() => setOpen(true)}
          className="flex w-full items-center justify-center gap-1.5 rounded border border-border px-2 py-1.5 text-xs hover:bg-muted">
          <FolderPlus size={13} /> {cases.length ? 'Create another case' : 'Create case'}
        </button>
      )}
      {open && (
        <form className="space-y-2 rounded border border-border bg-muted/20 p-2"
          onSubmit={(e) => { e.preventDefault(); if (title.trim()) submit() }}>
          <div>
            <label htmlFor="case-title" className="mb-1 block text-[11px] text-muted-foreground">Title</label>
            <input id="case-title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={255} required
              className="w-full rounded border border-border bg-background px-2 py-1 text-xs" />
          </div>
          <div>
            <label htmlFor="case-severity" className="mb-1 block text-[11px] text-muted-foreground">Severity</label>
            <select id="case-severity" value={severity}
              onChange={(e) => setSeverity(e.target.value as (typeof CASE_SEVERITIES)[number])}
              className="w-full rounded border border-border bg-background px-2 py-1 text-xs">
              {CASE_SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="case-description" className="mb-1 block text-[11px] text-muted-foreground">Description</label>
            <textarea id="case-description" value={description} onChange={(e) => setDescription(e.target.value)} rows={5}
              className="w-full rounded border border-border bg-background px-2 py-1 font-mono text-[11px]" />
          </div>
          <div className="flex gap-2">
            <button type="submit" disabled={!title.trim() || createCase.isPending}
              className="rounded bg-primary px-2 py-1 text-xs text-primary-foreground disabled:opacity-50">
              {createCase.isPending ? 'Creating…' : 'Create case'}
            </button>
            <button type="button" onClick={() => setOpen(false)}
              className="rounded border border-border px-2 py-1 text-xs hover:bg-muted">Cancel</button>
          </div>
        </form>
      )}
    </div>
  )
}

// ─── Modal ───────────────────────────────────────────────────────

/** Alert detail, shared by the full page (/alerts/:id) and the quick-look modal. */
export default function AlertDetailView({ alertId, summary, variant, onClose }: Props) {
  const { data: detail, isError } = useQuery<AlertDetail>({
    queryKey: ['alert-detail', alertId],
    queryFn: () => api.get(`/api/alerts/${alertId}`).then(r => r.data),
  })
  const alert = detail ?? summary
  if (!alert) {
    return (
      <div className="rounded-lg border border-border bg-card p-6 text-sm text-muted-foreground">
        {isError ? 'Alert not found, or you do not have access to it.' : 'Loading alert…'}
      </div>
    )
  }
  return <AlertDetailBody alert={alert} detail={detail} variant={variant} onClose={onClose} />
}

function AlertDetailBody({ alert, detail, variant, onClose }: {
  alert: Alert; detail?: AlertDetail; variant: Props['variant']; onClose?: () => void
}) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [tab, setTab] = useState<Tab>('overview')
  const [note, setNote] = useState('')
  const [fpSuggestion, setFpSuggestion] = useState<{ entity_type: string; entity_value: string } | null>(null)
  const [suppressDone, setSuppressDone] = useState(false)
  const isPage = variant === 'page'
  const doc = useMemo(() => buildDocument(alert, detail), [alert, detail])

  const updateAlert = useUpdateAlert()
  const addNote = useAddAlertNote()
  const { data: feedback, isLoading: feedbackLoading } = useAlertFeedback(alert.id)
  const submitFeedback = useSubmitAlertFeedback(alert.id)

  const { data: usersData } = useQuery({
    queryKey: ['users-list'],
    queryFn: () => api.get('/api/users', { params: { page_size: 100 } }).then(r => r.data),
  })
  const users: Array<{ id: string; username: string }> = usersData?.items ?? []

  const createSuppression = useMutation({
    mutationFn: (body: { entity_type: string; entity_value: string; reason: string }) =>
      api.post('/api/suppressions', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['suppressions'] })
      setSuppressDone(true)
      setFpSuggestion(null)
    },
  })

  const refresh = () => qc.invalidateQueries({ queryKey: ['alert-detail', alert.id] })

  const handleStatusChange = (newStatus: string) => {
    updateAlert.mutate(
      { id: alert.id, data: { status: newStatus } },
      {
        onSuccess: (data: any) => {
          refresh()
          if (data?.fp_suppression_suggestion) setFpSuggestion(data.fp_suppression_suggestion)
        },
      }
    )
  }

  const handleAssigneeChange = (assigneeId: string) => {
    updateAlert.mutate({ id: alert.id, data: { assignee_id: assigneeId || undefined } }, { onSuccess: refresh })
  }

  const pivot = (q: string) => {
    onClose?.()
    navigate(`/logs?q=${encodeURIComponent(q)}`)
  }

  const tabs: Array<[Tab, string, ReactNode]> = [
    ['overview', 'Overview', <Info size={13} />],
    ['table', 'Table', <LayoutList size={13} />],
    ['json', 'JSON', <Braces size={13} />],
  ]

  const content = (
      <div className={isPage
        ? 'flex flex-col rounded-lg border border-border bg-card'
        : 'flex max-h-[94vh] w-full max-w-5xl flex-col rounded-lg border border-border bg-card shadow-2xl'}
        onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="border-b border-border p-4">
          {isPage && (
            <button onClick={() => navigate('/alerts')}
              className="mb-2 flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
              <ArrowLeft size={13} /> Alerts
            </button>
          )}
          <div className="flex items-start gap-3">
            <div className="min-w-0 flex-1">
              <h2 className={`break-words font-bold leading-snug ${isPage ? 'text-xl' : 'text-base'}`}>{alert.title}</h2>
              <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
                <span>{format(new Date(alert.created_at), 'yyyy-MM-dd HH:mm:ss')}</span>
                {alert.source_ip && <span className="font-mono">{alert.source_ip}{alert.source_ip_country ? ` (${alert.source_ip_country})` : ''}</span>}
                {alert.kill_chain_stage && alert.kill_chain_stage !== 'Unknown' && (
                  <span className="rounded border border-border px-1.5 py-0.5">{alert.kill_chain_stage}</span>
                )}
                {alert.ai_verdict && <span className="rounded border border-primary/40 px-1.5 py-0.5 text-primary">AI: {alert.ai_verdict}</span>}
              </div>
            </div>
            {!isPage && (
              <div className="flex items-center gap-2">
                <button onClick={() => { onClose?.(); navigate(`/alerts/${alert.id}`) }}
                  className="flex items-center gap-1 rounded border border-border px-2 py-1 text-xs hover:bg-muted">
                  <Maximize2 size={12} /> Open full page
                </button>
                <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X size={20} /></button>
              </div>
            )}
          </div>
          <div className="mt-3 flex gap-1">
            {tabs.map(([key, label, icon]) => (
              <button key={key} onClick={() => setTab(key)}
                className={`flex items-center gap-1 rounded px-3 py-1 text-xs ${tab === key ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted hover:text-foreground'}`}>
                {icon}{label}
              </button>
            ))}
            {tab === 'json' && (
              <button onClick={() => copy(JSON.stringify(doc, null, 2))}
                className="ml-auto flex items-center gap-1 rounded border border-border px-2 py-1 text-xs hover:bg-muted">
                <Copy size={12} /> Copy JSON
              </button>
            )}
          </div>
        </div>

        {/* Body */}
        <div className={isPage
          ? 'grid gap-5 p-5 lg:grid-cols-[minmax(0,1fr)_300px]'
          : 'grid min-h-0 flex-1 gap-4 overflow-auto p-4 lg:grid-cols-[minmax(0,1fr)_260px]'}>
          <div className="min-w-0">
            {tab === 'overview' && <Overview a={alert} d={detail} onPivot={pivot} wide={isPage} />}
            {tab === 'table' && <DocumentTable doc={doc} onPivot={pivot} />}
            {tab === 'json' && (
              <pre className="max-h-[65vh] overflow-auto rounded border border-border bg-muted/20 p-3 font-mono text-xs">{JSON.stringify(doc, null, 2)}</pre>
            )}
          </div>

          {/* Triage side panel */}
          <aside className={`space-y-3 ${isPage ? 'lg:sticky lg:top-4 lg:self-start' : ''}`}>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">Status</label>
              <select value={alert.status} onChange={(e) => handleStatusChange(e.target.value)}
                className="w-full rounded border border-border bg-background px-2 py-1.5 text-sm">
                {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">Assignee</label>
              <select value={alert.assignee_id ?? ''} onChange={(e) => handleAssigneeChange(e.target.value)}
                className="w-full rounded border border-border bg-background px-2 py-1.5 text-sm">
                <option value="">Unassigned</option>
                {users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
              </select>
            </div>

            <AlertCasePanel key={alert.id} alert={alert}onOpenCase={(id) => { onClose?.(); navigate(`/cases/${id}`) }} />

            {fpSuggestion && !suppressDone && (
              <div className="rounded border border-yellow-600/40 bg-yellow-900/20 p-2 text-xs">
                <div className="mb-1 flex items-center gap-1 font-medium text-yellow-300"><ShieldOff size={13} /> Create suppression?</div>
                <div className="mb-2 text-muted-foreground">
                  Suppress future alerts for <span className="font-mono text-yellow-200">{fpSuggestion.entity_type}: {fpSuggestion.entity_value}</span>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => createSuppression.mutate({ ...fpSuggestion, reason: 'Confirmed false positive' })}
                    disabled={createSuppression.isPending}
                    className="rounded bg-yellow-600 px-2 py-1 font-medium text-black disabled:opacity-50">Yes, suppress</button>
                  <button onClick={() => setFpSuggestion(null)} className="rounded border border-border px-2 py-1 hover:bg-muted">Dismiss</button>
                </div>
              </div>
            )}
            {suppressDone && (
              <div className="flex items-center gap-2 rounded border border-emerald-600/40 bg-emerald-900/20 p-2 text-xs text-emerald-300">
                <CheckCircle size={13} /> Suppression rule created.
              </div>
            )}

            {alert.ai_verdict && (
              <AiFeedbackWidget
                aiVerdict={alert.ai_verdict}
                feedback={feedback}
                isLoading={feedbackLoading}
                onSubmit={body => submitFeedback.mutate(body)}
                isSubmitting={submitFeedback.isPending}
              />
            )}

            <div>
              <h3 className="mb-1 text-xs font-medium text-muted-foreground">Notes ({alert.notes.length})</h3>
              <div className="max-h-72 space-y-2 overflow-auto">
                {alert.notes.map((n) => (
                  <div key={n.id} className="rounded bg-muted p-2 text-xs">
                    <div className="mb-1 text-[10px] text-muted-foreground">{format(new Date(n.created_at), 'yyyy-MM-dd HH:mm')}</div>
                    <MarkdownNote content={n.content} />
                  </div>
                ))}
              </div>
              <div className="mt-2 flex gap-1">
                <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note…"
                  className="min-w-0 flex-1 rounded border border-border bg-background px-2 py-1 text-xs" />
                <button
                  onClick={() => {
                    addNote.mutate({ id: alert.id, content: note }, { onSuccess: refresh })
                    setNote('')
                  }}
                  disabled={!note} className="rounded bg-primary px-2 py-1 text-xs text-primary-foreground disabled:opacity-50">Add</button>
              </div>
            </div>
          </aside>
        </div>
      </div>
  )

  if (isPage) return content
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-2" onClick={onClose}>
      {content}
    </div>
  )
}
