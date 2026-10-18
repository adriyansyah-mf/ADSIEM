import { useState, type ReactNode } from 'react'
import type { Alert, AlertDetail, Event, RawLog } from '@/types'
import SeverityBadge from './SeverityBadge'
import StatusBadge from './StatusBadge'
import { useUpdateAlert, useAddAlertNote, useAlertFeedback, useSubmitAlertFeedback } from '@/hooks/useAlerts'
import { format, formatDistanceStrict } from 'date-fns'
import { X, ShieldOff, CheckCircle, FileText, Target, Server, Link2, Activity } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import MarkdownNote from './MarkdownNote'
import AiFeedbackWidget from './AiFeedbackWidget'

interface Props { alert: Alert; onClose: () => void }

const STATUS_OPTIONS = ['new', 'in_progress', 'resolved', 'false_positive']

function SourceLogPanel({ alertId }: { alertId: string }) {
  const { data, isLoading } = useQuery<{ event: Event | null; raw_log: RawLog | null }>({
    queryKey: ['alert-source-log', alertId],
    queryFn: () => api.get(`/api/alerts/${alertId}/source-log`).then(r => r.data),
  })

  if (isLoading) return <div className="text-xs text-muted-foreground">Loading source log…</div>

  if (!data?.raw_log && !data?.event) {
    return <div className="text-xs text-muted-foreground">No source log linked to this alert.</div>
  }

  return (
    <div className="space-y-2">
      {data.raw_log && (
        <pre className="text-xs font-mono bg-muted/20 p-2 rounded max-h-40 overflow-auto whitespace-pre-wrap break-all">
          {data.raw_log.raw_message}
        </pre>
      )}
      {data.raw_log?.log_type && (
        <div className="text-[11px] text-muted-foreground">
          log type <span className="font-mono">{data.raw_log.log_type}</span> · received{' '}
          {format(new Date(data.raw_log.received_at), 'yyyy-MM-dd HH:mm:ss')}
        </div>
      )}
      {data.event && Object.keys(data.event.decoded_fields ?? {}).length > 0 && (
        <FieldTable fields={data.event.decoded_fields as Record<string, unknown>} />
      )}
    </div>
  )
}

function FieldTable({ fields }: { fields: Record<string, unknown> }) {
  return (
    <table className="w-full text-xs font-mono">
      <tbody>
        {Object.entries(fields).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => (
          <tr key={k} className="border-b border-border/40 align-top">
            <td className="py-0.5 pr-3 text-muted-foreground whitespace-nowrap">{k}</td>
            <td className="py-0.5 break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v ?? '—')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function Section({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="mb-4">
      <h3 className="text-sm font-medium mb-2 flex items-center gap-1.5">{icon} {title}</h3>
      {children}
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <div><span className="text-muted-foreground">{label}:</span> {children}</div>
}

function DetectionPanel({ a }: { a: AlertDetail }) {
  const ctx = a.context ?? {}
  const mitre = a.mitre_techniques ?? []
  return (
    <div className="space-y-2 text-sm">
      {a.rule ? (
        <div>
          <div className="font-medium">{a.rule.title} <span className="text-xs text-muted-foreground">({a.rule.level})</span></div>
          {a.rule.description && <p className="text-xs text-muted-foreground whitespace-pre-line mt-0.5">{a.rule.description}</p>}
        </div>
      ) : (
        <div className="text-xs text-muted-foreground">
          {a.ueba ? 'Raised by UEBA (behavioural anomaly), not a signature rule.' : 'Detecting rule not found (it may have been deleted or renamed).'}
        </div>
      )}
      {ctx.correlation_hit_count != null && (
        <div className="text-xs rounded bg-muted/30 px-2 py-1">
          <span className="font-mono">{ctx.correlation_hit_count}</span>
          {ctx.correlation_type ? ` ${ctx.correlation_type.replace('_', ' ')}` : ' matching events'}
          {ctx.correlation_window ? ` within ${ctx.correlation_window}s` : ''}
          {ctx.correlation_group && ctx.correlation_group !== '_all'
            ? <> for <span className="font-mono">{ctx.correlation_group_by ?? 'group'} = {ctx.correlation_group}</span></> : ''}
          {ctx.correlation_rules?.length ? <> (rules: {ctx.correlation_rules.join(', ')})</> : null}
        </div>
      )}
      {(mitre.length > 0 || a.kill_chain_stage) && (
        <div className="flex flex-wrap gap-1 items-center">
          {a.kill_chain_stage && a.kill_chain_stage !== 'Unknown' && (
            <span className="text-[11px] rounded border border-border px-1.5 py-0.5">{a.kill_chain_stage}</span>
          )}
          {mitre.map(t => (
            <a key={t} href={`https://attack.mitre.org/techniques/${String(t).split(':')[0].trim().replace('.', '/')}/`}
              target="_blank" rel="noreferrer"
              className="text-[11px] font-mono rounded border border-primary/40 text-primary px-1.5 py-0.5 hover:underline">
              {t}
            </a>
          ))}
        </div>
      )}
      {a.rule && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground select-none">Rule definition</summary>
          <pre className="text-xs font-mono bg-muted/20 p-2 mt-2 rounded max-h-60 overflow-auto whitespace-pre-wrap">{a.rule.content}</pre>
        </details>
      )}
    </div>
  )
}

function UebaPanel({ u }: { u: NonNullable<AlertDetail['ueba']> }) {
  return (
    <div className="space-y-2 text-sm">
      <div className="text-xs">
        <span className="font-mono">{u.entity_type} {u.entity_value}</span> · risk <span className="font-mono">{u.risk_score.toFixed(0)}/100</span>
        {' '}· anomaly score <span className="font-mono">{u.anomaly_score.toFixed(3)}</span>
      </div>
      {u.reasons.length > 0 && (
        <ul className="list-disc pl-5 text-xs space-y-0.5">{u.reasons.map((r, i) => <li key={i}>{r.text}</li>)}</ul>
      )}
      {u.mitre_techniques.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {u.mitre_techniques.map(m => (
            <span key={m.id} className="text-[11px] font-mono rounded border border-primary/40 text-primary px-1.5 py-0.5">{m.id} · {m.name}</span>
          ))}
        </div>
      )}
      {u.ai_narrative && (
        <div className="text-xs rounded bg-muted/30 p-2"><span className="font-medium">AI ({u.ai_action}):</span> {u.ai_narrative}</div>
      )}
      <details className="text-xs">
        <summary className="cursor-pointer text-muted-foreground hover:text-foreground select-none">Feature values</summary>
        <div className="mt-2"><FieldTable fields={u.features} /></div>
      </details>
    </div>
  )
}

export default function AlertDetailModal({ alert: summary, onClose }: Props) {
  const qc = useQueryClient()
  const { data: detail } = useQuery<AlertDetail>({
    queryKey: ['alert-detail', summary.id],
    queryFn: () => api.get(`/api/alerts/${summary.id}`).then(r => r.data),
  })
  const alert: Alert = detail ?? summary
  const [note, setNote] = useState('')
  const [fpSuggestion, setFpSuggestion] = useState<{ entity_type: string; entity_value: string } | null>(null)
  const [suppressDone, setSuppressDone] = useState(false)

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

  const handleStatusChange = (newStatus: string) => {
    updateAlert.mutate(
      { id: alert.id, data: { status: newStatus } },
      {
        onSuccess: (data: any) => {
          if (data?.fp_suppression_suggestion) {
            setFpSuggestion(data.fp_suppression_suggestion)
          }
        },
      }
    )
  }

  const handleAssigneeChange = (assigneeId: string) => {
    updateAlert.mutate({ id: alert.id, data: { assignee_id: assigneeId || undefined } })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="w-full max-w-3xl rounded-lg border border-border bg-card p-6 shadow-2xl max-h-[90vh] overflow-auto"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold">{alert.title}</h2>
            <div className="flex gap-2 mt-1">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
            </div>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X size={20} /></button>
        </div>

        <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-sm mb-4">
          <Field label="Source IP">
            <span className="font-mono">{alert.source_ip ?? '—'}</span>
            {alert.source_ip_country && <span className="text-muted-foreground"> ({alert.source_ip_country})</span>}
          </Field>
          <Field label="Hostname">{alert.hostname ?? '—'}</Field>
          <Field label="First seen">{format(new Date(alert.created_at), 'yyyy-MM-dd HH:mm:ss')}</Field>
          <Field label="Occurrences">
            {(alert.duplicate_count ?? 0) + 1}
            {(alert.duplicate_count ?? 0) > 0 && (
              <span className="text-muted-foreground"> · last {formatDistanceStrict(new Date(alert.updated_at), new Date())} ago</span>
            )}
          </Field>
          <Field label="Group">{alert.group_id}</Field>
          {detail?.agent ? (
            <Field label="Agent">
              <span className="inline-flex items-center gap-1"><Server size={12} />{detail.agent.hostname}</span>
              <span className="text-muted-foreground"> ({detail.agent.status}{detail.agent.version ? `, v${detail.agent.version}` : ''})</span>
            </Field>
          ) : <Field label="Agent">—</Field>}
          {alert.ai_verdict && <Field label="AI verdict"><span className="font-mono">{alert.ai_verdict}</span></Field>}
        </div>

        {detail && (
          <Section icon={<Target size={14} />} title="Detection">
            <DetectionPanel a={detail} />
          </Section>
        )}

        {detail?.ueba && (
          <Section icon={<Activity size={14} />} title="Behavioural anomaly (UEBA)">
            <UebaPanel u={detail.ueba} />
          </Section>
        )}

        <div className="grid grid-cols-2 gap-3 mb-4">
          <div>
            <label className="block text-sm font-medium mb-1">Update Status</label>
            <select
              value={alert.status}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm"
            >
              {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Assignee</label>
            <select
              value={alert.assignee_id ?? ''}
              onChange={(e) => handleAssigneeChange(e.target.value)}
              className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm"
            >
              <option value="">Unassigned</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>{u.username}</option>
              ))}
            </select>
          </div>
        </div>

        {/* FP suppression suggestion */}
        {fpSuggestion && !suppressDone && (
          <div className="mb-4 p-3 rounded border border-yellow-600/40 bg-yellow-900/20 flex items-start gap-3">
            <ShieldOff size={16} className="text-yellow-400 mt-0.5 shrink-0" />
            <div className="flex-1 text-sm">
              <div className="font-medium text-yellow-300 mb-1">Create suppression rule?</div>
              <div className="text-muted-foreground text-xs mb-2">
                Suppress future alerts for{' '}
                <span className="font-mono text-yellow-200">{fpSuggestion.entity_type}: {fpSuggestion.entity_value}</span>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => createSuppression.mutate({
                    entity_type: fpSuggestion.entity_type,
                    entity_value: fpSuggestion.entity_value,
                    reason: 'Confirmed false positive',
                  })}
                  disabled={createSuppression.isPending}
                  className="px-3 py-1 rounded bg-yellow-600 text-black text-xs font-medium disabled:opacity-50"
                >
                  Yes, suppress
                </button>
                <button onClick={() => setFpSuggestion(null)}
                  className="px-3 py-1 rounded border border-border text-xs hover:bg-muted">
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        )}
        {suppressDone && (
          <div className="mb-4 p-2 rounded border border-emerald-600/40 bg-emerald-900/20 flex items-center gap-2 text-xs text-emerald-300">
            <CheckCircle size={13} /> Suppression rule created.
          </div>
        )}

        {(!detail?.ueba || alert.event_id) && (
          <Section icon={<FileText size={14} />} title="Source log">
            <SourceLogPanel alertId={alert.id} />
          </Section>
        )}

        {detail && detail.related.length > 0 && (
          <Section icon={<Link2 size={14} />} title={`Related alerts (same IP/host, ±24h) — ${detail.related.length}`}>
            <div className="max-h-48 overflow-auto divide-y divide-border/40 text-xs">
              {detail.related.map(r => (
                <div key={r.id} className="flex items-center gap-2 py-1">
                  <SeverityBadge severity={r.severity} />
                  <span className="flex-1 truncate" title={r.title}>{r.title}</span>
                  {r.duplicate_count > 0 && <span className="text-muted-foreground">×{r.duplicate_count + 1}</span>}
                  <span className="text-muted-foreground whitespace-nowrap">{format(new Date(r.created_at), 'MM-dd HH:mm')}</span>
                </div>
              ))}
            </div>
          </Section>
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

        <div className="mb-4">
          <h3 className="text-sm font-medium mb-2">Notes ({alert.notes.length})</h3>
          <div className="space-y-2 max-h-48 overflow-auto">
            {alert.notes.map((n) => (
              <div key={n.id} className="p-3 rounded bg-muted text-sm">
                <div className="text-xs text-muted-foreground mb-1">{format(new Date(n.created_at), 'yyyy-MM-dd HH:mm')}</div>
                <MarkdownNote content={n.content} />
              </div>
            ))}
          </div>
          <div className="flex gap-2 mt-2">
            <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note..."
              className="flex-1 px-3 py-1.5 rounded border border-border bg-background text-sm" />
            <button
              onClick={() => {
                addNote.mutate({ id: alert.id, content: note },
                  { onSuccess: () => qc.invalidateQueries({ queryKey: ['alert-detail', alert.id] }) })
                setNote('')
              }}
              disabled={!note} className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50">
              Add
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
