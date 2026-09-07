import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import { ShieldOff, CheckCircle, ArrowUpRight } from 'lucide-react'
import { api } from '@/api/client'
import { useUpdateAlert, useAddAlertNote, useAlertFeedback, useSubmitAlertFeedback } from '@/hooks/useAlerts'
import { PageHeader } from '@/components/ui/PageHeader'
import { GlassCard } from '@/components/ui/GlassCard'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import MarkdownNote from '@/components/MarkdownNote'
import AiFeedbackWidget from '@/components/AiFeedbackWidget'
import type { Alert, Event, RawLog, Case } from '@/types'

// Mirrors server-api's _RESOLVED_STATUSES (alerts.py) — see DESIGN.md Accepted
// Debt for the older AlertDetailModal's now-superseded, incomplete list.
const STATUS_OPTIONS = ['new', 'acknowledged', 'in_progress', 'resolved', 'closed', 'false_positive']

interface EntityPivot {
  entity_type: string
  entity_value: string
  risk_score: number | null
  anomaly_count: number
  alerts: { id: string; title: string; severity: string; created_at: string }[]
  cases: { id: string; title: string; status: string }[]
}
interface IocLookup {
  observations: { ioc_type: string; confidence: number; verdict: string; source: string }[]
}

function EntityContext({ alert }: { alert: Alert }) {
  const navigate = useNavigate()
  const entityType = alert.hostname ? 'hostname' : alert.source_ip ? 'ip' : null
  const entityValue = alert.hostname || alert.source_ip || null

  // group_id is required for superadmin callers (both routes 422 without it
  // for that role) — alert.group_id is always the right tenant to pivot in,
  // so pass it explicitly rather than relying on the caller's own scope.
  const { data: pivot } = useQuery<EntityPivot>({
    queryKey: ['entity-pivot', entityType, entityValue],
    queryFn: () => api.get(`/api/entities/${entityType}/${encodeURIComponent(entityValue!)}`, { params: { group_id: alert.group_id } }).then(r => r.data),
    enabled: !!entityType && !!entityValue,
    retry: false,
  })
  const { data: ioc } = useQuery<IocLookup>({
    queryKey: ['ioc-lookup', alert.source_ip],
    queryFn: () => api.get(`/api/iocs/${encodeURIComponent(alert.source_ip!)}`, { params: { group_id: alert.group_id } }).then(r => r.data),
    enabled: !!alert.source_ip,
    retry: false,
  })

  if (!entityType) {
    return <GlassCard title="Entity Context"><div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No IP or hostname on this alert to pivot from.</div></GlassCard>
  }

  return (
    <GlassCard title={`Entity Context — ${entityValue}`}>
      {pivot?.risk_score != null && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>UEBA risk score</span>
          <span style={{ fontWeight: 700, color: pivot.risk_score >= 80 ? 'var(--accent-red)' : pivot.risk_score >= 60 ? 'var(--accent-orange)' : 'var(--accent-yellow)' }}>
            {pivot.risk_score.toFixed(0)}
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>({pivot.anomaly_count} anomalies)</span>
        </div>
      )}

      {ioc && ioc.observations.length > 0 && (
        <div style={{ marginBottom: 10, padding: 8, borderRadius: 4, background: 'var(--bg-base)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 4 }}>Threat intel</div>
          {ioc.observations.map((o, i) => (
            <div key={i} style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {o.source}: <span style={{ color: o.verdict === 'malicious' ? 'var(--accent-red)' : 'var(--text-primary)' }}>{o.verdict}</span> (confidence {o.confidence})
            </div>
          ))}
        </div>
      )}

      <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 6 }}>
        Other alerts on this entity ({pivot?.alerts.length ?? 0})
      </div>
      {(pivot?.alerts ?? []).filter(a => a.id !== alert.id).slice(0, 5).map(a => (
        <button key={a.id} onClick={() => navigate(`/alerts/${a.id}`)} style={{
          display: 'flex', justifyContent: 'space-between', width: '100%', gap: 8, padding: '5px 8px', marginBottom: 4,
          borderRadius: 4, background: 'var(--bg-base)', border: '1px solid var(--border)', cursor: 'pointer', textAlign: 'left',
        }}>
          <span style={{ fontSize: 12, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</span>
          <span style={{ fontSize: 10, color: 'var(--text-muted)', flexShrink: 0 }}>{format(new Date(a.created_at), 'MM-dd')}</span>
        </button>
      ))}
      {(!pivot || pivot.alerts.filter(a => a.id !== alert.id).length === 0) && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No other alerts on this entity.</div>
      )}
    </GlassCard>
  )
}

export default function AlertInvestigationPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [note, setNote] = useState('')
  const [fpSuggestion, setFpSuggestion] = useState<{ entity_type: string; entity_value: string } | null>(null)
  const [suppressDone, setSuppressDone] = useState(false)

  const { data: alert, isLoading } = useQuery<Alert>({
    queryKey: ['alert', id],
    queryFn: () => api.get(`/api/alerts/${id}`).then(r => r.data),
    enabled: !!id,
  })
  const { data: sourceLog } = useQuery<{ event: Event | null; raw_log: RawLog | null }>({
    queryKey: ['alert-source-log', id],
    queryFn: () => api.get(`/api/alerts/${id}/source-log`).then(r => r.data),
    enabled: !!id,
  })
  const { data: casesData } = useQuery({
    queryKey: ['cases-for-alert-check'],
    queryFn: () => api.get('/api/cases', { params: { page_size: 200 } }).then(r => r.data),
  })
  const linkedCase: Case | undefined = (casesData?.items ?? []).find((c: Case) => c.alert_id === id)

  const updateAlert = useUpdateAlert()
  const addNote = useAddAlertNote()
  const { data: feedback, isLoading: feedbackLoading } = useAlertFeedback(id!)
  const submitFeedback = useSubmitAlertFeedback(id!)
  const { data: usersData } = useQuery({ queryKey: ['users-list'], queryFn: () => api.get('/api/users', { params: { page_size: 100 } }).then(r => r.data) })
  const users: Array<{ id: string; username: string }> = usersData?.items ?? []

  const createSuppression = useMutation({
    mutationFn: (body: { entity_type: string; entity_value: string; reason: string }) => api.post('/api/suppressions', body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['suppressions'] }); setSuppressDone(true); setFpSuggestion(null) },
  })
  const escalateToCase = useMutation({
    mutationFn: () => api.post('/api/cases', { title: alert!.title, severity: alert!.severity, alert_id: alert!.id }),
    onSuccess: (res) => navigate(`/cases/${res.data.id}`),
  })

  if (isLoading || !alert) return <div style={{ padding: 20, color: 'var(--text-muted)' }}>Loading investigation…</div>

  const handleStatusChange = (newStatus: string) => {
    updateAlert.mutate({ id: alert.id, data: { status: newStatus } }, {
      onSuccess: (data: any) => { if (data?.fp_suppression_suggestion) setFpSuggestion(data.fp_suppression_suggestion) },
    })
  }

  return (
    <div>
      <PageHeader
        breadcrumb={<button onClick={() => navigate('/alerts')} style={{ background: 'none', border: 'none', color: 'var(--accent-blue)', cursor: 'pointer', padding: 0, fontSize: 12 }}>&larr; Alerts</button>}
        title={alert.title}
        subtitle={<span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <SeverityBadge severity={alert.severity} /> <StatusBadge status={alert.status} />
          <span className="mono" style={{ fontSize: 11 }}>{alert.hostname || alert.source_ip || 'no entity'}</span>
          <span style={{ color: alert.sla_breached ? 'var(--accent-red)' : 'var(--accent-green)', fontSize: 11, fontWeight: 600 }}>
            {alert.sla_breached ? 'SLA Breached' : 'Within SLA'}
          </span>
        </span>}
        actions={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <select value={alert.status} onChange={e => handleStatusChange(e.target.value)} className="input" style={{ fontSize: 12, padding: '6px 10px' }}>
              {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>
            <select value={alert.assignee_id ?? ''} onChange={e => updateAlert.mutate({ id: alert.id, data: { assignee_id: e.target.value || undefined } })} className="input" style={{ fontSize: 12, padding: '6px 10px' }}>
              <option value="">Unassigned</option>
              {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
            </select>
            {linkedCase ? (
              <button onClick={() => navigate(`/cases/${linkedCase.id}`)} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, padding: '6px 12px', borderRadius: 6, border: '1px solid var(--accent-blue)', background: 'rgba(44,110,142,0.1)', color: 'var(--accent-blue)', cursor: 'pointer' }}>
                Open Case <ArrowUpRight size={12} />
              </button>
            ) : (
              <button onClick={() => escalateToCase.mutate()} disabled={escalateToCase.isPending} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, padding: '6px 12px', borderRadius: 6, border: '1px solid var(--accent-orange)', background: 'rgba(216,117,46,0.1)', color: 'var(--accent-orange)', cursor: 'pointer' }}>
                Escalate to Case <ArrowUpRight size={12} />
              </button>
            )}
          </div>
        }
      />

      {fpSuggestion && !suppressDone && (
        <div style={{ marginBottom: 14, padding: 12, borderRadius: 6, border: '1px solid var(--accent-yellow)', background: 'rgba(216,178,61,0.08)', display: 'flex', gap: 10 }}>
          <ShieldOff size={16} color="var(--accent-yellow)" style={{ flexShrink: 0, marginTop: 2 }} />
          <div style={{ flex: 1, fontSize: 13 }}>
            <div style={{ fontWeight: 600, color: 'var(--accent-yellow)', marginBottom: 4 }}>Create suppression rule?</div>
            <div style={{ color: 'var(--text-muted)', fontSize: 12, marginBottom: 8 }}>
              Suppress future alerts for <span className="mono">{fpSuggestion.entity_type}: {fpSuggestion.entity_value}</span>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => createSuppression.mutate({ ...fpSuggestion, reason: 'Confirmed false positive' })} disabled={createSuppression.isPending}
                style={{ padding: '5px 12px', borderRadius: 4, border: 'none', background: 'var(--accent-yellow)', color: '#000', fontSize: 12, fontWeight: 600, cursor: 'pointer' }}>
                Yes, suppress
              </button>
              <button onClick={() => setFpSuggestion(null)} style={{ padding: '5px 12px', borderRadius: 4, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-secondary)', fontSize: 12, cursor: 'pointer' }}>
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}
      {suppressDone && (
        <div style={{ marginBottom: 14, padding: 8, borderRadius: 4, border: '1px solid var(--accent-green)', background: 'rgba(79,143,99,0.08)', display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--accent-green)' }}>
          <CheckCircle size={13} /> Suppression rule created.
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 340px', gap: 14, alignItems: 'start' }} className="cc-grid">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
          <GlassCard title="Evidence Timeline">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{format(new Date(alert.created_at), 'yyyy-MM-dd HH:mm:ss')} — Alert created</div>
              {sourceLog?.raw_log && (
                <pre className="mono" style={{ fontSize: 11, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 4, padding: 8, maxHeight: 160, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {sourceLog.raw_log.raw_message}
                </pre>
              )}
              {sourceLog?.event && Object.keys(sourceLog.event.decoded_fields ?? {}).length > 0 && (
                <details style={{ fontSize: 11 }}>
                  <summary style={{ cursor: 'pointer', color: 'var(--text-muted)' }}>Decoded fields</summary>
                  <pre className="mono" style={{ fontSize: 11, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 4, padding: 8, marginTop: 6, maxHeight: 160, overflow: 'auto', whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(sourceLog.event.decoded_fields, null, 2)}
                  </pre>
                </details>
              )}
              {!sourceLog?.raw_log && !sourceLog?.event && (
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No source log linked to this alert.</div>
              )}
              {alert.notes.map(n => (
                <div key={n.id} style={{ padding: 8, borderRadius: 4, background: 'var(--bg-base)', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>{format(new Date(n.created_at), 'yyyy-MM-dd HH:mm')} — Analyst note</div>
                  <MarkdownNote content={n.content} />
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
              <input value={note} onChange={e => setNote(e.target.value)} placeholder="Add a note…" className="input" style={{ flex: 1, fontSize: 12 }} />
              <button onClick={() => { addNote.mutate({ id: alert.id, content: note }); setNote('') }} disabled={!note}
                style={{ padding: '6px 14px', borderRadius: 4, border: 'none', background: 'var(--accent-blue)', color: 'var(--text-on-primary, #0A0D11)', fontSize: 12, fontWeight: 600, cursor: note ? 'pointer' : 'not-allowed', opacity: note ? 1 : 0.5 }}>
                Add
              </button>
            </div>
          </GlassCard>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <GlassCard title="AI Context">
            {alert.ai_verdict ? (
              <AiFeedbackWidget aiVerdict={alert.ai_verdict} feedback={feedback} isLoading={feedbackLoading} onSubmit={body => submitFeedback.mutate(body)} isSubmitting={submitFeedback.isPending} />
            ) : (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Pending AI analysis — manual investigation is unaffected.</div>
            )}
          </GlassCard>
          <EntityContext alert={alert} />
        </div>
      </div>
    </div>
  )
}
