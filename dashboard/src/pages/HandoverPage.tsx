import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { format } from 'date-fns'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { useAnalystWorkload, useSocMetrics } from '@/hooks/useMetrics'
import { emitToast } from '@/hooks/useToast'
import { CanvasHeader, CanvasPage, Chip, Empty, KpiStrip, SectionTitle, type Tone } from '@/components/canvas/Canvas'
import type { Alert, CaseSummary, PaginatedResponse } from '@/types'

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

interface AuditEntry { readonly id: string; readonly actor_name?: string | null; readonly action: string; readonly resource_type?: string | null; readonly created_at: string | null }

// Three 8-hour shifts, local time. The backend stores the label only.
const SHIFTS = [
  { key: 'A', label: 'day', start: 7 },
  { key: 'B', label: 'evening', start: 15 },
  { key: 'C', label: 'night', start: 23 },
] as const

function currentShift(now = new Date()) {
  const hour = now.getHours()
  const index = hour >= 23 || hour < 7 ? 2 : hour >= 15 ? 1 : 0
  const shift = SHIFTS[index]
  const start = new Date(now)
  start.setHours(shift.start, 0, 0, 0)
  if (start > now) start.setDate(start.getDate() - 1)
  const end = new Date(start.getTime() + 8 * 3_600_000)
  return { shift, next: SHIFTS[(index + 1) % 3], start, end }
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function useTotal(key: string, url: string, params: Record<string, unknown>) {
  return useQuery<number>({
    queryKey: ['handover-count', key, params],
    queryFn: () => api.get(url, { params: { page: 1, page_size: 1, ...params } }).then(r => Number(r.data.total) || 0),
    refetchInterval: 60_000,
  })
}

interface CarryItem {
  readonly kind: 'case' | 'alert'
  readonly id: string
  readonly title: string
  readonly ref: string
  readonly href: string
  readonly state: string
  readonly tone: Tone
  readonly next: string
  readonly assignee: string | null
  readonly severity: string
}

function caseItem(item: CaseSummary): CarryItem {
  const state = item.status === 'escalated' ? 'Escalated' : item.status === 'in_review' ? 'In review' : 'Open'
  const tone: Tone = item.status === 'escalated' ? 'warn' : item.status === 'in_review' ? 'info' : 'bad'
  const next = !item.assignee_id ? 'Assign an owner and start triage'
    : item.status === 'escalated' ? 'Waiting on the escalation response'
    : item.status === 'in_review' ? 'Finish the review and decide on closure'
    : 'Continue the investigation'
  return { kind: 'case', id: item.id, title: item.title, ref: `Case · ${item.severity}`, href: `/cases/${item.id}`, state, tone, next, assignee: item.assignee_id, severity: item.severity }
}

function alertItem(item: Alert): CarryItem {
  return {
    kind: 'alert', id: item.id, title: item.title, ref: `Alert${item.hostname ? ` · ${item.hostname}` : ''} · ${item.severity}`,
    href: `/alerts?alert=${item.id}`, state: 'Untriaged', tone: 'bad', next: 'Triage; decide on a case or close', assignee: item.assignee_id, severity: item.severity,
  }
}

export default function HandoverPage() {
  const qc = useQueryClient()
  const { user, hasRole } = useAuthStore()
  const canEdit = hasRole('analyst')
  const isAdmin = hasRole('admin')
  const shiftWindow = useMemo(() => currentShift(), [])
  const since = shiftWindow.start.toISOString()
  const [notes, setNotes] = useState('')
  const [showHistory, setShowHistory] = useState(false)

  const alertsInShift = useTotal('alerts', '/api/alerts', { start_time: since })
  const alertsOpen = useTotal('alerts-open', '/api/alerts', { start_time: since, status: 'new,in_progress,acknowledged' })
  const casesOpened = useTotal('cases-opened', '/api/cases', { start_time: since })
  const casesCritical = useTotal('cases-critical', '/api/cases', { start_time: since, severity: 'critical' })
  const casesClosed = useTotal('cases-closed', '/api/cases', { updated_after: since, status: 'resolved,closed' })
  const escalated = useTotal('cases-escalated', '/api/cases', { status: 'escalated' })
  const metrics = useSocMetrics(1)
  const workload = useAnalystWorkload()

  const openCases = useQuery<PaginatedResponse<CaseSummary>>({
    queryKey: ['handover-carry', 'cases'],
    queryFn: () => api.get('/api/cases', { params: { page: 1, page_size: 50, summary: true, status: 'open,in_review,escalated' } }).then(r => r.data),
    refetchInterval: 60_000,
  })
  const untriaged = useQuery<PaginatedResponse<Alert>>({
    queryKey: ['handover-carry', 'alerts'],
    queryFn: () => api.get('/api/alerts', { params: { page: 1, page_size: 10, status: 'new', severity: 'critical,high', unassigned: true, sort: 'priority' } }).then(r => r.data),
    refetchInterval: 60_000,
  })
  const handovers = useQuery<Handover[]>({
    queryKey: ['handovers'],
    queryFn: () => api.get('/api/handover', { params: { limit: 20 } }).then(r => r.data),
    refetchInterval: 60_000,
  })
  const audit = useQuery<AuditEntry[]>({
    queryKey: ['handover-audit', since],
    queryFn: () => api.get('/api/audit-logs', { params: { limit: 12, since } }).then(r => r.data),
    enabled: isAdmin,
    refetchInterval: 60_000,
  })
  const recentCritical = useQuery<PaginatedResponse<Alert>>({
    queryKey: ['handover-notable', since],
    queryFn: () => api.get('/api/alerts', { params: { page: 1, page_size: 8, start_time: since, severity: 'critical,high' } }).then(r => r.data),
    enabled: !isAdmin,
  })

  const items = useMemo(() => {
    const cases = (openCases.data?.items ?? []).map(caseItem)
    const alerts = (untriaged.data?.items ?? []).map(alertItem)
    return [...cases, ...alerts].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5)).slice(0, 15)
  }, [openCases.data, untriaged.data])

  const people = workload.data ?? []
  const nameOf = (id: string | null) => !id ? null : id === user?.id ? `${user.username} (you)` : people.find(p => p.user_id === id)?.username ?? 'Assigned analyst'

  const reassign = useMutation({
    mutationFn: ({ item, assignee }: { item: CarryItem; assignee: string | null }) =>
      api.put(item.kind === 'case' ? `/api/cases/${item.id}` : `/api/alerts/${item.id}`, { assignee_id: assignee }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['handover-carry'] })
      void qc.invalidateQueries({ queryKey: ['metrics'] })
      emitToast('Owner updated', 'success')
    },
    onError: () => emitToast('Could not change the owner', 'error'),
  })

  const submit = useMutation({
    mutationFn: () => api.post('/api/handover', { shift_label: shiftWindow.shift.label, summary: notes.trim(), notes: '' }).then(r => r.data as Handover),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['handovers'] })
      setNotes('')
      emitToast('Handover submitted', 'success')
    },
    onError: () => emitToast('Could not submit the handover', 'error'),
  })

  const submittedThisShift = (handovers.data ?? []).find(h => h.created_at && new Date(h.created_at) >= shiftWindow.start)
  const mtta = metrics.data?.avg_ack_minutes
  const timeRange = `${format(shiftWindow.start, 'EEE d MMM')} · ${format(shiftWindow.start, 'HH:mm')}–${format(shiftWindow.end, 'HH:mm')}`

  const notable = isAdmin
    ? (audit.data ?? []).map(entry => ({ id: entry.id, at: entry.created_at, text: `${entry.actor_name ?? 'System'} · ${entry.action.replace(/_/g, ' ')}${entry.resource_type ? ` (${entry.resource_type})` : ''}` }))
    : (recentCritical.data?.items ?? []).map(alert => ({ id: alert.id, at: alert.created_at, text: `${alert.severity} · ${alert.title}${alert.hostname ? ` on ${alert.hostname}` : ''}` }))

  return (
    <CanvasPage>
      <CanvasHeader
        title={`Shift ${shiftWindow.shift.key} → Shift ${shiftWindow.next.key} handover`}
        sub={<>{timeRange} · prepared by {user?.username ?? 'you'} · {submittedThisShift ? 'submitted' : 'draft, auto-filled from shift activity'}</>}
        actions={<>
          <button type="button" className="cv-btn" aria-expanded={showHistory} onClick={() => setShowHistory(value => !value)}>
            {showHistory ? 'Hide previous handovers' : 'Previous handovers'}
          </button>
          {canEdit && (
            <button type="button" className="cv-btn cv-btn--primary" disabled={!notes.trim() || submit.isPending} onClick={() => submit.mutate()}>
              {submit.isPending ? 'Submitting…' : 'Submit for sign-off'}
            </button>
          )}
        </>}
      />
      <div className="cv-body">
        <KpiStrip items={[
          { label: 'Alerts this shift', value: alertsInShift.data ?? '–', note: alertsOpen.data != null ? `${alertsOpen.data} still open` : undefined, tone: alertsOpen.data ? 'warn' : 'muted' },
          { label: 'Cases opened', value: casesOpened.data ?? '–', note: casesCritical.data ? `${casesCritical.data} critical` : 'none critical', tone: casesCritical.data ? 'bad' : 'muted' },
          { label: 'Cases closed', value: casesClosed.data ?? '–', note: 'resolved or closed this shift', tone: 'muted' },
          { label: 'MTTA', value: mtta != null ? `${Math.round(mtta)}m` : '–', note: 'last 24 h', tone: mtta != null && mtta <= 15 ? 'good' : 'warn' },
          { label: 'Escalated', value: escalated.data ?? '–', note: escalated.data ? 'waiting on response' : 'nothing escalated', tone: escalated.data ? 'bad' : 'muted' },
        ]} />

        <div className="cv-cols">
          <section className="cv-main" aria-label="Carry-over">
            <h2 className="cv-h2">Carry-over items · {items.length}</h2>
            <div className="cv-tablewrap">
              <table className="cv-table" style={{ minWidth: 640 }}>
                <thead><tr><th>Item</th><th>State</th><th>Next action</th><th>Hand to</th></tr></thead>
                <tbody>
                  {items.map(item => (
                    <tr key={`${item.kind}-${item.id}`}>
                      <td>
                        <div className="cv-stack">
                          <Link to={item.href} style={{ color: '#E8ECF2', fontWeight: 500 }}>{item.title}</Link>
                          <span className="cv-mono cv-muted">{item.ref}</span>
                        </div>
                      </td>
                      <td><Chip tone={item.tone}>{item.state}</Chip></td>
                      <td className="cv-dim">{item.next}</td>
                      <td>
                        {canEdit ? (
                          <select className="cv-select cv-btn--sm" aria-label={`Hand ${item.title} to`} value={item.assignee ?? ''}
                            disabled={reassign.isPending}
                            onChange={event => reassign.mutate({ item, assignee: event.target.value || null })}>
                            <option value="">Unassigned</option>
                            {item.assignee && !people.some(p => p.user_id === item.assignee) && <option value={item.assignee}>{nameOf(item.assignee)}</option>}
                            {people.map(p => <option key={p.user_id} value={p.user_id}>{p.user_id === user?.id ? `${p.username} (you)` : p.username}</option>)}
                          </select>
                        ) : <span className="cv-dim">{nameOf(item.assignee) ?? 'Unassigned'}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!openCases.isLoading && !untriaged.isLoading && items.length === 0 && <Empty>No open cases or untriaged critical/high alerts to carry over.</Empty>}
              {(openCases.isLoading || untriaged.isLoading) && <Empty>Loading carry-over items…</Empty>}
            </div>

            <SectionTitle>Notes for the incoming shift</SectionTitle>
            <label htmlFor="handover-notes" className="sr-only">Handover notes</label>
            <textarea id="handover-notes" className="cv-textarea" rows={6} value={notes} onChange={event => setNotes(event.target.value)}
              disabled={!canEdit}
              placeholder="What is the priority, what is being watched, what must not be changed without approval…" />
            <p className="cv-muted cv-small" style={{ margin: 0 }}>
              Open alert, case and escalation counts are captured with the notes when you submit.
            </p>

            {showHistory && (
              <>
                <SectionTitle>Previous handovers</SectionTitle>
                {(handovers.data ?? []).length === 0 && <Empty>No handovers yet.</Empty>}
                {(handovers.data ?? []).map(h => (
                  <article key={h.id} className="cv-card">
                    <div className="cv-card__head">
                      <span className="cv-row">
                        <Chip tone="muted">{h.shift_label}</Chip>
                        {h.created_at && <span className="cv-mono cv-muted">{format(new Date(h.created_at), 'yyyy-MM-dd HH:mm')}</span>}
                      </span>
                      <span className="cv-row cv-small">
                        <span className="cv-t-warn">{h.open_alerts} alerts open</span>
                        <span className="cv-t-info">{h.open_cases} cases open</span>
                        {h.escalations > 0 && <span className="cv-t-bad">{h.escalations} escalated</span>}
                      </span>
                    </div>
                    <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{h.summary}</p>
                  </article>
                ))}
              </>
            )}
          </section>

          <aside className="cv-side">
            <section className="cv-card">
              <h2>Sign-off</h2>
              <div className="cv-kv">
                <div><span>Outgoing</span><span>{user?.username ?? 'You'} · {submittedThisShift?.created_at ? `submitted ${format(new Date(submittedThisShift.created_at), 'HH:mm')}` : 'not submitted'}</span></div>
                <div><span>Incoming</span><span>Shift {shiftWindow.next.key} · from {format(shiftWindow.end, 'HH:mm')}</span></div>
              </div>
              <p className="cv-muted cv-small" style={{ margin: 0 }}>
                Owners in the carry-over table change as soon as you pick them. The submitted handover is kept with its counts for the next shift to read.
              </p>
            </section>
            <section className="cv-card">
              <h2>Notable this shift</h2>
              <div className="cv-feed">
                {notable.map(entry => (
                  <div key={entry.id}>
                    <time>{entry.at ? format(new Date(entry.at), 'HH:mm') : '–'}</time>
                    <span style={{ minWidth: 0, overflowWrap: 'anywhere' }}>{entry.text}</span>
                  </div>
                ))}
                {notable.length === 0 && <span className="cv-muted cv-small">Nothing recorded since {format(shiftWindow.start, 'HH:mm')}.</span>}
              </div>
            </section>
          </aside>
        </div>
      </div>
    </CanvasPage>
  )
}
