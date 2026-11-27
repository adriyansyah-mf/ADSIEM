import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { format, formatDistanceToNowStrict } from 'date-fns'
import { Bot, Check, Clock } from 'lucide-react'
import { QueryState } from '@/components/Workspace'
import SeverityBadge from '@/components/SeverityBadge'
import { useCase, useUpdateCase, useEscalateCase, useAddCaseNote, useCaseFeedback, useSubmitCaseFeedback } from '@/hooks/useCases'
import { useCaseTasks, useUpdateCaseTask } from '@/hooks/useCaseTasks'
import { CaseEvidencePanel } from '@/components/CaseEvidencePanel'
import { CaseRemediations } from '@/components/CaseRemediations'
import { useAuthStore } from '@/stores/auth'
import CaseRelationGraph from '@/components/CaseRelationGraph'
import { api } from '@/api/client'
import type { Alert, Case, CaseNote } from '@/types'
import MarkdownNote from '@/components/MarkdownNote'
import AttackGraph, { type TimelineItem } from '@/components/AttackGraph'
import AlertDetailModal from '@/components/AlertDetailModal'
import AiFeedbackWidget from '@/components/AiFeedbackWidget'
import AiInvestigationPanel from '@/components/AiInvestigationPanel'
import CaseTasks from '@/components/CaseTasks'
import IncidentReportButton from '@/components/reports/IncidentReportButton'

type CaseTab = 'timeline' | 'evidence' | 'context' | 'tasks' | 'ai' | 'response'
const CASE_TABS: readonly { readonly key: CaseTab; readonly label: string }[] = [
  { key: 'timeline', label: 'Timeline' },
  { key: 'evidence', label: 'Evidence' },
  { key: 'context', label: 'Relation graph & IoCs' },
  { key: 'tasks', label: 'Tasks' },
  { key: 'ai', label: 'AI investigation' },
  { key: 'response', label: 'Response actions' },
]
// old ?tab= values keep working
const TAB_ALIASES: Readonly<Record<string, CaseTab>> = { overview: 'timeline', notes: 'timeline' }

type Status = Case['status']
const STAGES: readonly { readonly status: Status; readonly label: string }[] = [
  { status: 'open', label: 'Open' },
  { status: 'in_review', label: 'In review' },
  { status: 'escalated', label: 'Escalated' },
  { status: 'resolved', label: 'Resolved' },
  { status: 'closed', label: 'Closed' },
]
const NEXT: Partial<Record<Status, Status>> = { open: 'in_review', in_review: 'resolved', escalated: 'resolved', resolved: 'closed' }

interface Entry {
  readonly key: string
  readonly kind: 'alert' | 'note' | 'ai' | 'system'
  readonly at: string
  readonly title: string
  readonly body?: string
  readonly markdown?: boolean
  readonly severity?: string
}

const MARK: Record<Entry['kind'], string> = { alert: '!', note: 'N', ai: 'AI', system: 'S' }

function duration(from: string) {
  return formatDistanceToNowStrict(new Date(from)).replace(' minutes', 'm').replace(' minute', 'm').replace(' hours', 'h').replace(' hour', 'h').replace(' days', 'd').replace(' day', 'd')
}

function SideTasks({ caseId, onOpen }: { readonly caseId: string; readonly onOpen: () => void }) {
  const tasks = useCaseTasks(caseId)
  const update = useUpdateCaseTask(caseId)
  const canManage = useAuthStore(state => state.hasRole('analyst'))
  const items = tasks.data ?? []
  const done = items.filter(task => task.done).length
  return (
    <section className="cw-card">
      <div className="cw-card__head">
        <h2>Tasks {items.length > 0 && <span>{done} of {items.length} done</span>}</h2>
        <button type="button" className="cw-btn cw-btn--xs" onClick={onOpen}>{items.length ? 'Manage' : '+ Add task'}</button>
      </div>
      {items.length > 0 && <div className="cw-progress" aria-hidden="true"><div style={{ width: `${(done / items.length) * 100}%` }} /></div>}
      {tasks.isPending ? <p className="cw-muted">Loading tasks…</p>
        : items.length === 0 ? <p className="cw-muted">No tasks yet. Break the response into owned steps with due times.</p>
        : items.slice(0, 6).map(task => {
          const overdue = !task.done && task.due_at && new Date(task.due_at) < new Date()
          return (
            <label key={task.id} className="cw-task">
              <input type="checkbox" checked={task.done} disabled={!canManage || update.isPending}
                onChange={() => update.mutate({ id: task.id, change: { done: !task.done } })} />
              <span className="cw-task__text">
                <span className={task.done ? 'is-done' : ''}>{task.title}</span>
                <span className="cw-task__meta">
                  {task.assignee_id ? 'Assigned' : 'Unassigned'}
                  {task.done && task.completed_at ? <span className="is-ok"> · done {format(new Date(task.completed_at), 'HH:mm')}</span>
                    : task.due_at ? <span className={overdue ? 'is-bad' : ''}> · {overdue ? `overdue by ${duration(task.due_at)}` : `due ${format(new Date(task.due_at), 'dd MMM HH:mm')}`}</span> : null}
                </span>
              </span>
            </label>
          )
        })}
      {items.length > 6 && <button type="button" className="cw-link" onClick={onOpen}>All {items.length} tasks</button>}
    </section>
  )
}

export default function CaseDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { user, hasRole } = useAuthStore()
  const canManage = hasRole('analyst')
  const [noteText, setNoteText] = useState('')
  const [olderNotes, setOlderNotes] = useState<CaseNote[]>([])
  const [loadingOlder, setLoadingOlder] = useState(false)
  useEffect(() => { setOlderNotes([]) }, [id])
  const loadOlderNotes = async (offset: number) => {
    setLoadingOlder(true)
    try {
      const page = await api.get<CaseNote[]>(`/api/cases/${id}/notes`, { params: { offset, limit: 100 } }).then(r => r.data)
      setOlderNotes(prev => [...prev, ...page])
    } finally {
      setLoadingOlder(false)
    }
  }
  const [timelineView, setTimelineView] = useState<'list' | 'graph'>('list')
  const [showLinkedAlert, setShowLinkedAlert] = useState(false)
  const [params, setParams] = useSearchParams()
  const rawTab = params.get('tab') ?? ''
  const tab = (CASE_TABS.some(t => t.key === rawTab) ? rawTab : TAB_ALIASES[rawTab] ?? 'timeline') as CaseTab
  const selectTab = (next: CaseTab) => setParams(current => {
    const out = new URLSearchParams(current)
    if (next === 'timeline') out.delete('tab')
    else out.set('tab', next)
    return out
  }, { replace: true })

  const { data: caseData, isLoading, isError, refetch } = useCase(id!)
  const update = useUpdateCase(id!)
  const escalate = useEscalateCase(id!)
  const addNote = useAddCaseNote(id!)
  const { data: caseFeedback, isLoading: caseFeedbackLoading } = useCaseFeedback(id!)
  const submitCaseFeedback = useSubmitCaseFeedback(id!)
  const tasks = useCaseTasks(id ?? '')

  const { data: alertData } = useQuery<Alert>({
    queryKey: ['alert', caseData?.alert_id],
    queryFn: () => api.get(`/api/alerts/${caseData!.alert_id}`).then(r => r.data),
    enabled: !!caseData?.alert_id,
  })
  const { data: timeline } = useQuery<{ items: TimelineItem[] }>({
    queryKey: ['case-timeline', id],
    queryFn: () => api.get(`/api/cases/${id}/timeline`).then(r => r.data),
    enabled: !!id,
    refetchInterval: 30_000,
  })
  const users = useQuery<{ items: { id: string; username: string }[] }>({
    queryKey: ['users-list'],
    queryFn: () => api.get('/api/users', { params: { page_size: 100 } }).then(r => r.data),
    enabled: !!caseData?.assignee_id,
    retry: false,
  })

  const seenNotes = new Set<string>()
  const sortedNotes = [...(caseData?.notes ?? []), ...olderNotes]
    .filter(n => !seenNotes.has(n.id) && !!seenNotes.add(n.id))
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
  const notesTotal = Math.max(caseData?.notes_total ?? 0, sortedNotes.length)

  const entries = useMemo<Entry[]>(() => {
    if (!caseData) return []
    const fromNotes: Entry[] = sortedNotes.map(note => ({
      key: `n-${note.id}`, kind: note.is_ai_generated ? 'ai' : 'note', at: note.created_at,
      title: note.is_ai_generated ? 'AI note' : note.author_id === user?.id ? 'You' : 'Analyst note', body: note.content, markdown: true,
    }))
    const fromTimeline: Entry[] = (timeline?.items ?? []).filter(item => item.type === 'alert').map(item => ({
      key: `t-${item.id}`, kind: 'alert', at: item.ts, severity: item.severity,
      title: `${item.is_this_case ? 'Alert linked' : 'Related alert'}: ${item.title}`,
      body: item.source_ip ? `Source ${item.source_ip}` : undefined,
    }))
    const opened: Entry = { key: 'opened', kind: 'system', at: caseData.created_at,
      title: caseData.created_by_ai ? 'Case opened by AI triage' : 'Case opened', body: `Severity ${caseData.severity}.` }
    const escalatedEntry: Entry[] = caseData.escalated_at ? [{ key: 'esc', kind: 'system', at: caseData.escalated_at, title: 'Escalated to L2' }] : []
    return [...fromNotes, ...fromTimeline, opened, ...escalatedEntry].sort((a, b) => b.at.localeCompare(a.at))
  }, [caseData, sortedNotes, timeline, user?.id]) // eslint-disable-line react-hooks/exhaustive-deps

  if (isLoading) return <QueryState kind="loading" title="Loading case…" description="Fetching the case record and investigation context." />
  if (isError || !caseData) return <QueryState kind="error" title="Could not open this case"
    description="The case may be unavailable or outside your workspace. Try again or return to Cases."
    onRetry={() => { void refetch() }} />

  const ioc = (caseData.ioc_data ?? {}) as Record<string, unknown>
  const campaign = {
    hosts: (ioc.affected_hosts as string[] | undefined) ?? (ioc.hostname ? [String(ioc.hostname)] : []),
    keys: (ioc.ioc_keys as string[] | undefined) ?? [],
    stage: ioc.attack_family as string | undefined,
    families: (ioc.families_seen as string[] | undefined) ?? [],
    related: (ioc.related_cases as string[] | undefined) ?? [],
    mergedInto: ioc.merged_into as string | undefined,
  }
  const CAMPAIGN_FIELDS = new Set(['affected_hosts', 'ioc_keys', 'attack_family', 'families_seen', 'related_cases', 'merged_into', 'hostname'])
  const iocEntries = Object.entries(caseData.ioc_data ?? {}).filter(([k, v]) => {
    if (CAMPAIGN_FIELDS.has(k)) return false
    if (v == null || v === '') return false
    if (Array.isArray(v) && (v as unknown[]).length === 0) return false
    if (k === 'overall_risk' && (v === 0 || v === 0.0)) return false // 0 = no TI data, not zero risk
    return true
  })
  const searchResults = caseData.search_intel?.results ?? []
  const owner = !caseData.assignee_id ? null
    : caseData.assignee_id === user?.id ? `${user.username} (you)`
    : users.data?.items.find(u => u.id === caseData.assignee_id)?.username ?? 'Assigned analyst'
  const stageIndex = STAGES.findIndex(stage => stage.status === caseData.status)
  const next = NEXT[caseData.status]
  const nextLabel = STAGES.find(stage => stage.status === next)?.label
  const linkedAlerts = (timeline?.items ?? []).filter(item => item.type === 'alert' && item.is_this_case)
  const taskItems = tasks.data ?? []
  const confidence = caseData.ai_confidence

  const handleAddNote = (event: React.FormEvent) => {
    event.preventDefault()
    if (!noteText.trim()) return
    addNote.mutate(noteText, { onSuccess: () => setNoteText('') })
  }

  return (
    <div className="cw">
      <header className="cw-head">
        <nav aria-label="Breadcrumb" className="cw-crumb"><Link to="/cases">Cases</Link> / <span>{caseData.id.slice(0, 8)}</span></nav>
        <div className="cw-head__row">
          <div className="cw-head__title">
            <h1>{caseData.title}</h1>
            <div className="cw-head__meta">
              <SeverityBadge severity={caseData.severity} />
              <span>Owner <strong>{owner ?? 'Unassigned'}</strong></span>
              <span className="cw-dot">·</span>
              <span>{caseData.alert_count} alert{caseData.alert_count === 1 ? '' : 's'}{campaign.hosts.length ? ` · ${campaign.hosts.length} host${campaign.hosts.length === 1 ? '' : 's'}` : ''}</span>
              <span className="cw-dot">·</span>
              <span className="cw-age"><Clock size={14} aria-hidden="true" />{caseData.status === 'resolved' || caseData.status === 'closed' ? `opened ${format(new Date(caseData.created_at), 'dd MMM HH:mm')}` : `open for ${duration(caseData.created_at)}`}</span>
              {caseData.created_by_ai && <><span className="cw-dot">·</span><span className="cw-ai-chip"><Bot size={13} aria-hidden="true" /> AI-created</span></>}
            </div>
          </div>
          <div className="cw-head__actions">
            <IncidentReportButton caseId={caseData.id} />
            {canManage && user?.id && caseData.assignee_id !== user.id && (
              <button type="button" className="cw-btn" disabled={update.isPending} onClick={() => update.mutate({ assignee_id: user.id })}>Assign to me</button>
            )}
            {canManage && !['escalated', 'resolved', 'closed'].includes(caseData.status) && (
              <button type="button" className="cw-btn" disabled={escalate.isPending} onClick={() => escalate.mutate()}>Escalate to L2</button>
            )}
            {canManage && next && (
              <button type="button" className="cw-btn cw-btn--primary" disabled={update.isPending} onClick={() => update.mutate({ status: next })}>Move to {nextLabel}</button>
            )}
          </div>
        </div>
        <ol aria-label="Case stage" className="cw-stages">
          {STAGES.map((stage, index) => {
            const isDone = index < stageIndex && !(stage.status === 'escalated' && !caseData.escalated_at)
            const isCurrent = index === stageIndex
            return (
              <li key={stage.status} aria-current={isCurrent ? 'step' : undefined} className={isCurrent ? 'is-current' : isDone ? 'is-done' : stage.status === 'escalated' && index < stageIndex ? 'is-skipped' : ''}>
                {isDone ? <Check size={14} aria-hidden="true" /> : isCurrent ? <span className="cw-stages__dot" aria-hidden="true" /> : null}
                {stage.label}
              </li>
            )
          })}
        </ol>
        <nav className="cw-tabs" role="tablist" aria-label="Case sections">
          {CASE_TABS.map(t => (
            <button key={t.key} type="button" role="tab" aria-selected={tab === t.key} onClick={() => selectTab(t.key)}>
              {t.label}
              {t.key === 'timeline' && entries.length > 0 && <span>{entries.length}</span>}
              {t.key === 'tasks' && taskItems.length > 0 && <span>{taskItems.filter(task => task.done).length}/{taskItems.length}</span>}
            </button>
          ))}
        </nav>
      </header>

      <div className="cw-body">
        <section className="cw-main" role="tabpanel" aria-label={CASE_TABS.find(t => t.key === tab)?.label}>
          {tab === 'timeline' && <>
            {canManage && (
              <form className="cw-composer" onSubmit={handleAddNote}>
                <label htmlFor="case-note">Add a note, @mention, or paste an IoC</label>
                <textarea id="case-note" rows={2} value={noteText} onChange={event => setNoteText(event.target.value)} placeholder="What did you find?" />
                <div className="cw-composer__foot">
                  <span>Markdown supported</span>
                  <button type="submit" className="cw-btn cw-btn--soft" disabled={addNote.isPending || !noteText.trim()}>{addNote.isPending ? 'Posting…' : 'Post note'}</button>
                </div>
              </form>
            )}
            <div className="cw-timeline-head">
              <span>{entries.length} entries · newest first</span>
              <div className="cw-seg" role="group" aria-label="Timeline view">
                <button type="button" aria-pressed={timelineView === 'list'} onClick={() => setTimelineView('list')}>List</button>
                <button type="button" aria-pressed={timelineView === 'graph'} onClick={() => setTimelineView('graph')}>Attack graph</button>
              </div>
            </div>
            {timelineView === 'graph' ? <div className="cw-card"><AttackGraph items={timeline?.items ?? []} /></div> : (
              <ol className="cw-timeline">
                {entries.map(entry => (
                  <li key={entry.key}>
                    <div className="cw-timeline__rail">
                      <span className={`cw-mark cw-mark--${entry.kind} ${entry.severity ? `cw-mark--${entry.severity}` : ''}`}>{MARK[entry.kind]}</span>
                      <span className="cw-timeline__line" />
                    </div>
                    <div className="cw-timeline__body">
                      <div className="cw-timeline__title"><span>{entry.title}</span><time dateTime={entry.at}>{format(new Date(entry.at), 'dd MMM HH:mm')}</time></div>
                      {entry.body && (entry.markdown
                        ? <MarkdownNote content={entry.body} style={{ fontSize: '13px', color: '#A9B2C1' }} />
                        : <p>{entry.body}</p>)}
                    </div>
                  </li>
                ))}
              </ol>
            )}
            {sortedNotes.length < notesTotal && (
              <button type="button" className="cw-link" onClick={() => { void loadOlderNotes(sortedNotes.length) }} disabled={loadingOlder}>
                {loadingOlder ? 'Loading…' : `Showing ${sortedNotes.length} of ${notesTotal} notes — load older`}
              </button>
            )}
          </>}

          {tab === 'evidence' && <CaseEvidencePanel caseId={caseData.id} status={caseData.status} />}

          {tab === 'context' && <>
            {campaign.mergedInto && (
              <div className="cw-card cw-warn">Merged into <button type="button" className="cw-link" onClick={() => navigate(`/cases/${campaign.mergedInto}`)}>case {campaign.mergedInto.slice(0, 8)}</button>. Same attacker; work continues there.</div>
            )}
            <section className="cw-card">
              <div className="cw-card__head"><h2>Relation graph</h2></div>
              {campaign.related.length > 0
                ? <CaseRelationGraph center={caseData} relatedIds={campaign.related} onOpen={cid => navigate(`/cases/${cid}`)} />
                : <p className="cw-muted">No related cases share indicators with this one.</p>}
              {campaign.stage && <p className="cw-muted">Furthest stage: <strong>{campaign.stage.replace(/_/g, ' ')}</strong>{campaign.families.length > 1 && <> · seen: {campaign.families.map(f => f.replace(/_/g, ' ')).join(', ')}</>}</p>}
            </section>
            {(campaign.keys.length > 0 || iocEntries.length > 0) && (
              <section className="cw-card">
                <div className="cw-card__head"><h2>Indicators</h2></div>
                {campaign.keys.map(k => <div key={k} className="cw-mono cw-accent">{k}</div>)}
                {iocEntries.length > 0 && <div className="case-ioc-grid">
                  {iocEntries.map(([key, val]) => (
                    <div key={key} className="cw-ioc">
                      <div className="cw-ioc__k">{key === 'overall_risk' ? 'TI risk score' : key.replace(/_/g, ' ')}</div>
                      <div className="cw-mono">{key === 'overall_risk' ? `${Math.round(Number(val) * 100)}%`
                        : Array.isArray(val) ? (val as unknown[]).map((item, i) => <div key={i}>{typeof item === 'object' && item !== null
                          ? Object.entries(item as Record<string, unknown>).map(([k, v]) => `${k}: ${v}`).join(' | ') : String(item)}</div>)
                        : typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val)}</div>
                    </div>
                  ))}
                </div>}
              </section>
            )}
            {searchResults.length > 0 && (
              <section className="cw-card">
                <div className="cw-card__head"><h2>Search intel</h2></div>
                {searchResults.map((r, i) => (
                  <div key={i} className="cw-intel">
                    <strong>{r.title}</strong>
                    <p>{r.content}</p>
                    {r.url && <a href={r.url} target="_blank" rel="noopener noreferrer" className="cw-mono cw-accent">{r.url}</a>}
                  </div>
                ))}
              </section>
            )}
          </>}

          {tab === 'tasks' && id && <section className="cw-card"><CaseTasks caseId={id} /></section>}

          {tab === 'ai' && id && <>
            <section className="cw-card">
              <div className="cw-card__head"><h2>AI analysis</h2>{confidence != null && <span className="cw-muted">confidence {Math.round(confidence * 100)}%</span>}</div>
              {caseData.ai_reasoning ? <MarkdownNote content={caseData.ai_reasoning} style={{ fontSize: '14px', color: '#E8ECF2' }} /> : <p className="cw-muted">Pending AI analysis.</p>}
              {caseData.created_by_ai && <AiFeedbackWidget aiVerdict={(caseData.ioc_data?.verdict as string) ?? null} feedback={caseFeedback}
                isLoading={caseFeedbackLoading} onSubmit={body => submitCaseFeedback.mutate(body)} isSubmitting={submitCaseFeedback.isPending} />}
            </section>
            <section className="cw-card"><AiInvestigationPanel caseId={id} /></section>
          </>}

          {tab === 'response' && <CaseRemediations key={caseData.id} caseId={caseData.id} />}
        </section>

        <aside className="cw-side" aria-label="Case context">
          <section className="cw-card cw-summary">
            <h2>Summary so far</h2>
            {caseData.ai_reasoning
              ? <p>{caseData.ai_reasoning.replace(/[#*_`>]/g, '').slice(0, 320)}{caseData.ai_reasoning.length > 320 ? '…' : ''}</p>
              : <p>{caseData.description ?? 'No summary yet. Notes and the AI investigation build it up.'}</p>}
            <button type="button" className="cw-link" onClick={() => selectTab('ai')}>Continue the AI investigation</button>
          </section>

          {id && <SideTasks caseId={id} onOpen={() => selectTab('tasks')} />}

          {(campaign.hosts.length > 0 || campaign.keys.length > 0) && (
            <section className="cw-card">
              <div className="cw-card__head"><h2>Entities</h2></div>
              {campaign.hosts.map(host => (
                <div key={host} className="cw-entity"><span className="cw-mono">{host}</span><span className="cw-muted">Host</span></div>
              ))}
              {campaign.keys.slice(0, 4).map(key => (
                <div key={key} className="cw-entity"><span className="cw-mono">{key}</span><span className="cw-muted">Indicator</span></div>
              ))}
            </section>
          )}

          <section className="cw-card">
            <div className="cw-card__head"><h2>Linked alerts</h2></div>
            {alertData && (
              <button type="button" className="cw-linked" onClick={() => setShowLinkedAlert(true)}>
                <span>{alertData.title}</span><span className={`cw-sev cw-sev--${alertData.severity}`}>{alertData.severity}</span>
              </button>
            )}
            {linkedAlerts.filter(item => item.id !== alertData?.id).slice(0, 5).map(item => (
              <Link key={item.id} to={`/alerts/${item.id}`} className="cw-linked"><span>{item.title}</span><span className={`cw-sev cw-sev--${item.severity}`}>{item.severity}</span></Link>
            ))}
            {!alertData && linkedAlerts.length === 0 && <p className="cw-muted">No alerts linked yet.</p>}
          </section>

          <section className="cw-card cw-info">
            <div><span>Status</span><span>{caseData.status.replace('_', ' ')}</span></div>
            <div><span>Created</span><span>{format(new Date(caseData.created_at), 'dd MMM yyyy HH:mm')}</span></div>
            {caseData.escalated_at && <div><span>Escalated</span><span>{format(new Date(caseData.escalated_at), 'dd MMM yyyy HH:mm')}</span></div>}
            <div><span>Group</span><span>{caseData.group_id}</span></div>
            {canManage && caseData.status !== 'closed' && (
              <div className="cw-info__actions">
                {caseData.status !== 'in_review' && caseData.status !== 'resolved' && <button type="button" className="cw-btn cw-btn--xs" onClick={() => update.mutate({ status: 'in_review' })}>Mark in review</button>}
                {caseData.status !== 'resolved' && <button type="button" className="cw-btn cw-btn--xs" onClick={() => update.mutate({ status: 'resolved' })}>Resolve</button>}
                <button type="button" className="cw-btn cw-btn--xs" onClick={() => update.mutate({ status: 'closed' })}>Close</button>
              </div>
            )}
          </section>
        </aside>
      </div>
      {alertData && showLinkedAlert && <AlertDetailModal alert={alertData} onClose={() => setShowLinkedAlert(false)} />}
    </div>
  )
}
