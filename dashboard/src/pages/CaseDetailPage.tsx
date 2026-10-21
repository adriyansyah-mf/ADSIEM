import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { format } from 'date-fns'
import { ArrowLeft, Bot } from 'lucide-react'
import { PageHeader, Panel, QueryState } from '@/components/Workspace'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import { useCase, useUpdateCase, useEscalateCase, useAddCaseNote, useCaseFeedback, useSubmitCaseFeedback } from '@/hooks/useCases'
import { useBlockIp, useTasks } from '@/hooks/useTasks'
import { useAuthStore } from '@/stores/auth'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Alert } from '@/types'
import MarkdownNote from '@/components/MarkdownNote'
import AttackGraph from '@/components/AttackGraph'
import AlertDetailModal from '@/components/AlertDetailModal'
import AiFeedbackWidget from '@/components/AiFeedbackWidget'
import AiInvestigationPanel from '@/components/AiInvestigationPanel'

function Box({ title, children, actions }: { title: string; children: React.ReactNode; actions?: React.ReactNode }) {
  return <Panel title={title} actions={actions}>{children}</Panel>
}

function ActionBtn({ label, onClick, color, loading, disabled }: { label: string; onClick: () => void; color: string; loading?: boolean; disabled?: boolean }) {
  const canManage = useAuthStore(state => state.hasRole('analyst'))
  return <button onClick={onClick} disabled={loading || disabled || !canManage}
    className={`ui-button w-full justify-start mb-2 ${color === 'var(--accent-red)' ? 'ui-button--danger' : ''}`}
    title={canManage ? undefined : 'An analyst role is required for case actions'}>
    {loading ? 'Working…' : label}
  </button>
}

function AttackTimeline({ items }: { items: any[] }) {
  if (!items || items.length === 0) {
    return (
      <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', padding: '8px 0' }}>
        No related events found in ±24h window.
      </div>
    )
  }
  const sevColor = (s: string): string =>
    ({ critical: '#ff2244', high: '#ff6b00', medium: '#ffd700', low: '#00ff88' } as Record<string, string>)[s] ?? '#00d4ff'

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {items.map((item, idx) => (
        <div key={item.id} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
          {/* Vertical timeline connector */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
            <div style={{
              width: 10, height: 10, borderRadius: '50%', marginTop: 4, flexShrink: 0,
              background: item.type === 'alert' ? sevColor(item.severity) : '#64748b',
              border: '2px solid transparent',
            }} />
            {idx < items.length - 1 && (
              <div style={{ width: 1, flex: 1, minHeight: 16, background: '#1e2028', margin: '2px 0' }} />
            )}
          </div>
          {/* Event content */}
          <div style={{ flex: 1, paddingBottom: 10 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                {new Date(item.ts).toLocaleString('en-US', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}
              </span>
              {item.type === 'alert' && (
                <span style={{ fontSize: 12, padding: '1px 5px', borderRadius: 2, background: `${sevColor(item.severity)}22`, color: sevColor(item.severity), fontFamily: 'var(--font-mono)', textTransform: 'none' }}>
                  {item.severity}
                </span>
              )}
              {item.type === 'note' && (
                <span style={{ fontSize: 12, padding: '1px 5px', borderRadius: 2, background: 'rgba(100,116,139,0.15)', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                  NOTE
                </span>
              )}
              {item.is_this_case && (
                <span style={{ fontSize: 12, padding: '1px 5px', borderRadius: 2, background: 'rgba(0,212,255,0.15)', color: '#00d4ff', fontFamily: 'var(--font-mono)' }}>
                  THIS CASE
                </span>
              )}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-primary)', marginTop: 2, lineHeight: 1.4 }}>
              {item.title}
            </div>
            {item.source_ip && (
              <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', marginTop: 1 }}>
                {item.source_ip}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

export default function CaseDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { user } = useAuthStore()
  const [noteText, setNoteText] = useState('')
  const [timelineView, setTimelineView] = useState<'graph' | 'linear'>('graph')
  const [showLinkedAlert, setShowLinkedAlert] = useState(false)
  const [blockIpValue, setBlockIpValue] = useState('')
  const [blockDuration, setBlockDuration] = useState(3600)

  const { data: caseData, isLoading, isError, refetch } = useCase(id!)
  const update = useUpdateCase(id!)
  const escalate = useEscalateCase(id!)
  const addNote = useAddCaseNote(id!)
  const { data: caseFeedback, isLoading: caseFeedbackLoading } = useCaseFeedback(id!)
  const submitCaseFeedback = useSubmitCaseFeedback(id!)
  const blockIp = useBlockIp()

  const { data: alertData } = useQuery<Alert>({
    queryKey: ['alert', caseData?.alert_id],
    queryFn: () => api.get(`/api/alerts/${caseData!.alert_id}`).then(r => r.data),
    enabled: !!caseData?.alert_id,
  })

  const targetAgentId = alertData?.agent_id ?? null
  const { data: agentTasks = [] } = useTasks(targetAgentId ?? undefined)
  const recentBlocks = agentTasks
    .filter(t => t.task_type === 'block_ip')
    .slice(0, 3)

  // Prefill the block-IP field with the linked alert's source IP once it loads
  useEffect(() => {
    if (alertData?.source_ip && !blockIpValue) {
      setBlockIpValue(alertData.source_ip)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alertData?.source_ip])

  const handleBlockIp = () => {
    if (!targetAgentId || !blockIpValue.trim()) return
    blockIp.mutate({ agent_id: targetAgentId, ip: blockIpValue.trim(), duration_seconds: blockDuration })
  }

  const { data: timeline } = useQuery({
    queryKey: ['case-timeline', id],
    queryFn: () => api.get(`/api/cases/${id}/timeline`).then(r => r.data),
    enabled: !!id,
    refetchInterval: 30_000,
  })

  const handleAddNote = () => {
    if (!noteText.trim()) return
    addNote.mutate(noteText, {
      onSuccess: () => setNoteText(''),
    })
  }

  if (isLoading) return <QueryState kind="loading" title="Loading case…" description="Fetching the case record and investigation context." />
  if (isError || !caseData) return <QueryState kind="error" title="Could not open this case"
    description="The case may be unavailable or outside your workspace. Try again or return to Cases."
    onRetry={() => { void refetch() }} />

  // campaign fields (worker/case_grouping.py) get their own box
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
    // hide overall_risk=0 — means no TI data available, not an actual zero-risk score
    if (k === 'overall_risk' && (v === 0 || v === 0.0)) return false
    return true
  })
  const searchResults = caseData.search_intel?.results ?? []
  const sortedNotes = [...(caseData.notes ?? [])].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  )

  return (
    <div className="workspace case-page">
      <PageHeader eyebrow="Investigations" title={caseData.title}
        actions={<button className="ui-button" onClick={() => navigate('/cases')}><ArrowLeft size={14} /> Back to cases</button>} />
      <div className="control-cluster">
        <SeverityBadge severity={caseData.severity} />
        <StatusBadge status={caseData.status} />
        {caseData.created_by_ai && <span className="semantic-badge"><Bot size={14} /> AI-created case</span>}
        <span className="text-muted-foreground text-xs">Created {format(new Date(caseData.created_at), 'dd MMM yyyy, HH:mm')} · {caseData.group_id}</span>
      </div>
      {caseData.description && <Panel title="Case summary"><p className="whitespace-pre-wrap mb-0">{caseData.description}</p></Panel>}
      {/* 2-column layout */}
      <div className="case-layout">
        {/* Left column (wider) */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* AI investigation: the AI works the case on the endpoints */}
          {id && (
            <Box title="AI Investigation">
              <AiInvestigationPanel caseId={id} />
            </Box>
          )}

          {/* AI Analysis */}
          <Box title="AI Analysis">
            {caseData.ai_reasoning ? (
              <div>
                <MarkdownNote
                  content={caseData.ai_reasoning}
                  style={{ fontFamily: 'var(--font-ui)', fontSize: '14px', color: 'var(--text-primary)', marginBottom: '12px' }}
                />
                {(() => {
                  const pct = caseData.ai_confidence != null ? caseData.ai_confidence : null
                  if (pct == null) return null
                  const color = pct >= 0.75 ? 'var(--accent-green)' : pct >= 0.5 ? 'var(--accent-yellow)' : 'var(--accent-orange)'
                  return (
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '8px 12px',
                      borderRadius: '4px',
                      background: `color-mix(in srgb, ${color} 10%, transparent)`,
                      border: '1px solid var(--border-default)',
                    }}>
                      <span style={{ fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: '12px', color: 'var(--text-muted)', letterSpacing: 'normal' }}>
                        AI CONFIDENCE
                      </span>
                      <div style={{ flex: 1, height: '4px', borderRadius: '2px', background: 'var(--border)', overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: `${Math.round(pct * 100)}%`, background: color, borderRadius: '2px' }} />
                      </div>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color }}>{Math.round(pct * 100)}%</span>
                    </div>
                  )
                })()}
                {caseData.created_by_ai && (
                  <AiFeedbackWidget
                    aiVerdict={(caseData.ioc_data?.verdict as string) ?? null}
                    feedback={caseFeedback}
                    isLoading={caseFeedbackLoading}
                    onSubmit={body => submitCaseFeedback.mutate(body)}
                    isSubmitting={submitCaseFeedback.isPending}
                  />
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                Pending AI analysis
              </div>
            )}
          </Box>

          {/* Campaign: the attacker's IOCs and the hosts they touched */}
          {(campaign.hosts.length > 0 || campaign.keys.length > 0 || campaign.mergedInto) && (
            <Box title="Campaign">
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
                {campaign.mergedInto && (
                  <div style={{ color: 'var(--accent-yellow)' }}>
                    Merged into{' '}
                    <button onClick={() => navigate(`/cases/${campaign.mergedInto}`)} style={{ color: 'var(--accent-cyan)', textDecoration: 'underline' }}>
                      case {campaign.mergedInto.slice(0, 8)}
                    </button>{' '}— the same attacker. Work continues there.
                  </div>
                )}
                {campaign.hosts.length > 0 && (
                  <div>
                    <div style={{ fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: '12px', color: 'var(--text-muted)', letterSpacing: 'normal', marginBottom: '4px' }}>
                      AFFECTED HOSTS ({campaign.hosts.length})
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {campaign.hosts.map(h => (
                        <span key={h} style={{ fontFamily: 'var(--font-mono)', padding: '2px 8px', border: '1px solid var(--border)', borderRadius: '3px' }}>{h}</span>
                      ))}
                    </div>
                  </div>
                )}
                {campaign.keys.length > 0 && (
                  <div>
                    <div style={{ fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: '12px', color: 'var(--text-muted)', letterSpacing: 'normal', marginBottom: '4px' }}>
                      INDICATORS THAT TIE THIS CASE TOGETHER
                    </div>
                    {campaign.keys.map(k => (
                      <div key={k} style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>{k}</div>
                    ))}
                  </div>
                )}
                {campaign.stage && (
                  <div style={{ color: 'var(--text-muted)' }}>
                    Furthest stage: <b style={{ color: 'var(--text-primary)' }}>{campaign.stage.replace(/_/g, ' ')}</b>
                    {campaign.families.length > 1 && <> · seen: {campaign.families.map(f => f.replace(/_/g, ' ')).join(', ')}</>}
                  </div>
                )}
                {campaign.related.length > 0 && (
                  <div style={{ color: 'var(--text-muted)' }}>
                    Related cases:{' '}
                    {campaign.related.map((id, i) => (
                      <span key={id}>
                        {i > 0 && ', '}
                        <button onClick={() => navigate(`/cases/${id}`)} style={{ color: 'var(--accent-cyan)', textDecoration: 'underline' }}>{id.slice(0, 8)}</button>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </Box>
          )}

          {/* IOC Data */}
          {iocEntries.length > 0 && (
            <Box title="IOC Data">
              <div className="case-ioc-grid">
                {iocEntries.map(([key, val]) => (
                  <div key={key} style={{
                    padding: '8px 10px',
                    borderRadius: '4px',
                    background: 'var(--bg-panel)',
                    border: '1px solid var(--border)',
                  }}>
                    <div style={{ fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: '12px', color: 'var(--text-muted)', letterSpacing: 'normal', textTransform: 'none', marginBottom: '3px' }}>
                      {key === 'overall_risk' ? 'TI RISK SCORE' : key.replace(/_/g, ' ')}
                    </div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: key === 'overall_risk' ? (Number(val) >= 0.75 ? 'var(--accent-red)' : Number(val) >= 0.45 ? 'var(--accent-orange)' : 'var(--accent-yellow)') : 'var(--accent-cyan)', wordBreak: 'break-all' }}>
                      {key === 'overall_risk' ? `${Math.round(Number(val) * 100)}%` : Array.isArray(val)
                        ? (val as unknown[]).map((item, i) =>
                            typeof item === 'object' && item !== null
                              ? <div key={i} style={{ marginBottom: '2px' }}>
                                  {Object.entries(item as Record<string, unknown>).map(([k, v]) => `${k}: ${v}`).join(' | ')}
                                </div>
                              : <div key={i}>{String(item)}</div>
                          )
                        : typeof val === 'object' && val !== null
                          ? JSON.stringify(val)
                          : String(val)
                      }
                    </div>
                  </div>
                ))}
              </div>
            </Box>
          )}

          {/* Search Intel */}
          {searchResults.length > 0 && (
            <Box title="Search Intel">
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {searchResults.map((r, i) => (
                  <div key={i} style={{
                    padding: '10px',
                    borderRadius: '4px',
                    background: 'var(--bg-panel)',
                    border: '1px solid var(--border)',
                  }}>
                    <div style={{ fontFamily: 'var(--font-ui)', fontWeight: 600, fontSize: '14px', color: 'var(--text-primary)', marginBottom: '4px' }}>
                      {r.title}
                    </div>
                    <div style={{ fontFamily: 'var(--font-ui)', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                      {r.content}
                    </div>
                    {r.url && (
                      <a href={r.url} target="_blank" rel="noopener noreferrer"
                        style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--accent-cyan)', textDecoration: 'none', marginTop: '4px', display: 'block' }}>
                        {r.url}
                      </a>
                    )}
                  </div>
                ))}
              </div>
            </Box>
          )}

          {/* Linked Alert */}
          {alertData && (
            <Box title="Linked Alert">
              <div
                onClick={() => setShowLinkedAlert(true)}
                style={{
                  padding: '10px',
                  borderRadius: '4px',
                  background: 'var(--bg-panel)',
                  border: '1px solid var(--border)',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <SeverityBadge severity={alertData.severity} />
                  <span style={{ fontFamily: 'var(--font-ui)', fontWeight: 600, fontSize: '14px', color: 'var(--text-primary)' }}>
                    {alertData.title}
                  </span>
                </div>
                {alertData.source_ip && (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--accent-cyan)', marginTop: '6px' }}>
                    SRC: {alertData.source_ip}
                  </div>
                )}
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  {format(new Date(alertData.created_at), 'yyyy-MM-dd HH:mm:ss')}
                </div>
              </div>
            </Box>
          )}

          {alertData && showLinkedAlert && (
            <AlertDetailModal alert={alertData} onClose={() => setShowLinkedAlert(false)} />
          )}

          {/* Timeline / Notes */}
          <Box title="Timeline / Notes">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '12px' }}>
              {sortedNotes.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>No notes yet</div>
              ) : sortedNotes.map(note => (
                <div key={note.id} style={{
                  padding: '10px',
                  borderRadius: '4px',
                  background: 'var(--bg-panel)',
                  border: '1px solid var(--border)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <span style={{ fontFamily: 'var(--font-ui)', fontWeight: 600, fontSize: '12px', color: note.is_ai_generated ? 'var(--accent-cyan)' : 'var(--text-secondary)' }}>
                      {note.is_ai_generated ? 'AI' : note.author_id ?? 'System'}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>
                      {format(new Date(note.created_at), 'yyyy-MM-dd HH:mm:ss')}
                    </span>
                  </div>
                  <MarkdownNote
                    content={note.content}
                    style={{ fontFamily: 'var(--font-ui)', fontSize: '14px', color: 'var(--text-primary)' }}
                  />
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-end' }}>
              <textarea
                aria-label="Case note"
                value={noteText}
                onChange={e => setNoteText(e.target.value)}
                placeholder="Add a note..."
                rows={3}
                style={{
                  flex: 1,
                  background: 'var(--bg-panel)',
                  border: '1px solid var(--border)',
                  borderRadius: '4px',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-ui)',
                  fontSize: '14px',
                  padding: '8px 10px',
                  resize: 'vertical',
                  outline: 'none',
                }}
              />
              <button
                onClick={handleAddNote}
                disabled={addNote.isPending || !noteText.trim()}
                style={{
                  padding: '8px 16px',
                  borderRadius: '4px',
                  border: '1px solid var(--accent-cyan)',
                  background: 'rgba(0,212,255,0.15)',
                  color: 'var(--accent-cyan)',
                  fontFamily: 'var(--font-ui)',
                  fontWeight: 700,
                  fontSize: '12px',
                  letterSpacing: 'normal',
                  cursor: addNote.isPending ? 'wait' : 'pointer',
                  opacity: addNote.isPending || !noteText.trim() ? 0.6 : 1,
                }}
              >
                {addNote.isPending ? '...' : 'ADD NOTE'}
              </button>
            </div>
          </Box>

          <Box
            title={`Attack Timeline (${timeline?.items?.length ?? 0} events)`}
            actions={
              <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: '6px', overflow: 'hidden' }}>
                {(['graph', 'linear'] as const).map(v => (
                  <button
                    key={v}
                    onClick={() => setTimelineView(v)}
                    style={{
                      appearance: 'none',
                      border: 0,
                      borderLeft: v === 'linear' ? '1px solid var(--border)' : 'none',
                      background: timelineView === v ? 'rgba(0,212,255,0.12)' : 'transparent',
                      color: timelineView === v ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                      fontFamily: 'var(--font-ui)',
                      fontWeight: 700,
                      fontSize: '12px',
                      letterSpacing: 'normal',
                      padding: '5px 12px',
                      cursor: 'pointer',
                    }}
                  >
                    {v.toUpperCase()}
                  </button>
                ))}
              </div>
            }
          >
            {timelineView === 'graph'
              ? <AttackGraph items={timeline?.items ?? []} />
              : <AttackTimeline items={timeline?.items ?? []} />}
          </Box>
        </div>

        {/* Right column (narrower) */}
        <div className="case-sidebar">
          {/* Case Info */}
          <Box title="Case Info">
            {[
              { label: 'STATUS', value: caseData.status.replace('_', ' ').toUpperCase() },
              { label: 'SEVERITY', value: caseData.severity.toUpperCase() },
              { label: 'GROUP', value: caseData.group_id.slice(0, 8) + '...' },
              { label: 'CREATED', value: format(new Date(caseData.created_at), 'yyyy-MM-dd HH:mm') },
              caseData.escalated_at
                ? { label: 'ESCALATED', value: format(new Date(caseData.escalated_at), 'yyyy-MM-dd HH:mm') }
                : null,
              { label: 'ASSIGNED TO', value: caseData.assignee_id ? caseData.assignee_id.slice(0, 8) + '...' : 'Unassigned' },
            ].filter(Boolean).map((item) => (
              <div key={item!.label} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '5px 0',
                borderBottom: '1px solid var(--border)',
              }}>
                <span style={{ fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: '12px', color: 'var(--text-muted)', letterSpacing: 'normal' }}>
                  {item!.label}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-primary)' }}>
                  {item!.value}
                </span>
              </div>
            ))}
          </Box>

          {/* Actions */}
          <Box title="Actions">
            {user?.id && (
              <ActionBtn
                label="Assign to me"
                onClick={() => update.mutate({ assignee_id: user.id })}
                color="var(--accent-green)"
                loading={update.isPending}
                disabled={caseData.assignee_id === user.id}
              />
            )}
            <ActionBtn
              label="Escalate to L2"
              onClick={() => escalate.mutate()}
              color="var(--accent-orange)"
              loading={escalate.isPending}
              disabled={caseData.status === 'escalated'}
            />
            <ActionBtn
              label="Mark in review"
              onClick={() => update.mutate({ status: 'in_review' })}
              color="var(--accent-yellow)"
              loading={update.isPending}
              disabled={caseData.status === 'in_review'}
            />
            <ActionBtn
              label="Resolve case"
              onClick={() => update.mutate({ status: 'resolved' })}
              color="var(--accent-cyan)"
              loading={update.isPending}
              disabled={caseData.status === 'resolved' || caseData.status === 'closed'}
            />
            <ActionBtn
              label="Close case"
              onClick={() => update.mutate({ status: 'closed' })}
              color="var(--text-muted)"
              loading={update.isPending}
              disabled={caseData.status === 'closed'}
            />
          </Box>

          {/* Remediations */}
          <Box title="Remediations">
            {!targetAgentId ? (
              <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px', lineHeight: 1.5 }}>
                No agent linked to this case — remediation actions need a linked alert with a known host.
              </div>
            ) : (
              <div>
                <div style={{ fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: '12px', color: 'var(--text-muted)', letterSpacing: 'normal', marginBottom: '4px' }}>
                  TARGET HOST
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-primary)', marginBottom: '10px' }}>
                  {alertData?.hostname ?? targetAgentId.slice(0, 8)}
                </div>

                <label className="field mb-2"><span>IP address to block</span><input
                  value={blockIpValue}
                  onChange={e => setBlockIpValue(e.target.value)}
                  placeholder="IP address to block"
                  style={{
                    width: '100%',
                    background: 'var(--bg-panel)',
                    border: '1px solid var(--border)',
                    borderRadius: '4px',
                    color: 'var(--text-primary)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    padding: '7px 10px',
                    marginBottom: '6px',
                    outline: 'none',
                    boxSizing: 'border-box',
                  }}
                /></label>
                <label className="field mb-2"><span>Block duration</span><select
                  value={blockDuration}
                  onChange={e => setBlockDuration(Number(e.target.value))}
                  style={{
                    width: '100%',
                    background: 'var(--bg-panel)',
                    border: '1px solid var(--border)',
                    borderRadius: '4px',
                    color: 'var(--text-primary)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    padding: '7px 10px',
                    marginBottom: '8px',
                    outline: 'none',
                  }}
                >
                  <option value={3600}>1 hour</option>
                  <option value={86400}>24 hours</option>
                  <option value={604800}>7 days</option>
                </select></label>

                <ActionBtn
                  label="Block IP on host"
                  onClick={handleBlockIp}
                  color="var(--accent-red)"
                  loading={blockIp.isPending}
                  disabled={!blockIpValue.trim()}
                />

                {recentBlocks.length > 0 && (
                  <div style={{ marginTop: '10px' }}>
                    <div style={{ fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: '12px', color: 'var(--text-muted)', letterSpacing: 'normal', marginBottom: '6px' }}>
                      RECENT BLOCKS
                    </div>
                    {recentBlocks.map(t => (
                      <div key={t.id} style={{
                        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                        padding: '5px 0', borderBottom: '1px solid var(--border)',
                        fontFamily: 'var(--font-mono)', fontSize: '12px',
                      }}>
                        <span style={{ color: 'var(--text-secondary)' }}>{String((t.params as Record<string, unknown>)?.ip ?? '')}</span>
                        <span style={{
                          color: t.status === 'done' ? 'var(--accent-green)' : t.status === 'failed' ? 'var(--accent-red)' : 'var(--accent-yellow)',
                          textTransform: 'none',
                        }}>
                          {t.status}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </Box>
        </div>
      </div>
    </div>
  )
}
