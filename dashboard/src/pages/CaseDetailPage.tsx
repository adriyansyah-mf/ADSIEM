import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { format } from 'date-fns'
import { useCase, useUpdateCase, useEscalateCase, useAddCaseNote } from '@/hooks/useCases'
import { useAuthStore } from '@/stores/auth'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Alert } from '@/types'

const severityColors = {
  critical: { bg: 'rgba(255,34,68,0.15)', border: '#ff2244', color: '#ff2244' },
  high:     { bg: 'rgba(255,107,0,0.15)', border: '#ff6b00', color: '#ff6b00' },
  medium:   { bg: 'rgba(255,215,0,0.1)',  border: '#ffd700', color: '#ffd700' },
  low:      { bg: 'rgba(0,255,136,0.1)',  border: '#00ff88', color: '#00ff88' },
  info:     { bg: 'rgba(0,212,255,0.1)',  border: '#00d4ff', color: '#00d4ff' },
}

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity as keyof typeof severityColors
  const c = severityColors[s] ?? severityColors.info
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 10px',
      borderRadius: '4px',
      border: `1px solid ${c.border}`,
      background: c.bg,
      color: c.color,
      fontFamily: 'Rajdhani, sans-serif',
      fontWeight: 700,
      fontSize: '12px',
      letterSpacing: '1px',
      textTransform: 'uppercase',
      boxShadow: `0 0 8px ${c.border}44`,
    }}>
      {severity}
    </span>
  )
}

function Box({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{
      borderRadius: '6px',
      border: '1px solid var(--border)',
      background: 'var(--bg-card)',
      padding: '14px',
      marginBottom: '12px',
    }}>
      <div style={{
        fontFamily: 'Rajdhani, sans-serif',
        fontSize: '11px',
        fontWeight: 700,
        letterSpacing: '2px',
        textTransform: 'uppercase',
        color: 'var(--accent-cyan)',
        marginBottom: '12px',
      }}>
        {title}
      </div>
      {children}
    </div>
  )
}

function ActionBtn({ label, onClick, color, loading, disabled }: { label: string; onClick: () => void; color: string; loading?: boolean; disabled?: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={loading || disabled}
      style={{
        padding: '8px 16px',
        borderRadius: '4px',
        border: `1px solid ${color}`,
        background: `${color}18`,
        color,
        fontFamily: 'Rajdhani, sans-serif',
        fontWeight: 700,
        fontSize: '12px',
        letterSpacing: '1px',
        cursor: loading || disabled ? 'not-allowed' : 'pointer',
        opacity: loading || disabled ? 0.6 : 1,
        transition: 'all 0.15s',
        width: '100%',
        marginBottom: '6px',
        textAlign: 'left',
      }}
    >
      {loading ? 'WORKING...' : label}
    </button>
  )
}

export default function CaseDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { user } = useAuthStore()
  const [noteText, setNoteText] = useState('')

  const { data: caseData, isLoading } = useCase(id!)
  const update = useUpdateCase(id!)
  const escalate = useEscalateCase(id!)
  const addNote = useAddCaseNote(id!)

  const { data: alertData } = useQuery<Alert>({
    queryKey: ['alert', caseData?.alert_id],
    queryFn: () => api.get(`/api/alerts/${caseData!.alert_id}`).then(r => r.data),
    enabled: !!caseData?.alert_id,
  })

  const handleAddNote = () => {
    if (!noteText.trim()) return
    addNote.mutate(noteText, {
      onSuccess: () => setNoteText(''),
    })
  }

  if (isLoading) {
    return (
      <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--text-muted)', padding: '40px', textAlign: 'center' }}>
        LOADING CASE...
      </div>
    )
  }

  if (!caseData) {
    return (
      <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--accent-red)', padding: '40px', textAlign: 'center' }}>
        CASE NOT FOUND
      </div>
    )
  }

  const iocEntries = Object.entries(caseData.ioc_data ?? {}).filter(([, v]) => v != null && v !== '')
  const searchResults = caseData.search_intel?.results ?? []
  const sortedNotes = [...(caseData.notes ?? [])].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  )

  const statusColor = {
    open: 'var(--accent-cyan)',
    in_review: 'var(--accent-yellow)',
    escalated: 'var(--accent-orange)',
    resolved: 'var(--accent-green)',
    closed: 'var(--text-muted)',
  }[caseData.status] ?? 'var(--text-muted)'

  return (
    <div>
      {/* Back button + header */}
      <div style={{ marginBottom: '16px' }}>
        <button
          onClick={() => navigate('/cases')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 12px',
            borderRadius: '4px',
            border: '1px solid var(--border)',
            background: 'transparent',
            color: 'var(--text-secondary)',
            fontFamily: 'Rajdhani, sans-serif',
            fontWeight: 600,
            fontSize: '12px',
            letterSpacing: '1px',
            cursor: 'pointer',
            marginBottom: '12px',
          }}
        >
          ← BACK TO CASES
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <h1 style={{
            fontFamily: 'Exo 2, sans-serif',
            fontWeight: 700,
            fontSize: '20px',
            color: 'var(--text-primary)',
            margin: 0,
            flex: 1,
          }}>
            {caseData.created_by_ai && <span style={{ marginRight: '8px' }}>🤖</span>}
            {caseData.title}
          </h1>
          <SeverityBadge severity={caseData.severity} />
          <span style={{
            display: 'inline-block',
            padding: '2px 10px',
            borderRadius: '4px',
            border: `1px solid ${statusColor}`,
            color: statusColor,
            fontFamily: 'Rajdhani, sans-serif',
            fontWeight: 700,
            fontSize: '12px',
            letterSpacing: '1px',
            textTransform: 'uppercase',
            background: `${statusColor}18`,
          }}>
            {caseData.status.replace('_', ' ')}
          </span>
        </div>
      </div>

      {/* 2-column layout */}
      <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-start' }}>
        {/* Left column (wider) */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* AI Analysis */}
          <Box title="AI Analysis">
            {caseData.ai_reasoning ? (
              <div>
                <p style={{ fontFamily: 'Exo 2, sans-serif', fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.7, margin: '0 0 12px 0' }}>
                  {caseData.ai_reasoning}
                </p>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '8px 12px',
                  borderRadius: '4px',
                  background: 'rgba(0,255,136,0.07)',
                  border: '1px solid rgba(0,255,136,0.2)',
                }}>
                  <span style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px' }}>
                    AI CONFIDENCE
                  </span>
                  <div style={{ flex: 1, height: '4px', borderRadius: '2px', background: 'var(--border)', overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: '75%', background: 'var(--accent-green)', borderRadius: '2px' }} />
                  </div>
                  <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--accent-green)' }}>75%</span>
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px' }}>
                Pending AI analysis
              </div>
            )}
          </Box>

          {/* IOC Data */}
          {iocEntries.length > 0 && (
            <Box title="IOC Data">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                {iocEntries.map(([key, val]) => (
                  <div key={key} style={{
                    padding: '8px 10px',
                    borderRadius: '4px',
                    background: 'var(--bg-panel)',
                    border: '1px solid var(--border)',
                  }}>
                    <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '1px', textTransform: 'uppercase', marginBottom: '3px' }}>
                      {key.replace(/_/g, ' ')}
                    </div>
                    <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>
                      {String(val)}
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
                    <div style={{ fontFamily: 'Exo 2, sans-serif', fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)', marginBottom: '4px' }}>
                      {r.title}
                    </div>
                    <div style={{ fontFamily: 'Exo 2, sans-serif', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                      {r.content}
                    </div>
                    {r.url && (
                      <a href={r.url} target="_blank" rel="noopener noreferrer"
                        style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--accent-cyan)', textDecoration: 'none', marginTop: '4px', display: 'block' }}>
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
              <div style={{
                padding: '10px',
                borderRadius: '4px',
                background: 'var(--bg-panel)',
                border: '1px solid var(--border)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{
                    display: 'inline-block',
                    padding: '2px 8px',
                    borderRadius: '3px',
                    border: `1px solid ${severityColors[alertData.severity as keyof typeof severityColors]?.border ?? '#00d4ff'}`,
                    background: severityColors[alertData.severity as keyof typeof severityColors]?.bg ?? 'transparent',
                    color: severityColors[alertData.severity as keyof typeof severityColors]?.color ?? '#00d4ff',
                    fontFamily: 'Rajdhani, sans-serif',
                    fontWeight: 700,
                    fontSize: '11px',
                    textTransform: 'uppercase',
                  }}>
                    {alertData.severity}
                  </span>
                  <span style={{ fontFamily: 'Exo 2, sans-serif', fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)' }}>
                    {alertData.title}
                  </span>
                </div>
                {alertData.source_ip && (
                  <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--accent-cyan)', marginTop: '6px' }}>
                    SRC: {alertData.source_ip}
                  </div>
                )}
                <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  {format(new Date(alertData.created_at), 'yyyy-MM-dd HH:mm:ss')}
                </div>
              </div>
            </Box>
          )}

          {/* Timeline / Notes */}
          <Box title="Timeline / Notes">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '12px' }}>
              {sortedNotes.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px' }}>No notes yet</div>
              ) : sortedNotes.map(note => (
                <div key={note.id} style={{
                  padding: '10px',
                  borderRadius: '4px',
                  background: 'var(--bg-panel)',
                  border: '1px solid var(--border)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <span style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 600, fontSize: '11px', color: note.is_ai_generated ? 'var(--accent-cyan)' : 'var(--text-secondary)' }}>
                      {note.is_ai_generated ? '🤖 AI' : note.author_id ?? 'System'}
                    </span>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
                      {format(new Date(note.created_at), 'yyyy-MM-dd HH:mm:ss')}
                    </span>
                  </div>
                  <div style={{ fontFamily: 'Exo 2, sans-serif', fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.6 }}>
                    {note.content}
                  </div>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-end' }}>
              <textarea
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
                  fontFamily: 'Exo 2, sans-serif',
                  fontSize: '13px',
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
                  fontFamily: 'Rajdhani, sans-serif',
                  fontWeight: 700,
                  fontSize: '12px',
                  letterSpacing: '1px',
                  cursor: addNote.isPending ? 'wait' : 'pointer',
                  opacity: addNote.isPending || !noteText.trim() ? 0.6 : 1,
                }}
              >
                {addNote.isPending ? '...' : 'ADD NOTE'}
              </button>
            </div>
          </Box>
        </div>

        {/* Right column (narrower) */}
        <div style={{ width: '240px', flexShrink: 0 }}>
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
                <span style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '1px' }}>
                  {item!.label}
                </span>
                <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--text-primary)' }}>
                  {item!.value}
                </span>
              </div>
            ))}
          </Box>

          {/* Actions */}
          <Box title="Actions">
            {user?.id && (
              <ActionBtn
                label="ASSIGN TO ME"
                onClick={() => update.mutate({ assignee_id: user.id })}
                color="var(--accent-green)"
                loading={update.isPending}
                disabled={caseData.assignee_id === user.id}
              />
            )}
            <ActionBtn
              label="ESCALATE TO L2"
              onClick={() => escalate.mutate()}
              color="var(--accent-orange)"
              loading={escalate.isPending}
              disabled={caseData.status === 'escalated'}
            />
            <ActionBtn
              label="MARK IN REVIEW"
              onClick={() => update.mutate({ status: 'in_review' })}
              color="var(--accent-yellow)"
              loading={update.isPending}
              disabled={caseData.status === 'in_review'}
            />
            <ActionBtn
              label="RESOLVE"
              onClick={() => update.mutate({ status: 'resolved' })}
              color="var(--accent-cyan)"
              loading={update.isPending}
              disabled={caseData.status === 'resolved' || caseData.status === 'closed'}
            />
            <ActionBtn
              label="CLOSE"
              onClick={() => update.mutate({ status: 'closed' })}
              color="var(--text-muted)"
              loading={update.isPending}
              disabled={caseData.status === 'closed'}
            />
          </Box>
        </div>
      </div>
    </div>
  )
}
