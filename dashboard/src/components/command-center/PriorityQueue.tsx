import { format } from 'date-fns'
import { useNavigate } from 'react-router-dom'
import { GlassCard } from '@/components/ui/GlassCard'
import type { Alert } from '@/types'

interface WorkloadItem { user_id: string; username: string }

// Mirrors server-api's _RESOLVED_STATUSES (alerts.py) — the authoritative
// "no longer needs triage" set. Everything else (new/acknowledged/in_progress)
// is actionable.
const DONE_STATUSES = new Set(['resolved', 'closed', 'false_positive'])
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--accent-red)', high: 'var(--accent-orange)', medium: 'var(--accent-yellow)',
  low: 'var(--accent-green)', info: 'var(--accent-blue)',
}

/** Command Center's Priority Queue (Ironwatch spec 4.1): ranked actionable
 * alerts — SLA-breached and higher severity first — each with a single clear
 * next action. This is plain, always-available manual triage; it renders
 * identically whether or not the AI Situation Brief above it is available. */
export function PriorityQueue({ alerts, workload }: { alerts: Alert[]; workload: WorkloadItem[] }) {
  const navigate = useNavigate()
  const usernameById = new Map(workload.map(w => [w.user_id, w.username]))

  const actionable = alerts
    .filter(a => !DONE_STATUSES.has(a.status))
    .sort((a, b) => {
      if (a.sla_breached !== b.sla_breached) return a.sla_breached ? -1 : 1
      const rankDiff = (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
      if (rankDiff !== 0) return rankDiff
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    })
    .slice(0, 10)

  return (
    <GlassCard title={`Priority Queue — ${actionable.length} actionable`}>
      {actionable.length === 0 ? (
        <div style={{ fontSize: 13, color: 'var(--text-muted)', padding: '8px 0' }}>
          Nothing actionable right now — all alerts are acknowledged, resolved, or closed.
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
            <thead>
              <tr>
                {['Severity', 'Alert', 'Entity', 'SLA', 'Owner', 'AI verdict', ''].map(h => (
                  <th key={h} style={{
                    textAlign: 'left', padding: '6px 10px', borderBottom: '1px solid var(--border)',
                    fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '0.06em',
                    textTransform: 'uppercase', color: 'var(--text-muted)', whiteSpace: 'nowrap',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {actionable.map(a => (
                <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '7px 10px', whiteSpace: 'nowrap' }}>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                      color: SEVERITY_COLOR[a.severity] ?? 'var(--text-muted)',
                      border: `1px solid ${SEVERITY_COLOR[a.severity] ?? 'var(--border)'}`,
                      borderRadius: 3, padding: '1px 6px',
                    }}>{a.severity}</span>
                  </td>
                  <td style={{ padding: '7px 10px', maxWidth: 240, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.title}
                  </td>
                  <td style={{ padding: '7px 10px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {a.hostname || a.source_ip || '—'}
                  </td>
                  <td style={{ padding: '7px 10px', whiteSpace: 'nowrap' }}>
                    {a.sla_breached ? (
                      <span style={{ color: 'var(--accent-red)', fontWeight: 600 }}>Breached</span>
                    ) : a.sla_due_at ? (
                      <span style={{ color: 'var(--text-secondary)' }}>Due {format(new Date(a.sla_due_at), 'HH:mm')}</span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>—</span>
                    )}
                  </td>
                  <td style={{ padding: '7px 10px', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {a.assignee_id ? (usernameById.get(a.assignee_id) ?? 'Assigned') : 'Unassigned'}
                  </td>
                  <td style={{ padding: '7px 10px', maxWidth: 200, color: a.ai_verdict ? 'var(--text-secondary)' : 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.ai_verdict || 'Pending AI analysis'}
                  </td>
                  <td style={{ padding: '7px 10px', whiteSpace: 'nowrap' }}>
                    <button
                      onClick={() => navigate(`/alerts/${a.id}`)}
                      style={{
                        fontSize: 11, fontWeight: 600, padding: '4px 10px', borderRadius: 4,
                        border: '1px solid var(--accent-blue)', background: 'rgba(44,110,142,0.1)', color: 'var(--accent-blue)', cursor: 'pointer',
                      }}
                    >
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </GlassCard>
  )
}
