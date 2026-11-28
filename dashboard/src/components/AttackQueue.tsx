import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, ChevronRight, Network } from 'lucide-react'
import { format } from 'date-fns'
import { api } from '@/api/client'
import { QueryState } from '@/components/Workspace'
import { useCreateCase } from '@/hooks/useCases'
import { emitToast } from '@/hooks/useToast'
import { useAuthStore } from '@/stores/auth'
import { groupAttacks, primaryAlert, type Attack } from '@/lib/attackGroups'
import type { Alert, PaginatedResponse } from '@/types'

// Grouping needs the whole window, not one page of the queue.
const ATTACK_PAGE = 300
const LANE_COLOR: Readonly<Record<Alert['severity'], string>> = {
  critical: '#FF5D6C', high: '#FF9F43', medium: '#D9B53C', low: '#4F6FB8', info: '#5A6478',
}
const label = (value: string) => value.replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase())

function ownerLabel(attack: Attack, userId: string | undefined) {
  if (attack.owners.length > 1) return 'Several owners'
  const owner = attack.owners[0]
  return owner == null ? 'Unassigned' : owner === userId ? 'You' : 'Assigned'
}

function AttackCard({ attack, open, onToggle, canTriage }: {
  readonly attack: Attack; readonly open: boolean; readonly onToggle: () => void; readonly canTriage: boolean
}) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const user = useAuthStore(state => state.user)
  const createCase = useCreateCase()
  const assign = useMutation({
    mutationFn: async () => {
      const todo = attack.members.filter(m => m.alert.assignee_id !== user?.id)
      await Promise.all(todo.map(m => api.put(`/api/alerts/${m.alert.id}`, { assignee_id: user?.id })))
      return todo.length
    },
    onSuccess: count => { void queryClient.invalidateQueries({ queryKey: ['alerts'] }); emitToast(`Assigned ${count} alerts to you`, 'success') },
    onError: () => { void queryClient.invalidateQueries({ queryKey: ['alerts'] }); emitToast('Some alerts could not be assigned', 'error') },
  })
  const owner = ownerLabel(attack, user?.id)
  const openAsCase = () => {
    const lead = primaryAlert(attack)
    createCase.mutate({
      title: attack.title, severity: lead.severity === 'info' ? 'low' : lead.severity, alert_id: lead.id,
      alert_ids: attack.members.map(m => m.alert.id).filter(id => id !== lead.id),
      description: `Opened from grouped attack ${attack.id}: ${attack.members.length} alerts on ${attack.hosts.join(', ') || 'unknown hosts'} between ${format(attack.start, 'dd MMM HH:mm')} and ${format(attack.end, 'HH:mm')}.`,
    }, { onSuccess: created => navigate(`/cases/${created.id}`) })
  }

  return (
    <article className={`atk ${open ? 'atk--open' : ''}`}>
      <div className="atk__head">
        <button type="button" className="atk__toggle" aria-expanded={open} aria-label={open ? 'Collapse attack' : 'Expand attack'} onClick={onToggle}>
          {open ? <ChevronDown size={14} aria-hidden="true" /> : <ChevronRight size={14} aria-hidden="true" />}
        </button>
        <div className="atk__main">
          <div className="atk__meta">
            <span className={`severity-chip severity-chip--${attack.top}`}>{attack.top}</span>
            <span className="aq-mono">{attack.id} · {format(attack.start, 'HH:mm')} to {format(attack.end, 'HH:mm')}</span>
          </div>
          <h2>{attack.title}</h2>
          {attack.tactics.length > 0 && (
            <ol className="atk__tactics" aria-label="ATT&CK tactics in order">
              {attack.tactics.map((tactic, i) => <li key={tactic}>{i > 0 && <span aria-hidden="true">›</span>}<span className="atk__tactic">{label(tactic)}</span></li>)}
            </ol>
          )}
        </div>
        <dl className="atk__stats">
          <div><dt>Alerts</dt><dd>{attack.members.length}</dd></div>
          <div><dt>Hosts</dt><dd>{attack.hosts.length}</dd></div>
          <div><dt>Users</dt><dd>{attack.users.length}</dd></div>
          <div><dt>Owner</dt><dd className={owner === 'Unassigned' ? 'atk__unowned' : 'atk__owner'}>{owner}</dd></div>
        </dl>
        {canTriage && (
          <div className="atk__actions">
            <button type="button" className="aq-btn aq-btn--primary" onClick={openAsCase} disabled={createCase.isPending}>
              {createCase.isPending ? 'Opening…' : 'Open as case'}
            </button>
            <button type="button" className="aq-btn" onClick={() => assign.mutate()} disabled={assign.isPending || owner === 'You'}>
              {assign.isPending ? 'Assigning…' : 'Assign to me'}
            </button>
          </div>
        )}
      </div>
      {open && (
        <div className="atk__table">
          <table>
            <thead><tr><th>Severity</th><th>Alert</th><th>Host</th><th>Linked by</th><th>Time</th><th>Status</th></tr></thead>
            <tbody>
              {attack.members.map(({ alert, link }) => (
                <tr key={alert.id}>
                  <td><span className={`severity-chip severity-chip--${alert.severity}`}>{alert.severity}</span></td>
                  <td><Link to={`/alerts?alert=${alert.id}`}>{alert.title}</Link></td>
                  <td className="aq-mono">{alert.hostname ?? alert.source_ip ?? '—'}</td>
                  <td className="aq-muted">{link}</td>
                  <td className="aq-mono aq-muted">{format(new Date(alert.created_at), 'HH:mm')}</td>
                  <td>{label(alert.status)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </article>
  )
}

function Timeline({ attacks }: { readonly attacks: readonly Attack[] }) {
  const lanes = attacks.slice(0, 8)
  const from = Math.min(...lanes.map(a => a.start))
  const to = Date.now()
  const span = Math.max(1, to - from)
  const ticks = [0, 0.25, 0.5, 0.75].map(f => format(from + f * span, span > 86_400_000 ? 'dd MMM HH:mm' : 'HH:mm'))
  return (
    <div className="atk-timeline" role="img" aria-label={`When each of ${lanes.length} attacks was active`}>
      {lanes.map(attack => (
        <div key={attack.id} className="atk-timeline__lane">
          <span className="atk-timeline__name" title={attack.title}>{attack.id} {attack.hosts[0] ?? ''}</span>
          <div className="atk-timeline__track">
            <div className="atk-timeline__bar" style={{
              left: `${((attack.start - from) / span) * 100}%`,
              width: `${Math.max(0.8, ((attack.end - attack.start) / span) * 100)}%`,
              background: LANE_COLOR[attack.top],
            }} />
          </div>
        </div>
      ))}
      <div className="atk-timeline__axis">{ticks.map(t => <span key={t}>{t}</span>)}<span>now</span></div>
    </div>
  )
}

export default function AttackQueue({ params, canTriage, onShowUngrouped }: {
  readonly params: Record<string, unknown>; readonly canTriage: boolean; readonly onShowUngrouped: () => void
}) {
  const [showTimeline, setShowTimeline] = useState(true)
  const [openIds, setOpenIds] = useState<ReadonlySet<string> | null>(null)
  const query = useQuery<PaginatedResponse<Alert>>({
    queryKey: ['alerts', 'attacks', params],
    queryFn: () => api.get('/api/alerts', { params: { page: 1, page_size: ATTACK_PAGE, sort: 'priority', ...params } }).then(r => r.data),
    refetchInterval: 30_000,
  })
  const { attacks, ungrouped } = useMemo(() => groupAttacks(query.data?.items ?? []), [query.data])
  const open = openIds ?? new Set(attacks.slice(0, 1).map(a => a.id))
  const toggle = (id: string) => {
    const next = new Set(open)
    if (next.has(id)) next.delete(id); else next.add(id)
    setOpenIds(next)
  }

  if (query.isError) return <QueryState kind="error" title="Could not load alerts" onRetry={() => { void query.refetch() }} />
  if (query.isPending) return <QueryState kind="loading" title="Grouping alerts…" />
  const total = query.data.total
  return (
    <div className="atk-queue">
      <div className="atk-note">
        <Network size={16} aria-hidden="true" />
        <p>Alerts are grouped when they share a host, user, file hash or IP within 6 hours. Grouping only changes this view; each alert keeps its own status.</p>
        {attacks.length > 0 && <label><input type="checkbox" checked={showTimeline} onChange={e => setShowTimeline(e.target.checked)} /> Show timeline</label>}
      </div>
      {total > ATTACK_PAGE && <p className="aq-muted">Grouping the {ATTACK_PAGE} highest-priority of {total.toLocaleString()} alerts. Narrow the time window to group the rest.</p>}
      {attacks.length === 0
        ? <QueryState kind="empty" title="No attacks in this view" description="No two alerts here share a host, user, hash or IP within 6 hours." />
        : <>
          {showTimeline && <Timeline attacks={attacks} />}
          {attacks.map(attack => <AttackCard key={attack.id} attack={attack} open={open.has(attack.id)} onToggle={() => toggle(attack.id)} canTriage={canTriage} />)}
        </>}
      {ungrouped.length > 0 && (
        <button type="button" className="atk-ungrouped" onClick={onShowUngrouped}>
          <span>Ungrouped alerts: no shared entity with any other alert</span><span className="aq-accent">{ungrouped.length} alerts</span>
        </button>
      )}
    </div>
  )
}
