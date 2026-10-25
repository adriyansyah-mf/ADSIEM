import { useState } from 'react'
import { formatDistanceToNow } from 'date-fns'
import { RotateCcw } from 'lucide-react'
import StatusBadge from '@/components/StatusBadge'
import { QueryState } from '@/components/Workspace'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { useAgentEvidence, useRetryEvidence } from '@/hooks/useAgents'
import type { Agent, AgentEvidenceSummary, EvidenceDeadLetter } from '@/types'

// Upper end of the measured agent index cost (BenchmarkIndexMemory), for an estimate only.
const INDEX_BYTES_PER_EVENT = 65
const NOT_REPORTED: AgentEvidenceSummary ={ status: 'not_reported', reason: null, reported_at: null, stale: false }

// Reasons are short machine codes from the agent; say what they mean.
const REASONS: Readonly<Record<string, string>> = {
  capacity: 'local evidence storage is full',
  storage_failure: 'local evidence storage failed',
  journal_unavailable: 'the evidence journal could not open',
  source_failure: 'a log source failed',
  quarantined: 'records were rejected and quarantined',
  held: 'records are held for an operator',
  auth_blocked: 'the server rejected the agent token',
  pending_approval: 'the agent is waiting for approval',
  protocol_unsupported: 'the server does not accept durable evidence yet',
  repeated_rejections: 'the server rejects every record',
  unconfirmed_response: 'the server did not confirm receipt',
  network: 'the server is unreachable',
  backlog: 'events are waiting to be delivered',
}

function reasonText(reason: string | null | undefined): string | null {
  if (!reason) return null
  if (REASONS[reason]) return REASONS[reason]
  if (reason.startsWith('status_')) return `the server answered HTTP ${reason.slice(7)}`
  if (reason.startsWith('unexpected_status_')) return `unexpected server response HTTP ${reason.slice(18)}`
  return reason.replace(/_/g, ' ')
}

function ago(at: string | null | undefined): string {
  return at ? formatDistanceToNow(new Date(at), { addSuffix: true }) : 'never'
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let value = n / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++ }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`
}

/** Evidence delivery state for the agents table, next to connectivity. */
export function EvidenceBadge({ summary }: { readonly summary?: AgentEvidenceSummary }) {
  const s = summary ?? NOT_REPORTED
  const reason = reasonText(s.reason)
  return <div className="control-cluster" title={reason ?? undefined}>
    <StatusBadge status={s.status} />
    {s.stale && <StatusBadge status="stale" />}
  </div>
}

/** Expanded evidence delivery detail for one agent, with dead-letter retry. */
export function EvidenceHealthPanel({ agent, canManage }: { readonly agent: Agent; readonly canManage: boolean }) {
  const query = useAgentEvidence(agent.id)
  const [retrying, setRetrying] = useState<EvidenceDeadLetter | null>(null)
  if (query.isPending) return <QueryState kind="loading" title="Loading evidence delivery…" />
  if (query.isError) return <QueryState kind="error" title="Could not load evidence delivery" onRetry={() => { void query.refetch() }} />
  const e = query.data
  const h = e.health
  const losses = h ? Object.entries(h.known_loss).filter(([, n]) => n > 0) : []
  const sources = h ? Object.entries(h.sources).filter(([, s]) => s.state !== 'healthy') : []
  return <section className="space-y-3" aria-label="Evidence delivery" onClick={event => event.stopPropagation()}>
    <div className="control-cluster">
      <h3 className="text-xs font-medium text-muted-foreground">Evidence delivery</h3>
      <EvidenceBadge summary={e} />
      {e.status === 'not_reported'
        ? <span className="table-secondary">This agent does not report durable evidence delivery (legacy mode).</span>
        : <span className="table-secondary">
          {reasonText(e.reason) && <>{reasonText(e.reason)} · </>}reported {ago(e.reported_at)}
          {e.stale && ' · no recent heartbeat, last known state'}
        </span>}
    </div>
    {h && <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-4">
      <div><dt className="table-secondary">Waiting on the agent</dt><dd>{h.queued_events.toLocaleString()} events · {bytes(h.queued_bytes)}</dd></div>
      <div><dt className="table-secondary">Oldest waiting</dt><dd>{h.oldest_queued_at ? ago(h.oldest_queued_at) : '—'}</dd></div>
      <div><dt className="table-secondary">Last server receipt</dt><dd>{ago(h.last_receipt_at)}</dd></div>
      <div><dt className="table-secondary">Retries</dt><dd>{h.retries.toLocaleString()}</dd></div>
      <div><dt className="table-secondary">Lost</dt><dd>{losses.length ? losses.map(([r, n]) => `${n.toLocaleString()} ${reasonText(r) ?? r}`).join(' · ') : 'none recorded'}</dd></div>
      <div><dt className="table-secondary">Unknown gaps</dt><dd>{h.unknown_gaps.toLocaleString()}</dd></div>
      <div><dt className="table-secondary">Quarantined</dt><dd>{h.quarantined.toLocaleString()}</dd></div>
      <div><dt className="table-secondary">Held for an operator</dt><dd>{h.held.toLocaleString()}</dd></div>
      {!!h.indexed_events && <div><dt className="table-secondary">Agent memory index</dt>
        <dd title="Every retained event ID, delivered or not, until compaction; measured at 45-70 bytes each">
          {h.indexed_events.toLocaleString()} events · ≈{bytes(h.indexed_events * INDEX_BYTES_PER_EVENT)}</dd></div>}
    </dl>}
    {sources.length > 0 && <div>
      <h4 className="text-xs font-medium text-muted-foreground">Log sources needing attention</h4>
      <ul className="text-sm">{sources.map(([name, s]) =>
        <li key={name} className="control-cluster"><span className="font-mono break-all">{name}</span><StatusBadge status={s.state} /><span className="table-secondary">{reasonText(s.reason)}</span></li>)}
      </ul>
    </div>}
    <div>
      <h4 className="text-xs font-medium text-muted-foreground">Server inbox</h4>
      <p className="text-sm">{e.inbox.pending.toLocaleString()} processing · {e.inbox.dead_letter.toLocaleString()} failed
        {e.inbox.oldest_pending_at && <> · oldest received {ago(e.inbox.oldest_pending_at)}</>}</p>
      {e.inbox.dead_letters.length > 0 && <ul className="text-sm space-y-1">{e.inbox.dead_letters.map(d =>
        <li key={d.receipt_id} className="control-cluster">
          <span className="font-mono">{d.event_id.slice(0, 8)}</span>
          <span className="table-secondary">{d.failure_count} attempts · {d.last_error || 'no error recorded'} · received {ago(d.received_at)}</span>
          {canManage && <button className="ui-button ui-button--quiet" onClick={() => setRetrying(d)}><RotateCcw size={14} /> Retry</button>}
        </li>)}</ul>}
    </div>
    {retrying && <RetryDialog agent={agent} deadLetter={retrying} onClose={() => setRetrying(null)} />}
  </section>
}

function RetryDialog({ agent, deadLetter, onClose }: {
  readonly agent: Agent
  readonly deadLetter: EvidenceDeadLetter
  readonly onClose: () => void
}) {
  const mutation = useRetryEvidence(agent.id)
  return <WorkspaceDialog title="Retry failed evidence?" description={`${agent.hostname} · event ${deadLetter.event_id}`} busy={mutation.isPending} onClose={onClose}>
    <p>This processes the retained event again after {deadLetter.failure_count} failed attempts. Fix the cause first ({deadLetter.last_error || 'no error recorded'}).</p>
    <p>Detection rules, alerts and automated responses may run again for this event if an earlier attempt got that far. The stored event itself is not duplicated.</p>
    {mutation.isError && <p role="alert" className="text-destructive">Could not retry this event. Check your permissions and try again.</p>}
    <div className="control-cluster justify-end">
      <button className="ui-button" disabled={mutation.isPending} onClick={onClose}>Cancel</button>
      <button className="ui-button ui-button--primary" disabled={mutation.isPending}
        onClick={() => mutation.mutate(deadLetter.receipt_id, { onSuccess: onClose })}>
        {mutation.isPending ? 'Submitting…' : 'Retry event'}
      </button>
    </div>
  </WorkspaceDialog>
}
