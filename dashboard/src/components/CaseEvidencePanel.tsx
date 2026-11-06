import { Link } from 'react-router-dom'
import { Panel } from '@/components/Workspace'
import { useCaseEvidence, useCaseMembership } from '@/hooks/useCaseEvidence'
import { useAuthStore } from '@/stores/auth'

export function CaseEvidencePanel({ caseId, status }: { caseId: string; status: string }) {
  const evidence = useCaseEvidence(caseId)
  const membership = useCaseMembership(caseId)
  const canManage = useAuthStore(state => state.hasRole('analyst'))
  const linked = evidence.data?.alerts.filter(a => a.status === 'linked') ?? []
  const indicators = [...new Set(linked.flatMap(a => a.indicators))]
  return <Panel title={`Linked evidence (${linked.length} alerts · ${indicators.length} indicators)`}>
    {evidence.isPending && <p>Loading evidence…</p>}
    {evidence.isError && <p role="alert">Could not load case evidence. <button onClick={() => void evidence.refetch()}>Retry</button></p>}
    {membership.isError && <p role="alert">Could not update association. The case may no longer be open.</p>}
    {evidence.data?.alerts.length === 0 && <p>No linked alert evidence yet.</p>}
    {evidence.data?.alerts.map(alert => <article key={alert.id} className="border-b py-3">
      <div><Link to={`/alerts/${alert.id}`}>{alert.title}</Link> · <strong>{alert.status}</strong></div>
      <div className="text-sm">{alert.hostname ?? 'Unknown host'} · {new Date(alert.created_at).toLocaleString()}</div>
      <p className="text-sm">{alert.reason} {alert.confidence !== null && `(${Math.round(alert.confidence * 100)}% · ${alert.method})`}</p>
      <div className="font-mono text-xs break-all">{alert.indicators.join(' · ') || 'No extracted indicators'}</div>
      {alert.accounts.length > 0 && <div className="text-sm">Accounts: {alert.accounts.join(', ')}</div>}
      {canManage && status === 'open' && <div className="flex gap-2 mt-2">
        {alert.status !== 'linked' && <button className="ui-button" disabled={membership.isPending}
          onClick={() => membership.mutate({ alertId: alert.id, status: 'linked' })}>Accept association</button>}
        {alert.status !== 'detached' && <button className="ui-button" disabled={membership.isPending}
          onClick={() => membership.mutate({ alertId: alert.id, status: 'detached' })}>
          {alert.status === 'suggested' ? 'Reject suggestion' : 'Remove association'}</button>}
      </div>}
    </article>)}
  </Panel>
}
