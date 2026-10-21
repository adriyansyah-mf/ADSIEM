import { Link } from 'react-router-dom'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { QueryState } from '@/components/Workspace'
import StatusBadge from '@/components/StatusBadge'
import { UebaRisk, UebaRiskTrend } from '@/components/UebaRisk'
import { useUebaEntityDetail, useUebaRiskHistory } from '@/hooks/useUeba'
import type { UebaAnomaly } from '@/types'

export function UebaEntityDetails({ entityType, entityValue, onClose }: {
  readonly entityType: string; readonly entityValue: string; readonly onClose: () => void
}) {
  const query = useUebaEntityDetail(entityType, entityValue)
  const history = useUebaRiskHistory(entityType, entityValue)
  return <WorkspaceDialog title={`Entity · ${entityValue}`} description={`${entityType === 'ip' ? 'IP address' : 'User'} · Read-only behavior evidence`} onClose={onClose} wide>
    {query.isPending ? <QueryState kind="loading" title="Loading entity details…" />
      : query.isError ? <QueryState kind="error" title="Could not load entity details" description="The entity may be unavailable or outside your access scope." onRetry={() => { void query.refetch() }} />
        : <div className="space-y-6 min-w-0">
          <section aria-label="Entity risk summary" className="space-y-4"><UebaRisk score={query.data.score.risk_score} />
            <dl className="evidence-metadata">
              <div><dt>Recorded anomalies</dt><dd>{query.data.score.anomaly_count}</dd></div><div><dt>Group</dt><dd>{query.data.score.group_id}</dd></div>
              <div><dt>Last seen</dt><dd>{query.data.score.last_seen_at ?? 'Not recorded'}</dd></div><div><dt>Last anomaly</dt><dd>{query.data.score.last_anomaly_at ?? 'Not recorded'}</dd></div>
            </dl></section>
          <section aria-label="Risk history"><h3 className="text-sm font-semibold mb-3">30-day risk trend</h3>
            {history.isPending ? <QueryState kind="loading" title="Loading risk history…" />
              : history.isError ? <QueryState kind="error" title="Could not load risk history" onRetry={() => { void history.refetch() }} />
                : <UebaRiskTrend history={history.data.history} />}
          </section>
          <section aria-label="Anomaly evidence"><h3 className="text-sm font-semibold mb-3">Recent anomalies</h3>
            <p className="text-xs text-muted-foreground">Latest 50 records for this entity. Detail and history refresh every minute.</p>
            {query.data.anomalies.length === 0 ? <p className="text-muted-foreground">No anomalies recorded for this entity.</p>
              : <ol className="ueba-anomalies">{query.data.anomalies.map(anomaly => <li key={anomaly.id}><AnomalyEvidence anomaly={anomaly} /></li>)}</ol>}
          </section>
        </div>}
  </WorkspaceDialog>
}

function AnomalyEvidence({ anomaly }: { readonly anomaly: UebaAnomaly }) {
  const thresholds: Readonly<Record<string, number>> = { failed_ratio: 0.5, unique_ips: 3, unique_users: 5, sudo_count: 3, new_ip_seen: 0.5 }
  return <article className="space-y-4">
    <div className="control-cluster justify-between"><UebaRisk score={anomaly.risk_score} /><time className="text-xs text-muted-foreground" dateTime={anomaly.detected_at}>{anomaly.detected_at}</time></div>
    <p className="text-xs text-muted-foreground">Anomaly score: <span className="font-mono">{anomaly.anomaly_score.toFixed(3)}</span> · This model score is separate from the risk score.</p>
    {!!anomaly.reasons?.length && <section><h4 className="text-sm font-semibold mb-2">Why anomalous</h4><ul className="list-disc pl-5 space-y-2">{anomaly.reasons.map((reason, index) => <li key={`${reason.feature}-${index}`}>{reason.text}</li>)}</ul></section>}
    {!!anomaly.mitre_techniques?.length && <section><h4 className="text-sm font-semibold mb-2">MITRE techniques</h4><ul className="space-y-1">{anomaly.mitre_techniques.map(technique => <li key={technique.id}><span className="font-mono text-xs">{technique.id}</span> · {technique.name}</li>)}</ul></section>}
    <section className="ueba-assessment"><div className="control-cluster justify-between mb-3"><h4 className="text-sm font-semibold mb-0">AI assessment</h4>{anomaly.ai_action && <StatusBadge status={anomaly.ai_action} />}</div>
      {anomaly.ai_narrative ? <p className="whitespace-pre-wrap">{anomaly.ai_narrative}</p>
        : <p className="text-muted-foreground">{anomaly.alert_id ? 'AI triage pending…' : 'No alert was raised, so this anomaly was not sent to AI triage.'}</p>}
      {(anomaly.ai_action || anomaly.ai_narrative) && <p className="text-xs text-muted-foreground">AI-generated assessment · verify against the evidence before taking action.</p>}
      <div className="control-cluster">{anomaly.case_id && <Link className="ui-button" to={`/cases/${anomaly.case_id}`}>Open case</Link>}
        {anomaly.alert_id && <Link className="ui-button" to={`/alerts/${anomaly.alert_id}`}>Open alert</Link>}</div>
    </section>
    {!!Object.keys(anomaly.features).length && <details><summary className="ui-button w-fit">Feature values</summary>
      <p className="text-xs text-muted-foreground mt-3">Display thresholds flag notable values; they do not recalculate the model's risk score.</p>
      <div className="table-scroll mt-3"><table className="data-table"><thead><tr><th className="p-3">Feature</th><th className="p-3">Value</th><th className="p-3">Context</th></tr></thead>
        <tbody>{Object.entries(anomaly.features).map(([key, value]) => <tr key={key}><th scope="row" className="p-3 font-mono text-xs whitespace-normal break-all">{key}</th>
          <td className="p-3 font-mono text-xs">{value}</td><td className="p-3 text-xs">{thresholds[key] !== undefined && value >= thresholds[key] ? 'At or above display threshold' : '—'}</td></tr>)}</tbody>
      </table></div></details>}
  </article>
}
