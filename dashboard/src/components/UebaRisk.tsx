import SeverityBadge from '@/components/SeverityBadge'
import type { UebaRiskHistory } from '@/hooks/useUeba'

export function UebaRisk({ score }: { readonly score: number }) {
  const level = score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low'
  return <div className="control-cluster flex-nowrap"><span className="font-mono tabular-nums whitespace-nowrap">{score.toFixed(1)}<span className="text-xs text-muted-foreground"> / 100</span></span><SeverityBadge severity={level} /></div>
}

export function UebaRiskTrend({ history }: { readonly history: UebaRiskHistory['history'] }) {
  if (!history.length) return <p className="text-sm text-muted-foreground">No risk history recorded in the last 30 days.</p>
  const width = 640, height = 160, pad = 28
  const days = history.map(point => Date.parse(`${point.day}T00:00:00Z`))
  const first = Math.min(...days), last = Math.max(...days)
  const x = (index: number) => first === last ? width / 2 : pad + ((days[index] - first) / (last - first)) * (width - pad * 2)
  const y = (risk: number) => height - pad - Math.max(0, Math.min(100, risk)) / 100 * (height - pad * 2)
  return <div className="space-y-3">
    <div className="ueba-chart-frame">
    <div className="ueba-chart-scale" aria-hidden="true"><span>100</span><span>50</span><span>0</span></div>
    <svg className="ueba-risk-chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="Daily maximum risk over the last 30 days">
      {[0, 50, 100].map(value => <line key={value} x1={pad} x2={width - pad} y1={y(value)} y2={y(value)} stroke="var(--border-default)" />)}
      <polyline points={history.map((point, index) => `${x(index)},${y(point.max_risk)}`).join(' ')} fill="none" stroke="var(--accent-cyan)" strokeWidth={2} strokeLinejoin="round" />
      {history.map((point, index) => <circle key={point.day} cx={x(index)} cy={y(point.max_risk)} r={3} fill="var(--accent-cyan)"><title>{point.day}: risk {point.max_risk}, {point.anomaly_count} anomalies</title></circle>)}
    </svg>
    </div>
    <div className="flex justify-between text-xs text-muted-foreground"><span>{history[0].day}</span><span>{history[history.length - 1].day}</span></div>
    <p className="text-xs text-muted-foreground">Daily peaks on recorded days. Missing days are not treated as zero risk.</p>
    <details><summary className="ui-button w-fit">Daily risk values</summary><div className="table-scroll mt-3"><table className="data-table">
      <thead><tr><th className="p-3">Day</th><th className="p-3">Maximum risk</th><th className="p-3">Anomalies</th></tr></thead>
      <tbody>{history.map(point => <tr key={point.day}><td className="p-3"><time dateTime={point.day}>{point.day}</time></td><td className="p-3 tabular-nums">{point.max_risk}</td><td className="p-3 tabular-nums">{point.anomaly_count}</td></tr>)}</tbody>
    </table></div></details>
  </div>
}
