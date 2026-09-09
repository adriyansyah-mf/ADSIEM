import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { PageHeader } from '@/components/ui/PageHeader'
import { SituationBrief } from '@/components/command-center/SituationBrief'
import { AlertVolumeChart } from '@/components/command-center/AlertVolumeChart'
import { PriorityQueue } from '@/components/command-center/PriorityQueue'
import { OperationalHealth } from '@/components/command-center/OperationalHealth'
import { ExposureCoverage } from '@/components/command-center/ExposureCoverage'
import type { Alert, Agent } from '@/types'

interface WorkloadItem { user_id: string; username: string }

function KpiTile({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div style={{ borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-panel)', padding: '12px 14px' }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
        {label}
      </div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 28, fontWeight: 800, color: color ?? 'var(--text-primary)', marginTop: 4, fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </div>
    </div>
  )
}

/** Command Center — the Ironwatch landing surface (spec section 4.1). Answers
 * "what needs attention now" before any broad analytics: KPIs, an AI brief,
 * a manual-triage priority queue, operational health, and exposure/coverage.
 * Every section renders fully from real fetched data; nothing here is
 * fabricated trend data, per the spec's explicit non-goals. */
export default function CommandCenterPage() {
  const { data: alertsData } = useQuery({
    queryKey: ['command-center', 'alerts'],
    queryFn: () => api.get('/api/alerts', { params: { page_size: 200 } }).then(r => r.data),
    refetchInterval: 30_000,
  })
  const { data: agentsData } = useQuery({
    queryKey: ['command-center', 'agents'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 500 } }).then(r => r.data),
    refetchInterval: 30_000,
  })
  const { data: workload = [] } = useQuery<WorkloadItem[]>({
    queryKey: ['command-center', 'workload'],
    queryFn: () => api.get('/api/metrics/workload').then(r => r.data),
    refetchInterval: 60_000,
  })

  const alerts: Alert[] = alertsData?.items ?? []
  const agents: Agent[] = agentsData?.items ?? []
  const onlineAgents = agents.filter(a => a.status === 'online').length
  // Mirrors server-api's _RESOLVED_STATUSES (alerts.py) — see PriorityQueue.tsx.
  const DONE_STATUSES = new Set(['resolved', 'closed', 'false_positive'])
  const criticalCount = alerts.filter(a => a.severity === 'critical' && !DONE_STATUSES.has(a.status)).length
  const openCount = alerts.filter(a => !DONE_STATUSES.has(a.status)).length
  const slaBreachedCount = alerts.filter(a => a.sla_breached).length

  return (
    <div>
      <PageHeader title="Command Center" subtitle="What needs attention now, and why." />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 14 }}>
        <KpiTile label="Open Alerts" value={openCount} />
        <KpiTile label="Critical" value={criticalCount} color={criticalCount > 0 ? 'var(--accent-red)' : undefined} />
        <KpiTile label="SLA Breached" value={slaBreachedCount} color={slaBreachedCount > 0 ? 'var(--accent-orange)' : undefined} />
        <KpiTile label="Agents Online" value={`${onlineAgents}/${agents.length}`} color="var(--accent-blue)" />
      </div>

      <div className="cc-grid" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 340px', gap: 14, alignItems: 'start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
          <SituationBrief />
          <AlertVolumeChart alerts={alerts} />
          <PriorityQueue alerts={alerts} workload={workload} />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <OperationalHealth onlineAgents={onlineAgents} totalAgents={agents.length} />
          <ExposureCoverage />
        </div>
      </div>
    </div>
  )
}
