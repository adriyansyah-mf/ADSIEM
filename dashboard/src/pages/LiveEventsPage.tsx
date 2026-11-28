import { useState } from 'react'
import LiveEventsTable from '@/components/LiveEventsTable'
import { EventVolumeChart, StackedTypeBars, HorizontalBars, AuthFailuresChart } from '@/components/ElasticCharts'
import { CanvasHeader, CanvasPage, KpiStrip, Seg } from '@/components/canvas/Canvas'
import {
  useElasticStats,
  useElasticVolume,
  useElasticTop,
  useSecuritySignals,
  useAgentsVolume,
} from '@/hooks/useElastic'

const HOUR_OPTIONS = [
  { label: '1h', value: 1, interval: '1m' },
  { label: '6h', value: 6, interval: '5m' },
  { label: '24h', value: 24, interval: '15m' },
  { label: '7d', value: 168, interval: '1h' },
] as const
type RangeLabel = (typeof HOUR_OPTIONS)[number]['label']

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="cv-card" aria-label={title}>
      <h2>{title}</h2>
      {children}
    </section>
  )
}

export default function LiveEventsPage() {
  const [rangeLabel, setRangeLabel] = useState<RangeLabel>('24h')
  const range = HOUR_OPTIONS.find(o => o.label === rangeLabel) ?? HOUR_OPTIONS[2]

  const { data: stats } = useElasticStats()
  const { data: volume } = useElasticVolume(range.value, range.interval)
  const { data: topIps } = useElasticTop('source_ip', range.value, 10)
  const { data: topTypes } = useElasticTop('log_type', range.value, 8)
  const { data: signals } = useSecuritySignals(range.value, range.value <= 24 ? '1h' : '1d')
  const { data: agentsVol } = useAgentsVolume(range.value, 8)

  return (
    <CanvasPage>
      <CanvasHeader title="Live events" sub="Telemetry as it arrives: volume, sources, authentication failures and the newest events."
        actions={<Seg label="Time range" value={rangeLabel} onChange={setRangeLabel} options={HOUR_OPTIONS.map(o => ({ value: o.label, label: o.label }))} />} />
      <div className="cv-body cv-body--wide">
        <KpiStrip items={[
          { label: 'Stored documents', value: (stats?.docs ?? 0).toLocaleString() },
          { label: `Events, last ${range.label}`, value: (volume?.total ?? 0).toLocaleString() },
          { label: 'Unique source IPs', value: (signals?.unique_source_ips ?? 0).toLocaleString() },
        ]} />

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
          <Card title="Event volume"><EventVolumeChart points={volume?.points ?? []} height={180} /></Card>
          <Card title="Volume by log source"><StackedTypeBars points={volume?.points ?? []} height={180} /></Card>
          <Card title="Authentication failures"><AuthFailuresChart points={signals?.auth_failures ?? []} height={180} /></Card>
          <Card title="Top source IPs"><HorizontalBars values={topIps?.values ?? []} height={180} /></Card>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
          <Card title="Log sources">
            <HorizontalBars values={topTypes?.values ?? []} height={160} color="var(--accent-green)" />
          </Card>
          <Card title="Event actions">
            <HorizontalBars
              values={(signals?.action_mix ?? []).map(a => ({ value: a.action ?? 'unknown', count: a.count }))}
              height={160}
              color="var(--accent-orange)"
            />
          </Card>
          <Card title="Events per agent">
            <HorizontalBars
              values={(agentsVol?.agents ?? []).map(a => ({ value: a.agent_id ? a.agent_id.slice(0, 8) : 'unknown', count: a.count }))}
              height={160}
              color="var(--accent-cyan)"
            />
          </Card>
        </div>

        <section className="cv-card" aria-label="Newest events" style={{ minHeight: 320, overflow: 'auto' }}>
          <h2>Newest events</h2>
          <LiveEventsTable />
        </section>
      </div>
    </CanvasPage>
  )
}
