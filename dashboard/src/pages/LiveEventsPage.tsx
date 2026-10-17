import { useState } from 'react'
import { Database, Activity, ShieldAlert, Network } from 'lucide-react'
import LiveEventsTable from '@/components/LiveEventsTable'
import { EventVolumeChart, StackedTypeBars, HorizontalBars, AuthFailuresChart } from '@/components/ElasticCharts'
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
]

function Card({ title, icon, children }: { title: string; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
        {icon && <span style={{ color: 'var(--accent-cyan)', display: 'flex' }}>{icon}</span>}
        <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.6px', textTransform: 'uppercase', color: 'var(--text-secondary)', fontFamily: 'Rajdhani, sans-serif' }}>
          {title}
        </span>
      </div>
      {children}
    </div>
  )
}

export default function LiveEventsPage() {
  const [hourIdx, setHourIdx] = useState(2)
  const range = HOUR_OPTIONS[hourIdx]

  const { data: stats } = useElasticStats()
  const { data: volume } = useElasticVolume(range.value, range.interval)
  const { data: topIps } = useElasticTop('source_ip', range.value, 10)
  const { data: topTypes } = useElasticTop('log_type', range.value, 8)
  const { data: signals } = useSecuritySignals(range.value, range.value <= 24 ? '1h' : '1d')
  const { data: agentsVol } = useAgentsVolume(range.value, 8)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%', minHeight: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', gap: 4 }}>
          {HOUR_OPTIONS.map((o, i) => (
            <button
              key={o.label}
              onClick={() => setHourIdx(i)}
              style={{
                padding: '4px 10px', fontSize: 11, borderRadius: 3, cursor: 'pointer',
                fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, letterSpacing: '0.5px',
                border: '1px solid var(--border)',
                background: i === hourIdx ? 'rgba(0,212,255,0.12)' : 'transparent',
                color: i === hourIdx ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              }}
            >
              {o.label}
            </button>
          ))}
        </div>

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 16, fontSize: 11, fontFamily: 'Share Tech Mono, monospace' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: 'var(--text-secondary)' }}>
            <Database size={12} color="var(--accent-cyan)" />
            {(stats?.docs ?? 0).toLocaleString()} docs
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: 'var(--text-secondary)' }}>
            <Activity size={12} color="var(--accent-green)" />
            {(volume?.total ?? 0).toLocaleString()} events / {range.label}
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: 'var(--text-secondary)' }}>
            <Network size={12} color="var(--accent-orange)" />
            {signals?.unique_source_ips ?? 0} unique IPs
          </span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
        <Card title="Event Volume" icon={<Activity size={12} />}>
          <EventVolumeChart points={volume?.points ?? []} height={180} />
        </Card>
        <Card title="Volume by Log Source" icon={<Database size={12} />}>
          <StackedTypeBars points={volume?.points ?? []} height={180} />
        </Card>
        <Card title="Authentication Failures" icon={<ShieldAlert size={12} />}>
          <AuthFailuresChart points={signals?.auth_failures ?? []} height={180} />
        </Card>
        <Card title="Top Source IPs" icon={<Network size={12} />}>
          <HorizontalBars values={topIps?.values ?? []} height={180} />
        </Card>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
        <Card title="Log Sources">
          <HorizontalBars values={topTypes?.values ?? []} height={160} color="var(--accent-green)" />
        </Card>
        <Card title="Event Actions">
          <HorizontalBars
            values={(signals?.action_mix ?? []).map(a => ({ value: a.action ?? 'unknown', count: a.count }))}
            height={160}
            color="var(--accent-orange)"
          />
        </Card>
        <Card title="Events per Agent">
          <HorizontalBars
            values={(agentsVol?.agents ?? []).map(a => ({
              value: a.agent_id ? a.agent_id.slice(0, 8) : 'unknown',
              count: a.count,
            }))}
            height={160}
            color="var(--accent-cyan)"
          />
        </Card>
      </div>

      <div style={{ flex: 1, minHeight: 320, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: 12, overflow: 'auto' }}>
        <LiveEventsTable />
      </div>
    </div>
  )
}
