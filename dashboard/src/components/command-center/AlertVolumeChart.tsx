import { useMemo } from 'react'
import { GlassCard } from '@/components/ui/GlassCard'
import { StackedBarChart, type StackedBarDatum } from '@/components/charts/StackedBarChart'
import type { Alert } from '@/types'

const SEVERITY_SERIES = [
  { key: 'critical', color: 'var(--accent-red)' },
  { key: 'high', color: 'var(--accent-orange)' },
  { key: 'medium', color: 'var(--accent-yellow)' },
  { key: 'low', color: 'var(--accent-green)' },
  { key: 'info', color: 'var(--accent-blue)' },
]

function hourLabel(d: Date): string {
  return `${String(d.getHours()).padStart(2, '0')}:00`
}

/** Alert Volume — buckets the alerts Command Center already fetched (real
 * `created_at` timestamps, no synthetic trend data) into 24 hourly slots by
 * severity, so the queue/health panels get a quick "is this an unusual hour"
 * visual without a new backend endpoint. */
export function AlertVolumeChart({ alerts }: { alerts: Alert[] }) {
  const { data, totalLast24h } = useMemo(() => {
    const now = new Date()
    const buckets: StackedBarDatum[] = []
    const hourStarts: number[] = []
    for (let i = 23; i >= 0; i--) {
      const h = new Date(now.getTime() - i * 3600_000)
      h.setMinutes(0, 0, 0)
      hourStarts.push(h.getTime())
      buckets.push({ label: hourLabel(h), values: {} })
    }
    let total = 0
    for (const a of alerts) {
      const t = new Date(a.created_at).getTime()
      const idx = hourStarts.findIndex((start, i) => t >= start && t < (hourStarts[i + 1] ?? Infinity))
      if (idx === -1) continue
      buckets[idx].values[a.severity] = (buckets[idx].values[a.severity] ?? 0) + 1
      total++
    }
    return { data: buckets, totalLast24h: total }
  }, [alerts])

  return (
    <GlassCard
      title="Alert Volume — Last 24h"
      actions={<span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{totalLast24h} alerts</span>}
    >
      <StackedBarChart
        data={data}
        series={SEVERITY_SERIES}
        height={160}
        xLabelEvery={4}
        ariaLabel={`Alert volume by severity over the last 24 hours, ${totalLast24h} total alerts`}
      />
      <div style={{ display: 'flex', gap: 14, marginTop: 8, flexWrap: 'wrap' }}>
        {SEVERITY_SERIES.map(s => (
          <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: s.color, display: 'inline-block' }} />
            <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'capitalize' }}>{s.key}</span>
          </div>
        ))}
      </div>
    </GlassCard>
  )
}
