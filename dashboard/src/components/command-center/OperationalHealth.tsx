import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api } from '@/api/client'
import { GlassCard } from '@/components/ui/GlassCard'

interface QueueMetrics {
  webhook_deliveries: { pending: number; failed: number; oldest_pending_age_seconds: number | null }
  ingestion_dlq: { depth: number; oldest_age_seconds: number | null }
  ingestion_dead_letter: { depth: number; oldest_age_seconds: number | null }
}
interface Health { status: string; postgres: string; redis: string }
interface WorkerMetrics { status: string; ai_queue_depth: number; ingestion_stream_length: number }

function Row({ label, ok, value, onClick }: { label: string; ok: boolean; value: string; onClick?: () => void }) {
  const content = (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 10px',
      borderRadius: 4, background: 'var(--bg-base)', border: `1px solid ${ok ? 'var(--border)' : 'var(--accent-red)'}`,
      cursor: onClick ? 'pointer' : 'default', width: '100%', textAlign: 'left',
    }}>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>{label}</span>
      <span style={{ fontSize: 12, fontWeight: 700, color: ok ? 'var(--accent-green)' : 'var(--accent-red)' }}>{value}</span>
    </div>
  )
  return onClick ? <button onClick={onClick} style={{ background: 'none', border: 'none', padding: 0, width: '100%' }}>{content}</button> : content
}

/** Command Center's Operational Health (Ironwatch spec 4.1): ingestion lag,
 * queue depth, delivery failures, fleet health — every degraded row links to
 * its diagnosis page rather than just naming the problem. */
export function OperationalHealth({ onlineAgents, totalAgents }: { onlineAgents: number; totalAgents: number }) {
  const navigate = useNavigate()
  const { data: health } = useQuery<Health>({ queryKey: ['system-health'], queryFn: () => api.get('/health').then(r => r.data), refetchInterval: 30_000 })
  const { data: worker } = useQuery<WorkerMetrics>({ queryKey: ['worker-metrics'], queryFn: () => api.get('/api/metrics/worker').then(r => r.data), refetchInterval: 30_000 })
  const { data: queues, isError: queuesForbidden } = useQuery<QueueMetrics>({
    queryKey: ['queues-metrics'],
    queryFn: () => api.get('/api/queues/metrics').then(r => r.data),
    refetchInterval: 30_000,
    retry: false,
  })

  const fleetOk = totalAgents === 0 || onlineAgents === totalAgents

  return (
    <GlassCard title="Operational Health">
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 8 }}>
        <Row label="API" ok={health?.status === 'ok'} value={health?.status ?? '—'} />
        <Row label="Postgres" ok={health?.postgres === 'ok'} value={health?.postgres ?? '—'} />
        <Row label="Redis" ok={health?.redis === 'ok'} value={health?.redis ?? '—'} />
        <Row label="Worker" ok={worker?.status === 'ok'} value={worker?.status ?? '—'} />
        <Row label="AI queue depth" ok={(worker?.ai_queue_depth ?? 0) < 100} value={String(worker?.ai_queue_depth ?? '—')} />
        <Row label="Ingestion stream" ok value={String(worker?.ingestion_stream_length ?? '—')} />
        <Row
          label="Fleet"
          ok={fleetOk}
          value={`${onlineAgents}/${totalAgents} online`}
          onClick={() => navigate('/agents')}
        />
        {!queuesForbidden && (
          <>
            <Row
              label="Webhook failures"
              ok={(queues?.webhook_deliveries.failed ?? 0) === 0}
              value={String(queues?.webhook_deliveries.failed ?? '—')}
              onClick={() => navigate('/webhooks')}
            />
            <Row
              label="Ingestion DLQ"
              ok={(queues?.ingestion_dlq.depth ?? 0) === 0}
              value={String(queues?.ingestion_dlq.depth ?? '—')}
            />
          </>
        )}
      </div>
    </GlassCard>
  )
}
