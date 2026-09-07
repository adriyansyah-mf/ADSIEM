import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Sparkles, RefreshCw } from 'lucide-react'
import { api } from '@/api/client'
import { GlassCard } from '@/components/ui/GlassCard'

interface BriefResponse {
  status: 'ok' | 'unavailable' | 'error'
  reason?: string
  brief: string | null
  cited_alert_ids: string[]
  generated_at: string | null
}

const STALE_MS = 5 * 60_000

/** Command Center's AI Situation Brief (Ironwatch spec 4.1). Every AI
 * interaction rule applies: this never blocks manual triage — Priority Queue
 * and Operational Health render fully regardless of this panel's state. */
export function SituationBrief() {
  const navigate = useNavigate()
  const { data, isLoading, isFetching, dataUpdatedAt, refetch } = useQuery<BriefResponse>({
    queryKey: ['command-center', 'situation-brief'],
    queryFn: () => api.get('/api/command-center/situation-brief').then(r => r.data),
    refetchInterval: 5 * 60_000,
  })

  const isStale = !isFetching && dataUpdatedAt > 0 && Date.now() - dataUpdatedAt > STALE_MS

  return (
    <GlassCard
      title={<span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Sparkles size={14} aria-hidden="true" /> AI Situation Brief</span>}
      actions={
        <button onClick={() => refetch()} aria-label="Refresh situation brief" title="Refresh"
          style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex' }}>
          <RefreshCw size={13} className={isFetching ? 'animate-spin' : undefined} />
        </button>
      }
    >
      {isLoading && (
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Reviewing the last 24 hours…</div>
      )}

      {!isLoading && data?.status === 'unavailable' && (
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          AI brief isn't configured yet — an admin needs to set the 9router API key in Settings. Priority Queue below is unaffected.
        </div>
      )}

      {!isLoading && data?.status === 'error' && (
        <div style={{ fontSize: 13, color: 'var(--accent-orange)' }}>
          AI brief is temporarily unavailable — try refreshing in a moment. Manual triage below is unaffected.
        </div>
      )}

      {!isLoading && data?.status === 'ok' && (
        <div>
          {isStale && (
            <div style={{ fontSize: 11, color: 'var(--accent-yellow)', marginBottom: 6, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Stale — generated {new Date(data.generated_at!).toLocaleTimeString()}
            </div>
          )}
          <p style={{ fontSize: 13.5, color: 'var(--text-primary)', lineHeight: 1.6, margin: 0 }}>{data.brief}</p>
          {data.cited_alert_ids.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
              {data.cited_alert_ids.map(id => (
                <button
                  key={id}
                  onClick={() => navigate(`/alerts?open=${id}`)}
                  style={{
                    fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 7px', borderRadius: 3,
                    border: '1px solid var(--border)', background: 'var(--bg-base)', color: 'var(--accent-blue)', cursor: 'pointer',
                  }}
                >
                  {id.slice(0, 8)}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </GlassCard>
  )
}
