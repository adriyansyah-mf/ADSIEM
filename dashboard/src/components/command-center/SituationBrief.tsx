import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
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
  cached: boolean
}

// Matches the backend's _CACHE_TTL (situation_brief.py) — the brief only
// actually regenerates (and burns LLM tokens) once per this window, so
// "stale" here means "past the cache lifetime", not "React Query is old".
const CACHE_TTL_MS = 24 * 60 * 60_000

/** Command Center's AI Situation Brief (Ironwatch spec 4.1). Every AI
 * interaction rule applies: this never blocks manual triage — Priority Queue
 * and Operational Health render fully regardless of this panel's state. */
export function SituationBrief() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const queryKey = ['command-center', 'situation-brief']
  const { data, isLoading } = useQuery<BriefResponse>({
    queryKey,
    queryFn: () => api.get('/api/command-center/situation-brief').then(r => r.data),
    refetchInterval: 15 * 60_000,
  })
  const [isForcing, setIsForcing] = useState(false)

  const isStale = data?.generated_at != null && Date.now() - new Date(data.generated_at).getTime() > CACHE_TTL_MS

  // Regular refetches (mount, polling) hit the server-cached brief — cheap,
  // no LLM call. This button is the one deliberate way to bypass that cache
  // and pay for a fresh regeneration, e.g. after something big just happened.
  async function forceRefresh() {
    setIsForcing(true)
    try {
      const res = await api.get('/api/command-center/situation-brief', { params: { force: true } })
      queryClient.setQueryData(queryKey, res.data)
    } finally {
      setIsForcing(false)
    }
  }

  return (
    <GlassCard
      title={<span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Sparkles size={14} aria-hidden="true" /> AI Situation Brief</span>}
      actions={
        <button onClick={forceRefresh} disabled={isForcing} aria-label="Regenerate situation brief now (uses an AI call)" title="Regenerate now — bypasses the daily cache"
          style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: isForcing ? 'default' : 'pointer', display: 'flex' }}>
          <RefreshCw size={13} className={isForcing ? 'animate-spin' : undefined} />
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
          {data.generated_at && (
            <div style={{
              fontSize: 11, marginBottom: 6, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em',
              color: isStale ? 'var(--accent-yellow)' : 'var(--text-muted)',
            }}>
              {isStale ? 'Past due for refresh — ' : 'Generated '}
              {new Date(data.generated_at).toLocaleString()}
            </div>
          )}
          <p style={{ fontSize: 13.5, color: 'var(--text-primary)', lineHeight: 1.6, margin: 0 }}>{data.brief}</p>
          {data.cited_alert_ids.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
              {data.cited_alert_ids.map(id => (
                <button
                  key={id}
                  onClick={() => navigate(`/alerts/${id}`)}
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
