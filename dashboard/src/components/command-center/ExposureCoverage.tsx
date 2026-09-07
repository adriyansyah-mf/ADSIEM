import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api } from '@/api/client'
import { GlassCard } from '@/components/ui/GlassCard'

interface UebaEntity { entity_type: string; entity_value: string; risk_score: number; anomaly_count: number }
interface MitreTechnique { technique_id: string; technique_name: string; tactic: string; count: number }
interface MitreHeatmap { tactics: { tactic: string; techniques: MitreTechnique[] }[] }

/** Command Center's Exposure and Coverage (Ironwatch spec 4.1): high-risk
 * entities and MITRE technique coverage are real, fetched data. Active
 * campaigns/correlations and agent policy-drift have no backing data source
 * yet (the correlation-grouping and endpoint-agent-fleet-telemetry work is
 * unstarted per docs/AGENT_PRODUCTION_IMPROVEMENT_ROADMAP.md) — shown as an
 * explicit "not yet available" state rather than fabricated, per the
 * Ironwatch spec's own non-goals. */
export function ExposureCoverage() {
  const navigate = useNavigate()
  const { data: entities = [] } = useQuery<UebaEntity[]>({
    queryKey: ['ueba-top-entities'],
    queryFn: () => api.get('/api/ueba/entities', { params: { entity_type: 'all', min_risk: 0 } }).then(r => r.data),
    refetchInterval: 60_000,
  })
  const { data: mitre } = useQuery<MitreHeatmap>({
    queryKey: ['mitre-heatmap-summary'],
    queryFn: () => api.get('/api/mitre/heatmap', { params: { days: 30 } }).then(r => r.data),
    refetchInterval: 5 * 60_000,
  })

  const topEntities = [...entities].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5)
  const topTechniques = (mitre?.tactics ?? [])
    .flatMap(t => t.techniques)
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)

  return (
    <GlassCard title="Exposure & Coverage">
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
            High-risk entities
          </div>
          {topEntities.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No UEBA risk data yet.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {topEntities.map(e => (
                <button
                  key={`${e.entity_type}-${e.entity_value}`}
                  onClick={() => navigate('/ueba')}
                  style={{
                    display: 'flex', justifyContent: 'space-between', gap: 8, padding: '5px 8px', borderRadius: 4,
                    background: 'var(--bg-base)', border: '1px solid var(--border)', cursor: 'pointer', textAlign: 'left',
                  }}
                >
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {e.entity_value}
                  </span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: e.risk_score >= 80 ? 'var(--accent-red)' : e.risk_score >= 60 ? 'var(--accent-orange)' : 'var(--accent-yellow)', flexShrink: 0 }}>
                    {e.risk_score.toFixed(0)}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        <div>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
            Top MITRE techniques (30d)
          </div>
          {topTechniques.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No technique hits in the last 30 days.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {topTechniques.map(t => (
                <button
                  key={t.technique_id}
                  onClick={() => navigate('/mitre-heatmap')}
                  style={{
                    display: 'flex', justifyContent: 'space-between', gap: 8, padding: '5px 8px', borderRadius: 4,
                    background: 'var(--bg-base)', border: '1px solid var(--border)', cursor: 'pointer', textAlign: 'left',
                  }}
                >
                  <span style={{ fontSize: 11, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <span className="mono" style={{ color: 'var(--text-muted)' }}>{t.technique_id}</span> {t.technique_name}
                  </span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-blue)', flexShrink: 0 }}>{t.count}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--text-muted)' }}>
        Active campaign correlation and agent policy-drift coverage are not available yet — they depend on the endpoint-agent fleet telemetry roadmap, which has not started.
      </div>
    </GlassCard>
  )
}
