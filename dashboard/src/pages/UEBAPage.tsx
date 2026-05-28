import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useUebaEntities, useUebaEntityDetail, useUebaStatus, useUebaRiskHistory, useTriggerInvestigation } from '@/hooks/useUeba'
import type { UebaEntityScore, UebaAnomaly, UebaRiskPoint } from '@/types'

function riskColor(score: number) {
  if (score >= 80) return 'var(--accent-red)'
  if (score >= 60) return '#ff6b35'
  if (score >= 40) return 'var(--accent-yellow)'
  return 'var(--accent-green)'
}

function RiskBar({ score }: { score: number }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <div style={{ flex: 1, height: '4px', background: 'var(--bg-base)', borderRadius: '2px', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${score}%`, background: riskColor(score), borderRadius: '2px', transition: 'width 0.3s' }} />
      </div>
      <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: riskColor(score), minWidth: '28px', textAlign: 'right' }}>
        {score.toFixed(0)}
      </span>
    </div>
  )
}

function RiskSparkline({ data }: { data: UebaRiskPoint[] }) {
  if (data.length < 2) {
    return (
      <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace' }}>
        Not enough data for trend
      </div>
    )
  }
  const W = 280, H = 40
  const scores = data.map(d => d.risk_score)
  const min = Math.min(...scores)
  const max = Math.max(...scores) || 1
  const pts = data.map((d, i) => {
    const x = (i / (data.length - 1)) * W
    const y = H - ((d.risk_score - min) / (max - min || 1)) * H
    return `${x},${y}`
  }).join(' ')
  const lastScore = scores[scores.length - 1]
  const color = lastScore >= 80 ? '#ef4444' : lastScore >= 60 ? '#ff6b35' : lastScore >= 40 ? '#ffd600' : '#00ff88'
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
        <span style={{ fontFamily: 'Rajdhani, sans-serif', fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '1px' }}>7-DAY RISK TREND</span>
        <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color }}>{lastScore.toFixed(0)}/100</span>
      </div>
      <svg width={W} height={H} style={{ width: '100%' }}>
        <polyline points={pts} fill="none" stroke={color} strokeWidth={2} />
      </svg>
    </div>
  )
}

function EntityRow({ entity, selected, onClick }: { entity: UebaEntityScore; selected: boolean; onClick: () => void }) {
  const lastAnomaly = entity.last_anomaly_at ? new Date(entity.last_anomaly_at) : null
  const minsAgo = lastAnomaly ? Math.floor((Date.now() - lastAnomaly.getTime()) / 60000) : null
  return (
    <div
      onClick={onClick}
      style={{
        display: 'grid', gridTemplateColumns: '1fr auto',
        alignItems: 'center', gap: '10px',
        padding: '8px 12px',
        background: selected ? 'rgba(0,212,255,0.08)' : 'transparent',
        borderLeft: `2px solid ${selected ? 'var(--accent-cyan)' : riskColor(entity.risk_score) + (entity.risk_score >= 60 ? '88' : '33')}`,
        cursor: 'pointer',
        transition: 'background 0.15s',
      }}
    >
      <div>
        <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--text-primary)' }}>
          {entity.entity_value}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
          {entity.anomaly_count > 0 && (
            <span style={{ fontFamily: 'Rajdhani, sans-serif', fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '0.5px' }}>
              {entity.anomaly_count} anomal{entity.anomaly_count === 1 ? 'y' : 'ies'}
            </span>
          )}
          {minsAgo !== null && (
            <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: minsAgo < 60 ? 'var(--accent-yellow)' : 'var(--text-muted)' }}>
              {minsAgo < 60 ? `${minsAgo}m ago` : lastAnomaly!.toLocaleDateString()}
            </span>
          )}
        </div>
      </div>
      <div style={{ width: '80px' }}>
        <RiskBar score={entity.risk_score} />
      </div>
    </div>
  )
}

function FeatureTable({ features }: { features: Record<string, number> }) {
  const WARN_THRESHOLDS: Record<string, number> = {
    failed_ratio: 0.5,
    unique_ips: 3,
    unique_users: 5,
    sudo_count: 3,
    new_ip_seen: 0.5,
    // enrichment scores — same thresholds as MITRE mapper
    max_ps_score: 0.35,
    max_cmd_score: 0.40,
    max_ioc_ti_score: 0.50,
    ti_reputation: 0.50,
  }
  const CRIT_THRESHOLDS: Record<string, number> = {
    max_ps_score: 0.85,
    max_ioc_ti_score: 0.78,
    max_cmd_score: 0.70,
    ti_reputation: 0.80,
    failed_ratio: 0.8,
  }
  return (
    <table style={{ width: '100%', fontSize: '11px', borderCollapse: 'collapse' }}>
      <tbody>
        {Object.entries(features).map(([k, v]) => {
          const crit = CRIT_THRESHOLDS[k] !== undefined && v >= CRIT_THRESHOLDS[k]
          const warn = !crit && WARN_THRESHOLDS[k] !== undefined && v >= WARN_THRESHOLDS[k]
          return (
            <tr key={k}>
              <td style={{ color: 'var(--text-muted)', padding: '2px 8px 2px 0', fontFamily: 'Share Tech Mono, monospace', fontSize: '10px' }}>{k}</td>
              <td style={{ color: crit ? 'var(--accent-red)' : warn ? 'var(--accent-yellow)' : 'var(--text-primary)', padding: '2px 0', fontFamily: 'Share Tech Mono, monospace' }}>
                {typeof v === 'number' ? v.toFixed(2) : v}
                {crit && <span style={{ marginLeft: '4px', color: 'var(--accent-red)' }}>&#9888;&#9888;</span>}
                {warn && <span style={{ marginLeft: '4px', color: 'var(--accent-yellow)' }}>&#9888;</span>}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

function AnomalyTimeline({ anomalies }: { anomalies: UebaAnomaly[] }) {
  const navigate = useNavigate()
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const toggle = (id: string) => setExpanded(prev => {
    const s = new Set(prev)
    s.has(id) ? s.delete(id) : s.add(id)
    return s
  })

  if (anomalies.length === 0) return <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace' }}>No anomalies recorded</div>
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', maxHeight: '480px', overflow: 'auto' }}>
      {anomalies.map((a) => {
        const isOpen = expanded.has(a.id)
        const hasDetails = (a.ai_narrative || (a.mitre_techniques?.length ?? 0) > 0 ||
          (a.hash_ti_hits?.length ?? 0) > 0 || (a.domain_ti_hits?.length ?? 0) > 0 ||
          (a.url_ti_hits?.length ?? 0) > 0 || (a.ip_ti_hits?.length ?? 0) > 0 ||
          (a.powershell_hits?.length ?? 0) > 0 || (a.command_hits?.length ?? 0) > 0)
        return (
        <div key={a.id} style={{
          borderRadius: '3px',
          background: 'var(--bg-base)',
          border: `1px solid ${riskColor(a.risk_score)}44`,
          overflow: 'hidden',
        }}>
          {/* ── Header row (always visible, clickable to expand) ── */}
          <div
            onClick={() => hasDetails && toggle(a.id)}
            style={{
              padding: '5px 8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              cursor: hasDetails ? 'pointer' : 'default',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: riskColor(a.risk_score) }}>
                risk {a.risk_score.toFixed(0)}
              </span>
              <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
                score {a.anomaly_score.toFixed(3)}
              </span>
              {a.ai_action && (
                <span style={{
                  fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px',
                  padding: '1px 5px', borderRadius: '2px', letterSpacing: '0.5px',
                  background: a.ai_action === 'escalate' ? 'rgba(239,68,68,0.2)'
                    : a.ai_action === 'dismiss' ? 'rgba(100,100,100,0.2)'
                    : 'rgba(255,214,0,0.2)',
                  color: a.ai_action === 'escalate' ? '#ef4444'
                    : a.ai_action === 'dismiss' ? 'var(--text-muted)'
                    : '#ffd600',
                }}>
                  {a.ai_action.toUpperCase()}
                </span>
              )}
              {a.mitre_techniques?.map(t => (
                <span key={t.id} title={t.name} style={{
                  fontFamily: 'Share Tech Mono, monospace', fontSize: '9px',
                  padding: '1px 5px', borderRadius: '2px',
                  background: 'rgba(255,107,53,0.2)', color: '#ff6b35',
                }}>
                  {t.id}
                </span>
              ))}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
              <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)' }}>
                {new Date(a.detected_at).toLocaleString()}
              </span>
              {hasDetails && (
                <span style={{ color: 'var(--text-muted)', fontSize: '9px', lineHeight: 1 }}>
                  {isOpen ? '▲' : '▼'}
                </span>
              )}
            </div>
          </div>

          {/* ── Expanded detail ── */}
          {isOpen && (
          <div style={{ padding: '0 8px 8px', borderTop: '1px solid var(--border)' }}>
          {a.ai_narrative && (
            <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)', marginTop: '6px', lineHeight: 1.4, fontStyle: 'italic' }}>
              {a.ai_narrative}
            </div>
          )}
          {a.ai_action === 'escalate' && a.case_id && (
            <button onClick={() => navigate(`/cases/${a.case_id}`)} style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--accent-cyan)', marginTop: '4px', display: 'block', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
              View Case →
            </button>
          )}
          {a.alert_id && a.ai_action !== 'escalate' && (
            <button onClick={() => navigate(`/alerts?id=${a.alert_id}`)} style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--accent-yellow)', marginTop: '4px', display: 'block', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
              View Alert →
            </button>
          )}
          {a.hash_ti_hits && a.hash_ti_hits.length > 0 && (
            <div style={{ marginTop: '4px', padding: '4px 6px', borderRadius: '3px', background: 'rgba(251,191,36,0.06)', border: '1px solid rgba(251,191,36,0.2)' }}>
              <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', color: '#fbbf24', letterSpacing: '0.8px', marginBottom: '3px' }}>
                FILE HASH IOC ({a.hash_ti_hits.length})
              </div>
              {a.hash_ti_hits.map((h, i) => (
                <div key={i} style={{ marginBottom: '3px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: 'rgba(251,191,36,0.7)', background: 'rgba(251,191,36,0.12)', padding: '1px 4px', borderRadius: '2px' }}>
                      {h.ioc_type.replace('hash_', '').toUpperCase()}
                    </span>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: 'var(--text-muted)' }}>
                      {h.hash.slice(0, 16)}…
                    </span>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: h.score >= 0.7 ? '#ef4444' : h.score >= 0.3 ? '#fbbf24' : 'var(--text-muted)' }}>
                      score {h.score.toFixed(2)}
                    </span>
                  </div>
                  {h.bullets.map((b, j) => (
                    <div key={j} style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: 'var(--text-muted)', paddingLeft: '8px', lineHeight: 1.4 }}>
                      · {b}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
          {a.domain_ti_hits && a.domain_ti_hits.length > 0 && (
            <div style={{ marginTop: '4px', padding: '4px 6px', borderRadius: '3px', background: 'rgba(167,139,250,0.06)', border: '1px solid rgba(167,139,250,0.2)' }}>
              <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', color: '#a78bfa', letterSpacing: '0.8px', marginBottom: '3px' }}>
                DOMAIN IOC ({a.domain_ti_hits.length})
              </div>
              {a.domain_ti_hits.map((d, i) => (
                <div key={i} style={{ marginBottom: '3px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: '#a78bfa' }}>
                      {d.domain}
                    </span>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: d.score >= 0.7 ? '#ef4444' : d.score >= 0.3 ? '#fbbf24' : 'var(--text-muted)' }}>
                      score {d.score.toFixed(2)}
                    </span>
                  </div>
                  {d.bullets.map((b, j) => (
                    <div key={j} style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: 'var(--text-muted)', paddingLeft: '8px', lineHeight: 1.4 }}>
                      · {b}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
          {a.url_ti_hits && a.url_ti_hits.length > 0 && (
            <div style={{ marginTop: '4px', padding: '4px 6px', borderRadius: '3px', background: 'rgba(52,211,153,0.06)', border: '1px solid rgba(52,211,153,0.2)' }}>
              <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', color: '#34d399', letterSpacing: '0.8px', marginBottom: '3px' }}>
                URL IOC ({a.url_ti_hits.length})
              </div>
              {a.url_ti_hits.map((u, i) => (
                <div key={i} style={{ marginBottom: '3px' }}>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: '#34d399', wordBreak: 'break-all' }}>
                      {u.url.length > 60 ? u.url.slice(0, 60) + '…' : u.url}
                    </span>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: u.score >= 0.7 ? '#ef4444' : u.score >= 0.3 ? '#fbbf24' : 'var(--text-muted)', flexShrink: 0 }}>
                      score {u.score.toFixed(2)}
                    </span>
                  </div>
                  {u.bullets.map((b, j) => (
                    <div key={j} style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: 'var(--text-muted)', paddingLeft: '8px', lineHeight: 1.4 }}>
                      · {b}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
          {a.ip_ti_hits && a.ip_ti_hits.length > 0 && (
            <div style={{ marginTop: '4px', padding: '4px 6px', borderRadius: '3px', background: 'rgba(96,165,250,0.06)', border: '1px solid rgba(96,165,250,0.2)' }}>
              <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', color: '#60a5fa', letterSpacing: '0.8px', marginBottom: '3px' }}>
                RELATED IP IOC ({a.ip_ti_hits.length})
              </div>
              {a.ip_ti_hits.map((h, i) => (
                <div key={i} style={{ marginBottom: '3px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: '#60a5fa' }}>
                      {h.ip}
                    </span>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: h.score >= 0.7 ? '#ef4444' : h.score >= 0.3 ? '#fbbf24' : 'var(--text-muted)' }}>
                      score {h.score.toFixed(2)}
                    </span>
                  </div>
                  {h.bullets.map((b, j) => (
                    <div key={j} style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: 'var(--text-muted)', paddingLeft: '8px', lineHeight: 1.4 }}>
                      · {b}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
          {a.powershell_hits && a.powershell_hits.length > 0 && (
            <div style={{ marginTop: '4px', padding: '4px 6px', borderRadius: '3px', background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.25)' }}>
              <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', color: '#f87171', letterSpacing: '0.8px', marginBottom: '3px' }}>
                POWERSHELL ({a.powershell_hits.length})
              </div>
              {a.powershell_hits.map((p, i) => (
                <div key={i} style={{ marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: p.score >= 0.7 ? '#ef4444' : p.score >= 0.3 ? '#fbbf24' : 'var(--text-muted)' }}>
                      score {p.score.toFixed(2)}
                    </span>
                    {p.flags.map((f, j) => (
                      <span key={j} style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '7px', padding: '0 3px', borderRadius: '2px', background: 'rgba(239,68,68,0.15)', color: '#f87171' }}>
                        {f}
                      </span>
                    ))}
                  </div>
                  <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: 'var(--text-muted)', marginTop: '2px', wordBreak: 'break-all' }}>
                    {p.command.length > 80 ? p.command.slice(0, 80) + '…' : p.command}
                  </div>
                  {p.decoded && (
                    <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '7px', color: '#fbbf24', marginTop: '2px', paddingLeft: '6px', borderLeft: '2px solid rgba(251,191,36,0.3)', wordBreak: 'break-all' }}>
                      decoded: {p.decoded.length > 120 ? p.decoded.slice(0, 120) + '…' : p.decoded}
                    </div>
                  )}
                  {p.secondary_iocs.length > 0 && (
                    <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '7px', color: '#a78bfa', marginTop: '2px' }}>
                      iocs: {p.secondary_iocs.join(' · ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          {a.command_hits && a.command_hits.length > 0 && (
            <div style={{ marginTop: '4px', padding: '4px 6px', borderRadius: '3px', background: 'rgba(251,146,60,0.06)', border: '1px solid rgba(251,146,60,0.25)' }}>
              <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', color: '#fb923c', letterSpacing: '0.8px', marginBottom: '3px' }}>
                SUSPICIOUS CMD ({a.command_hits.length})
              </div>
              {a.command_hits.map((c, i) => (
                <div key={i} style={{ marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: c.score >= 0.7 ? '#ef4444' : c.score >= 0.3 ? '#fbbf24' : 'var(--text-muted)' }}>
                      score {c.score.toFixed(2)}
                    </span>
                    {c.flags.map((f, j) => (
                      <span key={j} style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '7px', padding: '0 3px', borderRadius: '2px', background: 'rgba(251,146,60,0.15)', color: '#fb923c' }}>
                        {f}
                      </span>
                    ))}
                  </div>
                  <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '8px', color: 'var(--text-muted)', marginTop: '2px', wordBreak: 'break-all' }}>
                    {c.command.length > 100 ? c.command.slice(0, 100) + '…' : c.command}
                  </div>
                  {c.secondary_iocs.length > 0 && (
                    <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '7px', color: '#a78bfa', marginTop: '2px' }}>
                      iocs: {c.secondary_iocs.join(' · ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          </div> {/* end expanded */}
          )}
        </div>
        )
      })}
    </div>
  )
}

function DetailPanel({ entityType, entityValue, onClose }: { entityType: string; entityValue: string; onClose: () => void }) {
  const { data, isLoading } = useUebaEntityDetail(entityType, entityValue)
  const { data: history = [] } = useUebaRiskHistory(entityType, entityValue)
  const investigate = useTriggerInvestigation()

  return (
    <div style={{
      width: '360px', flexShrink: 0,
      background: 'var(--bg-panel)', border: '1px solid var(--border)',
      borderRadius: '6px', overflow: 'hidden', display: 'flex', flexDirection: 'column',
    }}>
      <div style={{
        padding: '10px 14px', borderBottom: '1px solid var(--border)',
        background: 'var(--bg-base)', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      }}>
        <div>
          <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '14px', color: 'var(--accent-cyan)' }}>
            {entityValue}
          </div>
          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
            {entityType.toUpperCase()} ENTITY
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            onClick={() => investigate.mutate({ entityType, entityValue })}
            disabled={investigate.isPending}
            title="Force AI investigation now"
            style={{
              fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '10px',
              letterSpacing: '0.5px', padding: '3px 8px', borderRadius: '3px',
              border: '1px solid var(--accent-cyan)', background: investigate.isPending ? 'rgba(0,212,255,0.05)' : 'rgba(0,212,255,0.1)',
              color: investigate.isPending ? 'var(--text-muted)' : 'var(--accent-cyan)',
              cursor: investigate.isPending ? 'not-allowed' : 'pointer',
            }}
          >
            {investigate.isPending ? 'QUEUING…' : '⚡ INVESTIGATE'}
          </button>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '16px', cursor: 'pointer' }}>&#10005;</button>
        </div>
      </div>

      {isLoading ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace' }}>
          LOADING...
        </div>
      ) : data ? (
        <div style={{ flex: 1, overflow: 'auto', padding: '14px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <RiskSparkline data={history} />
          </div>
          <div>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '6px' }}>
              RISK SCORE
            </div>
            <RiskBar score={data.score.risk_score} />
            <div style={{ marginTop: '4px', fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)' }}>
              {data.score.anomaly_count} total anomalies &middot;
              last seen {data.score.last_seen_at ? new Date(data.score.last_seen_at).toLocaleString() : '&mdash;'}
            </div>
          </div>

          {data.anomalies.length > 0 && (
            <div>
              <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '6px' }}>
                LAST ANOMALY FEATURES
              </div>
              <FeatureTable features={data.anomalies[0].features} />
            </div>
          )}

          <div>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '6px' }}>
              ANOMALY TIMELINE ({data.anomalies.length})
            </div>
            <AnomalyTimeline anomalies={data.anomalies} />
          </div>
        </div>
      ) : null}
    </div>
  )
}

export default function UEBAPage() {
  const [tab, setTab] = useState<'user' | 'ip' | 'host'>('user')
  const [selected, setSelected] = useState<{ type: string; value: string } | null>(null)
  const { data: rawEntities = [], isLoading } = useUebaEntities(tab, 0)
  const { data: status } = useUebaStatus()

  const entities = [...rawEntities].sort((a, b) => b.risk_score - a.risk_score)
  const highRisk = entities.filter(e => e.risk_score >= 60).length
  const statusReady = status?.status === 'ready'

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '20px', color: 'var(--accent-cyan)', letterSpacing: '2px', textTransform: 'uppercase', margin: 0 }}>
            UEBA
          </h1>
          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
            User &amp; Entity Behavior Analytics &middot; Isolation Forest
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{
            padding: '4px 10px', borderRadius: '3px',
            border: `1px solid ${statusReady ? 'var(--accent-green)' : 'var(--accent-yellow)'}`,
            background: statusReady ? 'rgba(0,255,136,0.08)' : 'rgba(255,214,0,0.08)',
          }}>
            <span style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '10px', letterSpacing: '1px', color: statusReady ? 'var(--accent-green)' : 'var(--accent-yellow)' }}>
              {statusReady ? '● MODEL READY' : '● COLLECTING DATA'}
            </span>
            {status?.trained_at && (
              <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)', marginLeft: '6px' }}>
                trained {new Date(status.trained_at).toLocaleTimeString()}
              </span>
            )}
          </div>
          {[
            { label: 'HIGH RISK', value: highRisk, color: highRisk > 0 ? 'var(--accent-red)' : 'var(--text-primary)' },
            { label: 'USER SNAPS', value: status?.user_snapshot_count ?? 0, color: 'var(--text-primary)' },
            { label: 'IP SNAPS', value: status?.ip_snapshot_count ?? 0, color: 'var(--text-primary)' },
            { label: 'HOST SNAPS', value: status?.host_snapshot_count ?? 0, color: 'var(--text-primary)' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ textAlign: 'center' }}>
              <div style={{ fontFamily: 'Share Tech Mono, monospace', fontWeight: 700, fontSize: '18px', color, lineHeight: 1 }}>{value}</div>
              <div style={{ fontFamily: 'Rajdhani, sans-serif', fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '1px', marginTop: '2px' }}>{label}</div>
            </div>
          ))}
        </div>
      </div>

      {!statusReady && (
        <div style={{
          padding: '10px 14px', borderRadius: '4px',
          border: '1px solid rgba(255,214,0,0.3)', background: 'rgba(255,214,0,0.05)',
          fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--accent-yellow)',
        }}>
          &#9889; UEBA is collecting baseline data. Model trains automatically once 50 hourly snapshots are available
          (&#8776; 50 hours). Currently: {(status?.user_snapshot_count ?? 0) + (status?.ip_snapshot_count ?? 0)} snapshots collected.
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', gap: '12px', overflow: 'hidden' }}>
        <div style={{ flex: 1, background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '6px', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)' }}>
            {(['user', 'ip', 'host'] as const).map(t => (
              <button
                key={t}
                onClick={() => { setTab(t); setSelected(null) }}
                style={{
                  flex: 1, padding: '8px', border: 'none',
                  background: tab === t ? 'rgba(0,212,255,0.08)' : 'transparent',
                  borderBottom: `2px solid ${tab === t ? 'var(--accent-cyan)' : 'transparent'}`,
                  color: tab === t ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px',
                  letterSpacing: '1px', cursor: 'pointer',
                }}
              >
                {t.toUpperCase()}S
              </button>
            ))}
          </div>

          <div style={{ flex: 1, overflow: 'auto' }}>
            {isLoading ? (
              <div style={{ padding: '20px', textAlign: 'center', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace' }}>
                LOADING...
              </div>
            ) : entities.length === 0 ? (
              <div style={{ padding: '20px', textAlign: 'center', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace' }}>
                NO {tab.toUpperCase()} ENTITIES YET
              </div>
            ) : (
              entities.map(e => (
                <EntityRow
                  key={e.entity_value}
                  entity={e}
                  selected={selected?.value === e.entity_value && selected?.type === e.entity_type}
                  onClick={() => setSelected({ type: e.entity_type, value: e.entity_value })}
                />
              ))
            )}
          </div>
        </div>

        {selected && (
          <DetailPanel
            entityType={selected.type}
            entityValue={selected.value}
            onClose={() => setSelected(null)}
          />
        )}
      </div>
    </div>
  )
}
