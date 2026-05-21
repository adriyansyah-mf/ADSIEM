import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { format, isToday } from 'date-fns'
import type { Alert, Case, Event } from '@/types'

const severityColors = {
  critical: { bg: 'rgba(255,34,68,0.15)', border: '#ff2244', color: '#ff2244' },
  high:     { bg: 'rgba(255,107,0,0.15)', border: '#ff6b00', color: '#ff6b00' },
  medium:   { bg: 'rgba(255,215,0,0.1)',  border: '#ffd700', color: '#ffd700' },
  low:      { bg: 'rgba(0,255,136,0.1)',  border: '#00ff88', color: '#00ff88' },
  info:     { bg: 'rgba(0,212,255,0.1)',  border: '#00d4ff', color: '#00d4ff' },
}

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity as keyof typeof severityColors
  const c = severityColors[s] ?? severityColors.info
  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 7px',
      borderRadius: '3px',
      border: `1px solid ${c.border}`,
      background: c.bg,
      color: c.color,
      fontFamily: 'Rajdhani, sans-serif',
      fontWeight: 700,
      fontSize: '11px',
      letterSpacing: '0.5px',
      textTransform: 'uppercase',
      boxShadow: `0 0 6px ${c.border}44`,
    }}>
      {severity}
    </span>
  )
}

function SectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{
      borderRadius: '6px',
      border: '1px solid var(--border)',
      background: 'var(--bg-card)',
      padding: '14px',
      marginBottom: '12px',
    }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: '10px',
      }}>
        <span style={{
          fontFamily: 'Rajdhani, sans-serif',
          fontSize: '11px',
          fontWeight: 700,
          letterSpacing: '2px',
          textTransform: 'uppercase',
          color: 'var(--accent-cyan)',
        }}>
          {title}
        </span>
      </div>
      {children}
    </div>
  )
}

function StatRow({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '5px 0',
      borderBottom: '1px solid var(--border)',
    }}>
      <span style={{ fontFamily: 'Exo 2, sans-serif', fontSize: '12px', color: 'var(--text-secondary)' }}>{label}</span>
      <span style={{
        fontFamily: 'Share Tech Mono, monospace',
        fontSize: '14px',
        fontWeight: 700,
        color,
      }}>{value}</span>
    </div>
  )
}

export default function DashboardPage() {
  const { data: allAlerts } = useQuery({
    queryKey: ['alerts-dashboard'],
    queryFn: () => api.get('/api/alerts', { params: { page_size: 200 } }).then(r => r.data),
    refetchInterval: 15_000,
  })

  const { data: recentAlerts } = useQuery({
    queryKey: ['alerts-recent'],
    queryFn: () => api.get('/api/alerts', { params: { page_size: 20 } }).then(r => r.data),
    refetchInterval: 15_000,
  })

  const { data: recentEvents } = useQuery({
    queryKey: ['events-recent'],
    queryFn: () => api.get('/api/events', { params: { page_size: 10 } }).then(r => r.data),
    refetchInterval: 10_000,
  })

  const { data: casesData } = useQuery({
    queryKey: ['cases-dashboard'],
    queryFn: () => api.get('/api/cases', { params: { page_size: 50 } }).then(r => r.data),
    refetchInterval: 15_000,
  })

  const { data: agentsData } = useQuery({
    queryKey: ['agents-dashboard'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 1 } }).then(r => r.data),
    refetchInterval: 30_000,
  })

  const alerts: Alert[] = allAlerts?.items ?? []
  const todayAlerts = alerts.filter(a => isToday(new Date(a.created_at)))

  const severityCounts = {
    critical: todayAlerts.filter(a => a.severity === 'critical').length,
    high: todayAlerts.filter(a => a.severity === 'high').length,
    medium: todayAlerts.filter(a => a.severity === 'medium').length,
    low: todayAlerts.filter(a => a.severity === 'low').length,
  }

  // Top 5 source IPs
  const ipCounts: Record<string, number> = {}
  alerts.forEach(a => {
    if (a.source_ip) ipCounts[a.source_ip] = (ipCounts[a.source_ip] ?? 0) + 1
  })
  const topIPs = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)

  const recentAlertItems: Alert[] = recentAlerts?.items ?? []
  const recentEventItems: Event[] = recentEvents?.items ?? []
  const cases: Case[] = casesData?.items ?? []
  const openCases = cases.filter(c => c.status === 'open' || c.status === 'in_review')

  // Build case map for AI reasoning lookup
  const caseByAlertId: Record<string, Case> = {}
  cases.forEach(c => { if (c.alert_id) caseByAlertId[c.alert_id] = c })

  return (
    <div style={{ display: 'flex', gap: '12px', height: '100%', minHeight: 0 }}>
      {/* LEFT COLUMN */}
      <div style={{ width: '260px', flexShrink: 0, overflowY: 'auto' }}>
        <SectionCard title="Alert Statistics">
          <StatRow label="Critical" value={severityCounts.critical} color="#ff2244" />
          <StatRow label="High" value={severityCounts.high} color="#ff6b00" />
          <StatRow label="Medium" value={severityCounts.medium} color="#ffd700" />
          <StatRow label="Low" value={severityCounts.low} color="#00ff88" />
          <div style={{ marginTop: '6px', fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
            TODAY: {todayAlerts.length} TOTAL
          </div>
        </SectionCard>

        <SectionCard title="Top Source IPs">
          {topIPs.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No data</div>
          ) : topIPs.map(([ip, count]) => (
            <div key={ip} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '4px 0',
              borderBottom: '1px solid var(--border)',
            }}>
              <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--accent-cyan)' }}>{ip}</span>
              <span style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '13px', color: 'var(--accent-orange)' }}>{count}</span>
            </div>
          ))}
        </SectionCard>

        <SectionCard title="Live Events">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {recentEventItems.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No events</div>
            ) : recentEventItems.map(ev => (
              <div key={ev.id} style={{
                padding: '5px 7px',
                borderRadius: '4px',
                background: 'var(--bg-panel)',
                border: '1px solid var(--border)',
              }}>
                <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
                  {format(new Date(ev.created_at), 'HH:mm:ss')}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {ev.event_action ?? 'event'}
                </div>
                {ev.source_ip && (
                  <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--accent-cyan)' }}>
                    {ev.source_ip}
                  </div>
                )}
              </div>
            ))}
          </div>
        </SectionCard>
      </div>

      {/* CENTER COLUMN */}
      <div style={{ flex: 1, minWidth: 0, overflowY: 'auto' }}>
        <div style={{
          borderRadius: '6px',
          border: '1px solid var(--border)',
          background: 'var(--bg-card)',
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '12px 16px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}>
            <span style={{
              fontFamily: 'Rajdhani, sans-serif',
              fontSize: '11px',
              fontWeight: 700,
              letterSpacing: '2px',
              textTransform: 'uppercase',
              color: 'var(--accent-cyan)',
            }}>
              Agentic Triage Feed
            </span>
            <span style={{
              fontFamily: 'Share Tech Mono, monospace',
              fontSize: '10px',
              color: 'var(--text-muted)',
            }}>
              — LAST {recentAlertItems.length} ALERTS
            </span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: 'var(--bg-panel)' }}>
                  {['TIME', 'ALERT', 'SEVERITY', 'AI REASONING', 'STATUS'].map(h => (
                    <th key={h} style={{
                      padding: '8px 12px',
                      textAlign: 'left',
                      fontFamily: 'Rajdhani, sans-serif',
                      fontSize: '10px',
                      fontWeight: 700,
                      letterSpacing: '1.5px',
                      color: 'var(--text-muted)',
                      borderBottom: '1px solid var(--border)',
                      whiteSpace: 'nowrap',
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {recentAlertItems.map((alert, idx) => {
                  const linkedCase = caseByAlertId[alert.id]
                  const reasoning = linkedCase?.ai_reasoning ?? 'Pending AI analysis'
                  return (
                    <tr key={alert.id} style={{
                      borderBottom: '1px solid var(--border)',
                      background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                      transition: 'background 0.1s',
                    }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-hover)')}
                    onMouseLeave={e => (e.currentTarget.style.background = idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)')}
                    >
                      <td style={{ padding: '8px 12px', fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {format(new Date(alert.created_at), 'MM-dd HH:mm')}
                      </td>
                      <td style={{ padding: '8px 12px', maxWidth: '200px' }}>
                        <div style={{ fontFamily: 'Exo 2, sans-serif', fontWeight: 600, fontSize: '12px', color: 'var(--text-primary)' }}>
                          {alert.title}
                        </div>
                        {alert.hostname && (
                          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
                            {alert.hostname}
                          </div>
                        )}
                      </td>
                      <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td style={{ padding: '8px 12px', maxWidth: '280px' }}>
                        <div style={{
                          fontFamily: 'Exo 2, sans-serif',
                          fontSize: '11px',
                          color: linkedCase ? 'var(--text-primary)' : 'var(--text-muted)',
                          overflow: 'hidden',
                          display: '-webkit-box',
                          WebkitLineClamp: 2,
                          WebkitBoxOrient: 'vertical',
                        }}>
                          {reasoning}
                        </div>
                      </td>
                      <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                        <span style={{
                          display: 'inline-block',
                          padding: '2px 7px',
                          borderRadius: '3px',
                          fontSize: '10px',
                          fontFamily: 'Rajdhani, sans-serif',
                          fontWeight: 700,
                          letterSpacing: '0.5px',
                          textTransform: 'uppercase',
                          background: alert.status === 'new' ? 'rgba(0,212,255,0.1)' : 'rgba(0,255,136,0.1)',
                          color: alert.status === 'new' ? 'var(--accent-cyan)' : 'var(--accent-green)',
                          border: `1px solid ${alert.status === 'new' ? 'var(--accent-cyan)' : 'var(--accent-green)'}`,
                        }}>
                          {alert.status.replace('_', ' ')}
                        </span>
                      </td>
                    </tr>
                  )
                })}
                {recentAlertItems.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px' }}>
                      NO ALERTS IN FEED
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* RIGHT COLUMN */}
      <div style={{ width: '260px', flexShrink: 0, overflowY: 'auto' }}>
        <SectionCard title="Active Cases">
          {openCases.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No open cases</div>
          ) : openCases.slice(0, 8).map(c => (
            <div key={c.id} style={{
              padding: '7px 0',
              borderBottom: '1px solid var(--border)',
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '6px', marginBottom: '3px' }}>
                {c.created_by_ai && <span title="AI Generated" style={{ fontSize: '12px' }}>🤖</span>}
                <span style={{ fontFamily: 'Exo 2, sans-serif', fontWeight: 600, fontSize: '12px', color: 'var(--text-primary)', flex: 1 }}>
                  {c.title}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '5px', alignItems: 'center' }}>
                <SeverityBadge severity={c.severity} />
                <span style={{
                  fontFamily: 'Rajdhani, sans-serif',
                  fontSize: '10px',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  letterSpacing: '0.5px',
                  textTransform: 'uppercase',
                }}>{c.status.replace('_', ' ')}</span>
              </div>
              <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '3px' }}>
                {format(new Date(c.created_at), 'MM-dd HH:mm')}
              </div>
            </div>
          ))}
        </SectionCard>

        <SectionCard title="Performance Metrics">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {[
              { label: 'TOTAL ALERTS', value: allAlerts?.total ?? '—', color: 'var(--accent-cyan)' },
              { label: 'TOTAL CASES', value: casesData?.total ?? '—', color: 'var(--accent-green)' },
              { label: 'AGENTS ONLINE', value: agentsData?.total ?? '—', color: 'var(--accent-orange)' },
            ].map(m => (
              <div key={m.label} style={{
                padding: '10px',
                borderRadius: '4px',
                background: 'var(--bg-panel)',
                border: '1px solid var(--border)',
              }}>
                <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, letterSpacing: '1px', fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  {m.label}
                </div>
                <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '22px', fontWeight: 700, color: m.color, marginTop: '2px' }}>
                  {m.value}
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
      </div>
    </div>
  )
}
