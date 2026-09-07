import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api } from '@/api/client'
import { format } from 'date-fns'
import { BrainCircuit, Search, Loader2 } from 'lucide-react'
import AlertDetailModal from '@/components/AlertDetailModal'
import { GlassCard } from '@/components/ui/GlassCard'
import { Sparkline } from '@/components/charts/Sparkline'
import { StackedBarChart, type StackedBarDatum } from '@/components/charts/StackedBarChart'
import { DonutChart } from '@/components/charts/DonutChart'
import { HorizontalBarChart, type HBarRow } from '@/components/charts/HorizontalBarChart'
import type { Alert, Agent, Case, Event } from '@/types'

interface WorkloadItem { user_id: string; username: string; open_alerts: number; open_cases: number; total: number }

const severityColors = {
  critical: { bg: 'rgba(255,59,92,0.15)', border: '#D8393F', color: '#D8393F' },
  high:     { bg: 'rgba(255,122,69,0.15)', border: '#D8752E', color: '#D8752E' },
  medium:   { bg: 'rgba(255,197,61,0.1)',  border: '#D8B23D', color: '#D8B23D' },
  low:      { bg: 'rgba(46,212,122,0.1)',  border: '#4F8F63', color: '#4F8F63' },
  info:     { bg: 'rgba(44,110,142,0.1)',  border: '#2C6E8E', color: '#2C6E8E' },
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
      fontFamily: 'Public Sans, sans-serif',
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
    <GlassCard title={title} className="mb-3">
      {children}
    </GlassCard>
  )
}

function KpiTile({
  label, value, valueColor, sparkline, sparkColor,
}: { label: string; value: string | number; valueColor?: string; sparkline?: number[]; sparkColor?: string }) {
  return (
    <div style={{
      position: 'relative', borderRadius: '6px', border: '1px solid var(--border)',
      background: 'var(--bg-card)', padding: '12px 14px', overflow: 'hidden',
    }}>
      <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '10px', fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
        {label}
      </div>
      <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '22px', fontWeight: 700, color: valueColor ?? 'var(--text-primary)', marginTop: '4px', fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </div>
      {sparkline && sparkline.length > 1 && (
        <div style={{ position: 'absolute', right: 10, bottom: 8 }}>
          <Sparkline values={sparkline} color={sparkColor} width={64} height={22} />
        </div>
      )}
    </div>
  )
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const { data: allAlerts } = useQuery({
    queryKey: ['alerts-dashboard'],
    queryFn: () => api.get('/api/alerts', { params: { page_size: 200 } }).then(r => r.data),
    refetchInterval: 30_000,
  })

  const { data: recentAlerts } = useQuery({
    queryKey: ['alerts-recent'],
    queryFn: () => api.get('/api/alerts', { params: { page_size: 20 } }).then(r => r.data),
    refetchInterval: 30_000,
  })

  const { data: recentEvents } = useQuery({
    queryKey: ['events-recent'],
    queryFn: () => api.get('/api/events', { params: { page_size: 10 } }).then(r => r.data),
    refetchInterval: 30_000,
  })

  const { data: casesData } = useQuery({
    queryKey: ['cases-dashboard'],
    queryFn: () => api.get('/api/cases', { params: { page_size: 50 } }).then(r => r.data),
    refetchInterval: 30_000,
  })

  const { data: agentsData } = useQuery({
    queryKey: ['agents-dashboard'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 500 } }).then(r => r.data),
    refetchInterval: 30_000,
  })

  const { data: socMetrics } = useQuery({
    queryKey: ['metrics-soc'],
    queryFn: () => api.get('/api/metrics/soc').then(r => r.data),
    refetchInterval: 60_000,
  })

  const { data: workload = [] } = useQuery<WorkloadItem[]>({
    queryKey: ['metrics-workload'],
    queryFn: () => api.get('/api/metrics/workload').then(r => r.data),
    refetchInterval: 60_000,
  })

  const { data: health } = useQuery<{ status: string; postgres: string; redis: string; uptime_seconds: number }>({
    queryKey: ['system-health'],
    queryFn: () => api.get('/health').then(r => r.data),
    refetchInterval: 30_000,
  })

  const { data: workerMetrics } = useQuery<{ status: string; sigma_evaluations: number; memory_bytes: number; ai_queue_depth: number; ingestion_stream_length: number }>({
    queryKey: ['worker-metrics'],
    queryFn: () => api.get('/api/metrics/worker').then(r => r.data),
    refetchInterval: 30_000,
  })

  const [tiIoc, setTiIoc] = useState('')
  const [tiType, setTiType] = useState('ip')
  const [tiResult, setTiResult] = useState<Record<string, unknown> | null>(null)
  const [tiLoading, setTiLoading] = useState(false)

  const handleTiLookup = async () => {
    const val = tiIoc.trim()
    if (!val) return
    setTiLoading(true)
    setTiResult(null)
    try {
      const r = await api.get('/api/metrics/ti/quick', { params: { ioc: val, ioc_type: tiType } })
      setTiResult(r.data)
    } catch { setTiResult({ error: 'Lookup failed' }) }
    finally { setTiLoading(false) }
  }

  const agents: Agent[] = agentsData?.items ?? []
  const onlineAgentCount = agents.filter((a: Agent) => a.status === 'online').length

  const alerts: Alert[] = allAlerts?.items ?? []
  const cutoff24h = Date.now() - 24 * 60 * 60 * 1000
  const todayAlerts = alerts.filter(a => new Date(a.created_at).getTime() >= cutoff24h)

  const severityCounts = {
    critical: alerts.filter(a => a.severity === 'critical').length,
    high: alerts.filter(a => a.severity === 'high').length,
    medium: alerts.filter(a => a.severity === 'medium').length,
    low: alerts.filter(a => a.severity === 'low').length,
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

  // Hourly alert volume for the last 24h, stacked by severity — feeds both
  // the volume chart and (a coarser slice of) the KPI sparklines, so every
  // chart on this page is derived from the same real fetched alert data,
  // not a separate fabricated trend.
  const hourBuckets: StackedBarDatum[] = Array.from({ length: 24 }, (_, i) => {
    const hourStart = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000 - (23 - i) * 3_600_000)
    return { label: `${String(hourStart.getHours()).padStart(2, '0')}:00`, values: { critical: 0, high: 0, medium: 0, low: 0 } }
  })
  todayAlerts.forEach(a => {
    const hoursAgo = Math.floor((Date.now() - new Date(a.created_at).getTime()) / 3_600_000)
    const idx = 23 - hoursAgo
    if (idx >= 0 && idx < 24 && a.severity in hourBuckets[idx].values) {
      hourBuckets[idx].values[a.severity] += 1
    }
  })
  const openAlertsSparkline = hourBuckets.filter((_, i) => i % 3 === 0)
    .map(b => Object.values(b.values).reduce((s, v) => s + v, 0))
  const criticalSparkline = hourBuckets.filter((_, i) => i % 3 === 0).map(b => b.values.critical)

  const severitySegments = [
    { label: 'Critical', value: severityCounts.critical, color: 'var(--accent-red)' },
    { label: 'High', value: severityCounts.high, color: 'var(--accent-orange)' },
    { label: 'Medium', value: severityCounts.medium, color: 'var(--accent-yellow)' },
    { label: 'Low', value: severityCounts.low, color: 'var(--accent-green)' },
  ]
  const totalOpenSeverity = severityCounts.critical + severityCounts.high + severityCounts.medium + severityCounts.low

  const fleetSegments = [
    { label: 'Online', value: onlineAgentCount, color: 'var(--accent-green)' },
    { label: 'Offline', value: agents.length - onlineAgentCount, color: 'var(--text-muted)' },
  ]

  const topIPRows: HBarRow[] = topIPs.map(([ip, count]) => ({
    label: ip, segments: [{ value: count, color: 'var(--accent-blue)' }],
  }))

  const workloadRows: HBarRow[] = workload.slice(0, 7).map(w => ({
    label: w.username,
    segments: [
      { value: w.open_alerts, color: 'var(--accent-orange)' },
      { value: w.open_cases, color: 'var(--accent-blue)' },
    ],
    labelStyle: w.user_id === 'unassigned' ? { color: 'var(--accent-orange)', fontStyle: 'italic' } : undefined,
  }))

  return (
    <>
    <div className="dashboard-grid" style={{ display: 'flex', gap: '12px', height: '100%', minHeight: 0 }}>
      {/* LEFT COLUMN */}
      <div className="dashboard-left-rail" style={{ width: '220px', flexShrink: 0, overflowY: 'auto' }}>
        <SectionCard title="Alert Statistics">
          <DonutChart
            segments={severitySegments}
            size={84}
            centerLabel={String(totalOpenSeverity)}
            centerSublabel="OPEN"
          />
          <div style={{ marginTop: '8px', fontFamily: 'Public Sans, sans-serif', fontSize: '10px', color: 'var(--text-muted)' }}>
            LAST 24H: {todayAlerts.length} TOTAL
          </div>
        </SectionCard>

        <SectionCard title="Top Source IPs">
          {topIPs.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No data</div>
          ) : (
            <HorizontalBarChart rows={topIPRows} rowHeight={26} barHeight={13} />
          )}
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
                <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '10px', color: 'var(--text-muted)' }}>
                  {format(new Date(ev.created_at), 'HH:mm:ss')}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {ev.event_action ?? 'event'}
                </div>
                {ev.source_ip && (
                  <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '10px', color: 'var(--accent-blue)' }}>
                    {ev.source_ip}
                  </div>
                )}
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="Quick TI Lookup">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', gap: '4px' }}>
              <select value={tiType} onChange={e => setTiType(e.target.value)} style={{
                background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '3px',
                color: 'var(--text-primary)', fontSize: '11px', padding: '3px 4px',
              }}>
                <option value="ip">IP</option>
                <option value="hash">Hash</option>
                <option value="domain">Domain</option>
              </select>
              <input value={tiIoc} onChange={e => setTiIoc(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleTiLookup()}
                placeholder="IoC value…" style={{
                  flex: 1, background: 'var(--bg-panel)', border: '1px solid var(--border)',
                  borderRadius: '3px', color: 'var(--text-primary)', fontSize: '11px',
                  padding: '3px 6px', fontFamily: 'Public Sans, sans-serif',
                }} />
              <button aria-label="Run threat intelligence lookup" title="Run threat intelligence lookup" onClick={handleTiLookup} disabled={tiLoading} style={{
                background: 'var(--accent-blue)', color: '#000', border: 'none',
                borderRadius: '3px', padding: '3px 7px', cursor: 'pointer', display: 'flex', alignItems: 'center',
              }}>
                {tiLoading ? <Loader2 size={11} style={{ animation: 'spin 1s linear infinite' }} /> : <Search size={11} />}
              </button>
            </div>
            {tiResult && (
              <div style={{
                padding: '6px', borderRadius: '3px',
                background: 'var(--bg-panel)', border: '1px solid var(--border)',
                fontSize: '10px', fontFamily: 'Public Sans, sans-serif',
                color: 'var(--text-secondary)', overflowX: 'hidden',
              }}>
                {tiResult.error ? (
                  <span style={{ color: '#D8393F' }}>{String(tiResult.error)}</span>
                ) : (
                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {JSON.stringify(tiResult, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>
        </SectionCard>
      </div>

      {/* CENTER COLUMN */}
      <div className="dashboard-center" style={{ flex: 1, minWidth: 0, overflowY: 'auto' }}>
        {/* KPI row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '12px' }}>
          <KpiTile label="Open Alerts" value={totalOpenSeverity} sparkline={openAlertsSparkline} sparkColor="var(--accent-blue)" />
          <KpiTile label="Critical" value={severityCounts.critical} sparkline={criticalSparkline} sparkColor="var(--accent-red)" valueColor="var(--accent-red)" />
          <KpiTile label="Avg MTTR (24h)" value={socMetrics?.avg_mttr_minutes != null ? `${Math.round(socMetrics.avg_mttr_minutes)}m` : '—'} />
          <KpiTile label="Agents Online" value={`${onlineAgentCount}/${agents.length}`} valueColor="var(--accent-blue)" />
        </div>

        {/* Alert volume chart */}
        <div style={{
          borderRadius: '6px',
          border: '1px solid var(--border)',
          background: 'var(--bg-card)',
          overflow: 'hidden',
          marginBottom: '12px',
          padding: '14px 16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
            <span style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '11px', fontWeight: 700, letterSpacing: '2px', textTransform: 'uppercase', color: 'var(--accent-blue)' }}>
              Alert Volume — Last 24h
            </span>
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>{todayAlerts.length} TOTAL</span>
          </div>
          <StackedBarChart
            ariaLabel={`Alert volume over the last 24 hours by severity, ${todayAlerts.length} total alerts`}
            data={hourBuckets}
            series={[
              { key: 'low', color: 'var(--accent-green)' },
              { key: 'medium', color: 'var(--accent-yellow)' },
              { key: 'high', color: 'var(--accent-orange)' },
              { key: 'critical', color: 'var(--accent-red)' },
            ]}
          />
          <div style={{ display: 'flex', gap: '14px', marginTop: '8px' }}>
            {[
              ['Critical', 'var(--accent-red)'], ['High', 'var(--accent-orange)'],
              ['Medium', 'var(--accent-yellow)'], ['Low', 'var(--accent-green)'],
            ].map(([label, color]) => (
              <span key={label} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: color, display: 'inline-block' }} />
                {label}
              </span>
            ))}
          </div>
        </div>

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
              fontFamily: 'Public Sans, sans-serif',
              fontSize: '11px',
              fontWeight: 700,
              letterSpacing: '2px',
              textTransform: 'uppercase',
              color: 'var(--accent-blue)',
            }}>
              Agentic Triage Feed
            </span>
            <span style={{
              fontFamily: 'Public Sans, sans-serif',
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
                      fontFamily: 'Public Sans, sans-serif',
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
                    <tr key={alert.id}
                    onClick={() => setSelectedAlert(alert)}
                    style={{
                      borderBottom: '1px solid var(--border)',
                      background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                      transition: 'background 0.1s',
                      cursor: 'pointer',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; e.currentTarget.style.borderLeft = '2px solid rgba(44,110,142,0.3)' }}
                    onMouseLeave={e => { e.currentTarget.style.background = idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)'; e.currentTarget.style.borderLeft = '' }}
                    >
                      <td style={{ padding: '8px 12px', fontFamily: 'Public Sans, sans-serif', fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {format(new Date(alert.created_at), 'MM-dd HH:mm')}
                      </td>
                      <td style={{ padding: '8px 12px', maxWidth: '200px' }}>
                        <div style={{ fontFamily: 'Public Sans, sans-serif', fontWeight: 600, fontSize: '12px', color: 'var(--text-primary)' }}>
                          {alert.title}
                        </div>
                        {alert.hostname && (
                          <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '10px', color: 'var(--text-muted)' }}>
                            {alert.hostname}
                          </div>
                        )}
                      </td>
                      <td style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td style={{ padding: '8px 12px', maxWidth: '280px' }}>
                        <div style={{
                          fontFamily: 'Public Sans, sans-serif',
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
                          fontFamily: 'Public Sans, sans-serif',
                          fontWeight: 700,
                          letterSpacing: '0.5px',
                          textTransform: 'uppercase',
                          background: alert.status === 'new' ? 'rgba(44,110,142,0.1)' : 'rgba(46,212,122,0.1)',
                          color: alert.status === 'new' ? 'var(--accent-blue)' : 'var(--accent-green)',
                          border: `1px solid ${alert.status === 'new' ? 'var(--accent-blue)' : 'var(--accent-green)'}`,
                        }}>
                          {alert.status.replace('_', ' ')}
                        </span>
                      </td>
                    </tr>
                  )
                })}
                {recentAlertItems.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'Public Sans, sans-serif', fontSize: '12px' }}>
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
      <div className="dashboard-right-rail" style={{ width: '280px', flexShrink: 0, overflowY: 'auto' }}>
        <SectionCard title="Active Cases">
          {openCases.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No open cases</div>
          ) : openCases.slice(0, 8).map(c => (
            <div key={c.id} style={{
              padding: '7px 0',
              borderBottom: '1px solid var(--border)',
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '6px', marginBottom: '3px' }}>
                {c.created_by_ai && <BrainCircuit aria-label="AI generated" size={13} />}
                <span style={{ fontFamily: 'Public Sans, sans-serif', fontWeight: 600, fontSize: '12px', color: 'var(--text-primary)', flex: 1 }}>
                  {c.title}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '5px', alignItems: 'center' }}>
                <SeverityBadge severity={c.severity} />
                <span style={{
                  fontFamily: 'Public Sans, sans-serif',
                  fontSize: '10px',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  letterSpacing: '0.5px',
                  textTransform: 'uppercase',
                }}>{c.status.replace('_', ' ')}</span>
              </div>
              <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '10px', color: 'var(--text-muted)', marginTop: '3px' }}>
                {format(new Date(c.created_at), 'MM-dd HH:mm')}
              </div>
            </div>
          ))}
        </SectionCard>

        <SectionCard title="Fleet Health">
          <DonutChart
            segments={fleetSegments}
            size={100}
            centerLabel={agents.length > 0 ? `${Math.round((onlineAgentCount / agents.length) * 100)}%` : '—'}
            centerSublabel="ONLINE"
          />
          <div style={{ display: 'flex', gap: '8px', marginTop: '10px' }}>
            {[
              { label: 'TOTAL ALERTS', value: allAlerts?.total ?? '—' },
              { label: 'TOTAL CASES', value: casesData?.total ?? '—' },
            ].map(m => (
              <div key={m.label} style={{ flex: 1, padding: '6px 8px', borderRadius: '4px', background: 'var(--bg-panel)', border: '1px solid var(--border)' }}>
                <div style={{ fontFamily: 'Public Sans, sans-serif', fontWeight: 700, letterSpacing: '0.5px', fontSize: '9px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  {m.label}
                </div>
                <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                  {m.value}
                </div>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="System Health">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {[
              { label: 'API', value: health?.status ?? 'unknown', ok: health?.status === 'ok' },
              { label: 'POSTGRES', value: health?.postgres ?? 'unknown', ok: health?.postgres === 'ok' },
              { label: 'REDIS', value: health?.redis ?? 'unknown', ok: health?.redis === 'ok' },
              { label: 'WORKER', value: workerMetrics?.status ?? 'unknown', ok: workerMetrics?.status === 'ok' },
              { label: 'AI QUEUE', value: workerMetrics?.ai_queue_depth ?? 'unknown', ok: (workerMetrics?.ai_queue_depth ?? 0) < 100 },
              { label: 'INGESTION STREAM', value: workerMetrics?.ingestion_stream_length ?? 'unknown', ok: true },
            ].map(item => (
              <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderRadius: '3px', background: 'var(--bg-panel)', border: '1px solid var(--border)' }}>
                <span style={{ fontFamily: 'Public Sans, sans-serif', fontWeight: 700, letterSpacing: '1px', fontSize: '10px', color: 'var(--text-muted)' }}>{item.label}</span>
                <span style={{ color: item.ok ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' }}>{item.value}</span>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="SOC Response">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {[
              { label: 'AVG MTTD', value: socMetrics?.avg_ack_minutes != null ? `${Math.round(socMetrics.avg_ack_minutes)}m` : '—', color: '#2C6E8E' },
              { label: 'AVG MTTR', value: socMetrics?.avg_mttr_minutes != null ? `${Math.round(socMetrics.avg_mttr_minutes)}m` : '—', color: '#4F8F63' },
              { label: 'FP RATE', value: socMetrics?.false_positive_rate_pct != null ? `${(socMetrics.false_positive_rate_pct as number).toFixed(1)}%` : '—', color: '#D8B23D' },
              { label: 'SLA BREACHED', value: socMetrics?.sla_breached ?? '—', color: '#D8393F' },
              { label: 'UNASSIGNED', value: socMetrics?.unassigned_open ?? '—', color: '#D8752E' },
            ].map(m => (
              <div key={m.label} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '6px 8px', borderRadius: '3px',
                background: 'var(--bg-panel)', border: '1px solid var(--border)',
              }}>
                <span style={{ fontFamily: 'Public Sans, sans-serif', fontWeight: 700, letterSpacing: '1px', fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  {m.label}
                </span>
                <span style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '15px', fontWeight: 700, color: m.color }}>
                  {m.value}
                </span>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title="Analyst Workload">
          {workload.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No analysts assigned</div>
          ) : (
            <>
              <HorizontalBarChart rows={workloadRows} rowHeight={26} barHeight={13} />
              <div style={{ display: 'flex', gap: '14px', marginTop: '8px' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--accent-orange)', display: 'inline-block' }} />
                  Open alerts
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: 'var(--accent-blue)', display: 'inline-block' }} />
                  Open cases
                </span>
              </div>
            </>
          )}
        </SectionCard>
      </div>
    </div>
    {selectedAlert && <AlertDetailModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />}
    </>
  )
}
