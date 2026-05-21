import { useState } from 'react'
import { useHygieneLatest } from '@/hooks/useHygiene'
import type { HygieneSnapshot, HygieneIssue, DiskPartition, OpenPort } from '@/types'

const RISKY_PORTS = new Set([21, 22, 23, 25, 445, 3389, 5900, 6379, 9200, 27017])

function scoreColor(score: number) {
  if (score >= 80) return 'var(--accent-green)'
  if (score >= 50) return 'var(--accent-yellow)'
  return 'var(--accent-red)'
}

function severityColor(sev: string) {
  if (sev === 'critical') return 'var(--accent-red)'
  if (sev === 'high') return '#ff6b35'
  if (sev === 'medium') return 'var(--accent-yellow)'
  return 'var(--accent-cyan)'
}

function fmtBytes(mb: number | null) {
  if (mb == null) return '—'
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`
  return `${mb} MB`
}

function DiskBar({ part }: { part: DiskPartition }) {
  const pct = Math.min(part.use_pct, 100)
  const color = pct >= 95 ? 'var(--accent-red)' : pct >= 85 ? '#ff6b35' : pct >= 75 ? 'var(--accent-yellow)' : 'var(--accent-green)'
  return (
    <div style={{ marginBottom: '6px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '2px' }}>
        <span style={{ fontFamily: 'Share Tech Mono, monospace' }}>{part.mount}</span>
        <span style={{ color }}>{pct}% — {fmtBytes(part.used_mb)} / {fmtBytes(part.total_mb)}</span>
      </div>
      <div style={{ height: '4px', background: 'var(--bg-base)', borderRadius: '2px', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: '2px', transition: 'width 0.3s' }} />
      </div>
    </div>
  )
}

function PortTag({ port }: { port: OpenPort }) {
  const risky = RISKY_PORTS.has(port.port)
  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 6px',
      borderRadius: '3px',
      fontFamily: 'Share Tech Mono, monospace',
      fontSize: '10px',
      margin: '2px',
      border: `1px solid ${risky ? 'var(--accent-red)' : 'var(--border)'}`,
      color: risky ? 'var(--accent-red)' : 'var(--text-secondary)',
      background: risky ? 'rgba(255,68,68,0.08)' : 'transparent',
    }}>
      {port.port}/{port.proto}
    </span>
  )
}

function HostCard({ snap, onClick, selected }: { snap: HygieneSnapshot; onClick: () => void; selected: boolean }) {
  const memPct = snap.mem_total_mb && snap.mem_used_mb
    ? Math.round((snap.mem_used_mb / snap.mem_total_mb) * 100) : null

  return (
    <div
      onClick={onClick}
      style={{
        background: 'var(--bg-panel)',
        border: `1px solid ${selected ? 'var(--accent-cyan)' : 'var(--border)'}`,
        borderRadius: '6px',
        padding: '14px',
        cursor: 'pointer',
        transition: 'border-color 0.15s',
        position: 'relative',
      }}
    >
      {/* Score badge */}
      <div style={{
        position: 'absolute',
        top: '12px',
        right: '12px',
        width: '42px',
        height: '42px',
        borderRadius: '50%',
        border: `2px solid ${scoreColor(snap.hygiene_score)}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: scoreColor(snap.hygiene_score),
        fontFamily: 'Share Tech Mono, monospace',
        fontWeight: 700,
        fontSize: '13px',
      }}>
        {snap.hygiene_score}
      </div>

      <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)', marginBottom: '2px', paddingRight: '50px' }}>
        {snap.hostname ?? snap.agent_id.slice(0, 8)}
      </div>
      <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginBottom: '10px' }}>
        {snap.os_name} {snap.os_version} · {snap.arch}
      </div>

      {/* Memory bar */}
      {memPct != null && (
        <div style={{ marginBottom: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '2px' }}>
            <span>MEM</span>
            <span style={{ color: memPct >= 95 ? 'var(--accent-red)' : memPct >= 85 ? 'var(--accent-yellow)' : 'var(--text-secondary)' }}>
              {memPct}% — {fmtBytes(snap.mem_used_mb)} / {fmtBytes(snap.mem_total_mb)}
            </span>
          </div>
          <div style={{ height: '3px', background: 'var(--bg-base)', borderRadius: '2px', overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: `${memPct}%`,
              background: memPct >= 95 ? 'var(--accent-red)' : memPct >= 85 ? 'var(--accent-yellow)' : 'var(--accent-green)',
              borderRadius: '2px',
            }} />
          </div>
        </div>
      )}

      {/* Issue summary */}
      {snap.issues.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
          {snap.issues.slice(0, 3).map((issue, i) => (
            <span key={i} style={{
              padding: '1px 6px',
              borderRadius: '3px',
              fontSize: '9px',
              fontFamily: 'Rajdhani, sans-serif',
              fontWeight: 700,
              letterSpacing: '0.5px',
              background: `${severityColor(issue.severity)}22`,
              color: severityColor(issue.severity),
              border: `1px solid ${severityColor(issue.severity)}55`,
            }}>
              {issue.category.toUpperCase()}
            </span>
          ))}
          {snap.issues.length > 3 && (
            <span style={{ fontSize: '9px', color: 'var(--text-muted)', alignSelf: 'center' }}>
              +{snap.issues.length - 3} more
            </span>
          )}
        </div>
      )}

      <div style={{ marginTop: '8px', fontSize: '9px', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace' }}>
        {new Date(snap.collected_at).toLocaleString()}
      </div>
    </div>
  )
}

function DetailPanel({ snap, onClose }: { snap: HygieneSnapshot; onClose: () => void }) {
  return (
    <div style={{
      width: '380px',
      flexShrink: 0,
      background: 'var(--bg-panel)',
      border: '1px solid var(--border)',
      borderRadius: '6px',
      overflow: 'hidden',
      display: 'flex',
      flexDirection: 'column',
    }}>
      {/* Header */}
      <div style={{
        padding: '12px 14px',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'var(--bg-base)',
      }}>
        <div>
          <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '15px', color: 'var(--accent-cyan)' }}>
            {snap.hostname ?? snap.agent_id.slice(0, 8)}
          </div>
          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
            Score: <span style={{ color: scoreColor(snap.hygiene_score), fontWeight: 700 }}>{snap.hygiene_score}</span>
            {' · '}{snap.kernel}
          </div>
        </div>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '16px', cursor: 'pointer' }}
        >✕</button>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '14px' }}>
        {/* System info */}
        <div style={{ marginBottom: '16px' }}>
          <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '8px' }}>
            SYSTEM INFO
          </div>
          <table style={{ width: '100%', fontSize: '11px', borderCollapse: 'collapse' }}>
            <tbody>
              {[
                ['OS', `${snap.os_name ?? '—'} ${snap.os_version ?? ''}`],
                ['Kernel', snap.kernel ?? '—'],
                ['Arch', snap.arch ?? '—'],
                ['CPUs', snap.cpu_count != null ? String(snap.cpu_count) : '—'],
                ['Uptime', snap.uptime_seconds != null ? `${Math.floor(snap.uptime_seconds / 3600)}h ${Math.floor((snap.uptime_seconds % 3600) / 60)}m` : '—'],
              ].map(([k, v]) => (
                <tr key={k}>
                  <td style={{ color: 'var(--text-muted)', padding: '2px 8px 2px 0', width: '70px', fontFamily: 'Share Tech Mono, monospace', fontSize: '10px' }}>{k}</td>
                  <td style={{ color: 'var(--text-primary)', padding: '2px 0' }}>{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Issues */}
        {snap.issues.length > 0 && (
          <div style={{ marginBottom: '16px' }}>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '8px' }}>
              ISSUES ({snap.issues.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {snap.issues.map((issue: HygieneIssue, i: number) => (
                <div key={i} style={{
                  padding: '8px 10px',
                  borderRadius: '4px',
                  border: `1px solid ${severityColor(issue.severity)}44`,
                  background: `${severityColor(issue.severity)}0d`,
                }}>
                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center', marginBottom: '2px' }}>
                    <span style={{
                      padding: '1px 5px',
                      borderRadius: '2px',
                      fontSize: '9px',
                      fontFamily: 'Rajdhani, sans-serif',
                      fontWeight: 700,
                      letterSpacing: '0.5px',
                      color: severityColor(issue.severity),
                      border: `1px solid ${severityColor(issue.severity)}66`,
                    }}>
                      {issue.severity.toUpperCase()}
                    </span>
                    <span style={{ fontSize: '10px', color: 'var(--text-secondary)', fontFamily: 'Rajdhani, sans-serif', fontWeight: 600 }}>
                      {issue.category}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-primary)', lineHeight: 1.4 }}>
                    {issue.message}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Disk */}
        {snap.disk_partitions.length > 0 && (
          <div style={{ marginBottom: '16px' }}>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '8px' }}>
              DISK USAGE
            </div>
            {snap.disk_partitions.map((p: DiskPartition, i: number) => (
              <DiskBar key={i} part={p} />
            ))}
          </div>
        )}

        {/* Open ports */}
        {snap.open_ports.length > 0 && (
          <div style={{ marginBottom: '16px' }}>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '8px' }}>
              LISTENING PORTS
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap' }}>
              {snap.open_ports
                .slice()
                .sort((a: OpenPort, b: OpenPort) => (RISKY_PORTS.has(b.port) ? 1 : 0) - (RISKY_PORTS.has(a.port) ? 1 : 0))
                .map((p: OpenPort, i: number) => <PortTag key={i} port={p} />)}
            </div>
          </div>
        )}

        {/* Local users */}
        {snap.users.length > 0 && (
          <div>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '8px' }}>
              LOCAL USERS ({snap.users.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
              {snap.users.map((u, i) => (
                <div key={i} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  padding: '4px 8px',
                  borderRadius: '3px',
                  background: 'var(--bg-base)',
                  fontSize: '10px',
                  fontFamily: 'Share Tech Mono, monospace',
                }}>
                  <span style={{ color: 'var(--text-primary)' }}>{u.name}</span>
                  <span style={{ color: 'var(--text-muted)' }}>uid:{u.uid} · {u.shell.split('/').pop()}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function HygienePage() {
  const { data: snapshots = [], isLoading, isError } = useHygieneLatest()
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const selected = snapshots.find(s => s.agent_id === selectedId) ?? null

  const avgScore = snapshots.length
    ? Math.round(snapshots.reduce((acc, s) => acc + s.hygiene_score, 0) / snapshots.length)
    : null

  const critical = snapshots.filter(s => s.issues.some(i => i.severity === 'critical')).length
  const totalIssues = snapshots.reduce((acc, s) => acc + s.issues.length, 0)

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '20px', color: 'var(--accent-cyan)', letterSpacing: '2px', textTransform: 'uppercase', margin: 0 }}>
            IT HYGIENE
          </h1>
          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Host health snapshots · auto-refresh 5 min
          </div>
        </div>
        {avgScore != null && (
          <div style={{ display: 'flex', gap: '16px' }}>
            {[
              { label: 'HOSTS', value: snapshots.length, color: 'var(--text-primary)' },
              { label: 'AVG SCORE', value: avgScore, color: scoreColor(avgScore) },
              { label: 'ISSUES', value: totalIssues, color: totalIssues > 0 ? 'var(--accent-yellow)' : 'var(--accent-green)' },
              { label: 'CRITICAL HOSTS', value: critical, color: critical > 0 ? 'var(--accent-red)' : 'var(--accent-green)' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ textAlign: 'center' }}>
                <div style={{ fontFamily: 'Share Tech Mono, monospace', fontWeight: 700, fontSize: '20px', color, lineHeight: 1 }}>{value}</div>
                <div style={{ fontFamily: 'Rajdhani, sans-serif', fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '1px', marginTop: '2px' }}>{label}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Body */}
      {isLoading ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px' }}>
          LOADING HYGIENE DATA...
        </div>
      ) : isError ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-red)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px' }}>
          FAILED TO LOAD HYGIENE SNAPSHOTS
        </div>
      ) : snapshots.length === 0 ? (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '8px', color: 'var(--text-muted)' }}>
          <div style={{ fontSize: '32px' }}>🛡</div>
          <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '16px', letterSpacing: '1px' }}>NO HYGIENE DATA YET</div>
          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px' }}>Agents send their first snapshot 30 seconds after enrollment.</div>
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', gap: '12px', overflow: 'hidden' }}>
          {/* Host grid */}
          <div style={{ flex: 1, overflow: 'auto' }}>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
              gap: '10px',
              alignContent: 'start',
            }}>
              {snapshots.map(snap => (
                <HostCard
                  key={snap.agent_id}
                  snap={snap}
                  selected={selectedId === snap.agent_id}
                  onClick={() => setSelectedId(selectedId === snap.agent_id ? null : snap.agent_id)}
                />
              ))}
            </div>
          </div>

          {/* Detail panel */}
          {selected && (
            <DetailPanel snap={selected} onClose={() => setSelectedId(null)} />
          )}
        </div>
      )}
    </div>
  )
}
