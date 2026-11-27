import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { format } from 'date-fns'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { useFimEvents } from '@/hooks/useFim'
import { CanvasHeader, CanvasPage, Chip, Empty, Meter, SectionTitle, severityTone, type Tone } from '@/components/canvas/Canvas'
import { useHygieneLatest, useAgentVulns } from '@/hooks/useHygiene'
import type { HygieneSnapshot, HygieneIssue, DiskPartition, OpenPort, InstalledPackage, VulnerablePackage, HostNetwork } from '@/types'

// Same list as the agent's scoring (agent/internal/hygiene/score.go).
const RISKY_PORTS = new Set([21, 23, 25, 135, 139, 445, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017])

// Reachable from other hosts: bound to anything but loopback (unknown: assume so).
function exposed(p: OpenPort) {
  if (!p.addr) return true
  return !(p.addr.startsWith('127.') || p.addr === '::1')
}

function riskyExposed(p: OpenPort) {
  return RISKY_PORTS.has(p.port) && exposed(p)
}

function scoreColor(score: number) {
  if (score >= 80) return 'var(--accent-green)'
  if (score >= 50) return 'var(--accent-yellow)'
  return 'var(--accent-red)'
}

function severityColor(sev: string) {
  const s = sev.toLowerCase()
  if (s === 'critical') return 'var(--accent-red)'
  if (s === 'high') return '#ff6b35'
  if (s === 'medium') return 'var(--accent-yellow)'
  return 'var(--accent-cyan)'
}

function fmtBytes(mb: number | null) {
  if (mb == null) return '—'
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`
  return `${mb} MB`
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', color: 'var(--text-muted)', letterSpacing: '1px', marginBottom: '8px' }}>
      {children}
    </div>
  )
}

function DiskBar({ part }: { part: DiskPartition }) {
  const pct = Math.min(part.use_pct, 100)
  const color = pct >= 95 ? 'var(--accent-red)' : pct >= 85 ? '#ff6b35' : pct >= 75 ? 'var(--accent-yellow)' : 'var(--accent-green)'
  return (
    <div style={{ marginBottom: '6px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '2px' }}>
        <span style={{ fontFamily: 'Share Tech Mono, monospace' }}>{part.mount}</span>
        <span style={{ color }}>{pct.toFixed(0)}% — {fmtBytes(part.used_mb)} / {fmtBytes(part.total_mb)}</span>
      </div>
      <div style={{ height: '4px', background: 'var(--bg-base)', borderRadius: '2px', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: '2px', transition: 'width 0.3s' }} />
      </div>
    </div>
  )
}

function PortTag({ port }: { port: OpenPort }) {
  const risky = riskyExposed(port)
  const local = !exposed(port)
  const where = [port.process, port.addr && `on ${port.addr}`].filter(Boolean).join(' ')
  return (
    <span title={local ? 'Bound to loopback: not reachable from other hosts' : where || undefined} style={{
      display: 'inline-block', padding: '1px 6px', borderRadius: '3px',
      fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', margin: '2px',
      border: `1px solid ${risky ? 'var(--accent-red)' : 'var(--border)'}`,
      color: risky ? 'var(--accent-red)' : local ? 'var(--text-muted, #6b7280)' : 'var(--text-secondary)',
      background: risky ? 'rgba(255,68,68,0.08)' : 'transparent',
    }}>
      {port.port}/{port.proto}{port.process ? ` ${port.process}` : ''}{port.addr ? ` @${port.addr}` : ''}
    </span>
  )
}

function KV({ k, v }: { k: string; v?: string | null }) {
  if (!v) return null
  return (
    <div style={{ display: 'flex', gap: '8px', fontSize: '11px', marginBottom: '3px' }}>
      <span style={{ color: 'var(--text-secondary)', minWidth: '96px' }}>{k}</span>
      <span style={{ fontFamily: 'Share Tech Mono, monospace', color: 'var(--text-primary)', wordBreak: 'break-all' }}>{v}</span>
    </div>
  )
}

// The host's IPv4 addresses (no loopback or link-local), else the address
// the server saw its reports come from (agents before 1.27.6).
function hostIPs(net?: HostNetwork | null): string[] {
  if (!net) return []
  const v4 = (net.interfaces ?? [])
    .flatMap(i => i.addrs)
    .map(a => a.split('/')[0])
    .filter(a => a.includes('.') && !a.startsWith('127.') && !a.startsWith('169.254.'))
  if (v4.length) return v4
  return net.seen_from ? [net.seen_from] : []
}

function NetworkSection({ net }: { net: HostNetwork }) {
  const ifaces = net.interfaces ?? []
  const sessions = net.sessions ?? []
  return (
    <>
      <div style={{ marginBottom: '16px' }}>
        <SectionLabel>NETWORK</SectionLabel>
        <KV k="FQDN" v={net.fqdn} />
        <KV k="Domain" v={net.domain} />
        <KV k="Seen from" v={net.seen_from} />
        <KV k="Gateway" v={net.default_gateway} />
        <KV k="DNS" v={(net.dns_servers ?? []).join(', ')} />
        <KV k="Time zone" v={[net.timezone, net.utc_offset && `(UTC${net.utc_offset})`].filter(Boolean).join(' ')} />
        <KV k="Booted" v={net.boot_time && new Date(net.boot_time).toLocaleString()} />
        {ifaces.map(i => (
          <KV key={i.name} k={i.name + (i.up ? '' : ' (down)')} v={[...i.addrs, i.mac].filter(Boolean).join('  ')} />
        ))}
      </div>
      {sessions.length > 0 && (
        <div style={{ marginBottom: '16px' }}>
          <SectionLabel>LOGGED-IN SESSIONS ({sessions.length})</SectionLabel>
          {sessions.map((s, i) => (
            <KV key={i} k={s.user} v={[s.line, s.from && `from ${s.from}`, s.since && `since ${new Date(s.since).toLocaleString()}`]
              .filter(Boolean).join('  ')} />
          ))}
        </div>
      )}
    </>
  )
}

function PackagesTab({ snap, agentId }: { snap: HygieneSnapshot; agentId: string }) {
  const [search, setSearch] = useState('')
  const [showVulnOnly, setShowVulnOnly] = useState(false)
  const { data: vulnReport, isLoading: vulnLoading } = useAgentVulns(agentId, snap.packages.length > 0)

  const vulnMap = new Map<string, VulnerablePackage>()
  vulnReport?.vulnerable.forEach(v => vulnMap.set(v.package.name, v))

  const filtered = snap.packages.filter(p => {
    if (showVulnOnly && !vulnMap.has(p.name)) return false
    if (search && !p.name.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const vuln_count = vulnReport?.vulnerable_count ?? 0

  return (
    <div>
      {/* OSV summary bar */}
      <div style={{
        padding: '8px 10px', borderRadius: '4px', marginBottom: '10px',
        background: vuln_count > 0 ? 'rgba(255,68,68,0.07)' : 'rgba(0,255,136,0.06)',
        border: `1px solid ${vuln_count > 0 ? 'rgba(255,68,68,0.3)' : 'rgba(0,255,136,0.2)'}`,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px' }}>
          {vulnLoading ? (
            <span style={{ color: 'var(--text-muted)' }}>Querying osv.dev...</span>
          ) : vulnReport ? (
            <>
              <span style={{ color: 'var(--text-muted)' }}>{vulnReport.package_count} packages scanned · </span>
              <span style={{ color: vuln_count > 0 ? 'var(--accent-red)' : 'var(--accent-green)', fontWeight: 700 }}>
                {vuln_count} vulnerable
              </span>
              <span style={{ color: 'var(--text-muted)' }}> via osv.dev</span>
            </>
          ) : (
            <span style={{ color: 'var(--text-muted)' }}>{snap.packages.length} packages · OSV scan pending</span>
          )}
        </div>
        {vuln_count > 0 && (
          <button
            onClick={() => setShowVulnOnly(v => !v)}
            style={{
              background: showVulnOnly ? 'rgba(255,68,68,0.2)' : 'transparent',
              border: '1px solid rgba(255,68,68,0.4)',
              borderRadius: '3px', padding: '2px 8px',
              color: 'var(--accent-red)', fontFamily: 'Rajdhani, sans-serif',
              fontWeight: 700, fontSize: '9px', letterSpacing: '0.5px', cursor: 'pointer',
            }}
          >
            {showVulnOnly ? 'SHOW ALL' : 'VULN ONLY'}
          </button>
        )}
      </div>

      {/* Search */}
      <input
        value={search}
        onChange={e => setSearch(e.target.value)}
        placeholder="Filter packages..."
        style={{
          width: '100%', boxSizing: 'border-box', marginBottom: '8px',
          background: 'var(--bg-base)', border: '1px solid var(--border)',
          borderRadius: '4px', padding: '5px 8px', color: 'var(--text-primary)',
          fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', outline: 'none',
        }}
      />

      {/* Package list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', maxHeight: '340px', overflowY: 'auto' }}>
        {filtered.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', textAlign: 'center', padding: '12px 0' }}>
            {snap.packages.length === 0 ? 'No packages collected yet' : 'No matches'}
          </div>
        ) : filtered.map((pkg: InstalledPackage, i: number) => {
          const vuln = vulnMap.get(pkg.name)
          return (
            <div key={i} style={{
              display: 'flex', alignItems: 'flex-start', gap: '6px',
              padding: '4px 6px', borderRadius: '3px',
              background: vuln ? 'rgba(255,68,68,0.05)' : 'var(--bg-base)',
              border: `1px solid ${vuln ? 'rgba(255,68,68,0.2)' : 'transparent'}`,
            }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{
                    fontFamily: 'Share Tech Mono, monospace', fontSize: '10px',
                    color: vuln ? 'var(--accent-red)' : 'var(--text-primary)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {pkg.name}
                  </span>
                  <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)', flexShrink: 0 }}>
                    {pkg.version}
                  </span>
                </div>
                {vuln && (
                  <div style={{ marginTop: '3px', display: 'flex', flexDirection: 'column', gap: '2px' }}>
                    {vuln.vulns.map((v, vi) => (
                      <div key={vi} style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <span style={{
                          padding: '0px 4px', borderRadius: '2px', fontSize: '8px',
                          fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, letterSpacing: '0.5px',
                          color: severityColor(v.severity),
                          border: `1px solid ${severityColor(v.severity)}55`,
                          background: `${severityColor(v.severity)}11`,
                          flexShrink: 0,
                        }}>
                          {v.severity}
                        </span>
                        <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--accent-cyan)', flexShrink: 0 }}>
                          {v.id}
                        </span>
                        <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {v.summary}
                        </span>
                      </div>
                    ))}
                    {vuln.vuln_count > vuln.vulns.length && (
                      <span style={{ fontSize: '9px', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace' }}>
                        +{vuln.vuln_count - vuln.vulns.length} more CVEs
                      </span>
                    )}
                  </div>
                )}
              </div>
              <span style={{
                padding: '0px 4px', borderRadius: '2px', fontSize: '8px',
                fontFamily: 'Rajdhani, sans-serif', fontWeight: 600, letterSpacing: '0.5px',
                color: 'var(--text-muted)', border: '1px solid var(--border)',
                flexShrink: 0, alignSelf: 'flex-start', marginTop: '2px',
              }}>
                {pkg.source}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function DetailPanel({ snap, onClose }: { snap: HygieneSnapshot; onClose: () => void }) {
  const [tab, setTab] = useState<'overview' | 'packages'>('overview')

  return (
    <div style={{
      width: '420px', flexShrink: 0,
      background: 'var(--bg-panel)', border: '1px solid var(--border)',
      borderRadius: '6px', overflow: 'hidden', display: 'flex', flexDirection: 'column',
    }}>
      {/* Header */}
      <div style={{
        padding: '12px 14px', borderBottom: '1px solid var(--border)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
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
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '16px', cursor: 'pointer' }}>✕</button>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-base)' }}>
        {(['overview', 'packages'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              flex: 1, padding: '8px', background: 'none', border: 'none',
              borderBottom: tab === t ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              color: tab === t ? 'var(--accent-cyan)' : 'var(--text-muted)',
              fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px',
              letterSpacing: '1px', cursor: 'pointer', textTransform: 'uppercase',
            }}
          >
            {t === 'packages' ? `PACKAGES (${snap.packages.length})` : 'OVERVIEW'}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '14px' }}>
        {tab === 'overview' ? (
          <>
            {/* System info */}
            <div style={{ marginBottom: '16px' }}>
              <SectionLabel>SYSTEM INFO</SectionLabel>
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
                <SectionLabel>ISSUES ({snap.issues.length})</SectionLabel>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {snap.issues.map((issue: HygieneIssue, i: number) => (
                    <div key={i} style={{
                      padding: '8px 10px', borderRadius: '4px',
                      border: `1px solid ${severityColor(issue.severity)}44`,
                      background: `${severityColor(issue.severity)}0d`,
                    }}>
                      <div style={{ display: 'flex', gap: '6px', alignItems: 'center', marginBottom: '2px' }}>
                        <span style={{
                          padding: '1px 5px', borderRadius: '2px', fontSize: '9px',
                          fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, letterSpacing: '0.5px',
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

            {snap.network && <NetworkSection net={snap.network} />}

            {/* Disk */}
            {snap.disk_partitions.length > 0 && (
              <div style={{ marginBottom: '16px' }}>
                <SectionLabel>DISK USAGE</SectionLabel>
                {snap.disk_partitions.map((p: DiskPartition, i: number) => <DiskBar key={i} part={p} />)}
              </div>
            )}

            {/* Memory detail */}
            {snap.mem_total_mb != null && (
              <div style={{ marginBottom: '16px' }}>
                <SectionLabel>MEMORY</SectionLabel>
                {(() => {
                  const pct = snap.mem_used_mb != null ? Math.round((snap.mem_used_mb / snap.mem_total_mb!) * 100) : 0
                  const color = pct >= 95 ? 'var(--accent-red)' : pct >= 85 ? 'var(--accent-yellow)' : 'var(--accent-green)'
                  return (
                    <>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                        <span>Used: {fmtBytes(snap.mem_used_mb)} / {fmtBytes(snap.mem_total_mb)}</span>
                        <span style={{ color }}>{pct}%</span>
                      </div>
                      <div style={{ height: '5px', background: 'var(--bg-base)', borderRadius: '3px', overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: '3px' }} />
                      </div>
                    </>
                  )
                })()}
              </div>
            )}

            {/* Open ports */}
            {snap.open_ports.length > 0 && (
              <div style={{ marginBottom: '16px' }}>
                <SectionLabel>LISTENING PORTS ({snap.open_ports.length})</SectionLabel>
                <div style={{ display: 'flex', flexWrap: 'wrap' }}>
                  {snap.open_ports
                    .slice()
                    .sort((a: OpenPort, b: OpenPort) => (riskyExposed(b) ? 2 : exposed(b) ? 1 : 0) - (riskyExposed(a) ? 2 : exposed(a) ? 1 : 0))
                    .map((p: OpenPort, i: number) => <PortTag key={i} port={p} />)}
                </div>
              </div>
            )}

            {/* Local users */}
            {snap.users.length > 0 && (
              <div>
                <SectionLabel>LOCAL USERS ({snap.users.length})</SectionLabel>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  {snap.users.map((u, i) => (
                    <div key={i} style={{
                      display: 'flex', justifyContent: 'space-between',
                      padding: '4px 8px', borderRadius: '3px',
                      background: 'var(--bg-base)', fontSize: '10px',
                      fontFamily: 'Share Tech Mono, monospace',
                    }}>
                      <span style={{ color: u.uid === 0 ? 'var(--accent-red)' : 'var(--text-primary)' }}>{u.name}</span>
                      <span style={{ color: 'var(--text-muted)' }}>uid:{u.uid} · {u.shell.split('/').pop()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        ) : (
          <PackagesTab snap={snap} agentId={snap.agent_id} />
        )}
      </div>
    </div>
  )
}

function HostCard({ snap, onClick, selected }: { snap: HygieneSnapshot; onClick: () => void; selected: boolean }) {
  const memPct = snap.mem_total_mb && snap.mem_used_mb
    ? Math.round((snap.mem_used_mb / snap.mem_total_mb) * 100) : null

  return (
    <div
      onClick={onClick}
      style={{
        background: 'var(--bg-panel)', border: `1px solid ${selected ? 'var(--accent-cyan)' : 'var(--border)'}`,
        borderRadius: '6px', padding: '14px', cursor: 'pointer',
        transition: 'border-color 0.15s', position: 'relative',
      }}
    >
      <div style={{
        position: 'absolute', top: '12px', right: '12px',
        width: '42px', height: '42px', borderRadius: '50%',
        border: `2px solid ${scoreColor(snap.hygiene_score)}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: scoreColor(snap.hygiene_score),
        fontFamily: 'Share Tech Mono, monospace', fontWeight: 700, fontSize: '13px',
      }}>
        {snap.hygiene_score}
      </div>

      <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)', marginBottom: '2px', paddingRight: '50px' }}>
        {snap.hostname ?? snap.agent_id.slice(0, 8)}
      </div>
      <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginBottom: hostIPs(snap.network).length ? '2px' : '10px' }}>
        {snap.os_name} {snap.os_version} · {snap.arch}
      </div>
      {hostIPs(snap.network).length > 0 && (
        <div title={snap.network?.seen_from ? `Reports from ${snap.network.seen_from}` : undefined} style={{
          fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-secondary)',
          marginBottom: '10px', wordBreak: 'break-all',
        }}>
          {hostIPs(snap.network).join(' · ')}{snap.network?.fqdn ? ` · ${snap.network.fqdn}` : ''}
        </div>
      )}

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
              height: '100%', width: `${memPct}%`,
              background: memPct >= 95 ? 'var(--accent-red)' : memPct >= 85 ? 'var(--accent-yellow)' : 'var(--accent-green)',
              borderRadius: '2px',
            }} />
          </div>
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: snap.issues.length > 0 ? '8px' : '0' }}>
        {snap.packages.length > 0 && (
          <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)' }}>
            {snap.packages.length} pkgs
          </span>
        )}
      </div>

      {snap.issues.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
          {snap.issues.slice(0, 3).map((issue, i) => (
            <span key={i} style={{
              padding: '1px 6px', borderRadius: '3px', fontSize: '9px',
              fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, letterSpacing: '0.5px',
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

interface VulnSummary { cves: number; by_priority: Record<string, number>; kev: number; hosts: number }
interface VulnItem { cve_id: string; title: string | null; priority: string; kev: boolean; hosts: number; hostnames: string[]; packages: string[]; fixes: string[] }

const SEV_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }

function postureTone(score: number): Tone {
  return score >= 80 ? 'good' : score >= 60 ? 'yellow' : 'warn'
}

export default function HygienePage() {
  const { data: snapshots = [], isLoading, isError } = useHygieneLatest()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const vulns = useQuery<{ summary: VulnSummary; items: VulnItem[] }>({
    queryKey: ['vulnerabilities', 'posture'],
    queryFn: () => api.get('/api/vulnerabilities', { params: { limit: 6 } }).then(r => r.data),
    retry: false,
    staleTime: 5 * 60_000,
  })
  const fim = useFimEvents()
  const selected = snapshots.find(s => s.agent_id === selectedId) ?? null

  const avgScore = snapshots.length ? Math.round(snapshots.reduce((acc, s) => acc + s.hygiene_score, 0) / snapshots.length) : null
  const failing = snapshots.reduce((acc, s) => acc + s.issues.length, 0)
  const latestScan = snapshots.reduce<string | null>((max, s) => !max || s.collected_at > max ? s.collected_at : max, null)

  // Category score: share of hosts with no finding in that category.
  const categories = useMemo(() => {
    const names = [...new Set(snapshots.flatMap(s => s.issues.map(i => i.category)))]
    return names.map(name => ({
      name,
      score: Math.round((snapshots.filter(s => !s.issues.some(i => i.category === name)).length / Math.max(1, snapshots.length)) * 100),
    })).sort((a, b) => a.score - b.score).slice(0, 6)
  }, [snapshots])

  // Fix first: configuration findings grouped by message, and the top CVEs, ranked by severity × hosts.
  const fixes = useMemo(() => {
    const byMessage = new Map<string, { title: string; category: string; severity: string; hosts: Set<string> }>()
    for (const snap of snapshots) {
      for (const issue of snap.issues) {
        const entry = byMessage.get(issue.message) ?? { title: issue.message, category: issue.category, severity: issue.severity, hosts: new Set<string>() }
        entry.hosts.add(snap.hostname ?? snap.agent_id)
        if ((SEV_WEIGHT[issue.severity] ?? 0) > (SEV_WEIGHT[entry.severity] ?? 0)) entry.severity = issue.severity
        byMessage.set(issue.message, entry)
      }
    }
    const config = [...byMessage.values()].map(e => ({
      key: `cfg-${e.title}`, title: e.title, detail: e.category, type: 'Configuration', tone: 'info' as Tone,
      hosts: e.hosts.size, severity: e.severity, rank: (SEV_WEIGHT[e.severity] ?? 1) * e.hosts.size, href: undefined as string | undefined,
    }))
    const cves = (vulns.data?.items ?? []).map(v => ({
      key: `cve-${v.cve_id}`, title: v.title ? `${v.cve_id} · ${v.title}` : v.cve_id,
      detail: `${v.packages.slice(0, 2).join(', ')}${v.fixes.length ? ` · fix: ${v.fixes.slice(0, 2).join(', ')}` : ''}${v.kev ? ' · known exploited' : ''}`,
      type: 'Vulnerability', tone: 'bad' as Tone, hosts: v.hosts, severity: v.priority,
      rank: ((SEV_WEIGHT[v.priority] ?? 1) + (v.kev ? 2 : 0)) * v.hosts, href: `/vulnerabilities?q=${encodeURIComponent(v.cve_id)}`,
    }))
    return [...cves, ...config].sort((a, b) => b.rank - a.rank).slice(0, 8)
  }, [snapshots, vulns.data])

  const since = Date.now() - 86_400_000
  const recentFim = (fim.data ?? []).filter(e => Date.parse(e.detected_at) >= since)
  const hostOf = (agentId: string) => snapshots.find(s => s.agent_id === agentId)?.hostname ?? agentId.slice(0, 8)
  const byPriority = vulns.data?.summary.by_priority ?? {}

  return (
    <CanvasPage>
      <CanvasHeader
        title="Security posture"
        sub={`Configuration checks, vulnerabilities and file integrity from ${snapshots.length} agents${latestScan ? ` · last snapshot ${format(new Date(latestScan), 'HH:mm')}` : ''}`}
        counts={{ '/hygiene': failing || null, '/vulnerabilities': byPriority.critical ?? null, '/fim': recentFim.length || null }}
        actions={<Link className="cv-btn" to="/vulnerabilities">Scan for vulnerabilities</Link>}
      />
      <div className="cv-body">
        {isLoading ? <Empty>Loading posture…</Empty> : isError ? <Empty>Could not load hygiene snapshots.</Empty> : snapshots.length === 0 ? (
          <Empty>No hygiene data yet. Agents send their first snapshot 30 seconds after enrollment.</Empty>
        ) : <>
          <div className="cv-cols">
            <section className="cv-card" style={{ flex: '1 1 300px', maxWidth: 380 }}>
              <h2>Posture score</h2>
              <p style={{ margin: 0 }}>
                <span className={`cv-t-${postureTone(avgScore ?? 0)}`} style={{ fontSize: 40, fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{avgScore}</span>
                <span className="cv-muted" style={{ fontSize: 18 }}> / 100</span>
              </p>
              <span className="cv-muted cv-small">Average of {snapshots.length} host scores · {failing} findings open</span>
              <div className="cv-stack" style={{ gap: 10, marginTop: 6 }}>
                {categories.map(c => (
                  <div key={c.name} className="cv-stack" style={{ gap: 4 }}>
                    <span className="cv-row cv-row--between"><span className="cv-dim" style={{ textTransform: 'capitalize' }}>{c.name.replace(/_/g, ' ')}</span><span className="cv-mono">{c.score}</span></span>
                    <Meter value={c.score} tone={postureTone(c.score)} />
                  </div>
                ))}
                {categories.length === 0 && <span className="cv-t-good cv-small">No failing checks.</span>}
              </div>
            </section>
            <section className="cv-main" aria-label="Fix first">
              <div className="cv-row cv-row--between"><h2 className="cv-h2">Fix first · ranked by severity and reach</h2><Link to="/vulnerabilities">All vulnerabilities</Link></div>
              <div className="cv-tablewrap">
                <table className="cv-table" style={{ minWidth: 560 }}>
                  <thead><tr><th>Finding</th><th>Type</th><th className="is-num">Hosts</th><th>Severity</th></tr></thead>
                  <tbody>
                    {fixes.map(f => (
                      <tr key={f.key}>
                        <td>
                          <div className="cv-stack">
                            {f.href ? <Link to={f.href} style={{ color: '#E8ECF2', fontWeight: 500 }}>{f.title}</Link> : <span style={{ fontWeight: 500 }}>{f.title}</span>}
                            {f.detail && <span className="cv-muted cv-small" style={{ textTransform: f.type === 'Configuration' ? 'capitalize' : undefined }}>{f.detail.replace(/_/g, ' ')}</span>}
                          </div>
                        </td>
                        <td><Chip tone={f.tone}>{f.type}</Chip></td>
                        <td className="is-num">{f.hosts}</td>
                        <td><Chip tone={severityTone(f.severity)}>{f.severity}</Chip></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {fixes.length === 0 && <Empty>Nothing to fix right now.</Empty>}
              </div>
            </section>
          </div>

          <div className="cv-cols">
            <section className="cv-card" style={{ flex: '1 1 320px' }}>
              <div className="cv-card__head"><h2>Vulnerabilities by priority</h2><Link to="/vulnerabilities">Open</Link></div>
              {vulns.data ? <div className="cv-row" style={{ gap: 22 }}>
                {(['critical', 'high', 'medium', 'low'] as const).map(p => (
                  <span key={p} className="cv-stack">
                    <strong className={`cv-t-${severityTone(p)}`} style={{ fontSize: 22 }}>{byPriority[p] ?? 0}</strong>
                    <span className="cv-muted cv-small" style={{ textTransform: 'capitalize' }}>{p}{p === 'critical' && vulns.data.summary.kev ? ` · ${vulns.data.summary.kev} known exploited` : ''}</span>
                  </span>
                ))}
              </div> : <span className="cv-muted cv-small">{vulns.isError ? 'Vulnerability data unavailable.' : 'Loading…'}</span>}
            </section>
            <section className="cv-card" style={{ flex: '1 1 320px' }}>
              <div className="cv-card__head"><h2>File integrity, last 24 h</h2><Link to="/fim">Open</Link></div>
              <div className="cv-kv">
                {recentFim.slice(0, 5).map(e => (
                  <div key={e.id}>
                    <span className="cv-mono" style={{ color: '#C9D0DB', overflowWrap: 'anywhere', textAlign: 'left' }}>{e.path}</span>
                    <span className={e.event_type === 'CREATE' ? 'cv-t-bad' : e.event_type === 'MODIFY' ? 'cv-t-warn' : 'cv-dim'} style={{ whiteSpace: 'nowrap' }}>
                      {e.event_type.toLowerCase()} · {hostOf(e.agent_id)}
                    </span>
                  </div>
                ))}
                {recentFim.length === 0 && <span className="cv-muted cv-small">No watched file changed in the last 24 h.</span>}
              </div>
            </section>
          </div>

          <SectionTitle>Hosts · {snapshots.length}</SectionTitle>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
            <div style={{ flex: 1, display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10, alignContent: 'start' }}>
              {snapshots.map(snap => (
                <HostCard key={snap.agent_id} snap={snap} selected={selectedId === snap.agent_id}
                  onClick={() => setSelectedId(selectedId === snap.agent_id ? null : snap.agent_id)} />
              ))}
            </div>
            {selected && <DetailPanel snap={selected} onClose={() => setSelectedId(null)} />}
          </div>
        </>}
      </div>
    </CanvasPage>
  )
}
