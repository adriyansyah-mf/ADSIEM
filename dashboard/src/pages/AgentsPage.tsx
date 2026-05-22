import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, X, Plus, ShieldOff, ShieldCheck } from 'lucide-react'
import DataTable from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { useAgents } from '@/hooks/useAgents'
import { useAuthStore } from '@/stores/auth'
import { api } from '@/api/client'
import { formatDistanceToNow } from 'date-fns'
import type { Agent, AgentPackage } from '@/types'

function fmt(bytes: number) {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024).toFixed(0)} KB`
}

function InstallModal({ onClose }: { onClose: () => void }) {
  const { data: packages = [] } = useQuery<AgentPackage[]>({
    queryKey: ['agent-packages'],
    queryFn: () => api.get('/api/agents/packages').then(r => r.data),
  })
  const [tab, setTab] = useState<'deb' | 'rpm'>('deb')

  const pkg = packages.find(p => p.type === tab)
  const serverUrl = window.location.origin
  const enrollToken = 'bootstrap-token'

  const cmds = pkg
    ? `# 1. Download
wget ${serverUrl}/api/agents/packages/${pkg.filename}

# 2. Install
sudo ${tab === 'deb' ? `dpkg -i ${pkg.filename}` : `rpm -i ${pkg.filename}`}

# 3. Configure
sudo sed -i 's|server_url:.*|server_url: ${serverUrl}|' /etc/siem-agent/config.yaml
sudo sed -i 's|enrollment_token:.*|enrollment_token: ${enrollToken}|' /etc/siem-agent/config.yaml

# 4. Enable & start
sudo systemctl enable --now siem-agent`
    : 'Package not available.'

  return (
    <div
      style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.65)' }}
      onClick={onClose}
    >
      <div
        style={{ width: '100%', maxWidth: '640px', background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 18px', borderBottom: '1px solid var(--border)', background: 'var(--bg-base)' }}>
          <div>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '15px', color: 'var(--accent-cyan)', letterSpacing: '1px' }}>
              INSTALL AGENT
            </div>
            <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Deploy the SIEM log collection agent on a host
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px' }}>
            <X size={18} />
          </button>
        </div>

        <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* Package type selector */}
          <div>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '10px', letterSpacing: '1.5px', color: 'var(--text-muted)', marginBottom: '10px' }}>
              PACKAGE FORMAT
            </div>
            <div style={{ display: 'flex', gap: '10px' }}>
              {(['deb', 'rpm'] as const).map(t => {
                const p = packages.find(x => x.type === t)
                const active = tab === t
                return (
                  <button
                    key={t}
                    onClick={() => setTab(t)}
                    style={{
                      flex: 1, padding: '12px 14px', borderRadius: '6px', cursor: 'pointer',
                      border: `1px solid ${active ? 'var(--accent-cyan)' : 'var(--border)'}`,
                      background: active ? 'rgba(0,212,255,0.08)' : 'var(--bg-base)',
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    }}
                  >
                    <div style={{ textAlign: 'left' }}>
                      <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '13px', color: active ? 'var(--accent-cyan)' : 'var(--text-primary)', letterSpacing: '0.5px' }}>
                        .{t.toUpperCase()}
                      </div>
                      <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {t === 'deb' ? 'Debian / Ubuntu' : 'RHEL / CentOS / Rocky'}
                      </div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      {p ? (
                        <>
                          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>{fmt(p.size_bytes)}</div>
                          <a
                            href={`/api/agents/packages/${p.filename}`}
                            download
                            onClick={e => e.stopPropagation()}
                            style={{
                              display: 'inline-flex', alignItems: 'center', gap: '4px',
                              marginTop: '4px', padding: '3px 8px', borderRadius: '3px',
                              border: `1px solid ${active ? 'var(--accent-cyan)' : 'var(--border)'}`,
                              background: 'transparent',
                              color: active ? 'var(--accent-cyan)' : 'var(--text-muted)',
                              fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px',
                              letterSpacing: '1px', textDecoration: 'none',
                            }}
                          >
                            <Download size={10} /> DOWNLOAD
                          </a>
                        </>
                      ) : (
                        <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)' }}>not available</div>
                      )}
                    </div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Install commands */}
          <div>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '10px', letterSpacing: '1.5px', color: 'var(--text-muted)', marginBottom: '8px' }}>
              INSTALL COMMANDS
            </div>
            <pre style={{
              background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: '5px',
              padding: '12px 14px', fontFamily: 'Share Tech Mono, monospace', fontSize: '11px',
              color: 'var(--text-primary)', overflowX: 'auto', whiteSpace: 'pre', lineHeight: 1.6, margin: 0,
            }}>
              {cmds}
            </pre>
          </div>

          {/* Enrollment info */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            {[
              { label: 'SERVER URL', value: serverUrl },
              { label: 'ENROLLMENT TOKEN', value: enrollToken },
            ].map(({ label, value }) => (
              <div key={label} style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: '5px', padding: '10px 12px' }}>
                <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', letterSpacing: '1.5px', color: 'var(--text-muted)', marginBottom: '4px' }}>{label}</div>
                <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>{value}</div>
              </div>
            ))}
          </div>

          {/* Hints */}
          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', padding: '8px 10px', background: 'rgba(0,212,255,0.04)', border: '1px solid rgba(0,212,255,0.15)', borderRadius: '4px' }}>
            Config: <span style={{ color: 'var(--text-primary)' }}>/etc/siem-agent/config.yaml</span>
            &nbsp;&middot;&nbsp;
            Logs: <span style={{ color: 'var(--text-primary)' }}>journalctl -u siem-agent -f</span>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function AgentsPage() {
  const [page, setPage] = useState(1)
  const [showInstall, setShowInstall] = useState(false)
  const { data, isLoading } = useAgents(page)
  const { hasRole } = useAuthStore()
  const navigate = useNavigate()
  const qc = useQueryClient()

  const isolate = useMutation({
    mutationFn: (id: string) => api.post(`/api/agents/${id}/isolate`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
  const unisolate = useMutation({
    mutationFn: (id: string) => api.delete(`/api/agents/${id}/isolate`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const columns = [
    { key: 'name', header: 'Name', render: (r: Agent) => r.name },
    { key: 'hostname', header: 'Hostname', render: (r: Agent) => r.hostname },
    { key: 'group', header: 'Group', render: (r: Agent) => r.group_id },
    { key: 'status', header: 'Status', render: (r: Agent) => (
      <div className="flex items-center gap-2">
        <StatusBadge status={r.status} />
        {r.is_isolated && (
          <span style={{ fontSize: '10px', fontWeight: 700, letterSpacing: '0.5px', padding: '1px 6px', borderRadius: '3px', background: 'rgba(239,68,68,0.15)', color: '#f87171', border: '1px solid rgba(239,68,68,0.4)', fontFamily: 'Rajdhani, sans-serif' }}>
            ISOLATED
          </span>
        )}
      </div>
    )},
    { key: 'version', header: 'Version', render: (r: Agent) => r.version ?? '—' },
    { key: 'last_seen', header: 'Last Seen', render: (r: Agent) =>
      r.last_seen_at ? formatDistanceToNow(new Date(r.last_seen_at), { addSuffix: true }) : 'Never'
    },
    { key: 'sources', header: 'Sources', render: (r: Agent) => r.log_sources.length },
    ...(hasRole('admin') ? [{
      key: 'isolate', header: 'Isolate', render: (r: Agent) => (
        <button
          onClick={e => { e.stopPropagation(); r.is_isolated ? unisolate.mutate(r.id) : isolate.mutate(r.id) }}
          disabled={isolate.isPending || unisolate.isPending}
          title={r.is_isolated ? 'Lift isolation' : 'Isolate host'}
          style={{
            display: 'flex', alignItems: 'center', gap: '4px',
            padding: '3px 8px', borderRadius: '3px', fontSize: '11px', fontWeight: 700,
            fontFamily: 'Rajdhani, sans-serif', letterSpacing: '0.5px', cursor: 'pointer',
            border: r.is_isolated ? '1px solid rgba(34,197,94,0.5)' : '1px solid rgba(239,68,68,0.5)',
            background: r.is_isolated ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
            color: r.is_isolated ? '#4ade80' : '#f87171',
          }}
        >
          {r.is_isolated ? <><ShieldCheck size={11} /> LIFT</> : <><ShieldOff size={11} /> ISOLATE</>}
        </button>
      ),
    }] : []),
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Agents</h1>
        <button
          onClick={() => setShowInstall(true)}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm"
        >
          <Plus size={14} /> Install Agent
        </button>
      </div>

      {isLoading ? (
        <div className="text-muted-foreground">Loading...</div>
      ) : (
        <DataTable
          columns={columns}
          data={data?.items ?? []}
          total={data?.total ?? 0}
          page={page}
          pageSize={25}
          onPageChange={setPage}
          onRowClick={hasRole('admin') ? (r) => navigate(`/agents/${r.id}/sources`) : undefined}
        />
      )}

      {showInstall && <InstallModal onClose={() => setShowInstall(false)} />}
    </div>
  )
}
