import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, X, Plus, ShieldOff, ShieldCheck, Key, Copy, Check, Trash2, RefreshCw, ArrowUpCircle } from 'lucide-react'
import DataTable from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { useAgents } from '@/hooks/useAgents'
import { useAuthStore } from '@/stores/auth'
import { api } from '@/api/client'
import { formatDistanceToNow, format } from 'date-fns'
import type { Agent, AgentPackage } from '@/types'

function fmt(bytes: number) {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024).toFixed(0)} KB`
}

function parseLatestVersion(packages: AgentPackage[]): string | null {
  const versions = packages
    .map(p => { const m = p.filename.match(/siem-agent[_-](\d+\.\d+\.\d+)/); return m ? m[1] : null })
    .filter(Boolean) as string[]
  if (!versions.length) return null
  return versions.sort((a, b) => {
    const pa = a.split('.').map(Number), pb = b.split('.').map(Number)
    for (let i = 0; i < 3; i++) { if (pa[i] !== pb[i]) return pb[i] - pa[i] }
    return 0
  })[0]
}

interface EnrollmentToken {
  id: string
  label: string
  group_id: string
  expires_at: string | null
  is_active: boolean
  used_at: string | null
  used_by_agent_id: string | null
  created_at: string
}

interface CreatedToken extends EnrollmentToken {
  token: string
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button onClick={copy} title="Copy" style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied ? '#4ade80' : 'var(--text-muted)', padding: '2px 4px' }}>
      {copied ? <Check size={13} /> : <Copy size={13} />}
    </button>
  )
}

function TokenBadge({ token }: { token: EnrollmentToken }) {
  const now = new Date()
  const expired = token.expires_at ? new Date(token.expires_at) < now : false
  if (token.used_at) return (
    <span style={{ fontSize: '10px', fontWeight: 700, padding: '1px 6px', borderRadius: '3px', background: 'rgba(100,100,100,0.15)', color: '#888', border: '1px solid rgba(100,100,100,0.3)', fontFamily: 'Rajdhani, sans-serif' }}>USED</span>
  )
  if (!token.is_active || expired) return (
    <span style={{ fontSize: '10px', fontWeight: 700, padding: '1px 6px', borderRadius: '3px', background: 'rgba(239,68,68,0.12)', color: '#f87171', border: '1px solid rgba(239,68,68,0.35)', fontFamily: 'Rajdhani, sans-serif' }}>REVOKED</span>
  )
  return (
    <span style={{ fontSize: '10px', fontWeight: 700, padding: '1px 6px', borderRadius: '3px', background: 'rgba(34,197,94,0.12)', color: '#4ade80', border: '1px solid rgba(34,197,94,0.35)', fontFamily: 'Rajdhani, sans-serif' }}>ACTIVE</span>
  )
}

function TokensModal({ onClose, onUseToken }: { onClose: () => void; onUseToken: () => void }) {
  const qc = useQueryClient()
  const [label, setLabel] = useState('')
  const [groupId, setGroupId] = useState('default')
  const [expiresHours, setExpiresHours] = useState(24)
  const [creating, setCreating] = useState(false)

  const { data: tokens = [], isLoading } = useQuery<EnrollmentToken[]>({
    queryKey: ['enrollment-tokens'],
    queryFn: () => api.get('/api/enrollment-tokens').then(r => r.data),
  })

  const create = useMutation({
    mutationFn: () => api.post('/api/enrollment-tokens', { label, group_id: groupId, expires_hours: expiresHours }).then(r => r.data as CreatedToken),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['enrollment-tokens'] })
      setCreating(false)
      onUseToken()
    },
  })

  const revoke = useMutation({
    mutationFn: (id: string) => api.delete(`/api/enrollment-tokens/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['enrollment-tokens'] }),
  })

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.65)' }} onClick={onClose}>
      <div style={{ width: '100%', maxWidth: '680px', maxHeight: '85vh', display: 'flex', flexDirection: 'column', background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 18px', borderBottom: '1px solid var(--border)', background: 'var(--bg-base)' }}>
          <div>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '15px', color: 'var(--accent-cyan)', letterSpacing: '1px' }}>ENROLLMENT TOKENS</div>
            <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>One-time tokens for agent registration</div>
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button onClick={() => setCreating(true)} style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '5px 12px', borderRadius: '4px', border: '1px solid var(--accent-cyan)', background: 'rgba(0,212,255,0.08)', color: 'var(--accent-cyan)', cursor: 'pointer', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '12px', letterSpacing: '0.5px' }}>
              <Plus size={13} /> GENERATE TOKEN
            </button>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px' }}><X size={18} /></button>
          </div>
        </div>

        {creating && (
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', background: 'rgba(0,212,255,0.03)' }}>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '10px', letterSpacing: '1.5px', color: 'var(--text-muted)', marginBottom: '10px' }}>NEW TOKEN</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 120px', gap: '10px', marginBottom: '10px' }}>
              {[
                { label: 'LABEL', value: label, set: setLabel, placeholder: 'e.g. web-server-01' },
                { label: 'GROUP', value: groupId, set: setGroupId, placeholder: 'default' },
              ].map(({ label: lbl, value, set, placeholder }) => (
                <div key={lbl}>
                  <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', letterSpacing: '1.5px', color: 'var(--text-muted)', marginBottom: '4px' }}>{lbl}</div>
                  <input value={value} onChange={e => set(e.target.value)} placeholder={placeholder} style={{ width: '100%', background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: '4px', padding: '6px 10px', color: 'var(--text-primary)', fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', boxSizing: 'border-box' }} />
                </div>
              ))}
              <div>
                <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', letterSpacing: '1.5px', color: 'var(--text-muted)', marginBottom: '4px' }}>EXPIRY (HOURS)</div>
                <input type="number" value={expiresHours} onChange={e => setExpiresHours(Number(e.target.value))} min={0} style={{ width: '100%', background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: '4px', padding: '6px 10px', color: 'var(--text-primary)', fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', boxSizing: 'border-box' }} />
              </div>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button onClick={() => create.mutate()} disabled={create.isPending} style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '5px 14px', borderRadius: '4px', border: '1px solid var(--accent-cyan)', background: 'rgba(0,212,255,0.1)', color: 'var(--accent-cyan)', cursor: 'pointer', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '12px' }}>
                {create.isPending ? <RefreshCw size={13} className="animate-spin" /> : <Key size={13} />} GENERATE
              </button>
              <button onClick={() => setCreating(false)} style={{ padding: '5px 12px', borderRadius: '4px', border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '12px' }}>CANCEL</button>
            </div>
          </div>
        )}

        <div style={{ overflowY: 'auto', flex: 1 }}>
          {isLoading ? (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px' }}>Loading...</div>
          ) : tokens.length === 0 ? (
            <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px' }}>No tokens yet. Generate one to install agents.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['LABEL', 'GROUP', 'STATUS', 'EXPIRES', 'USED', 'CREATED'].map(h => (
                    <th key={h} style={{ padding: '8px 14px', textAlign: 'left', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', letterSpacing: '1.5px', color: 'var(--text-muted)' }}>{h}</th>
                  ))}
                  <th />
                </tr>
              </thead>
              <tbody>
                {tokens.map(t => (
                  <tr key={t.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <td style={{ padding: '10px 14px', fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--text-primary)' }}>{t.label || <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                    <td style={{ padding: '10px 14px', fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--text-muted)' }}>{t.group_id}</td>
                    <td style={{ padding: '10px 14px' }}><TokenBadge token={t} /></td>
                    <td style={{ padding: '10px 14px', fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
                      {t.expires_at ? format(new Date(t.expires_at), 'MMM d, HH:mm') : 'Never'}
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
                      {t.used_at ? formatDistanceToNow(new Date(t.used_at), { addSuffix: true }) : '—'}
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
                      {formatDistanceToNow(new Date(t.created_at), { addSuffix: true })}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      {t.is_active && !t.used_at && (
                        <button onClick={() => revoke.mutate(t.id)} title="Revoke" style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#f87171', padding: '2px 4px' }}>
                          <Trash2 size={13} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}

function InstallModal({ onClose }: { onClose: () => void }) {
  const { data: packages = [] } = useQuery<AgentPackage[]>({
    queryKey: ['agent-packages'],
    queryFn: () => api.get('/api/agents/packages').then(r => r.data),
  })
  const [tab, setTab] = useState<'deb' | 'rpm'>('deb')

  const pkg = packages.find(p => p.type === tab)
  const serverUrl = window.location.origin
  const installCmd = pkg ? (tab === 'deb' ? 'dpkg -i ' + pkg.filename : 'rpm -i ' + pkg.filename) : ''

  const cmds = pkg
    ? '# 1. Download\n' +
      'wget ' + serverUrl + '/api/agents/packages/' + pkg.filename + '\n\n' +
      '# 2. Install\n' +
      'sudo ' + installCmd + '\n\n' +
      '# 3. Set server URL\n' +
      "sudo sed -i 's|REPLACE_WITH_SERVER_URL|" + serverUrl + "|' /etc/siem-agent/config.yaml\n\n" +
      '# 4. Enable & start\n' +
      'sudo systemctl enable --now siem-agent'
    : null

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.65)' }} onClick={onClose}>
      <div style={{ width: '100%', maxWidth: '620px', background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 18px', borderBottom: '1px solid var(--border)', background: 'var(--bg-base)' }}>
          <div>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '15px', color: 'var(--accent-cyan)', letterSpacing: '1px' }}>INSTALL AGENT</div>
            <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>Deploy the SIEM log collection agent on a host</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px' }}><X size={18} /></button>
        </div>

        <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Package selector */}
          <div>
            <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '10px', letterSpacing: '1.5px', color: 'var(--text-muted)', marginBottom: '10px' }}>STEP 1 — PACKAGE FORMAT</div>
            <div style={{ display: 'flex', gap: '10px' }}>
              {(['deb', 'rpm'] as const).map(t => {
                const p = packages.find(x => x.type === t)
                const active = tab === t
                return (
                  <button key={t} onClick={() => setTab(t)} style={{ flex: 1, padding: '10px 14px', borderRadius: '6px', cursor: 'pointer', border: `1px solid ${active ? 'var(--accent-cyan)' : 'var(--border)'}`, background: active ? 'rgba(0,212,255,0.08)' : 'var(--bg-base)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ textAlign: 'left' }}>
                      <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '13px', color: active ? 'var(--accent-cyan)' : 'var(--text-primary)', letterSpacing: '0.5px' }}>.{t.toUpperCase()}</div>
                      <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)', marginTop: '2px' }}>{t === 'deb' ? 'Debian / Ubuntu' : 'RHEL / CentOS / Rocky'}</div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      {p ? (
                        <>
                          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>{fmt(p.size_bytes)}</div>
                          <a href={`/api/agents/packages/${p.filename}`} download onClick={e => e.stopPropagation()} style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', marginTop: '4px', padding: '3px 8px', borderRadius: '3px', border: `1px solid ${active ? 'var(--accent-cyan)' : 'var(--border)'}`, background: 'transparent', color: active ? 'var(--accent-cyan)' : 'var(--text-muted)', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '9px', letterSpacing: '1px', textDecoration: 'none' }}>
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
          {cmds && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '10px', letterSpacing: '1.5px', color: 'var(--text-muted)' }}>STEP 2 — INSTALL COMMANDS</div>
                <CopyButton text={cmds} />
              </div>
              <pre style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: '5px', padding: '12px 14px', fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--text-primary)', overflowX: 'auto', whiteSpace: 'pre', lineHeight: 1.6, margin: 0 }}>
                {cmds}
              </pre>
            </div>
          )}

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
  const [showTokens, setShowTokens] = useState(false)
  const { data, isLoading } = useAgents(page)
  const { hasRole } = useAuthStore()
  const navigate = useNavigate()
  const qc = useQueryClient()

  const { data: packages = [] } = useQuery<AgentPackage[]>({
    queryKey: ['agent-packages'],
    queryFn: () => api.get('/api/agents/packages').then(r => r.data),
  })
  const latestVersion = parseLatestVersion(packages)

  const isolate = useMutation({
    mutationFn: (id: string) => api.post(`/api/agents/${id}/isolate`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
  const unisolate = useMutation({
    mutationFn: (id: string) => api.delete(`/api/agents/${id}/isolate`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
  const upgrade = useMutation({
    mutationFn: (id: string) => api.post(`/api/agents/${id}/upgrade`).then(r => r.data),
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
    }, {
      key: 'upgrade', header: 'Upgrade', render: (r: Agent) => {
        const hasUpgrade = latestVersion && r.version && r.version !== latestVersion
        if (!hasUpgrade) return <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>—</span>
        return (
          <button
            onClick={e => { e.stopPropagation(); upgrade.mutate(r.id) }}
            disabled={upgrade.isPending}
            title={`Upgrade to ${latestVersion}`}
            style={{
              display: 'flex', alignItems: 'center', gap: '4px',
              padding: '3px 8px', borderRadius: '3px', fontSize: '11px', fontWeight: 700,
              fontFamily: 'Rajdhani, sans-serif', letterSpacing: '0.5px', cursor: 'pointer',
              border: '1px solid rgba(251,191,36,0.5)',
              background: 'rgba(251,191,36,0.08)',
              color: '#fbbf24',
            }}
          >
            {upgrade.isPending ? <RefreshCw size={11} className="animate-spin" /> : <ArrowUpCircle size={11} />}
            {latestVersion}
          </button>
        )
      },
    }] : []),
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Agents</h1>
        <div style={{ display: 'flex', gap: '8px' }}>
          {hasRole('admin') && (
            <button
              onClick={() => setShowTokens(true)}
              style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '6px 12px', borderRadius: '5px', border: '1px solid var(--border)', background: 'var(--bg-base)', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '13px', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, letterSpacing: '0.3px' }}
            >
              <Key size={13} /> Tokens
            </button>
          )}
          <button
            onClick={() => setShowInstall(true)}
            className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm"
          >
            <Plus size={14} /> Install Agent
          </button>
        </div>
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

      {showTokens && (
        <TokensModal
          onClose={() => setShowTokens(false)}
          onUseToken={() => { setShowTokens(false) }}
        />
      )}

      {showInstall && (
        <InstallModal
          onClose={() => setShowInstall(false)}
        />
      )}
    </div>
  )
}
