import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowUpCircle, Pause, Play, RotateCcw, Trash2, ChevronsRight, PackageCheck } from 'lucide-react'
import { api } from '@/api/client'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { useAuthStore } from '@/stores/auth'

// Actions that change what agents install are confirmed first.
interface Confirm { title: string; body: string; label: string; run: () => Promise<unknown> }

// server-api/app/api/routes/agent_updates.py
interface SignedPackage {
  file: string; version: string; os: string; arch: string; format: string
  size: number; key_id: string; verified: boolean | null; archived: boolean
}
interface Progress {
  agents: number
  states: Record<string, number>
  rings: Record<string, Record<string, number>>
  failures: { agent_id: string; hostname: string; state: string; error: string }[]
}
interface Policy {
  group_id: string; target_version: string; stage: number; paused: boolean
  pause_reason: string | null; revision: number; max_failures: number; progress: Progress
}
interface AgentRow {
  id: string; hostname: string; group_id: string; version: string | null; update_ring: number
  update_status: { state: string; kind: string; target: string; error: string } | null
}

const RINGS = [0, 1, 2]
const RING_NAMES = ['Ring 0 · canary', 'Ring 1 · early', 'Ring 2 · everyone']
// services/agent_update.classify
const STATE_LABELS: Record<string, string> = {
  updated: 'Updated', pending: 'Pending', in_progress: 'Installing', failed: 'Failed', stalled: 'Stalled',
  waiting_ring: 'Waiting for ring', no_package: 'No package', unsupported: 'Unsupported', not_reporting: 'Older agent',
}
const STATE_COLORS: Record<string, string> = {
  updated: '#3ddc84', failed: '#ff5c5c', stalled: '#ff9f43', in_progress: 'var(--accent-cyan)',
}

function errorText(e: unknown): string {
  const d = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof d === 'string' ? d : 'Request rejected'
}

export default function AgentUpdatesPage() {
  const qc = useQueryClient()
  const { user, hasRole } = useAuthStore()
  const canManage = hasRole('admin')
  const packages = useQuery<SignedPackage[]>({
    queryKey: ['agent-update-packages'],
    queryFn: () => api.get('/api/agent-updates/packages').then(r => r.data),
  })
  const policies = useQuery<Policy[]>({
    queryKey: ['agent-update-policies'],
    queryFn: () => api.get('/api/agent-updates/policies').then(r => r.data),
    refetchInterval: 15000,
  })
  const agents = useQuery<{ items: AgentRow[] }>({
    queryKey: ['agents', 'update-rings'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 200 } }).then(r => r.data),
  })
  const versions = useMemo(() => [...new Set((packages.data ?? []).filter(p => p.verified !== false)
    .map(p => p.version))].sort((a, b) => b.localeCompare(a, undefined, { numeric: true })), [packages.data])

  const [group, setGroup] = useState(user?.group_id || 'default')
  const [version, setVersion] = useState('')
  const [maxFailures, setMaxFailures] = useState('1')
  const [error, setError] = useState('')
  const [confirm, setConfirm] = useState<Confirm | null>(null)
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['agent-update-policies'] })
    qc.invalidateQueries({ queryKey: ['agents'] })
  }
  const target = version || versions[0]
  const confirmed = useMutation({
    mutationFn: (c: Confirm) => c.run(),
    onSuccess: () => { setError(''); setConfirm(null); refresh() },
  })
  const act = useMutation({
    mutationFn: ({ g, action }: { g: string; action: string }) =>
      api.post(`/api/agent-updates/policies/${encodeURIComponent(g)}/${action}`),
    onSuccess: () => { setError(''); refresh() },
    onError: e => setError(errorText(e)),
  })
  const policyUrl = (g: string) => `/api/agent-updates/policies/${encodeURIComponent(g)}`
  const ask = (c: Confirm) => { confirmed.reset(); setConfirm(c) }
  const setRing = useMutation({
    mutationFn: ({ id, ring }: { id: string; ring: number }) => api.put(`/api/agents/${id}`, { update_ring: ring }),
    onSuccess: refresh,
    onError: e => setError(errorText(e)),
  })

  return (
    <div style={{ padding: '20px 24px', maxWidth: 1200, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        <ArrowUpCircle size={20} color="var(--accent-cyan)" />
        <h1 style={{ margin: 0, fontSize: 20, letterSpacing: '0.5px' }}>Agent updates</h1>
      </div>
      <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 0, marginBottom: 20 }}>
        Each group runs one target version, offered ring by ring. Agents install only packages signed by a
        key they trust and check the download against the signature, so this page chooses which signed
        release runs, never what is in it. A failed or stalled agent pauses the rollout.
      </p>

      {canManage && (
        <div style={card}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 0.8fr auto', gap: 8, alignItems: 'center' }}>
            <input aria-label="Group" placeholder="group" value={group} onChange={e => setGroup(e.target.value)}
              disabled={user?.role !== 'superadmin'} style={inputStyle} />
            <select aria-label="Target version" value={version || versions[0] || ''}
              onChange={e => setVersion(e.target.value)} style={inputStyle}>
              {!versions.length && <option value="">no signed packages</option>}
              {versions.map(v => <option key={v} value={v}>{v}</option>)}
            </select>
            <input aria-label="Failures before pausing" type="number" min={1} value={maxFailures}
              onChange={e => setMaxFailures(e.target.value)} style={inputStyle} title="failed or stalled agents before the rollout pauses" />
            <button disabled={!versions.length} style={primary} onClick={() => ask({
              title: `Update ${group} to ${target}?`, label: 'Start rollout',
              body: `Ring 0 agents in ${group} install ${target} on their next heartbeat. Open further rings once they report updated. A group already on another target starts over at ring 0.`,
              run: () => api.put(policyUrl(group), { target_version: target, max_failures: Number(maxFailures) || 1 }),
            })}>
              <PackageCheck size={14} /> Set target
            </button>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: 11, margin: '8px 0 0' }}>
            A new target starts at ring 0. Targeting an older version rolls the group back.
          </p>
        </div>
      )}
      {error && <p role="alert" style={{ color: '#ff5c5c', fontSize: 12 }}>{error}</p>}
      {confirm && (
        <WorkspaceDialog title={confirm.title} busy={confirmed.isPending} onClose={() => setConfirm(null)}>
          <p>{confirm.body}</p>
          {confirmed.isError && <p role="alert" className="text-destructive">{errorText(confirmed.error)}</p>}
          <div className="control-cluster justify-end">
            <button className="ui-button" disabled={confirmed.isPending} onClick={() => setConfirm(null)}>Cancel</button>
            <button className="ui-button ui-button--primary" disabled={confirmed.isPending}
              onClick={() => confirmed.mutate(confirm)}>{confirmed.isPending ? 'Submitting…' : confirm.label}</button>
          </div>
        </WorkspaceDialog>
      )}

      {policies.isError ? (
        <p role="alert" style={{ color: '#ff5c5c' }}>Could not load rollouts.</p>
      ) : !policies.data?.length ? (
        <div style={empty}>No rollout yet. Agents keep the version they run until a group gets a target.</div>
      ) : policies.data.map(p => (
        <section key={p.group_id} style={card} aria-label={`Rollout for ${p.group_id}`}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 8 }}>
            <h2 style={{ margin: 0, fontSize: 15 }}>
              {p.group_id} → <span style={{ fontFamily: 'Share Tech Mono, monospace' }}>{p.target_version}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: 11, marginLeft: 8 }}>revision {p.revision}</span>
            </h2>
            {canManage && (
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <button style={secondary} disabled={p.paused || p.stage >= 2} onClick={() => ask({
                  title: `Open ring ${p.stage + 1} in ${p.group_id}?`, label: `Open ring ${p.stage + 1}`,
                  body: `${RING_NAMES[p.stage + 1]} agents install ${p.target_version} on their next heartbeat.`,
                  run: () => api.post(`${policyUrl(p.group_id)}/advance`),
                })}>
                  <ChevronsRight size={14} /> {p.stage >= 2 ? 'All rings' : `Open ring ${p.stage + 1}`}
                </button>
                {p.paused
                  ? <button style={secondary} onClick={() => act.mutate({ g: p.group_id, action: 'resume' })}><Play size={14} /> Resume</button>
                  : <button style={secondary} onClick={() => act.mutate({ g: p.group_id, action: 'pause' })}><Pause size={14} /> Pause</button>}
                <button style={secondary} title="failed agents attempt the update again" onClick={() => ask({
                  title: `Retry ${p.target_version} in ${p.group_id}?`, label: 'Retry',
                  body: 'Failed agents attempt the update again and the rollout resumes. Fix what made them fail first.',
                  run: () => api.post(`${policyUrl(p.group_id)}/retry`),
                })}><RotateCcw size={14} /> Retry failed</button>
                <button style={{ ...secondary, color: '#ff5c5c' }} aria-label={`Stop updates for ${p.group_id}`} onClick={() => ask({
                  title: `Stop updates for ${p.group_id}?`, label: 'Stop updates',
                  body: 'No agent in this group is offered an update until a new target is set. Agents keep the version they run.',
                  run: () => api.delete(policyUrl(p.group_id)),
                })}><Trash2 size={14} /></button>
              </div>
            )}
          </div>
          {p.paused && (
            <p role="status" style={{ color: '#ff9f43', fontSize: 12, margin: '8px 0 0' }}>
              Paused{p.pause_reason ? `: ${p.pause_reason}` : ''}
            </p>
          )}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 8, marginTop: 12 }}>
            {RINGS.map(r => {
              const counts = p.progress.rings[String(r)] ?? {}
              const open = r <= p.stage
              return (
                <div key={r} style={{ border: '1px solid var(--border)', borderRadius: 6, padding: 10, opacity: open ? 1 : 0.6 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1, color: open ? 'var(--accent-cyan)' : 'var(--text-muted)' }}>
                    {RING_NAMES[r].toUpperCase()} {open ? '· OPEN' : ''}
                  </div>
                  {Object.keys(counts).length === 0
                    ? <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>no agents</div>
                    : Object.entries(counts).map(([s, n]) => (
                      <div key={s} style={{ fontSize: 12, marginTop: 4, color: STATE_COLORS[s] ?? 'var(--text)' }}>
                        {STATE_LABELS[s] ?? s}: {n}
                      </div>
                    ))}
                </div>
              )
            })}
          </div>
          {p.progress.failures.length > 0 && (
            <ul style={{ margin: '10px 0 0', paddingLeft: 18, fontSize: 12 }}>
              {p.progress.failures.map(f => (
                <li key={f.agent_id} style={{ color: STATE_COLORS[f.state] }}>
                  {f.hostname} ({STATE_LABELS[f.state]}){f.error ? `: ${f.error}` : ''}
                </li>
              ))}
            </ul>
          )}
        </section>
      ))}

      <h2 style={{ fontSize: 14, margin: '24px 0 8px' }}>Agents and rings</h2>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ background: 'var(--bg-panel)' }}>
            {['HOST', 'GROUP', 'VERSION', 'RING', 'UPDATE'].map(h => <th key={h} style={thStyle}>{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {(agents.data?.items ?? []).map(a => (
            <tr key={a.id} style={{ borderBottom: '1px solid var(--border)' }}>
              <td style={tdStyle}>{a.hostname}</td>
              <td style={tdStyle}>{a.group_id}</td>
              <td style={{ ...tdStyle, fontFamily: 'Share Tech Mono, monospace' }}>{a.version ?? '—'}</td>
              <td style={tdStyle}>
                {canManage ? (
                  <select aria-label={`Ring for ${a.hostname}`} value={a.update_ring ?? 2} style={inputStyle}
                    onChange={e => setRing.mutate({ id: a.id, ring: Number(e.target.value) })}>
                    {RINGS.map(r => <option key={r} value={r}>{RING_NAMES[r]}</option>)}
                  </select>
                ) : RING_NAMES[a.update_ring ?? 2]}
              </td>
              <td style={{ ...tdStyle, color: a.update_status?.state === 'failed' ? '#ff5c5c' : 'var(--text-muted)' }}
                title={a.update_status?.error || undefined}>
                {a.update_status ? `${a.update_status.state}${a.update_status.kind ? ` (${a.update_status.kind})` : ''}` : 'not reported'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 style={{ fontSize: 14, margin: '24px 0 8px' }}>Signed packages</h2>
      {!packages.data?.length ? (
        <div style={empty}>
          No signed packages in the package directory. Releases ship a .sig per package; local builds are
          signed when package-builder runs with SIEM_UPDATE_SIGNING_KEY.
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ background: 'var(--bg-panel)' }}>
              {['FILE', 'VERSION', 'PLATFORM', 'KEY', 'SERVER CHECK'].map(h => <th key={h} style={thStyle}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {packages.data.map(p => (
              <tr key={p.file} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ ...tdStyle, fontFamily: 'Share Tech Mono, monospace' }}>{p.file}{p.archived ? ' (archived)' : ''}</td>
                <td style={tdStyle}>{p.version}</td>
                <td style={tdStyle}>{p.os}/{p.arch} {p.format}</td>
                <td style={{ ...tdStyle, fontFamily: 'Share Tech Mono, monospace' }}>{p.key_id}</td>
                <td style={{ ...tdStyle, color: p.verified === false ? '#ff5c5c' : p.verified ? '#3ddc84' : 'var(--text-muted)' }}>
                  {p.verified === null ? 'not configured' : p.verified ? 'verified' : 'not verified: never offered'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

const card: React.CSSProperties = {
  border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg-card)', padding: 16, marginBottom: 16,
}
const empty: React.CSSProperties = {
  border: '1px dashed var(--border)', borderRadius: 8, padding: 24, textAlign: 'center',
  color: 'var(--text-muted)', fontSize: 13, marginBottom: 16,
}
const inputStyle: React.CSSProperties = {
  padding: '8px 10px', background: 'var(--bg-panel)', border: '1px solid var(--border)',
  borderRadius: 6, color: 'var(--text)', fontSize: 13,
}
const primary: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', background: 'var(--accent-cyan)',
  color: '#001018', border: 'none', borderRadius: 6, fontWeight: 600, cursor: 'pointer',
}
const secondary: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 6, padding: '6px 10px', background: 'var(--bg-panel)',
  color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12, cursor: 'pointer',
}
const thStyle: React.CSSProperties = {
  padding: '8px 12px', textAlign: 'left', fontSize: 10, fontWeight: 700, letterSpacing: '1.5px',
  color: 'var(--text-muted)', borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap',
}
const tdStyle: React.CSSProperties = { padding: '8px 12px', whiteSpace: 'nowrap' }
