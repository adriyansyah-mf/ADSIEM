import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, ShieldOff, ShieldCheck, Check, KeyRound, X } from 'lucide-react'
import DataTable from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { useAgents } from '@/hooks/useAgents'
import { useAuthStore } from '@/stores/auth'
import { api } from '@/api/client'
import { formatDistanceToNow } from 'date-fns'
import DeployAgentModal from '@/components/DeployAgentModal'
import type { Agent } from '@/types'

export default function AgentsPage() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [showInstall, setShowInstall] = useState(false)
  const [tokenFor, setTokenFor] = useState<Agent | null>(null)
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const { data, isLoading } = useAgents(page, pageSize, search, statusFilter)

  useEffect(() => {
    const t = setTimeout(() => { setSearch(searchInput); setPage(1) }, 300)
    return () => clearTimeout(t)
  }, [searchInput])
  const { hasRole } = useAuthStore()
  const navigate = useNavigate()
  const qc = useQueryClient()

  const isolate = useMutation({
    mutationFn: (id: string) => api.post(`/api/agents/${id}/isolate`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
  const approve = useMutation({
    mutationFn: (id: string) => api.post(`/api/agents/${id}/approve`).then(r => r.data),
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
        {r.approved === false && (
          <span title="Enrolled with a key that requires approval: logs are dropped and no tasks are sent until approved"
            style={{ fontSize: '10px', fontWeight: 700, letterSpacing: '0.5px', padding: '1px 6px', borderRadius: '3px', background: 'rgba(251,191,36,0.15)', color: '#fbbf24', border: '1px solid rgba(251,191,36,0.4)', fontFamily: 'Rajdhani, sans-serif' }}>
            PENDING
          </span>
        )}
        {r.approved === false && hasRole('admin') && (
          <button onClick={e => { e.stopPropagation(); approve.mutate(r.id) }} disabled={approve.isPending}
            className="flex items-center gap-1 px-2 py-0.5 rounded border border-border text-xs hover:bg-muted">
            <Check size={11} /> Approve
          </button>
        )}
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
      key: 'uninstall', header: 'Uninstall', render: (r: Agent) => (
        <button onClick={e => { e.stopPropagation(); setTokenFor(r) }}
          title="Show the token needed to uninstall this agent (agent 1.8.0+)"
          className="flex items-center gap-1 px-2 py-0.5 rounded border border-border text-xs hover:bg-muted">
          <KeyRound size={11} /> Token
        </button>
      ),
    }] : []),
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Agents</h1>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={searchInput}
            onChange={e => setSearchInput(e.target.value)}
            placeholder="Search name or hostname..."
            className="px-3 py-1.5 rounded border border-border bg-background text-sm"
          />
          <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1) }}
            className="px-3 py-1.5 rounded border border-border bg-background text-sm">
            <option value="">All statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
          </select>
          <button
            onClick={() => setShowInstall(true)}
            className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm"
          >
            <Plus size={14} /> Deploy agent
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
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={(s) => { setPageSize(s); setPage(1) }}
          onRowClick={hasRole('admin') ? (r) => navigate(`/agents/${r.id}/sources`) : undefined}
        />
      )}

      {showInstall && <DeployAgentModal onClose={() => setShowInstall(false)} />}
      {tokenFor && <UninstallTokenModal agent={tokenFor} onClose={() => setTokenFor(null)} />}
    </div>
  )
}

interface UninstallToken {
  token: string
  commands: { windows: string; debian: string; rhel: string }
}

function UninstallTokenModal({ agent, onClose }: { agent: Agent; onClose: () => void }) {
  const { data, error, isLoading } = useQuery<UninstallToken>({
    queryKey: ['uninstall-token', agent.id],
    queryFn: () => api.get(`/api/agents/${agent.id}/uninstall-token`).then(r => r.data),
    gcTime: 0,
  })
  const mono: React.CSSProperties = { fontFamily: 'Share Tech Mono, monospace' }
  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50, padding: '16px' }}>
      <div onClick={e => e.stopPropagation()} className="rounded border border-border bg-background"
        style={{ width: 'min(640px, 100%)', padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <div className="flex items-center justify-between">
          <h2 className="font-bold">Uninstall token · {agent.hostname}</h2>
          <button onClick={onClose} className="text-muted-foreground"><X size={16} /></button>
        </div>
        <p className="text-sm text-muted-foreground">
          Removing the agent package (1.8.0+) is refused without this token, so a local admin can&apos;t quietly
          uninstall it. Viewing it is recorded in the audit log.
        </p>
        {isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
        {error && <div className="text-sm" style={{ color: 'var(--accent-red)' }}>Could not load the token</div>}
        {data && (
          <>
            <div style={{ ...mono, fontSize: '18px', letterSpacing: '1px', padding: '8px 10px', border: '1px solid var(--border)', borderRadius: '4px' }}>
              {data.token}
            </div>
            {([['Windows', data.commands.windows], ['Debian / Ubuntu', data.commands.debian], ['RHEL / Fedora', data.commands.rhel]] as const).map(([os, cmd]) => (
              <div key={os}>
                <div className="text-xs text-muted-foreground">{os}</div>
                <pre style={{ ...mono, fontSize: '12px', margin: 0, padding: '6px 8px', whiteSpace: 'pre-wrap', wordBreak: 'break-all', border: '1px solid var(--border)', borderRadius: '4px' }}>{cmd}</pre>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  )
}
