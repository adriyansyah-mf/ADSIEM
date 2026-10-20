import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'
import { CheckCircle2, Hand, Plus, Shield, Trash2, Workflow, X } from 'lucide-react'
import {
  useCreatePlaybook, useDecideRun, useDeletePlaybook, usePlaybooks, useUpdatePlaybook, useWaitingRuns,
} from '@/hooks/useSoar'
import { useAuthStore } from '@/stores/auth'
import { NODE_META, defaultGraph } from '@/components/soar/meta'
import { S } from '@/components/soar/ui'
import type { Playbook, Run } from '@/types/soar'

const EVENT_LABEL: Record<string, string> = {
  'alert.created': 'on new alert',
  'alert.triaged': 'after AI triage',
  manual: 'manual only',
}

function Approvals({ runs, playbooks, canEdit }: { runs: Run[]; playbooks: Playbook[]; canEdit: boolean }) {
  const decide = useDecideRun()
  if (!runs.length) return null
  const name = (id: string) => playbooks.find(p => p.id === id)?.name ?? 'playbook'
  return (
    <div style={{ ...S.card, borderColor: 'var(--accent-yellow)', marginBottom: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, color: 'var(--accent-yellow)', fontWeight: 700, fontSize: 13 }}>
        <Hand size={15} /> {runs.length} run{runs.length > 1 ? 's' : ''} waiting for approval
      </div>
      {runs.map(r => (
        <div key={r.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderTop: '1px solid var(--border)', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 220 }}>
            <div style={{ fontSize: 13, color: 'var(--text-primary)' }}>{r.approval?.message ?? 'Approval needed'}</div>
            <div style={S.hint}>
              {name(r.playbook_id)} · times out{' '}
              {r.wait_until ? formatDistanceToNow(new Date(r.wait_until), { addSuffix: true }) : ''}
            </div>
          </div>
          <Link to={`/soar/${r.playbook_id}?run=${r.id}`} style={{ ...S.ghost, textDecoration: 'none' }}>Open</Link>
          {canEdit && (
            <>
              <button style={S.btn('var(--accent-green)')} disabled={decide.isPending}
                onClick={() => decide.mutate({ runId: r.id, decision: 'approved' })}><CheckCircle2 size={13} /> Approve</button>
              <button style={S.btn('var(--accent-red)', '#fff')} disabled={decide.isPending}
                onClick={() => decide.mutate({ runId: r.id, decision: 'rejected' })}><X size={13} /> Reject</button>
            </>
          )}
        </div>
      ))}
    </div>
  )
}

export default function SoarPage() {
  const navigate = useNavigate()
  const canEdit = useAuthStore(s => s.hasRole('admin'))
  const playbooks = usePlaybooks()
  const waiting = useWaitingRuns()
  const create = useCreatePlaybook()
  const update = useUpdatePlaybook()
  const del = useDeletePlaybook()
  const [newName, setNewName] = useState('')
  const [adding, setAdding] = useState(false)

  const submit = () => {
    if (!newName.trim()) return
    create.mutate({ name: newName.trim(), graph: defaultGraph() }, {
      onSuccess: pb => navigate(`/soar/${pb.id}`),
    })
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 6 }}>
        <Shield size={20} color="var(--accent-cyan)" />
        <h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 20, color: 'var(--accent-cyan)',
          letterSpacing: 2, textTransform: 'uppercase', margin: 0 }}>SOAR Workflows</h1>
        {canEdit && (
          <button style={{ ...S.btn(), marginLeft: 'auto' }} onClick={() => setAdding(v => !v)}><Plus size={13} /> New workflow</button>
        )}
      </div>
      <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: '0 0 16px' }}>
        Workflows run on alerts: branch with If, enrich, ask the AI, wait for an analyst, act on the agent, call any API
        and pass its answer along.
      </p>

      {adding && (
        <div style={{ ...S.card, display: 'flex', gap: 8, marginBottom: 16 }}>
          <input autoFocus style={S.input} placeholder="Workflow name, e.g. Block brute-force IPs after approval"
            value={newName} onChange={e => setNewName(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') submit() }} />
          <button style={S.btn()} disabled={!newName.trim() || create.isPending} onClick={submit}>Create</button>
        </div>
      )}

      <Approvals runs={waiting.data ?? []} playbooks={playbooks.data ?? []} canEdit={canEdit} />

      {playbooks.isLoading && <div style={S.hint}>Loading…</div>}
      {playbooks.data?.length === 0 && (
        <div style={{ ...S.card, textAlign: 'center', color: 'var(--text-secondary)', fontSize: 13 }}>
          No workflows yet.{canEdit ? ' Create one to start.' : ''}
        </div>
      )}

      <div style={{ display: 'grid', gap: 10 }}>
        {playbooks.data?.map(pb => {
          const types = [...new Set(pb.graph.nodes.filter(n => n.type !== 'trigger').map(n => n.type))]
          return (
            <div key={pb.id} style={{ ...S.card, display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap',
              opacity: pb.is_enabled ? 1 : 0.6 }}>
              <Workflow size={18} color="var(--accent-cyan)" />
              <div style={{ flex: 1, minWidth: 220 }}>
                <Link to={`/soar/${pb.id}`} style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', textDecoration: 'none' }}>
                  {pb.name}
                </Link>
                {pb.legacy && <span style={{ marginLeft: 8, fontSize: 10, color: 'var(--accent-yellow)' }}>OLD EDITOR</span>}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{EVENT_LABEL[pb.trigger_event] ?? pb.trigger_event}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>· {pb.graph.nodes.length - 1} steps</span>
                  {types.map(t => {
                    const Icon = NODE_META[t].icon
                    return <span key={t} title={NODE_META[t].label}><Icon size={13} color={NODE_META[t].color} /></span>
                  })}
                </div>
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
                <input type="checkbox" checked={pb.is_enabled} disabled={!canEdit}
                  onChange={e => update.mutate({ id: pb.id, data: { is_enabled: e.target.checked } })} />
                enabled
              </label>
              <Link to={`/soar/${pb.id}`} style={{ ...S.ghost, textDecoration: 'none' }}>Open</Link>
              {canEdit && (
                <button style={S.ghost} title="Delete" disabled={del.isPending}
                  onClick={() => { if (window.confirm(`Delete “${pb.name}” and its run history?`)) del.mutate(pb.id) }}>
                  <Trash2 size={13} />
                </button>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
