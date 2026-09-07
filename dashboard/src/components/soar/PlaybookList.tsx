import type { UseMutationResult } from '@tanstack/react-query'
import { Shield, Trash2, ToggleLeft, ToggleRight } from 'lucide-react'
import { S } from './styles'
import type { Playbook } from './types'

export function PlaybookList({
  playbooks, isLoading, onEdit, toggle, del,
}: {
  playbooks: Playbook[]
  isLoading: boolean
  onEdit: (pb: Playbook) => void
  toggle: UseMutationResult<unknown, unknown, { id: string; enabled: boolean }>
  del: UseMutationResult<unknown, unknown, string>
}) {
  if (isLoading) {
    return <div style={{ color: 'var(--text-secondary)', fontSize: 13 }}>Loading...</div>
  }

  if (playbooks.length === 0) {
    return (
      <div style={{ ...S.card, textAlign: 'center', padding: 48 }}>
        <Shield size={32} color="var(--text-muted)" style={{ margin: '0 auto 12px' }} />
        <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>No playbooks defined yet.</div>
        <div style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 4 }}>
          Create a playbook to automate responses to alerts.
        </div>
      </div>
    )
  }

  return (
    <>
      {playbooks.map(pb => (
        <div key={pb.id} style={S.card}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span style={{ fontSize: 14, fontWeight: 600, color: pb.is_enabled ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                  {pb.name}
                </span>
                <span style={{
                  fontSize: 11, padding: '1px 8px', borderRadius: 3,
                  background: pb.is_enabled ? 'rgba(46,212,122,0.12)' : 'var(--border)',
                  color: pb.is_enabled ? 'var(--accent-green)' : 'var(--text-muted)',
                }}>
                  {pb.is_enabled ? 'ENABLED' : 'DISABLED'}
                </span>
              </div>
              {pb.description && (
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8 }}>{pb.description}</div>
              )}
              <div style={{ display: 'flex', gap: 12, fontSize: 12, color: 'var(--text-muted)' }}>
                <span>{pb.trigger_conditions?.conditions?.length ?? 0} condition(s)</span>
                <span>·</span>
                <span>{pb.actions.length} action(s)</span>
                <span>·</span>
                <span>Match: {pb.trigger_conditions?.match?.toUpperCase() ?? 'ALL'}</span>
              </div>
              {pb.actions.length > 0 && (
                <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {pb.actions.map(a => (
                    <span key={a.id} style={{
                      fontSize: 11, background: 'var(--bg-panel)', border: '1px solid var(--border)',
                      borderRadius: 4, padding: '2px 8px', color: 'var(--accent-blue)',
                    }}>
                      {a.action_type}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 6, marginLeft: 16 }}>
              <button
                style={S.ghost}
                title={pb.is_enabled ? 'Disable' : 'Enable'}
                onClick={() => toggle.mutate({ id: pb.id, enabled: !pb.is_enabled })}
              >
                {pb.is_enabled
                  ? <ToggleRight size={18} color="var(--accent-green)" />
                  : <ToggleLeft size={18} color="var(--text-muted)" />}
              </button>
              <button style={S.ghost} onClick={() => onEdit(pb)}>
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Edit</span>
              </button>
              <button style={S.ghost} onClick={() => { if (confirm(`Delete "${pb.name}"?`)) del.mutate(pb.id) }}>
                <Trash2 size={14} color="var(--accent-red)" />
              </button>
            </div>
          </div>
        </div>
      ))}
    </>
  )
}
