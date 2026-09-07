import type { UseMutationResult } from '@tanstack/react-query'
import { S } from './styles'
import type { SoarExecution } from './types'

export function ExecutionsPanel({
  executions, approve, rollback,
}: {
  executions: SoarExecution[]
  approve: UseMutationResult<unknown, unknown, { id: string; key: string }>
  rollback: UseMutationResult<unknown, unknown, { id: string; key: string }>
}) {
  return (
    <div style={{ ...S.card, marginTop: 24 }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>Recent executions</div>
      {executions.length === 0 && <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No SOAR executions yet.</div>}
      {executions.map(run => (
        <div key={run.id} style={{ borderTop: '1px solid var(--border)', padding: '12px 0' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <div style={{ color: 'var(--text-primary)', fontSize: 13, fontWeight: 600 }}>{run.trigger_type} · {run.status}</div>
              <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>{new Date(run.started_at).toLocaleString()}</div>
            </div>
            <div style={{ display: 'grid', gap: 6, minWidth: 260 }}>
              {run.steps.map(step => (
                <div key={step.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, fontSize: 12 }}>
                  <span style={{ color: 'var(--text-secondary)' }}>{step.action_type} · {step.status}</span>
                  <div style={{ display: 'flex', gap: 4 }}>
                    {step.status === 'pending_approval' && (
                      <button style={S.btn()} onClick={() => approve.mutate({ id: run.id, key: step.idempotency_key })} disabled={approve.isPending}>Approve</button>
                    )}
                    {step.status === 'succeeded' && step.is_reversible && (
                      <button style={S.btn('var(--accent-red)')} onClick={() => rollback.mutate({ id: run.id, key: `rollback-${step.id}` })} disabled={rollback.isPending}>Rollback</button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
