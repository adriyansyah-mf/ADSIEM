import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Plus } from 'lucide-react'
import { S } from './styles'
import { ConditionRow } from './ConditionRow'
import { ActionRow } from './ActionRow'
import { ACTION_TYPES, emptyTrigger, generateId, type Action, type Playbook, type TriggerConditions } from './types'

export function PlaybookEditor({ playbook, onClose }: { playbook: Playbook | null; onClose: () => void }) {
  const qc = useQueryClient()
  const isNew = playbook === null

  const [name, setName] = useState(playbook?.name ?? '')
  const [description, setDescription] = useState(playbook?.description ?? '')
  const [deletedActionIds, setDeletedActionIds] = useState<string[]>([])

  const normalizeConditions = (tc: TriggerConditions): TriggerConditions => ({
    ...tc,
    conditions: tc.conditions.map(c => ({ ...c, id: generateId() })),
  })

  const [trigger, setTrigger] = useState<TriggerConditions>(
    playbook?.trigger_conditions ? normalizeConditions(playbook.trigger_conditions) : emptyTrigger()
  )
  const [actions, setActions] = useState<Action[]>(playbook?.actions ?? [])

  const savePlaybook = useMutation({
    mutationFn: async () => {
      if (isNew) {
        const resp = await api.post('/api/soar/playbooks', { name, description, trigger_conditions: trigger })
        const pb = resp.data
        for (const act of actions) {
          await api.post(`/api/soar/playbooks/${pb.id}/actions`, {
            action_type: act.action_type, order_index: act.order_index, params: act.params,
          })
        }
      } else {
        await api.patch(`/api/soar/playbooks/${playbook!.id}`, { name, description, trigger_conditions: trigger })
        for (const id of deletedActionIds) {
          await api.delete(`/api/soar/actions/${id}`)
        }
        for (const act of actions) {
          if (act.id.startsWith('new-')) {
            await api.post(`/api/soar/playbooks/${playbook!.id}/actions`, {
              action_type: act.action_type, order_index: act.order_index, params: act.params,
            })
          } else {
            await api.patch(`/api/soar/actions/${act.id}`, { params: act.params, order_index: act.order_index })
          }
        }
      }
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['soar-playbooks'] }); onClose() },
  })

  const addCondition = () =>
    setTrigger(t => ({ ...t, conditions: [...t.conditions, { id: generateId(), field: 'severity', operator: 'eq', value: 'high' }] }))

  const addAction = (type: string) =>
    setActions(a => [...a, { id: `new-${Date.now()}`, action_type: type, order_index: a.length, params: {} }])

  const removeAction = (act: Action) => {
    if (!act.id.startsWith('new-')) {
      setDeletedActionIds(ids => [...ids, act.id])
    }
    setActions(a => a.filter(x => x.id !== act.id))
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 10, padding: 24, width: 680, maxHeight: '90vh', overflow: 'auto' }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 20 }}>
          {isNew ? 'New Playbook' : 'Edit Playbook'}
        </div>

        <div style={{ marginBottom: 14 }}>
          <div style={S.label}>Name</div>
          <input style={S.input} value={name} onChange={e => setName(e.target.value)} />
        </div>
        <div style={{ marginBottom: 20 }}>
          <div style={S.label}>Description</div>
          <input style={S.input} value={description} onChange={e => setDescription(e.target.value)} />
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>Trigger Conditions</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Match</span>
              <select style={S.select} value={trigger.match} onChange={e => setTrigger(t => ({ ...t, match: e.target.value as 'all' | 'any' }))}>
                <option value="all">ALL</option>
                <option value="any">ANY</option>
              </select>
              <button style={S.btn('var(--border)')} onClick={addCondition}><Plus size={13} /> Add</button>
            </div>
          </div>
          {trigger.conditions.length === 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>No conditions — playbook fires on every alert</div>
          )}
          {trigger.conditions.map((c, i) => (
            <ConditionRow
              key={c.id}
              cond={c}
              onChange={nc => setTrigger(t => ({ ...t, conditions: t.conditions.map((x, j) => j === i ? nc : x) }))}
              onRemove={() => setTrigger(t => ({ ...t, conditions: t.conditions.filter((_, j) => j !== i) }))}
            />
          ))}
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>Actions</div>
            <select
              style={S.select}
              onChange={e => { if (e.target.value) { addAction(e.target.value); e.target.value = '' } }}
              defaultValue=""
            >
              <option value="" disabled>+ Add action</option>
              {ACTION_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          {actions.length === 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>No actions defined</div>
          )}
          {actions.map((act, i) => (
            <ActionRow
              key={act.id}
              action={{ ...act, order_index: i }}
              onUpdate={params => setActions(a => a.map(x => x.id === act.id ? { ...x, params } : x))}
              onRemove={() => removeAction(act)}
            />
          ))}
        </div>

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button style={{ ...S.btn('var(--border)'), color: 'var(--text-secondary)' }} onClick={onClose}>Cancel</button>
          <button style={S.btn()} onClick={() => savePlaybook.mutate()} disabled={!name.trim()}>
            {savePlaybook.isPending ? 'Saving...' : 'Save Playbook'}
          </button>
        </div>
      </div>
    </div>
  )
}
