import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Shield, Plus, Trash2, ToggleLeft, ToggleRight, ChevronDown, ChevronRight } from 'lucide-react'

const TRIGGER_FIELDS = ['severity', 'rule_title', 'source_ip', 'hostname', 'user_name', 'tags', 'mitre_tags']
const OPERATORS = ['eq', 'neq', 'contains', 'in', 'not_null']
const ACTION_TYPES = ['enrich_ioc', 'send_webhook', 'create_case', 'suppress_alert', 'add_note']

interface Condition {
  field: string
  operator: string
  value: string | string[] | null
}

interface TriggerConditions {
  match: 'all' | 'any'
  conditions: Condition[]
}

interface Action {
  id: string
  action_type: string
  order_index: number
  params: Record<string, string>
}

interface Playbook {
  id: string
  name: string
  description: string | null
  trigger_conditions: TriggerConditions
  is_enabled: boolean
  group_id: string
  created_at: string
  actions: Action[]
}

const emptyTrigger = (): TriggerConditions => ({ match: 'all', conditions: [] })

const S = {
  card: { background: '#161920', border: '1px solid #1e2028', borderRadius: 8, padding: 16, marginBottom: 12 } as React.CSSProperties,
  label: { fontSize: 11, color: '#64748b', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, marginBottom: 4 },
  input: {
    background: '#0d0f14', border: '1px solid #1e2028', borderRadius: 6,
    color: '#e2e8f0', fontSize: 13, padding: '6px 10px', width: '100%', outline: 'none',
  } as React.CSSProperties,
  select: {
    background: '#0d0f14', border: '1px solid #1e2028', borderRadius: 6,
    color: '#e2e8f0', fontSize: 13, padding: '6px 8px',
  } as React.CSSProperties,
  btn: (color = '#3b82f6') => ({
    padding: '6px 14px', borderRadius: 6, border: 'none',
    background: color, color: '#fff', fontSize: 12, fontWeight: 600,
    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
  } as React.CSSProperties),
  ghost: { padding: '4px 8px', borderRadius: 4, border: 'none', background: 'transparent', cursor: 'pointer', color: '#64748b' } as React.CSSProperties,
}

function ConditionRow({
  cond, onChange, onRemove,
}: { cond: Condition; onChange: (c: Condition) => void; onRemove: () => void }) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
      <select style={S.select} value={cond.field} onChange={e => onChange({ ...cond, field: e.target.value })}>
        {TRIGGER_FIELDS.map(f => <option key={f}>{f}</option>)}
      </select>
      <select style={S.select} value={cond.operator} onChange={e => onChange({ ...cond, operator: e.target.value })}>
        {OPERATORS.map(o => <option key={o}>{o}</option>)}
      </select>
      {cond.operator !== 'not_null' && (
        <input
          style={{ ...S.input, flex: 1 }}
          value={Array.isArray(cond.value) ? cond.value.join(',') : (cond.value ?? '')}
          placeholder={cond.operator === 'in' ? 'val1,val2' : 'value'}
          onChange={e => {
            const raw = e.target.value
            onChange({ ...cond, value: cond.operator === 'in' ? raw.split(',').map(s => s.trim()) : raw })
          }}
        />
      )}
      <button style={S.ghost} onClick={onRemove}><Trash2 size={13} /></button>
    </div>
  )
}

function ActionRow({
  action, onUpdate, onRemove,
}: { action: Action; onUpdate: (params: Record<string, string>) => void; onRemove: () => void }) {
  const [open, setOpen] = useState(false)
  const paramKeys: Record<string, string[]> = {
    send_webhook: ['url'],
    create_case: ['title_template', 'description_template'],
    suppress_alert: ['entity_type', 'reason'],
    add_note: ['content'],
  }
  const keys = paramKeys[action.action_type] || []

  return (
    <div style={{ ...S.card, padding: 12, marginBottom: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 11, color: '#94a3b8', background: '#1e2028', padding: '2px 8px', borderRadius: 4 }}>
            #{action.order_index + 1}
          </span>
          <span style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 500 }}>{action.action_type}</span>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {keys.length > 0 && (
            <button style={S.ghost} onClick={() => setOpen(o => !o)}>
              {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
            </button>
          )}
          <button style={S.ghost} onClick={onRemove}><Trash2 size={13} /></button>
        </div>
      </div>

      {open && keys.length > 0 && (
        <div style={{ marginTop: 10, display: 'grid', gap: 8 }}>
          {keys.map(k => (
            <div key={k}>
              <div style={S.label}>{k}</div>
              <input
                style={S.input}
                value={action.params[k] ?? ''}
                onChange={e => onUpdate({ ...action.params, [k]: e.target.value })}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function PlaybookEditor({ playbook, onClose }: { playbook: Playbook | null; onClose: () => void }) {
  const qc = useQueryClient()
  const isNew = playbook === null

  const [name, setName] = useState(playbook?.name ?? '')
  const [description, setDescription] = useState(playbook?.description ?? '')
  const [trigger, setTrigger] = useState<TriggerConditions>(playbook?.trigger_conditions ?? emptyTrigger())
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
    setTrigger(t => ({ ...t, conditions: [...t.conditions, { field: 'severity', operator: 'eq', value: 'high' }] }))

  const addAction = (type: string) =>
    setActions(a => [...a, { id: `new-${Date.now()}`, action_type: type, order_index: a.length, params: {} }])

  const removeAction = async (act: Action) => {
    if (!act.id.startsWith('new-') && playbook) {
      await api.delete(`/api/soar/actions/${act.id}`)
      qc.invalidateQueries({ queryKey: ['soar-playbooks'] })
    }
    setActions(a => a.filter(x => x.id !== act.id))
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: '#111318', border: '1px solid #1e2028', borderRadius: 10, padding: 24, width: 680, maxHeight: '90vh', overflow: 'auto' }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0', marginBottom: 20 }}>
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
            <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8' }}>Trigger Conditions</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: '#64748b' }}>Match</span>
              <select style={S.select} value={trigger.match} onChange={e => setTrigger(t => ({ ...t, match: e.target.value as 'all' | 'any' }))}>
                <option value="all">ALL</option>
                <option value="any">ANY</option>
              </select>
              <button style={S.btn('#1e2028')} onClick={addCondition}><Plus size={13} /> Add</button>
            </div>
          </div>
          {trigger.conditions.length === 0 && (
            <div style={{ fontSize: 12, color: '#3f4558', fontStyle: 'italic' }}>No conditions — playbook fires on every alert</div>
          )}
          {trigger.conditions.map((c, i) => (
            <ConditionRow
              key={i}
              cond={c}
              onChange={nc => setTrigger(t => ({ ...t, conditions: t.conditions.map((x, j) => j === i ? nc : x) }))}
              onRemove={() => setTrigger(t => ({ ...t, conditions: t.conditions.filter((_, j) => j !== i) }))}
            />
          ))}
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8' }}>Actions</div>
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
            <div style={{ fontSize: 12, color: '#3f4558', fontStyle: 'italic' }}>No actions defined</div>
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
          <button style={{ ...S.btn('#1e2028'), color: '#94a3b8' }} onClick={onClose}>Cancel</button>
          <button style={S.btn()} onClick={() => savePlaybook.mutate()} disabled={!name.trim()}>
            {savePlaybook.isPending ? 'Saving...' : 'Save Playbook'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function SoarPage() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<Playbook | null | undefined>(undefined)

  const { data: playbooks = [], isLoading } = useQuery<Playbook[]>({
    queryKey: ['soar-playbooks'],
    queryFn: () => api.get('/api/soar/playbooks').then(r => r.data),
  })

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch(`/api/soar/playbooks/${id}`, { is_enabled: enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-playbooks'] }),
  })

  const del = useMutation({
    mutationFn: (id: string) => api.delete(`/api/soar/playbooks/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-playbooks'] }),
  })

  return (
    <div>
      {editing !== undefined && (
        <PlaybookEditor playbook={editing} onClose={() => setEditing(undefined)} />
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0' }}>SOAR Playbooks</div>
          <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
            Define trigger conditions and automated response actions
          </div>
        </div>
        <button style={S.btn()} onClick={() => setEditing(null)}>
          <Plus size={14} /> New Playbook
        </button>
      </div>

      {isLoading && <div style={{ color: '#64748b', fontSize: 13 }}>Loading...</div>}

      {!isLoading && playbooks.length === 0 && (
        <div style={{ ...S.card, textAlign: 'center', padding: 48 }}>
          <Shield size={32} color="#3f4558" style={{ margin: '0 auto 12px' }} />
          <div style={{ color: '#64748b', fontSize: 14 }}>No playbooks defined yet.</div>
          <div style={{ color: '#3f4558', fontSize: 12, marginTop: 4 }}>
            Create a playbook to automate responses to alerts.
          </div>
        </div>
      )}

      {playbooks.map(pb => (
        <div key={pb.id} style={S.card}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span style={{ fontSize: 14, fontWeight: 600, color: pb.is_enabled ? '#e2e8f0' : '#475569' }}>
                  {pb.name}
                </span>
                <span style={{
                  fontSize: 11, padding: '1px 8px', borderRadius: 3,
                  background: pb.is_enabled ? 'rgba(52,211,153,0.1)' : '#1e2028',
                  color: pb.is_enabled ? '#34d399' : '#475569',
                }}>
                  {pb.is_enabled ? 'ENABLED' : 'DISABLED'}
                </span>
              </div>
              {pb.description && (
                <div style={{ fontSize: 12, color: '#64748b', marginBottom: 8 }}>{pb.description}</div>
              )}
              <div style={{ display: 'flex', gap: 12, fontSize: 12, color: '#475569' }}>
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
                      fontSize: 11, background: '#1a1f2e', border: '1px solid #2d3748',
                      borderRadius: 4, padding: '2px 8px', color: '#7dd3fc',
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
                  ? <ToggleRight size={18} color="#34d399" />
                  : <ToggleLeft size={18} color="#475569" />}
              </button>
              <button style={S.ghost} onClick={() => setEditing(pb)}>
                <span style={{ fontSize: 12, color: '#94a3b8' }}>Edit</span>
              </button>
              <button style={S.ghost} onClick={() => { if (confirm(`Delete "${pb.name}"?`)) del.mutate(pb.id) }}>
                <Trash2 size={14} color="#ef4444" />
              </button>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
