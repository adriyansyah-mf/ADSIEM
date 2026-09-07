import { useState } from 'react'
import { ChevronDown, ChevronRight, Trash2 } from 'lucide-react'
import { S } from './styles'
import type { Action } from './types'

export function ActionRow({
  action, onUpdate, onRemove,
}: { action: Action; onUpdate: (params: Record<string, string>) => void; onRemove: () => void }) {
  const [open, setOpen] = useState(false)
  const paramKeys: Record<string, string[]> = {
    send_webhook: ['url'],
    create_case: ['title_template', 'description_template'],
    suppress_alert: ['entity_type', 'reason'],
    add_note: ['content'],
    block_ip: ['duration_seconds'],
  }
  const keys = paramKeys[action.action_type] || []

  return (
    <div style={{ ...S.card, padding: 12, marginBottom: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)', background: 'var(--border)', padding: '2px 8px', borderRadius: 4 }}>
            #{action.order_index + 1}
          </span>
          <span style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>{action.action_type}</span>
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
