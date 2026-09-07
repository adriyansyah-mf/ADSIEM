import { Trash2 } from 'lucide-react'
import { S } from './styles'
import { TRIGGER_FIELDS, OPERATORS, type Condition } from './types'

export function ConditionRow({
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
