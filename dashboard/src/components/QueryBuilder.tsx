import { Plus, X } from 'lucide-react'
import { useId } from 'react'

export type Operator = 'contains' | 'equals' | 'not_equals' | 'starts_with' | 'exists' | 'not_exists' | 'gt' | 'gte' | 'lt' | 'lte'
export type Condition = { field: string; operator: Operator; value: string }
export type Group = { logic: 'AND' | 'OR'; children: (Condition | Group)[] }

export const EMPTY_GROUP: Group = { logic: 'AND', children: [] }

function isGroup(node: Condition | Group): node is Group {
  return 'children' in node
}

/** A group with no conditions/sub-groups produces no filter at all. */
export function isEmptyTree(node: Group): boolean {
  return node.children.length === 0
}

const OPERATORS: { value: Operator; label: string; needsValue: boolean }[] = [
  { value: 'contains', label: 'contains', needsValue: true },
  { value: 'equals', label: 'equals', needsValue: true },
  { value: 'not_equals', label: 'not equals', needsValue: true },
  { value: 'starts_with', label: 'starts with', needsValue: true },
  { value: 'gt', label: '>', needsValue: true },
  { value: 'gte', label: '>=', needsValue: true },
  { value: 'lt', label: '<', needsValue: true },
  { value: 'lte', label: '<=', needsValue: true },
  { value: 'exists', label: 'exists', needsValue: false },
  { value: 'not_exists', label: 'does not exist', needsValue: false },
]

interface Props {
  node: Group
  onChange: (node: Group) => void
  fields: string[]
  depth?: number
}

export default function QueryBuilder({ node, onChange, fields, depth = 0 }: Props) {
  const fieldsId = useId()
  const updateChild = (i: number, child: Condition | Group) => {
    const children = [...node.children]
    children[i] = child
    onChange({ ...node, children })
  }
  const removeChild = (i: number) => {
    onChange({ ...node, children: node.children.filter((_, idx) => idx !== i) })
  }
  const addCondition = () => {
    onChange({ ...node, children: [...node.children, { field: fields[0] ?? '', operator: 'contains', value: '' }] })
  }
  const addGroup = () => {
    onChange({ ...node, children: [...node.children, { logic: 'AND', children: [] }] })
  }

  return (
    <div className="space-y-3 min-w-0" role="group" aria-label={depth ? `Nested filter group ${depth}` : 'Filter conditions'}>
      <div className="control-cluster">
        <select
          value={node.logic}
          onChange={(e) => onChange({ ...node, logic: e.target.value as 'AND' | 'OR' })}
          aria-label="Match logic" className="ui-input w-auto"
        >
          <option value="AND">AND</option>
          <option value="OR">OR</option>
        </select>
        <span className="text-xs text-muted-foreground">of the following match:</span>
      </div>

      {node.children.map((child, i) => (
        <div key={i} className="flex items-start gap-2 min-w-0">
          {isGroup(child) ? (
            <div className="flex-1 min-w-0 rounded border border-border p-2">
              <QueryBuilder node={child} onChange={(c) => updateChild(i, c)} fields={fields} depth={depth + 1} />
            </div>
          ) : (
            <div className="query-condition flex-1 min-w-0">
              <input
                value={child.field}
                onChange={(e) => updateChild(i, { ...child, field: e.target.value })}
                list={fieldsId}
                aria-label={`Field ${i + 1}`}
                placeholder="field"
                className="ui-input font-mono"
              />
              <select
                value={child.operator}
                onChange={(e) => updateChild(i, { ...child, operator: e.target.value as Operator })}
                aria-label={`Operator ${i + 1}`} className="ui-input"
              >
                {OPERATORS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              {OPERATORS.find((o) => o.value === child.operator)?.needsValue && (
                <input
                  value={child.value}
                  onChange={(e) => updateChild(i, { ...child, value: e.target.value })}
                  placeholder="value"
                  aria-label={`Value ${i + 1}`} className="ui-input"
                />
              )}
            </div>
          )}
          <button onClick={() => removeChild(i)} className="ui-icon-button" aria-label={`Remove ${isGroup(child) ? 'group' : 'condition'} ${i + 1}`} title="Remove">
            <X size={14} />
          </button>
        </div>
      ))}

      <div className="control-cluster">
        <button onClick={addCondition} className="ui-button">
          <Plus size={14} /> Add condition
        </button>
        <button onClick={addGroup} className="ui-button">
          <Plus size={14} /> Add group
        </button>
      </div>

      <datalist id={fieldsId}>
        {fields.map((f) => <option key={f} value={f} />)}
      </datalist>
    </div>
  )
}
