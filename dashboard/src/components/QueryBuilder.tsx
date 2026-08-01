import { Plus, X } from 'lucide-react'

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
    <div className={depth > 0 ? 'pl-4 border-l-2 border-border space-y-2' : 'space-y-2'}>
      <div className="flex items-center gap-2">
        <select
          value={node.logic}
          onChange={(e) => onChange({ ...node, logic: e.target.value as 'AND' | 'OR' })}
          className="bg-muted border border-border rounded px-2 py-1 text-xs font-semibold focus:outline-none focus:ring-1 focus:ring-primary"
        >
          <option value="AND">AND</option>
          <option value="OR">OR</option>
        </select>
        <span className="text-xs text-muted-foreground">of the following match:</span>
      </div>

      {node.children.map((child, i) => (
        <div key={i} className="flex items-start gap-2">
          {isGroup(child) ? (
            <div className="flex-1 rounded border border-border/60 p-2">
              <QueryBuilder node={child} onChange={(c) => updateChild(i, c)} fields={fields} depth={depth + 1} />
            </div>
          ) : (
            <div className="flex-1 flex flex-wrap items-center gap-2">
              <input
                value={child.field}
                onChange={(e) => updateChild(i, { ...child, field: e.target.value })}
                list="qb-fields"
                placeholder="field"
                className="bg-muted border border-border rounded px-2 py-1 text-xs font-mono w-44 focus:outline-none focus:ring-1 focus:ring-primary"
              />
              <select
                value={child.operator}
                onChange={(e) => updateChild(i, { ...child, operator: e.target.value as Operator })}
                className="bg-muted border border-border rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
              >
                {OPERATORS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              {OPERATORS.find((o) => o.value === child.operator)?.needsValue && (
                <input
                  value={child.value}
                  onChange={(e) => updateChild(i, { ...child, value: e.target.value })}
                  placeholder="value"
                  className="bg-muted border border-border rounded px-2 py-1 text-xs flex-1 min-w-[120px] focus:outline-none focus:ring-1 focus:ring-primary"
                />
              )}
            </div>
          )}
          <button onClick={() => removeChild(i)} className="text-muted-foreground hover:text-destructive shrink-0 mt-1.5" title="Remove">
            <X size={14} />
          </button>
        </div>
      ))}

      <div className="flex gap-3">
        <button onClick={addCondition} className="flex items-center gap-1 text-xs text-primary hover:underline">
          <Plus size={12} /> Condition
        </button>
        <button onClick={addGroup} className="flex items-center gap-1 text-xs text-primary hover:underline">
          <Plus size={12} /> Group
        </button>
      </div>

      {depth === 0 && (
        <datalist id="qb-fields">
          {fields.map((f) => <option key={f} value={f} />)}
        </datalist>
      )}
    </div>
  )
}
