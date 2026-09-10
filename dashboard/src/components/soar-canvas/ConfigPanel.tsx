import type { JsonSchemaField, NodeTypeMeta } from '@/hooks/useSoarWorkflows'

interface Props {
  meta: NodeTypeMeta
  name: string
  config: Record<string, unknown>
  onNameChange: (name: string) => void
  onConfigChange: (config: Record<string, unknown>) => void
  onDelete: () => void
}

const inputClass =
  'w-full rounded border border-[var(--border)] bg-[var(--bg-base)] px-2 py-1.5 text-[13px] text-[var(--text-primary)] outline-none focus:border-[var(--accent-blue)]'

const labelClass = 'mb-1 block text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]'

/** Renders a node's configuration form directly from the JSON Schema the server
 *  publishes for its type. Adding a node type server-side therefore needs no
 *  change here — which is the whole point of the registry contract. */
export function ConfigPanel({ meta, name, config, onNameChange, onConfigChange, onDelete }: Props) {
  const properties = meta.config_schema?.properties ?? {}
  const required = new Set(meta.config_schema?.required ?? [])

  function set(key: string, value: unknown) {
    onConfigChange({ ...config, [key]: value })
  }

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-4">
      <div>
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-[var(--text-primary)]">{meta.label}</span>
          {meta.is_destructive && (
            <span className="rounded bg-[var(--sev-critical,#7f1d1d)] px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-white">
              needs approval
            </span>
          )}
        </div>
        <p className="mt-1 text-[11px] leading-relaxed text-[var(--text-secondary)]">
          {meta.is_destructive
            ? 'This action never runs on its own. The workflow pauses here until a human approves it.'
            : `Emits: ${meta.handles.join(', ')}`}
        </p>
      </div>

      <div>
        <label className={labelClass} htmlFor="node-name">Step name</label>
        <input
          id="node-name"
          className={inputClass}
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
        />
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Other steps read this step's output as <code>{`{{ nodes.${name || 'name'}.output.field }}`}</code>
        </p>
      </div>

      {Object.entries(properties).map(([key, field]) => (
        <Field
          key={key}
          name={key}
          field={field}
          required={required.has(key)}
          value={config[key]}
          onChange={(v) => set(key, v)}
        />
      ))}

      <button
        type="button"
        onClick={onDelete}
        className="mt-auto rounded border border-[var(--border)] px-3 py-1.5 text-[12px] text-[var(--text-secondary)] hover:border-red-500 hover:text-red-400"
      >
        Delete step
      </button>
    </div>
  )
}

function Field({
  name,
  field,
  required,
  value,
  onChange,
}: {
  name: string
  field: JsonSchemaField
  required: boolean
  value: unknown
  onChange: (v: unknown) => void
}) {
  const id = `cfg-${name}`
  const label = (
    <label className={labelClass} htmlFor={id}>
      {name.replace(/_/g, ' ')}
      {required && <span className="ml-1 text-[var(--accent-orange,#f59e0b)]">*</span>}
    </label>
  )

  if (field.enum) {
    return (
      <div>
        {label}
        <select id={id} className={inputClass} value={String(value ?? '')} onChange={(e) => onChange(e.target.value)}>
          <option value="">—</option>
          {field.enum.map((option) => (
            <option key={option} value={option}>{option}</option>
          ))}
        </select>
      </div>
    )
  }

  if (field.type === 'array' && field.items?.enum) {
    const selected = Array.isArray(value) ? (value as string[]) : []
    return (
      <div>
        {label}
        <div className="flex flex-wrap gap-1.5">
          {field.items.enum.map((option) => {
            const on = selected.includes(option)
            return (
              <button
                key={option}
                type="button"
                onClick={() => onChange(on ? selected.filter((s) => s !== option) : [...selected, option])}
                className={`rounded border px-2 py-1 text-[11px] ${
                  on
                    ? 'border-[var(--accent-blue)] bg-[var(--accent-blue)] text-white'
                    : 'border-[var(--border)] text-[var(--text-secondary)]'
                }`}
              >
                {option}
              </button>
            )
          })}
        </div>
        {selected.length === 0 && (
          <p className="mt-1 text-[11px] text-[var(--text-muted)]">Nothing selected — matches everything.</p>
        )}
      </div>
    )
  }

  if (field.type === 'integer') {
    return (
      <div>
        {label}
        <input
          id={id}
          type="number"
          min={field.minimum}
          className={inputClass}
          value={value === undefined || value === null ? '' : String(value)}
          onChange={(e) => onChange(e.target.value === '' ? undefined : Number(e.target.value))}
        />
      </div>
    )
  }

  return (
    <div>
      {label}
      <input
        id={id}
        className={inputClass}
        value={value === undefined || value === null ? '' : String(value)}
        onChange={(e) => onChange(e.target.value)}
        placeholder="text, or {{ trigger.alert.source_ip }}"
      />
    </div>
  )
}
