import type { NodeTypeMeta } from '@/hooks/useSoarWorkflows'

interface Props {
  nodeTypes: NodeTypeMeta[]
  onAdd: (meta: NodeTypeMeta) => void
}

export function NodePalette({ nodeTypes, onAdd }: Props) {
  const byCategory = nodeTypes.reduce<Record<string, NodeTypeMeta[]>>((acc, meta) => {
    (acc[meta.category] ??= []).push(meta)
    return acc
  }, {})

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-3">
      {Object.entries(byCategory).map(([category, metas]) => (
        <div key={category}>
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">
            {category}
          </div>
          <div className="flex flex-col gap-1">
            {metas.map((meta) => (
              <button
                key={meta.node_type}
                type="button"
                onClick={() => onAdd(meta)}
                title={meta.is_destructive ? 'Pauses for human approval before it runs' : undefined}
                className="flex items-center justify-between rounded border border-[var(--border)] px-2 py-1.5 text-left text-[12px] text-[var(--text-primary)] hover:border-[var(--accent-blue)]"
              >
                <span>{meta.label}</span>
                {meta.is_destructive && <span className="text-[10px] text-[var(--accent-orange,#f59e0b)]">approval</span>}
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
