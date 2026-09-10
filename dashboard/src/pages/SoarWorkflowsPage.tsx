import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Workflow } from 'lucide-react'
import { PageHeader } from '@/components/ui/PageHeader'
import { GlassCard } from '@/components/ui/GlassCard'
import {
  saveErrorMessage,
  useCreateWorkflow,
  useDeleteWorkflow,
  useWorkflows,
} from '@/hooks/useSoarWorkflows'

export default function SoarWorkflowsPage() {
  const navigate = useNavigate()
  const { data: workflows = [], isLoading } = useWorkflows()
  const create = useCreateWorkflow()
  const remove = useDeleteWorkflow()
  const [name, setName] = useState('')
  const [error, setError] = useState<string | null>(null)

  function onCreate() {
    const trimmed = name.trim()
    if (!trimmed) return
    setError(null)
    // A workflow is created empty and then drawn on the canvas, so the server
    // accepts a graph with no steps. It only insists on a single entry point
    // once steps exist.
    create.mutate(
      { name: trimmed, description: null, is_enabled: false, nodes: [], edges: [] },
      {
        onSuccess: (workflow) => navigate(`/soar/workflows/${workflow.id}`),
        onError: (e) => setError(saveErrorMessage(e)),
      },
    )
  }

  return (
    <div>
      <PageHeader
        title="Workflows"
        breadcrumb="Automation / SOAR"
        subtitle="Visual response workflows. Steps that block an IP or isolate a host always pause for human approval before they run."
      />

      <GlassCard
        title="New workflow"
        className="mb-4"
        actions={
          <button
            type="button"
            onClick={onCreate}
            disabled={create.isPending || !name.trim()}
            className="flex items-center gap-1.5 rounded bg-[var(--accent-blue)] px-3 py-1.5 text-[12px] font-semibold text-white disabled:opacity-50"
          >
            <Plus size={13} /> {create.isPending ? 'Creating…' : 'Create'}
          </button>
        }
      >
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && onCreate()}
          placeholder="e.g. Critical WAF alert — enrich, then block on approval"
          className="w-full rounded border border-[var(--border)] bg-[var(--bg-base)] px-2 py-1.5 text-[13px] text-[var(--text-primary)] outline-none focus:border-[var(--accent-blue)]"
        />
        {error && <p className="mt-2 text-[12px] text-red-400">{error}</p>}
      </GlassCard>

      <GlassCard title={`Workflows (${workflows.length})`}>
        {isLoading ? (
          <p className="text-[12px] text-[var(--text-muted)]">Loading…</p>
        ) : workflows.length === 0 ? (
          <p className="text-[12px] leading-relaxed text-[var(--text-muted)]">
            No workflows yet. Create one above, then draw it on the canvas.
          </p>
        ) : (
          <div className="flex flex-col gap-1">
            {workflows.map((workflow) => (
              <div
                key={workflow.id}
                className="flex items-center justify-between gap-3 rounded border border-[var(--border)] px-3 py-2"
              >
                <button
                  type="button"
                  onClick={() => navigate(`/soar/workflows/${workflow.id}`)}
                  className="flex min-w-0 items-center gap-2 text-left"
                >
                  <Workflow size={14} className="shrink-0 text-[var(--text-muted)]" />
                  <span className="truncate text-[13px] text-[var(--text-primary)]">{workflow.name}</span>
                  <span
                    className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                      workflow.is_enabled
                        ? 'bg-emerald-500/15 text-emerald-300'
                        : 'bg-[var(--bg-base)] text-[var(--text-muted)]'
                    }`}
                  >
                    {workflow.is_enabled ? 'enabled' : 'disabled'}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => remove.mutate(workflow.id)}
                  className="shrink-0 text-[11px] text-[var(--text-muted)] hover:text-red-400"
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        )}
      </GlassCard>
    </div>
  )
}
