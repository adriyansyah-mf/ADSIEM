import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Play } from 'lucide-react'
import { usePlaybooks, useRunPlaybook } from '@/hooks/useSoar'
import { emitToast } from '@/hooks/useToast'

/** Runs an enabled SOAR workflow with this case as its trigger (canvas: Case › Run playbook). */
export default function RunPlaybookButton({ caseId, className }: { readonly caseId: string; readonly className?: string }) {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  const playbooks = usePlaybooks()
  const run = useRunPlaybook()
  const enabled = (playbooks.data ?? []).filter(pb => pb.is_enabled && !pb.legacy)

  useEffect(() => {
    if (!open) return
    const close = (event: MouseEvent | KeyboardEvent) => {
      if (event instanceof KeyboardEvent ? event.key === 'Escape' : !box.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => { document.removeEventListener('mousedown', close); document.removeEventListener('keydown', close) }
  }, [open])

  return (
    <div className="pb-run" ref={box}>
      <button type="button" className={className} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(o => !o)} disabled={run.isPending}>
        <Play size={14} aria-hidden="true" /> {run.isPending ? 'Starting…' : 'Run playbook'}
      </button>
      {open && (
        <div className="pb-run__menu" role="menu" aria-label="Playbooks">
          {playbooks.isPending ? <p className="pb-run__note">Loading workflows…</p>
            : playbooks.isError ? <p className="pb-run__note">Could not load workflows.</p>
            : enabled.length === 0 ? <p className="pb-run__note">No enabled workflows. Build one under Respond › Automations.</p>
            : enabled.map(pb => (
              <button key={pb.id} type="button" role="menuitem" className="pb-run__item"
                onClick={() => {
                  setOpen(false)
                  run.mutate({ id: pb.id, case_id: caseId }, {
                    onSuccess: () => emitToast(`Started "${pb.name}" for this case`, 'success'),
                  })
                }}>
                <span>{pb.name}</span>
                {pb.description && <span className="pb-run__desc">{pb.description}</span>}
              </button>
            ))}
          <button type="button" role="menuitem" className="pb-run__item pb-run__manage" onClick={() => navigate('/soar')}>Manage workflows</button>
        </div>
      )}
    </div>
  )
}
