import { useState } from 'react'
import { useUpdateCase, useEscalateCase } from '@/hooks/useCases'
import { useAuthStore } from '@/stores/auth'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import type { Case } from '@/types'

export function CaseQuickActions({ caseData }: { readonly caseData: Case }) {
  const user = useAuthStore(state => state.user)
  const canManage = useAuthStore(state => state.hasRole('analyst'))
  const update = useUpdateCase(caseData.id)
  const escalate = useEscalateCase(caseData.id)
  const [closing, setClosing] = useState(false)
  const busy = update.isPending || escalate.isPending
  const assigned = caseData.assignee_id === user?.id
  if (!canManage) return null
  return <div className="space-y-3">
    <div className="control-cluster" aria-label={`Actions for ${caseData.title}`}>
      <button className="ui-button" disabled={busy || assigned} onClick={() => { if (user) update.mutate({ assignee_id: user.id }) }}>{assigned ? 'Assigned to you' : 'Assign to me'}</button>
      {!['escalated', 'resolved', 'closed'].includes(caseData.status) && <button className="ui-button" disabled={busy} onClick={() => escalate.mutate()}>Escalate to L2</button>}
      {caseData.status !== 'closed' && <button className="ui-button" disabled={busy} onClick={() => { update.reset(); setClosing(true) }}>Close case</button>}
    </div>
    {!closing && (update.isError || escalate.isError) && <p className="text-destructive text-sm mb-0" role="alert">Could not update the case. Check your permissions and try again.</p>}
    {closing && <WorkspaceDialog title="Close this case?" description={caseData.title} busy={update.isPending} onClose={() => setClosing(false)}>
      <p>The case will move to Closed. Its evidence and notes will remain available.</p>
      {update.isError && <p role="alert" className="text-destructive">Could not close the case. Please try again.</p>}
      <div className="control-cluster justify-end"><button className="ui-button" disabled={update.isPending} onClick={() => setClosing(false)}>Cancel</button>
        <button className="ui-button ui-button--primary" disabled={update.isPending} onClick={() => update.mutate({ status: 'closed' }, { onSuccess: () => setClosing(false) })}>{update.isPending ? 'Closing…' : 'Close case'}</button></div>
    </WorkspaceDialog>}
  </div>
}
