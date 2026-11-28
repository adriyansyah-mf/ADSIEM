import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { emitToast } from '@/hooks/useToast'
import type { CaseSummary, PaginatedResponse } from '@/types'

const ACTIVE = 'open,in_review,escalated'

/** Records an event (or any finding) on an open case as a note: canvas Search › Add to case. */
export default function AddToCaseDialog({ subject, note, onClose }: {
  readonly subject: string; readonly note: string; readonly onClose: () => void
}) {
  const queryClient = useQueryClient()
  const [caseId, setCaseId] = useState('')
  const [comment, setComment] = useState('')
  const cases = useQuery<PaginatedResponse<CaseSummary>>({
    queryKey: ['cases', 'active-picker'],
    queryFn: () => api.get('/api/cases', { params: { status: ACTIVE, page_size: 100, summary: true } }).then(r => r.data),
  })
  const add = useMutation({
    mutationFn: () => api.post(`/api/cases/${caseId}/notes`, { content: comment.trim() ? `${comment.trim()}\n\n${note}` : note }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['case', caseId] })
      emitToast('Added to the case', 'success')
      onClose()
    },
    onError: () => emitToast('Could not add to the case', 'error'),
  })
  const items = cases.data?.items ?? []

  return (
    <WorkspaceDialog title="Add to case" description={subject} onClose={onClose} busy={add.isPending}>
      <form className="atc" onSubmit={event => { event.preventDefault(); if (caseId) add.mutate() }}>
        <label className="atc__field">
          <span>Case</span>
          <select value={caseId} onChange={event => setCaseId(event.target.value)} required disabled={cases.isPending}>
            <option value="">{cases.isPending ? 'Loading cases…' : items.length ? 'Choose an open case' : 'No open cases'}</option>
            {items.map(item => <option key={item.id} value={item.id}>{item.title} · {item.severity}</option>)}
          </select>
        </label>
        <label className="atc__field">
          <span>Why it matters (optional)</span>
          <textarea rows={3} value={comment} onChange={event => setComment(event.target.value)} placeholder="e.g. same parent process as the LSASS read" />
        </label>
        <details className="atc__preview"><summary>What gets added</summary><pre>{note}</pre></details>
        {cases.isError && <p className="atc__error">Could not load cases.</p>}
        <div className="atc__actions">
          {!cases.isPending && items.length === 0 && <Link to="/cases" className="atc__link">Go to cases</Link>}
          <button type="button" className="cv-btn" onClick={onClose} disabled={add.isPending}>Cancel</button>
          <button type="submit" className="cv-btn cv-btn--primary" disabled={!caseId || add.isPending}>{add.isPending ? 'Adding…' : 'Add to case'}</button>
        </div>
      </form>
    </WorkspaceDialog>
  )
}
