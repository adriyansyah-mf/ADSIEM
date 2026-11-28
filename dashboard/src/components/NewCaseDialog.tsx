import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { useCreateCase } from '@/hooks/useCases'
import type { Case } from '@/types'

const SEVERITIES: readonly Case['severity'][] = ['critical', 'high', 'medium', 'low']

/** Opens a case that does not start from an alert (a report, a tip, a hunt finding). */
export default function NewCaseDialog({ onClose }: { readonly onClose: () => void }) {
  const navigate = useNavigate()
  const create = useCreateCase()
  const [title, setTitle] = useState('')
  const [severity, setSeverity] = useState<Case['severity']>('medium')
  const [description, setDescription] = useState('')

  return (
    <WorkspaceDialog title="New case" description="For an investigation that does not start from an alert. Alerts can be linked later." onClose={onClose} busy={create.isPending}>
      <form className="atc" onSubmit={event => {
        event.preventDefault()
        if (!title.trim()) return
        create.mutate({ title: title.trim(), severity, description: description.trim() || undefined },
          { onSuccess: created => { onClose(); navigate(`/cases/${created.id}`) } })
      }}>
        <label className="atc__field">
          <span>Title</span>
          <input value={title} onChange={event => setTitle(event.target.value)} required autoFocus maxLength={200} placeholder="e.g. Phishing report from Finance" />
        </label>
        <label className="atc__field">
          <span>Severity</span>
          <select value={severity} onChange={event => setSeverity(event.target.value as Case['severity'])}>
            {SEVERITIES.map(value => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
          </select>
        </label>
        <label className="atc__field">
          <span>What is known so far (optional)</span>
          <textarea rows={4} value={description} onChange={event => setDescription(event.target.value)} />
        </label>
        <div className="atc__actions">
          <button type="button" className="cv-btn" onClick={onClose} disabled={create.isPending}>Cancel</button>
          <button type="submit" className="cv-btn cv-btn--primary" disabled={!title.trim() || create.isPending}>{create.isPending ? 'Creating…' : 'Create case'}</button>
        </div>
      </form>
    </WorkspaceDialog>
  )
}
