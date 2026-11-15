import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { FileText, Loader2 } from 'lucide-react'
import { api } from '@/api/client'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { useAuthStore } from '@/stores/auth'
import { CLASSIFICATIONS, apiError, type IncidentReportSummary } from './types'

// "Incident report" on a case: write a new draft, or open one already written
// (server-api/app/api/routes/incident_reports.py).

export default function IncidentReportButton({ caseId }: { readonly caseId: string }) {
  const navigate = useNavigate()
  const canWrite = useAuthStore(s => s.hasRole('analyst'))
  const [open, setOpen] = useState(false)
  const [language, setLanguage] = useState<'id' | 'en'>('id')
  const [useAi, setUseAi] = useState(true)
  const [classification, setClassification] = useState('confidential')
  const [audience, setAudience] = useState('')
  const existing = useQuery<IncidentReportSummary[]>({
    queryKey: ['incident-reports', 'case', caseId],
    queryFn: () => api.get('/api/incident-reports', { params: { case_id: caseId } }).then(r => r.data),
    enabled: open,
  })
  const create = useMutation({
    mutationFn: () => api.post(`/api/cases/${caseId}/incident-reports`,
      { language, use_ai: useAi, classification, audience: audience.trim() || null }).then(r => r.data),
    onSuccess: r => navigate(`/reports/incidents/${r.id}`),
  })

  return (
    <>
      <button type="button" className="ui-button" onClick={() => setOpen(true)}><FileText size={14} /> Incident report</button>
      {open && (
        <WorkspaceDialog title="Incident report" busy={create.isPending} onClose={() => setOpen(false)}
          description="A report of this case for management or auditors: what happened, what was affected, the evidence, what was done, and what to do next.">
          <div className="space-y-4">
            {(existing.data?.length ?? 0) > 0 && (
              <div className="space-y-1">
                <p className="text-sm font-medium">Reports of this case</p>
                <ul className="text-sm space-y-1">
                  {existing.data!.map(r => (
                    <li key={r.id}><Link className="underline" to={`/reports/incidents/${r.id}`}>
                      {r.number ?? 'Draft'} · {r.title}</Link>
                      <span className="text-xs text-muted-foreground"> ({r.status === 'final' ? 'final' : 'draft'})</span></li>
                  ))}
                </ul>
              </div>
            )}
            {canWrite ? (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <label className="field"><span>Language</span>
                    <select className="ui-input" value={language} onChange={e => setLanguage(e.target.value as 'id' | 'en')}>
                      <option value="id">Bahasa Indonesia</option><option value="en">English</option>
                    </select></label>
                  <label className="field"><span>Classification</span>
                    <select className="ui-input" value={classification} onChange={e => setClassification(e.target.value)}>
                      {CLASSIFICATIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                    </select></label>
                  <label className="field col-span-2"><span>For (optional)</span>
                    <input className="ui-input" value={audience} maxLength={300} placeholder="e.g. Head of IT, Management"
                      onChange={e => setAudience(e.target.value)} /></label>
                </div>
                <label className="flex items-start gap-2 text-sm cursor-pointer">
                  <input type="checkbox" className="mt-1" checked={useAi} onChange={e => setUseAi(e.target.checked)} />
                  <span>Let AI write the summary, analysis, impact and recommendations from the case's evidence.
                    <span className="block text-xs text-muted-foreground">Without it, the draft still lists the timeline, assets, indicators, findings and actions.</span></span>
                </label>
                {create.isError && <p role="alert" className="text-xs text-destructive">{apiError(create.error, 'Could not write the report.')}</p>}
                <div className="control-cluster justify-end">
                  <button type="button" className="ui-button ui-button--quiet" onClick={() => setOpen(false)}>Cancel</button>
                  <button type="button" className="ui-button ui-button--primary" disabled={create.isPending} onClick={() => create.mutate()}>
                    {create.isPending ? <><Loader2 size={14} className="animate-spin" /> Writing…</> : 'Write draft'}</button>
                </div>
              </>
            ) : <p className="text-sm text-muted-foreground">An analyst role is needed to write a report.</p>}
          </div>
        </WorkspaceDialog>
      )}
    </>
  )
}
