import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import { ArrowLeft, Download, FileCheck2, Loader2, Lock, Plus, RefreshCw, Save, Trash2, X } from 'lucide-react'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import {
  CLASSIFICATIONS, PRIORITIES, SECTIONS, apiError, downloadPdf, type IncidentReport, type Ioc, type Row,
} from '@/components/reports/types'

// Edit a draft incident report, finalize it (admins), or read a final one
// (server-api/app/api/routes/incident_reports.py).

interface Draft {
  title: string; language: 'id' | 'en'; classification: string; priority: string; audience: string
  sections: Record<string, string>; timeline: Row[]; actions: Row[]; iocs: Ioc[]
}

const toDraft = (r: IncidentReport): Draft => ({
  title: r.title, language: r.language, classification: r.classification, priority: r.priority, audience: r.audience ?? '',
  sections: { ...r.content.sections }, timeline: r.content.timeline ?? [], actions: r.content.actions ?? [], iocs: r.content.iocs ?? [],
})

const when = (v: string | null | undefined) => (v ? format(new Date(v), 'yyyy-MM-dd HH:mm') : '')

function Rows({ label, rows, onChange, readOnly }: {
  readonly label: string; readonly rows: Row[]; readonly onChange: (r: Row[]) => void; readonly readOnly: boolean
}) {
  return (
    <section className="space-y-2">
      <h2 className="text-sm font-semibold">{label}</h2>
      {!rows.length && <p className="text-xs text-muted-foreground">None.</p>}
      <ul className="space-y-1">
        {rows.map((r, i) => (
          <li key={i} className="grid grid-cols-[150px_minmax(0,1fr)_auto] gap-2 items-start">
            {readOnly ? <>
              <span className="text-xs text-muted-foreground tabular-nums pt-1">{when(r.time) || '—'}</span>
              <span className="text-sm">{r.text}{r.by ? ` (${r.by})` : ''}</span><span />
            </> : <>
              <input className="ui-input text-xs" type="datetime-local" aria-label="Time"
                value={r.time ? format(new Date(r.time), "yyyy-MM-dd'T'HH:mm") : ''}
                onChange={e => onChange(rows.map((x, j) => j === i ? { ...x, time: e.target.value ? new Date(e.target.value).toISOString() : null } : x))} />
              <input className="ui-input text-sm" aria-label="Event" value={r.text} maxLength={2000}
                onChange={e => onChange(rows.map((x, j) => j === i ? { ...x, text: e.target.value } : x))} />
              <button type="button" className="ui-icon-button" aria-label="Remove row" onClick={() => onChange(rows.filter((_, j) => j !== i))}><X size={14} /></button>
            </>}
          </li>
        ))}
      </ul>
      {!readOnly && <button type="button" className="ui-button ui-button--quiet text-xs" onClick={() => onChange([...rows, { time: null, text: '' }])}><Plus size={12} /> Add row</button>}
    </section>
  )
}

export default function IncidentReportPage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const isAdmin = useAuthStore(s => s.hasRole('admin'))
  const canWrite = useAuthStore(s => s.hasRole('analyst'))
  const report = useQuery<IncidentReport>({
    queryKey: ['incident-report', id],
    queryFn: () => api.get(`/api/incident-reports/${id}`).then(r => r.data),
  })
  const [draft, setDraft] = useState<Draft | null>(null)
  const [dirty, setDirty] = useState(false)
  const [confirm, setConfirm] = useState<'finalize' | 'delete' | null>(null)
  useEffect(() => { if (report.data && !dirty) setDraft(toDraft(report.data)) }, [report.data, dirty])
  const set = (patch: Partial<Draft>) => { setDraft(d => d && { ...d, ...patch }); setDirty(true) }
  const done = (r: IncidentReport) => { qc.setQueryData(['incident-report', id], r); setDirty(false); void qc.invalidateQueries({ queryKey: ['incident-reports'] }) }

  const save = useMutation({
    mutationFn: () => api.put(`/api/incident-reports/${id}`, { ...draft, audience: draft?.audience || null }).then(r => r.data as IncidentReport),
    onSuccess: done,
  })
  const rebuild = useMutation({
    mutationFn: (useAi: boolean) => api.post(`/api/incident-reports/${id}/regenerate`, null, { params: { use_ai: useAi } }).then(r => r.data as IncidentReport),
    onSuccess: done,
  })
  const finalize = useMutation({
    mutationFn: async () => {
      if (dirty) await api.put(`/api/incident-reports/${id}`, { ...draft, audience: draft?.audience || null })
      return api.post(`/api/incident-reports/${id}/finalize`).then(r => r.data as IncidentReport)
    },
    onSuccess: r => { done(r); setConfirm(null) },
  })
  const remove = useMutation({
    mutationFn: () => api.delete(`/api/incident-reports/${id}`),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['incident-reports'] }); navigate('/reports') },
  })
  const [downloading, setDownloading] = useState(false)

  if (report.isLoading || !draft) return <div className="p-6"><Loader2 size={16} className="animate-spin" /></div>
  if (report.isError || !report.data) return <div className="p-6 text-sm text-destructive">{apiError(report.error, 'Report not found.')}</div>
  const r = report.data
  const final = r.status === 'final'
  const readOnly = final || !canWrite
  const error = save.error ?? rebuild.error ?? finalize.error ?? remove.error

  return (
    <div className="p-6 space-y-5 max-w-5xl">
      <div className="flex flex-wrap items-center gap-2">
        <Link to="/reports" className="ui-button ui-button--quiet"><ArrowLeft size={14} /> Reports</Link>
        {r.case_id && <Link to={`/cases/${r.case_id}`} className="ui-button ui-button--quiet">Open the case</Link>}
        <div className="flex-1" />
        <button type="button" className="ui-button" disabled={downloading}
          onClick={async () => { setDownloading(true); try { await downloadPdf(api, id, `${r.number ?? 'DRAFT'}.pdf`) } finally { setDownloading(false) } }}>
          <Download size={14} /> {final ? 'Download PDF' : 'Preview PDF'}</button>
        {!readOnly && <>
          <button type="button" className="ui-button" disabled={rebuild.isPending} title="Rebuild from the case as it is now; your edits are replaced"
            onClick={() => rebuild.mutate(r.ai_used)}><RefreshCw size={14} /> {rebuild.isPending ? 'Rebuilding…' : 'Rebuild from case'}</button>
          <button type="button" className="ui-button ui-button--primary" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>
            <Save size={14} /> {save.isPending ? 'Saving…' : dirty ? 'Save draft' : 'Saved'}</button>
        </>}
      </div>

      <header className="space-y-1">
        <div className="text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-2">
          {final ? <><Lock size={12} /> Final · {r.number}</> : 'Draft incident report'}
          {r.ai_used && <span className="normal-case tracking-normal">· prose written with AI</span>}
        </div>
        {readOnly ? <h1 className="text-xl font-bold">{r.title}</h1>
          : <input className="ui-input text-lg font-semibold w-full" aria-label="Title" value={draft.title} maxLength={300} onChange={e => set({ title: e.target.value })} />}
      </header>

      {final && (
        <section className="rounded border border-green-500/40 p-3 text-xs space-y-1">
          <div className="flex items-center gap-1.5 font-medium text-sm"><FileCheck2 size={14} className="text-green-400" />
            Finalized by {r.finalized_by_name} on {when(r.finalized_at)}. The PDF is stored and can no longer change.</div>
          <div className="font-mono break-all text-muted-foreground">PDF SHA-256: {r.pdf_sha256}</div>
          <div className="text-muted-foreground">Anyone can check a copy under Reports → Verify a report.</div>
        </section>
      )}

      <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <label className="field"><span>Language</span>
          <select className="ui-input" disabled={readOnly} value={draft.language} onChange={e => set({ language: e.target.value as 'id' | 'en' })}>
            <option value="id">Bahasa Indonesia</option><option value="en">English</option></select></label>
        <label className="field"><span>Classification</span>
          <select className="ui-input" disabled={readOnly} value={draft.classification} onChange={e => set({ classification: e.target.value })}>
            {CLASSIFICATIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        <label className="field"><span>Priority</span>
          <select className="ui-input" disabled={readOnly} value={draft.priority} onChange={e => set({ priority: e.target.value })}>
            {PRIORITIES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        <label className="field"><span>For</span>
          <input className="ui-input" disabled={readOnly} value={draft.audience} maxLength={300} placeholder="Head of IT" onChange={e => set({ audience: e.target.value })} /></label>
      </section>

      {SECTIONS.map(([key, label]) => (
        <section key={key} className="space-y-1">
          <h2 className="text-sm font-semibold">{label}</h2>
          {readOnly ? <p className="text-sm whitespace-pre-wrap">{draft.sections[key] || <span className="text-muted-foreground">None.</span>}</p>
            : <textarea className="ui-input w-full min-h-[90px] text-sm" aria-label={label} value={draft.sections[key] ?? ''} maxLength={8000}
              onChange={e => set({ sections: { ...draft.sections, [key]: e.target.value } })} />}
          {key === 'scope' && r.content.assets.length > 0 && (
            <p className="text-xs text-muted-foreground">Hosts: {r.content.assets.map(a => `${a.host} (${a.alerts} alerts)`).join(', ')}</p>
          )}
        </section>
      ))}

      <Rows label="Timeline" rows={draft.timeline} readOnly={readOnly} onChange={timeline => set({ timeline })} />
      <Rows label="Actions taken" rows={draft.actions} readOnly={readOnly} onChange={actions => set({ actions })} />

      <section className="space-y-2">
        <h2 className="text-sm font-semibold">Indicators of compromise</h2>
        {!draft.iocs.length && <p className="text-xs text-muted-foreground">None.</p>}
        <ul className="space-y-1">
          {draft.iocs.map((ioc, i) => (
            <li key={i} className="grid grid-cols-[110px_minmax(0,1fr)_minmax(0,0.7fr)_auto] gap-2 items-center text-sm">
              {readOnly ? <><span className="text-muted-foreground">{ioc.type}</span><span className="font-mono break-all">{ioc.value}</span><span className="text-xs">{ioc.note}</span><span /></> : <>
                <input className="ui-input text-xs" aria-label="Type" value={ioc.type} maxLength={40} onChange={e => set({ iocs: draft.iocs.map((x, j) => j === i ? { ...x, type: e.target.value } : x) })} />
                <input className="ui-input text-xs font-mono" aria-label="Value" value={ioc.value} maxLength={300} onChange={e => set({ iocs: draft.iocs.map((x, j) => j === i ? { ...x, value: e.target.value } : x) })} />
                <input className="ui-input text-xs" aria-label="Note" value={ioc.note} maxLength={200} onChange={e => set({ iocs: draft.iocs.map((x, j) => j === i ? { ...x, note: e.target.value } : x) })} />
                <button type="button" className="ui-icon-button" aria-label="Remove indicator" onClick={() => set({ iocs: draft.iocs.filter((_, j) => j !== i) })}><X size={14} /></button>
              </>}
            </li>
          ))}
        </ul>
        {!readOnly && <button type="button" className="ui-button ui-button--quiet text-xs" onClick={() => set({ iocs: [...draft.iocs, { type: 'ip', value: '', note: '' }] })}><Plus size={12} /> Add indicator</button>}
      </section>

      <section className="space-y-2">
        <h2 className="text-sm font-semibold">Evidence annex</h2>
        <p className="text-xs text-muted-foreground">From the case's AI investigation. The text cites these as [E1], [E2]…</p>
        {!r.content.evidence.length ? <p className="text-xs text-muted-foreground">No investigation evidence yet. Run Investigate with AI on the case, then rebuild.</p> : (
          <ul className="text-sm space-y-1">
            {r.content.evidence.map(e => (
              <li key={e.ref} className="grid grid-cols-[40px_80px_minmax(0,1fr)] gap-2">
                <span className="font-mono">{e.ref}</span><span className="text-muted-foreground text-xs pt-0.5">{e.type}</span>
                <span>{e.title} <span className="text-xs text-muted-foreground">{when(e.observed_at)}</span></span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {error && <p role="alert" className="text-sm text-destructive">{apiError(error, 'That did not work.')}</p>}

      {!final && canWrite && (
        <section className="rounded border border-border p-3 space-y-2">
          {confirm === 'finalize' ? (
            <div className="space-y-2 text-sm">
              <p>Finalize this report? It gets a number, its PDF is stored, and it can no longer be edited or deleted.</p>
              <div className="control-cluster">
                <button type="button" className="ui-button ui-button--primary" disabled={finalize.isPending} onClick={() => finalize.mutate()}>
                  <Lock size={14} /> {finalize.isPending ? 'Finalizing…' : 'Finalize'}</button>
                <button type="button" className="ui-button ui-button--quiet" onClick={() => setConfirm(null)}>Cancel</button>
              </div>
            </div>
          ) : confirm === 'delete' ? (
            <div className="space-y-2 text-sm">
              <p>Delete this draft?</p>
              <div className="control-cluster">
                <button type="button" className="ui-button ui-button--danger" disabled={remove.isPending} onClick={() => remove.mutate()}><Trash2 size={14} /> Delete draft</button>
                <button type="button" className="ui-button ui-button--quiet" onClick={() => setConfirm(null)}>Keep</button>
              </div>
            </div>
          ) : (
            <div className="control-cluster flex-wrap">
              <button type="button" className="ui-button ui-button--primary" disabled={!isAdmin} onClick={() => setConfirm('finalize')}
                title={isAdmin ? undefined : 'An admin finalizes reports'}><Lock size={14} /> Finalize…</button>
              {!isAdmin && <span className="text-xs text-muted-foreground">An admin finalizes reports.</span>}
              <div className="flex-1" />
              <button type="button" className="ui-button ui-button--quiet" onClick={() => setConfirm('delete')}><Trash2 size={14} /> Delete draft</button>
            </div>
          )}
        </section>
      )}
    </div>
  )
}
