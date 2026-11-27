import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { FileCheck2, FileText, FileX2, Loader2, Search } from 'lucide-react'
import { format } from 'date-fns'
import { api } from '@/api/client'
import { apiError, type IncidentReportSummary } from '@/components/reports/types'
import PeriodicSummary from '@/components/reports/PeriodicSummary'
import { CanvasHeader, CanvasPage, Empty } from '@/components/canvas/Canvas'

// Incident reports written from cases (archive), the periodic summary PDF,
// and a check that a PDF copy is a real, unchanged final report.

type Tab = 'incidents' | 'periodic' | 'verify'

async function downloadPdf(report: IncidentReportSummary) {
  const r = await api.get(`/api/incident-reports/${report.id}/pdf`, { responseType: 'blob' })
  const url = URL.createObjectURL(r.data as Blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${report.number ?? report.title}.pdf`
  a.click()
  URL.revokeObjectURL(url)
}

function IncidentArchive() {
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [downloadError, setDownloadError] = useState('')
  const list = useQuery<IncidentReportSummary[]>({
    queryKey: ['incident-reports', status, q],
    queryFn: () => api.get('/api/incident-reports', { params: { status: status || undefined, q: q || undefined } }).then(r => r.data),
  })
  const reports = list.data ?? []
  const selected = reports.find(r => r.id === selectedId) ?? reports[0] ?? null
  return (
    <div className="cv-split">
      <section className="cv-pane" aria-label="Reports">
        <div className="cv-row">
          <div className="cv-search" style={{ flex: '1 1 240px', maxWidth: 320 }}>
            <Search size={14} aria-hidden="true" />
            <label htmlFor="report-search" className="sr-only">Search reports</label>
            <input id="report-search" placeholder="Title or number" value={q} onChange={e => setQ(e.target.value)} />
          </div>
          <select className="cv-select" aria-label="Status" value={status} onChange={e => setStatus(e.target.value)}>
            <option value="">Status: all</option><option value="draft">Drafts</option><option value="final">Final</option>
          </select>
          <Link className="cv-btn" to="/cases">Write from a case</Link>
        </div>
        <div className="cv-tablewrap">
          <table className="cv-table" style={{ minWidth: 680 }}>
            <thead><tr><th>Report</th><th>Status</th><th>Classification</th><th>Written by</th><th>Updated</th></tr></thead>
            <tbody>
              {reports.map(r => (
                <tr key={r.id} className={selected?.id === r.id ? 'is-active' : undefined} style={{ cursor: 'pointer' }} onClick={() => setSelectedId(r.id)}>
                  <td>
                    <div className="cv-stack">
                      <button type="button" className="cv-rowlink" onClick={() => setSelectedId(r.id)}>{r.title}</button>
                      <span className="cv-muted cv-small">Incident{r.number ? ` · ${r.number}` : ' · draft from case'}{r.ai_used ? ' · AI-assisted' : ''}</span>
                    </div>
                  </td>
                  <td>{r.status === 'final' ? <span className="cv-t-good">Final</span> : <span className="cv-t-warn">Draft</span>}</td>
                  <td className="cv-dim" style={{ textTransform: 'capitalize' }}>{r.classification}</td>
                  <td className="cv-dim">{r.created_by_name ?? '—'}</td>
                  <td className="cv-dim cv-small" style={{ whiteSpace: 'nowrap' }}>{format(new Date(r.finalized_at ?? r.updated_at), 'd MMM yyyy HH:mm')}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {list.isLoading && <Empty>Loading reports…</Empty>}
          {list.isError && <Empty>Could not load reports.</Empty>}
          {!list.isLoading && !list.isError && reports.length === 0 && <Empty>No incident reports yet. Open a case and choose Incident report to write the first one.</Empty>}
        </div>
        <p className="cv-muted cv-small" style={{ margin: 0 }}>
          A report is written from a case. Drafts can be edited; an admin finalizes a report, which numbers it and stores its PDF for good.
        </p>
      </section>
      <aside className="cv-list" aria-label="Report preview" style={{ flex: '1 1 360px', maxWidth: 440, borderRight: 0, borderLeft: '1px solid #222733', padding: 16, gap: 12 }}>
        {selected ? <>
          <div className="cv-row cv-row--between">
            <h2 className="cv-h2">Preview</h2>
            <span className="cv-row" style={{ gap: 6 }}>
              {selected.status === 'final' && <button type="button" className="cv-btn cv-btn--sm"
                onClick={() => { setDownloadError(''); downloadPdf(selected).catch(e => setDownloadError(apiError(e, 'Could not download the PDF.'))) }}>Download PDF</button>}
              <Link className="cv-btn cv-btn--sm" to={`/reports/incidents/${selected.id}`}>{selected.status === 'final' ? 'Open' : 'Edit draft'}</Link>
            </span>
          </div>
          {downloadError && <span className="cv-t-bad cv-small">{downloadError}</span>}
          <div className="cv-paper">
            <span className="cv-small" style={{ color: '#6B7280' }}>{selected.classification} · {selected.language === 'id' ? 'Bahasa Indonesia' : 'English'}</span>
            <h3 style={{ margin: '6px 0 2px', fontSize: 17, color: '#111827' }}>{selected.title}</h3>
            <span className="cv-small" style={{ color: '#6B7280' }}>{selected.number ?? 'Draft'} · {format(new Date(selected.created_at), 'd MMMM yyyy')}</span>
            <div className="cv-paper__facts">
              <span><b>{selected.status === 'final' ? 'Final' : 'Draft'}</b>Status</span>
              <span><b style={{ textTransform: 'capitalize' }}>{selected.priority}</b>Priority</span>
              <span><b>{selected.audience ?? 'Internal'}</b>Audience</span>
            </div>
            <span className="cv-small" style={{ color: '#374151' }}>
              Written by {selected.created_by_name ?? 'unknown'}{selected.finalized_by_name ? `, finalized by ${selected.finalized_by_name}${selected.finalized_at ? ` on ${format(new Date(selected.finalized_at), 'd MMM yyyy')}` : ''}` : ''}.
            </span>
            {selected.pdf_sha256 && <span className="cv-mono" style={{ color: '#6B7280', fontSize: 10.5 }}>SHA-256 {selected.pdf_sha256}</span>}
          </div>
          {selected.case_id && <Link to={`/cases/${selected.case_id}`}>Open the case</Link>}
        </> : <Empty>Select a report to preview it.</Empty>}
      </aside>
    </div>
  )
}

interface VerifyResult { match: boolean; number?: string; title?: string; finalized_by_name?: string; finalized_at?: string; id?: string }

function VerifyReport() {
  const [busy, setBusy] = useState(false)
  const [file, setFile] = useState('')
  const [hash, setHash] = useState('')
  const [result, setResult] = useState<VerifyResult | null>(null)
  const [error, setError] = useState('')
  const check = async (f: File) => {
    setBusy(true); setError(''); setResult(null); setFile(f.name)
    try {
      const digest = await crypto.subtle.digest('SHA-256', await f.arrayBuffer())
      const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
      setHash(hex)
      setResult((await api.post('/api/incident-reports/verify', { sha256: hex })).data)
    } catch (e) {
      setError(apiError(e, 'Could not check this file.'))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="space-y-3 max-w-2xl">
      <p className="text-sm text-muted-foreground">
        Pick a report PDF someone sent you. Your browser computes its SHA-256 and only that hash is sent; the file stays on
        your computer. A match means it is exactly the PDF that was finalized, not a single byte changed.
      </p>
      <label className="ui-button cursor-pointer w-fit">
        <FileText size={14} /> Choose PDF…
        <input type="file" accept="application/pdf,.pdf" className="sr-only" onChange={e => { const f = e.target.files?.[0]; if (f) void check(f); e.target.value = '' }} />
      </label>
      {busy && <p className="text-sm flex items-center gap-2"><Loader2 size={14} className="animate-spin" /> Checking {file}…</p>}
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      {result && (result.match ? (
        <div className="rounded border border-green-500/50 p-3 text-sm space-y-1">
          <div className="flex items-center gap-1.5 font-medium text-green-400"><FileCheck2 size={16} /> Genuine: {result.number}</div>
          <div>{result.title}</div>
          <div className="text-xs text-muted-foreground">Finalized by {result.finalized_by_name} on {result.finalized_at && format(new Date(result.finalized_at), 'yyyy-MM-dd HH:mm')}.
            {' '}<Link className="underline" to={`/reports/incidents/${result.id}`}>Open it</Link></div>
        </div>
      ) : (
        <div className="rounded border border-red-500/50 p-3 text-sm space-y-1">
          <div className="flex items-center gap-1.5 font-medium text-red-400"><FileX2 size={16} /> No final report has this file</div>
          <div className="text-xs text-muted-foreground">The file was changed after it was finalized, is a draft, or comes from another group or system.</div>
        </div>
      ))}
      {hash && <p className="text-xs font-mono break-all text-muted-foreground">{file}: {hash}</p>}
    </div>
  )
}

export default function ReportsPage() {
  const [params] = useSearchParams()
  const tab: Tab = (['incidents', 'periodic', 'verify'] as const).find(t => t === params.get('tab')) ?? 'incidents'
  return (
    <CanvasPage>
      <CanvasHeader
        title="Reports"
        sub="Incident reports written from cases, period summaries, and a check that a PDF copy is genuine"
        tabs={[
          { to: '/reports', label: 'Incident reports', active: tab === 'incidents' },
          { to: '/reports?tab=periodic', label: 'Periodic summaries', active: tab === 'periodic' },
          { to: '/reports?tab=verify', label: 'Verify a report', active: tab === 'verify' },
        ]}
        actions={<>
          <Link className="cv-btn" to="/reports?tab=periodic">Generate summary</Link>
          <Link className="cv-btn cv-btn--primary" to="/cases">New incident report</Link>
        </>}
      />
      {tab === 'incidents' ? <IncidentArchive /> : <div className="cv-body">{tab === 'periodic' ? <PeriodicSummary /> : <VerifyReport />}</div>}
    </CanvasPage>
  )
}
