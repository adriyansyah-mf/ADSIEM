import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Download, FileBarChart, FileCheck2, FileText, FileX2, Loader2, Lock } from 'lucide-react'
import { format, subDays } from 'date-fns'
import { api } from '@/api/client'
import { apiError, type IncidentReportSummary } from '@/components/reports/types'

// Incident reports written from cases (archive), the periodic summary PDF,
// and a check that a PDF copy is a real, unchanged final report.

const LANGUAGES = ['English', 'Indonesian', 'Spanish', 'French', 'German', 'Japanese']
type Tab = 'incidents' | 'periodic' | 'verify'

function IncidentArchive() {
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const list = useQuery<IncidentReportSummary[]>({
    queryKey: ['incident-reports', status, q],
    queryFn: () => api.get('/api/incident-reports', { params: { status: status || undefined, q: q || undefined } }).then(r => r.data),
  })
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground max-w-3xl">
        A report is written from a case (open a case, then <b>Incident report</b>). Drafts can be edited; an admin finalizes
        a report, which numbers it and stores its PDF for good.
      </p>
      <div className="flex flex-wrap items-end gap-2">
        <label className="field"><span>Search</span>
          <input className="ui-input w-64" placeholder="title or number" value={q} onChange={e => setQ(e.target.value)} /></label>
        <label className="field"><span>Status</span>
          <select className="ui-input w-auto" value={status} onChange={e => setStatus(e.target.value)}>
            <option value="">All</option><option value="draft">Drafts</option><option value="final">Final</option>
          </select></label>
      </div>
      {list.isLoading ? <Loader2 size={16} className="animate-spin" />
        : list.isError ? <p className="text-sm text-destructive">Could not load reports.</p>
        : !list.data?.length ? (
          <div className="rounded border border-dashed border-border p-6 text-sm text-muted-foreground">
            No incident reports yet. Open a case and choose <b>Incident report</b> to write the first one.
            <div className="mt-2"><Link className="ui-button" to="/cases">Open cases</Link></div>
          </div>
        ) : (
          <div className="rounded border border-border bg-card overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted text-muted-foreground">
                <tr className="text-left text-[11px] uppercase tracking-wider">
                  <th className="px-3 py-2">Number</th><th className="px-3 py-2">Title</th><th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Classification</th><th className="px-3 py-2">Language</th><th className="px-3 py-2">Written by</th>
                  <th className="px-3 py-2">Updated</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map(r => (
                  <tr key={r.id} className="border-t border-border hover:bg-white/[0.03]">
                    <td className="px-3 py-2 font-mono whitespace-nowrap">{r.number ?? '—'}</td>
                    <td className="px-3 py-2"><Link className="hover:underline" to={`/reports/incidents/${r.id}`}>{r.title}</Link></td>
                    <td className="px-3 py-2 whitespace-nowrap">{r.status === 'final'
                      ? <span className="inline-flex items-center gap-1 text-green-400"><Lock size={12} /> final</span>
                      : <span className="text-muted-foreground">draft</span>}</td>
                    <td className="px-3 py-2 capitalize">{r.classification}</td>
                    <td className="px-3 py-2 uppercase text-xs">{r.language}</td>
                    <td className="px-3 py-2">{r.created_by_name ?? '—'}</td>
                    <td className="px-3 py-2 text-muted-foreground whitespace-nowrap tabular-nums">{format(new Date(r.finalized_at ?? r.updated_at), 'yyyy-MM-dd HH:mm')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
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

function PeriodicReport() {
  const [dateFrom, setDateFrom] = useState(format(subDays(new Date(), 7), 'yyyy-MM-dd'))
  const [dateTo, setDateTo] = useState(format(new Date(), 'yyyy-MM-dd'))
  const [language, setLanguage] = useState('English')
  const [isGenerating, setIsGenerating] = useState(false)
  const [error, setError] = useState('')

  const handleGenerate = async () => {
    setError('')
    if (!dateFrom || !dateTo) { setError('Select a date range'); return }
    if (new Date(dateFrom) > new Date(dateTo)) { setError('Start date must be before end date'); return }
    setIsGenerating(true)
    let href: string | null = null
    try {
      const res = await api.post('/api/reports/generate', { date_from: dateFrom, date_to: dateTo, language }, { responseType: 'blob' })
      href = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = href
      a.download = `security-report-${dateFrom}-to-${dateTo}.pdf`
      a.click()
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Failed to generate report')
    } finally {
      if (href) URL.revokeObjectURL(href)
      setIsGenerating(false)
    }
  }

  return (
    <div className="rounded-lg border border-border bg-card p-5 space-y-4 max-w-xl">
      <p className="text-xs text-muted-foreground">
        A PDF of a period: alert volume, severity breakdown, top triggered rules, AI verdict distribution, MITRE ATT&amp;CK
        techniques observed, and an AI-written executive summary. The organization name on reports is set on the Settings page.
      </p>
      <div className="grid grid-cols-2 gap-3">
        <label className="field"><span>From</span><input type="date" className="ui-input" value={dateFrom} onChange={e => setDateFrom(e.target.value)} /></label>
        <label className="field"><span>To</span><input type="date" className="ui-input" value={dateTo} onChange={e => setDateTo(e.target.value)} /></label>
      </div>
      <label className="field"><span>Report language</span>
        <input className="ui-input" value={language} onChange={e => setLanguage(e.target.value)} list="report-languages" placeholder="English" />
        <datalist id="report-languages">{LANGUAGES.map(l => <option key={l} value={l} />)}</datalist></label>
      {error && <p className="text-xs text-destructive">{error}</p>}
      <button onClick={handleGenerate} disabled={isGenerating} className="ui-button ui-button--primary">
        {isGenerating ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
        {isGenerating ? 'Generating…' : 'Generate PDF'}
      </button>
    </div>
  )
}

export default function ReportsPage() {
  const [tab, setTab] = useState<Tab>('incidents')
  const TABS: [Tab, string][] = [['incidents', 'Incident reports'], ['periodic', 'Periodic summary'], ['verify', 'Verify a report']]
  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <FileBarChart size={20} />
        <h1 className="text-xl font-bold">Reports</h1>
      </div>
      <div role="tablist" className="flex gap-1 border-b border-border">
        {TABS.map(([t, label]) => (
          <button key={t} role="tab" aria-selected={tab === t} type="button" onClick={() => setTab(t)}
            className={`px-3 py-2 text-sm -mb-px border-b-2 ${tab === t ? 'border-primary text-foreground font-medium' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
            {label}</button>
        ))}
      </div>
      {tab === 'incidents' ? <IncidentArchive /> : tab === 'periodic' ? <PeriodicReport /> : <VerifyReport />}
    </div>
  )
}
