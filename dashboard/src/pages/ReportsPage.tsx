import { useState } from 'react'
import { FileBarChart, Download, Loader2 } from 'lucide-react'
import { format, subDays } from 'date-fns'
import { api } from '@/api/client'
import { PageHeader } from '@/components/ui/PageHeader'

const LANGUAGES = ['English', 'Indonesian', 'Spanish', 'French', 'German', 'Japanese']

export default function ReportsPage() {
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
      const res = await api.post(
        '/api/reports/generate',
        { date_from: dateFrom, date_to: dateTo, language },
        { responseType: 'blob' }
      )
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
    <div className="space-y-6">
      <PageHeader title={<><FileBarChart aria-hidden="true" size={20} /> Reports</>} />

      <div className="enterprise-panel rounded-lg border border-border bg-card p-5 space-y-4 max-w-xl">
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
          Generate Security Report
        </h2>
        <p className="text-xs text-muted-foreground">
          Builds a PDF covering alert volume, severity breakdown, top triggered rules,
          AI verdict distribution, MITRE ATT&amp;CK techniques observed, and an AI-written
          executive summary for the selected period. Organization name shown on the report
          can be set on the Settings page ("Organization Name").
        </p>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">From</label>
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">To</label>
            <input
              type="date"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
        </div>

        <div>
          <label className="text-xs text-muted-foreground block mb-1">Report Language</label>
          <input
            value={language}
            onChange={(e) => setLanguage(e.target.value)}
            list="report-languages"
            placeholder="English"
            className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <datalist id="report-languages">
            {LANGUAGES.map((l) => <option key={l} value={l} />)}
          </datalist>
        </div>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <button
          onClick={handleGenerate}
          disabled={isGenerating}
          className="flex items-center gap-2 px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50"
        >
          {isGenerating ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
          {isGenerating ? 'Generating…' : 'Generate PDF'}
        </button>
      </div>
    </div>
  )
}
