// Shapes of server-api/app/api/routes/incident_reports.py.

export interface Row { time: string | null; text: string; by?: string | null; source?: string | null }
export interface Ioc { type: string; value: string; note: string }
export interface Evidence { ref: string; id: string; type: string; title: string; observed_at: string | null; hash: string }

export interface IncidentReportSummary {
  id: string
  case_id: string | null
  number: string | null
  status: 'draft' | 'final'
  language: 'id' | 'en'
  title: string
  classification: string
  priority: string
  audience: string | null
  ai_used: boolean
  created_by_name: string | null
  finalized_by_name: string | null
  finalized_at: string | null
  pdf_sha256: string | null
  content_sha256: string | null
  created_at: string
  updated_at: string
}

export interface IncidentReport extends IncidentReportSummary {
  content: {
    facts: Record<string, unknown> & { case_title?: string; verdict?: string; mitre?: string[] }
    sections: Record<string, string>
    timeline: Row[]
    actions: Row[]
    iocs: Ioc[]
    assets: { host: string; alerts: number }[]
    evidence: Evidence[]
  }
}

export const CLASSIFICATIONS: [string, string][] = [
  ['public', 'Public'], ['internal', 'Internal'], ['confidential', 'Confidential'], ['restricted', 'Restricted'],
]
export const PRIORITIES: [string, string][] = [['low', 'Low'], ['normal', 'Normal'], ['high', 'High'], ['urgent', 'Urgent']]
export const SECTIONS: [string, string][] = [
  ['summary', 'Summary'], ['scope', 'Assets and scope (notes)'], ['analysis', 'Analysis'], ['impact', 'Impact'],
  ['recommendations', 'Recommendations'], ['conclusion', 'Conclusion'],
]

export function apiError(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d) && d[0] && typeof d[0].msg === 'string') return d[0].msg
  return fallback
}

export async function downloadPdf(api: { get: (u: string, c: object) => Promise<{ data: Blob }> }, id: string, name: string) {
  const res = await api.get(`/api/incident-reports/${id}/pdf`, { responseType: 'blob' })
  const href = URL.createObjectURL(res.data)
  try {
    const a = document.createElement('a')
    a.href = href
    a.download = name
    a.click()
  } finally {
    URL.revokeObjectURL(href)
  }
}
