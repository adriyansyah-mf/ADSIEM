import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { ChevronDown, ChevronRight, Loader2, RefreshCw, ShieldAlert } from 'lucide-react'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

// Fleet vulnerabilities ranked for patching (server-api/app/api/routes/vulnerabilities.py):
// exploited in the wild (CISA KEV) > likely exploited (EPSS) > severe (CVSS).

type Priority = 'critical' | 'high' | 'medium' | 'low'

interface Cve {
  cve_id: string
  title: string | null
  priority: Priority
  severity: string | null
  cvss: number | null
  epss: number | null
  epss_percentile: number | null
  kev: boolean
  kev_due_date: string | null
  kev_ransomware: boolean
  hosts: number
  hostnames: string[]
  packages: string[]
  fixes: string[]
  first_seen: string | null
}

interface HostRow {
  agent_id: string
  hostname: string | null
  package: string
  installed_version: string | null
  fixed_version: string | null
  kb: string | null
  first_seen: string | null
}

interface Listing {
  total: number
  summary: { cves: number; kev: number; hosts: number; by_priority: Record<Priority, number> }
  items: Cve[]
  intel: Record<string, string>
  scan: Record<string, string>
}

const PRIORITY: Record<Priority, { label: string; tone: string; hint: string }> = {
  critical: { label: 'Patch now', tone: 'text-red-400 border-red-400/50', hint: 'Exploited in the wild (CISA KEV)' },
  high: { label: 'High', tone: 'text-orange-400 border-orange-400/50', hint: 'Likely to be exploited soon (EPSS ≥ 10%), or critical with some chance' },
  medium: { label: 'Medium', tone: 'text-amber-400 border-amber-400/50', hint: 'Severe (CVSS ≥ 7) or some chance of exploitation' },
  low: { label: 'Low', tone: 'text-muted-foreground border-border', hint: 'Neither severe nor likely to be exploited' },
}

function ago(ts?: string | null) {
  if (!ts) return 'never'
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : formatDistanceToNow(d, { addSuffix: true })
}

function Hosts({ cve }: { cve: string }) {
  const q = useQuery<HostRow[]>({
    queryKey: ['vuln-hosts', cve],
    queryFn: () => api.get(`/api/vulnerabilities/${encodeURIComponent(cve)}/hosts`).then(r => r.data),
  })
  if (q.isLoading) return <Loader2 size={14} className="animate-spin" />
  if (q.isError) return <p className="text-xs text-destructive">Could not load the hosts.</p>
  return (
    <div className="overflow-x-auto">
      <table className="text-xs w-full">
        <thead className="text-muted-foreground text-left"><tr>
          {['Host', 'Package', 'Installed', 'Fix', 'Found'].map(h => <th key={h} className="py-1 pr-4 font-medium">{h}</th>)}
        </tr></thead>
        <tbody>{(q.data ?? []).map(h => (
          <tr key={`${h.agent_id}-${h.package}`}>
            <td className="py-1 pr-4">{h.hostname ?? h.agent_id}</td>
            <td className="py-1 pr-4 font-mono">{h.package}</td>
            <td className="py-1 pr-4 font-mono break-all">{h.installed_version ?? '—'}</td>
            <td className="py-1 pr-4 font-mono break-all">{h.kb ? `${h.kb} (${h.fixed_version})` : h.fixed_version ?? 'no fix yet'}</td>
            <td className="py-1 pr-4 whitespace-nowrap">{ago(h.first_seen)}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  )
}

export default function VulnerabilitiesPage() {
  const qc = useQueryClient()
  const canSync = useAuthStore(s => s.hasRole('admin'))
  const [priority, setPriority] = useState<Priority | ''>('')
  const [kevOnly, setKevOnly] = useState(false)
  const [search, setSearch] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  const list = useQuery<Listing>({
    queryKey: ['vulnerabilities', priority, kevOnly, search],
    queryFn: () => api.get('/api/vulnerabilities', {
      params: { priority: priority || undefined, kev: kevOnly || undefined, q: search.trim() || undefined, limit: 300 },
    }).then(r => r.data),
  })
  const sync = useMutation({
    mutationFn: () => api.post('/api/vulnerabilities/sync'),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['vulnerabilities'] }), 2000),
  })
  const s = list.data?.summary

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <ShieldAlert size={18} />
        <h1 className="text-xl font-bold">Vulnerabilities</h1>
        <div className="flex-1" />
        {canSync && (
          <button onClick={() => sync.mutate()} disabled={sync.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-border text-sm disabled:opacity-50">
            <RefreshCw size={14} className={sync.isPending ? 'animate-spin' : ''} /> Refresh data and rescan
          </button>
        )}
      </div>
      <p className="text-xs text-muted-foreground max-w-3xl">
        Linux packages are matched against OSV.dev for the host's own distro release; Windows hosts by build and update
        revision against Microsoft's monthly security releases, with the KB that fixes them. Ranked by what attackers
        use: CISA's Known Exploited Vulnerabilities first, then FIRST EPSS (chance of exploitation in 30 days), then CVSS.
        {list.data && <> Last scan {ago(list.data.scan.last_attempt)} · intel updated {ago(list.data.intel.last_success)}
          {list.data.intel.error ? ` (${list.data.intel.error})` : ''}.</>}
      </p>

      {s && (
        <div className="flex flex-wrap gap-3">
          {(['critical', 'high', 'medium', 'low'] as Priority[]).map(p => (
            <button key={p} onClick={() => setPriority(priority === p ? '' : p)} title={PRIORITY[p].hint}
              aria-pressed={priority === p}
              className={`rounded-lg border bg-card px-4 py-3 text-left min-w-[130px] ${priority === p ? 'border-primary' : 'border-border'}`}>
              <div className={`text-xs ${PRIORITY[p].tone.split(' ')[0]}`}>{PRIORITY[p].label}</div>
              <div className="text-xl font-semibold tabular-nums">{s.by_priority[p].toLocaleString()}</div>
            </button>
          ))}
          <div className="rounded-lg border border-border bg-card px-4 py-3 min-w-[130px]">
            <div className="text-xs text-muted-foreground">Hosts affected</div>
            <div className="text-xl font-semibold tabular-nums">{s.hosts.toLocaleString()}</div>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="CVE, package or host"
          aria-label="Search vulnerabilities"
          className="bg-muted border border-border rounded px-3 py-1.5 text-sm w-64 max-w-full" />
        <label className="flex items-center gap-1.5 text-sm cursor-pointer select-none">
          <input type="checkbox" checked={kevOnly} onChange={e => setKevOnly(e.target.checked)} /> Exploited in the wild only
        </label>
        {list.data && <span className="text-xs text-muted-foreground">{list.data.total.toLocaleString()} CVEs</span>}
      </div>

      {list.isLoading ? <Loader2 size={16} className="animate-spin" />
        : list.isError ? <p className="text-sm text-destructive">Could not load vulnerabilities.</p>
        : !list.data?.items.length ? (
          <p className="text-sm text-muted-foreground">
            {list.data?.summary.cves ? 'Nothing matches the filter.' : 'No open vulnerability found yet. Hosts are scanned every few hours after their agent reports.'}
          </p>
        ) : (
          <div className="rounded-lg border border-border divide-y divide-border">
            {list.data.items.map(v => (
              <div key={v.cve_id}>
                <button onClick={() => setOpen(open === v.cve_id ? null : v.cve_id)}
                  className="w-full flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-left text-sm hover:bg-muted/40">
                  {open === v.cve_id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  <span className={`text-[11px] uppercase tracking-wide px-1.5 py-0.5 rounded border ${PRIORITY[v.priority].tone}`}
                    title={PRIORITY[v.priority].hint}>{PRIORITY[v.priority].label}</span>
                  <span className="font-mono">{v.cve_id}</span>
                  {v.kev && <span className="text-[11px] text-red-400" title={`CISA due date ${v.kev_due_date ?? '—'}`}>
                    KEV{v.kev_ransomware ? ' · ransomware' : ''}</span>}
                  <span className="min-w-0 flex-1 truncate text-muted-foreground">{v.title ?? ''}</span>
                  <span className="text-xs tabular-nums text-muted-foreground" title="CVSS base score">CVSS {v.cvss ?? '—'}</span>
                  <span className="text-xs tabular-nums text-muted-foreground" title="Chance of exploitation in the next 30 days (FIRST EPSS)">
                    EPSS {v.epss != null ? `${(v.epss * 100).toFixed(v.epss < 0.01 ? 2 : 1)}%` : '—'}</span>
                  <span className="text-xs tabular-nums">{v.hosts} host{v.hosts === 1 ? '' : 's'}</span>
                </button>
                {open === v.cve_id && (
                  <div className="px-9 pb-3 space-y-2">
                    <div className="text-xs text-muted-foreground flex flex-wrap gap-x-4">
                      <span>Packages: <span className="font-mono">{v.packages.join(', ')}</span></span>
                      <span>Fix: <span className="font-mono">{v.fixes.join(', ') || 'none published yet'}</span></span>
                      {v.kev_due_date && <span>CISA due date: {v.kev_due_date}</span>}
                      <a className="underline" href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noreferrer">NVD</a>
                    </div>
                    <Hosts cve={v.cve_id} />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
    </div>
  )
}
