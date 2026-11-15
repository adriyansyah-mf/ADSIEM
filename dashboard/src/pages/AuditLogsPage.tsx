import { Fragment, useState } from 'react'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { ChevronDown, ChevronRight, ClipboardList, Download, Loader2, ShieldAlert, ShieldCheck } from 'lucide-react'
import { format, subDays, subHours } from 'date-fns'
import { api } from '@/api/client'

// Append-only, hash-chained audit log (server-api/app/api/routes/audit_logs.py,
// services/audit_chain.py). Nothing here edits or deletes an entry.

interface AuditLog {
  id: string
  seq: number | null
  actor_id: string | null
  actor_name: string | null
  group_id: string
  action: string
  outcome: 'success' | 'failure' | 'denied' | null
  resource_type: string | null
  resource_id: string | null
  detail: Record<string, unknown>
  ip_address: string | null
  user_agent: string | null
  request: string | null
  hash: string | null
  created_at: string
}

interface Verdict {
  ok: boolean
  checked: number
  last_seq?: number | null
  problems: { seq?: number; problem: string }[]
  checkpoint: { seq?: number; status: 'ok' | 'missing' | 'mismatch' | null; recorded_at?: string }
}

const PAGE = 100
const RANGES: [string, string][] = [['', 'All time'], ['1h', 'Last hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']]
const OUTCOME_STYLE: Record<string, string> = {
  success: 'bg-green-500/15 text-green-400',
  failure: 'bg-orange-500/15 text-orange-400',
  denied: 'bg-red-500/15 text-red-400',
}

function since(range: string): string | undefined {
  const now = new Date()
  if (range === '1h') return subHours(now, 1).toISOString()
  if (range === '24h') return subHours(now, 24).toISOString()
  if (range === '7d') return subDays(now, 7).toISOString()
  if (range === '30d') return subDays(now, 30).toISOString()
  return undefined
}

function ChainStatus() {
  const v = useQuery<Verdict>({
    queryKey: ['audit-verify'],
    queryFn: () => api.get('/api/audit-logs/verify').then(r => r.data),
    refetchInterval: 5 * 60_000,
  })
  if (v.isLoading) return <span className="text-xs text-muted-foreground flex items-center gap-1"><Loader2 size={12} className="animate-spin" /> Checking the chain…</span>
  if (v.isError || !v.data) return <span className="text-xs text-muted-foreground">Could not check the chain.</span>
  const cp = v.data.checkpoint?.status
  return (
    <div className={`rounded border px-3 py-2 text-xs space-y-1 ${v.data.ok ? 'border-green-500/40' : 'border-red-500/50 bg-red-500/5'}`}>
      <div className="flex items-center gap-1.5 font-medium">
        {v.data.ok ? <ShieldCheck size={14} className="text-green-400" /> : <ShieldAlert size={14} className="text-red-400" />}
        {v.data.ok ? `Chain intact: ${v.data.checked.toLocaleString()} entries, none changed or removed` : 'Chain broken: entries were changed or removed'}
        <button type="button" className="ml-2 underline text-muted-foreground" onClick={() => void v.refetch()} disabled={v.isFetching}>
          {v.isFetching ? 'Checking…' : 'Check again'}</button>
      </div>
      {cp && <div className="text-muted-foreground">
        Elasticsearch checkpoint: {cp === 'ok' ? 'matches' : cp === 'missing' ? 'its entry is gone (newest entries deleted)' : 'does not match'}
        {v.data.checkpoint.seq ? ` (entry #${v.data.checkpoint.seq})` : ''}
      </div>}
      {!cp && v.data.ok && <div className="text-muted-foreground">No Elasticsearch checkpoint yet (the worker writes one every 5 minutes).</div>}
      {!v.data.ok && (
        <ul className="list-disc pl-5 text-red-300">
          {v.data.problems.slice(0, 8).map((p, i) => <li key={i}>{p.seq ? `#${p.seq}: ` : ''}{p.problem}</li>)}
        </ul>
      )}
    </div>
  )
}

export default function AuditLogsPage() {
  const [q, setQ] = useState('')
  const [actor, setActor] = useState('')
  const [ip, setIp] = useState('')
  const [outcome, setOutcome] = useState('')
  const [range, setRange] = useState('7d')
  const [open, setOpen] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)
  const params = { q: q || undefined, actor: actor || undefined, ip: ip || undefined, outcome: outcome || undefined, since: since(range) }

  const logs = useInfiniteQuery<AuditLog[]>({
    queryKey: ['audit-logs', q, actor, ip, outcome, range],
    queryFn: ({ pageParam }) => api.get('/api/audit-logs', { params: { ...params, limit: PAGE, offset: pageParam } }).then(r => r.data),
    initialPageParam: 0,
    getNextPageParam: (last, all) => (last.length === PAGE ? all.length * PAGE : undefined),
    refetchInterval: 30_000,
  })
  const rows = logs.data?.pages.flat() ?? []

  const exportCsv = async () => {
    setExporting(true)
    let href: string | null = null
    try {
      const res = await api.get('/api/audit-logs/export.csv', { params, responseType: 'blob' })
      href = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = href
      a.download = `audit-log-${format(new Date(), 'yyyyMMdd-HHmm')}.csv`
      a.click()
    } finally {
      if (href) URL.revokeObjectURL(href)
      setExporting(false)
    }
  }

  return (
    <div className="p-6 space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <ClipboardList size={20} aria-hidden="true" />
        <h1 className="text-xl font-bold">Audit Log</h1>
        <div className="flex-1" />
        <button type="button" className="ui-button" onClick={() => void exportCsv()} disabled={exporting}>
          {exporting ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />} Export CSV</button>
      </div>
      <p className="text-xs text-muted-foreground max-w-3xl">
        Every entry records who acted, from which address and browser, and whether it worked. Entries cannot be
        edited or deleted: the database refuses it, and each entry carries a hash of the one before, so a change
        made around the database is caught by the check below.
      </p>
      <ChainStatus />

      <div className="flex flex-wrap items-end gap-2">
        <label className="field"><span>Search</span>
          <input className="ui-input w-56" placeholder="action, resource, request…" value={q} onChange={e => setQ(e.target.value)} /></label>
        <label className="field"><span>User</span>
          <input className="ui-input w-40" placeholder="username" value={actor} onChange={e => setActor(e.target.value)} /></label>
        <label className="field"><span>IP address</span>
          <input className="ui-input w-40 font-mono" placeholder="203.0.113.7" value={ip} onChange={e => setIp(e.target.value.trim())} /></label>
        <label className="field"><span>Result</span>
          <select className="ui-input w-auto" value={outcome} onChange={e => setOutcome(e.target.value)}>
            <option value="">Any</option><option value="success">Success</option><option value="failure">Failure</option><option value="denied">Denied</option>
          </select></label>
        <label className="field"><span>When</span>
          <select className="ui-input w-auto" value={range} onChange={e => setRange(e.target.value)}>
            {RANGES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select></label>
        <button type="button" className="ui-button ui-button--quiet" onClick={() => setOutcome('failure')}>Failed logins and errors</button>
      </div>

      {logs.isLoading ? <div className="text-sm text-muted-foreground">Loading...</div>
        : logs.isError ? <div className="text-sm text-destructive">Could not load the audit log.</div>
        : rows.length === 0 ? <div className="text-sm text-muted-foreground">No audit log entries match.</div>
        : (
          <div className="rounded border border-border bg-card overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted text-muted-foreground">
                <tr className="text-left text-[11px] uppercase tracking-wider">
                  <th className="px-3 py-2 w-6" aria-label="Expand" /><th className="px-3 py-2">Time</th><th className="px-3 py-2">User</th>
                  <th className="px-3 py-2">Action</th><th className="px-3 py-2">Result</th><th className="px-3 py-2">IP address</th>
                  <th className="px-3 py-2">Resource</th><th className="px-3 py-2">Request</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(log => (
                  <Fragment key={log.id}>
                    <tr className="border-t border-border hover:bg-white/[0.03] cursor-pointer" onClick={() => setOpen(open === log.id ? null : log.id)}>
                      <td className="px-3 py-2 text-muted-foreground">{open === log.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                      <td className="px-3 py-2 text-muted-foreground whitespace-nowrap tabular-nums">{format(new Date(log.created_at), 'yyyy-MM-dd HH:mm:ss')}</td>
                      <td className="px-3 py-2 whitespace-nowrap">{log.actor_name ?? (log.actor_id ? log.actor_id.slice(0, 8) : <span className="text-muted-foreground">system</span>)}</td>
                      <td className="px-3 py-2 font-mono text-xs">{log.action}</td>
                      <td className="px-3 py-2">{log.outcome && <span className={`px-1.5 py-0.5 rounded text-xs ${OUTCOME_STYLE[log.outcome] ?? ''}`}>{log.outcome}</span>}</td>
                      <td className="px-3 py-2 font-mono text-xs whitespace-nowrap">
                        {log.ip_address ? <button type="button" className="hover:underline" title="Show only this address"
                          onClick={e => { e.stopPropagation(); setIp(log.ip_address ?? '') }}>{log.ip_address}</button> : '—'}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground text-xs">{log.resource_type}{log.resource_id && <span className="ml-1 opacity-70">#{log.resource_id.slice(0, 12)}</span>}</td>
                      <td className="px-3 py-2 text-muted-foreground font-mono text-xs whitespace-nowrap">{log.request ?? '—'}</td>
                    </tr>
                    {open === log.id && (
                      <tr className="bg-muted/30">
                        <td />
                        <td colSpan={7} className="px-3 py-3 text-xs space-y-2">
                          <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1">
                            <dt className="text-muted-foreground">Browser / client</dt><dd className="break-all">{log.user_agent ?? '—'}</dd>
                            <dt className="text-muted-foreground">Group</dt><dd>{log.group_id}</dd>
                            <dt className="text-muted-foreground">Entry</dt><dd className="font-mono break-all">{log.seq ? `#${log.seq} · ${log.hash}` : 'written before the chain existed'}</dd>
                          </dl>
                          {Object.keys(log.detail ?? {}).length > 0 && (
                            <pre className="whitespace-pre-wrap break-all font-mono text-[11px] bg-background/60 rounded p-2">{JSON.stringify(log.detail, null, 2)}</pre>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      {logs.hasNextPage && (
        <button type="button" className="ui-button" onClick={() => void logs.fetchNextPage()} disabled={logs.isFetchingNextPage}>
          {logs.isFetchingNextPage ? 'Loading…' : 'Load more'}</button>
      )}
    </div>
  )
}
