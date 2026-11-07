import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Check, Copy, Crosshair, Loader2, Search, ShieldX, X } from 'lucide-react'
import { IOC_PAGE, IOC_TYPES, type Ioc, type IocFilter, type IocType, useIocAlerts, useIocs } from '@/hooks/useIocs'
import { useAddMalwareHashes } from '@/hooks/useMalwareHashes'
import { useStartHunt } from '@/hooks/useHunts'

const TYPE_LABEL: Record<IocType, string> = {
  ip: 'IP', domain: 'Domain', url: 'URL', sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5', email: 'Email',
}
const WINDOWS = [{ days: 1, label: '24 h' }, { days: 7, label: '7 days' }, { days: 30, label: '30 days' },
  { days: 90, label: '90 days' }, { days: 0, label: 'All time' }]
const SEVERITY_CLASS: Record<string, string> = {
  critical: 'text-red-500', high: 'text-orange-500', medium: 'text-yellow-500', low: 'text-blue-400', info: 'text-muted-foreground',
}

function ago(iso: string | null): string {
  if (!iso) return '—'
  const s = (Date.now() - new Date(iso).getTime()) / 1000
  if (s < 90) return 'just now'
  if (s < 5400) return `${Math.round(s / 60)} min ago`
  if (s < 172800) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} days ago`
}

function huntType(type: IocType): 'ip' | 'hash' | null {
  if (type === 'ip') return 'ip'
  return type === 'sha256' || type === 'sha1' || type === 'md5' ? 'hash' : null
}

function Detail({ ioc, onClose }: { ioc: Ioc; onClose: () => void }) {
  const { data, isLoading } = useIocAlerts(ioc)
  const hunt = useStartHunt()
  const addHash = useAddMalwareHashes()
  const navigate = useNavigate()
  const kind = huntType(ioc.type)
  return (
    <aside className="rounded-lg border border-border p-4 space-y-3 lg:w-96 shrink-0">
      <div className="flex items-start gap-2">
        <div className="min-w-0">
          <div className="text-xs text-muted-foreground">{TYPE_LABEL[ioc.type]}</div>
          <div className="font-mono text-sm break-all">{ioc.value}</div>
        </div>
        <button onClick={onClose} aria-label="Close" className="ml-auto p-1 rounded hover:bg-muted"><X size={14} /></button>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div><div className="text-muted-foreground">Alerts</div>{ioc.alerts}</div>
        <div><div className="text-muted-foreground">Hosts</div>{ioc.hosts}</div>
        <div><div className="text-muted-foreground">First seen</div>{ago(ioc.first_seen)}</div>
        <div><div className="text-muted-foreground">Last seen</div>{ago(ioc.last_seen)}</div>
      </div>
      <div className="flex flex-wrap gap-2">
        {kind && (
          <button disabled={hunt.isPending}
            onClick={() => hunt.mutate({ ioc_type: kind, ioc_value: ioc.value }, { onSuccess: () => navigate('/hunts') })}
            className="text-xs px-2 py-1 rounded border border-border hover:bg-muted inline-flex items-center gap-1">
            <Crosshair size={12} /> Hunt
          </button>
        )}
        {ioc.type === 'sha256' && (
          <button disabled={addHash.isPending || addHash.isSuccess}
            onClick={() => addHash.mutate({ hashes: [ioc.value], label: '', reference: 'Threat IoCs' })}
            className="text-xs px-2 py-1 rounded border border-border hover:bg-muted inline-flex items-center gap-1">
            <ShieldX size={12} /> {addHash.isSuccess ? 'Added to malware hashes' : 'Add to malware hashes'}
          </button>
        )}
      </div>
      <div className="text-xs font-semibold">Alerts with this indicator</div>
      {isLoading ? <Loader2 size={14} className="animate-spin" /> : !data?.items.length ? (
        <p className="text-xs text-muted-foreground">No alerts visible to you.</p>
      ) : (
        <ul className="space-y-1">
          {data.items.map(a => (
            <li key={a.id} className="text-xs border-t border-border pt-1">
              <Link to={`/alerts/${a.id}`} className="hover:underline font-medium">{a.title}</Link>
              <div className="text-muted-foreground">
                <span className={SEVERITY_CLASS[a.severity] ?? ''}>{a.severity}</span>
                {' · '}{a.hostname ?? 'no host'}{' · '}{ago(a.created_at)}{a.ai_verdict ? ` · AI: ${a.ai_verdict}` : ''}
              </div>
            </li>
          ))}
        </ul>
      )}
    </aside>
  )
}

export default function ThreatIocsPage() {
  const [filter, setFilter] = useState<IocFilter>({ type: '', q: '', days: 30, sort: 'last_seen', offset: 0 })
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Ioc | null>(null)
  const [copied, setCopied] = useState('')
  const { data, isLoading, isFetching } = useIocs(filter)
  const update = (patch: Partial<IocFilter>) => setFilter(f => ({ ...f, offset: 0, ...patch }))
  const counts = data?.type_counts ?? {}
  const all = Object.values(counts).reduce((sum, n) => sum + (n ?? 0), 0)

  const copy = (value: string) => {
    navigator.clipboard?.writeText(value)
    setCopied(value)
    setTimeout(() => setCopied(''), 1500)
  }

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-xl font-bold">Threat IoCs</h1>
        <p className="text-sm text-muted-foreground">Attacker indicators recorded in your alerts.</p>
      </div>

      <div className="flex flex-wrap gap-1 border-b border-border" role="tablist">
        {[{ key: '' as const, label: 'All', count: all }, ...IOC_TYPES.map(t => ({ key: t, label: TYPE_LABEL[t], count: counts[t] ?? 0 }))]
          .map(tab => (
            <button key={tab.key || 'all'} role="tab" aria-selected={filter.type === tab.key}
              onClick={() => { update({ type: tab.key }); setSelected(null) }}
              className={`px-3 py-1.5 text-sm border-b-2 -mb-px ${filter.type === tab.key
                ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
              {tab.label} <span className="text-xs text-muted-foreground">{tab.count.toLocaleString()}</span>
            </button>
          ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <form onSubmit={e => { e.preventDefault(); update({ q: search }) }} className="flex items-center gap-1">
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search indicator"
            aria-label="Search indicator" className="bg-muted border border-border rounded px-2 py-1.5 text-sm w-64" />
          <button type="submit" aria-label="Search" className="p-1.5 rounded border border-border hover:bg-muted"><Search size={14} /></button>
        </form>
        <select value={filter.days} onChange={e => update({ days: Number(e.target.value) })} aria-label="Time window"
          className="bg-muted border border-border rounded px-2 py-1.5 text-sm">
          {WINDOWS.map(w => <option key={w.days} value={w.days}>{w.label}</option>)}
        </select>
        <select value={filter.sort} onChange={e => update({ sort: e.target.value as IocFilter['sort'] })} aria-label="Sort"
          className="bg-muted border border-border rounded px-2 py-1.5 text-sm">
          <option value="last_seen">Most recent</option>
          <option value="alerts">Most alerts</option>
        </select>
        {isFetching && <Loader2 size={14} className="animate-spin text-muted-foreground" />}
        <span className="text-xs text-muted-foreground ml-auto">{data ? `${data.total.toLocaleString()} indicators` : ''}</span>
      </div>

      <div className="flex flex-col lg:flex-row gap-4 items-start">
        <div className="flex-1 min-w-0 space-y-2">
          {isLoading ? <Loader2 size={16} className="animate-spin" /> : !data?.items.length ? (
            <p className="text-sm text-muted-foreground">No indicators in this window.</p>
          ) : (
            <div className="rounded-lg border border-border overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-muted/40 text-xs text-muted-foreground uppercase">
                  <tr>
                    <th className="text-left px-3 py-2">Indicator</th>
                    <th className="text-right px-3 py-2">Alerts</th>
                    <th className="text-right px-3 py-2">Hosts</th>
                    <th className="text-left px-3 py-2">Severity</th>
                    <th className="text-left px-3 py-2">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map(ioc => (
                    <tr key={`${ioc.type}:${ioc.value}`} onClick={() => setSelected(ioc)}
                      className={`border-t border-border cursor-pointer hover:bg-muted/40 ${selected?.value === ioc.value && selected.type === ioc.type ? 'bg-muted/60' : ''}`}>
                      <td className="px-3 py-2 max-w-md">
                        <div className="text-xs text-muted-foreground">{TYPE_LABEL[ioc.type]}</div>
                        <button onClick={e => { e.stopPropagation(); copy(ioc.value) }} title={ioc.value}
                          className="font-mono text-xs inline-flex items-center gap-1 hover:underline max-w-full">
                          <span className="truncate">{ioc.value}</span>
                          {copied === ioc.value ? <Check size={11} className="text-primary shrink-0" /> : <Copy size={11} className="opacity-50 shrink-0" />}
                        </button>
                      </td>
                      <td className="px-3 py-2 text-right tabular-nums">{ioc.alerts}</td>
                      <td className="px-3 py-2 text-right tabular-nums">{ioc.hosts}</td>
                      <td className={`px-3 py-2 text-xs ${SEVERITY_CLASS[ioc.max_severity ?? ''] ?? ''}`}>{ioc.max_severity ?? '—'}</td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{ago(ioc.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {data && data.total > IOC_PAGE && (
            <div className="flex items-center gap-2 text-xs">
              <button disabled={filter.offset === 0} onClick={() => setFilter(f => ({ ...f, offset: Math.max(0, f.offset - IOC_PAGE) }))}
                className="px-2 py-1 rounded border border-border disabled:opacity-40">Previous</button>
              <span className="text-muted-foreground">
                {filter.offset + 1}–{Math.min(filter.offset + IOC_PAGE, data.total)} of {data.total.toLocaleString()}
              </span>
              <button disabled={filter.offset + IOC_PAGE >= data.total} onClick={() => setFilter(f => ({ ...f, offset: f.offset + IOC_PAGE }))}
                className="px-2 py-1 rounded border border-border disabled:opacity-40">Next</button>
            </div>
          )}
          {data && data.total >= 1000 && (
            <p className="text-xs text-muted-foreground">Showing the top 1,000 indicators of this window. Search or narrow the window to see others.</p>
          )}
        </div>
        {selected && <Detail ioc={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  )
}
