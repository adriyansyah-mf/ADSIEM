import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import { ChevronDown, ChevronRight, History, Loader2, Play } from 'lucide-react'
import { api } from '@/api/client'

// Search the stored logs for an indicator, or run a rule over them
// (server-api/app/api/routes/retro_hunts.py, worker/worker/retro_hunt.py).

interface HostHit {
  agent_id: string | null
  hostname: string
  count: number
  first_seen: string | null
  last_seen: string | null
  samples: { event_id: string; log_type: string; created_at: string; line: string }[]
}

interface RuleMatch {
  event_id: string
  created_at: string
  hostname: string | null
  log_type: string
  line: string
}

interface RetroHunt {
  id: string
  kind: 'ioc' | 'rule'
  ioc_type: string | null
  ioc_value: string | null
  rule_title: string | null
  days: number
  group_id: string
  trigger: string
  create_alerts: boolean
  status: 'pending' | 'running' | 'done' | 'failed'
  scanned: number
  matched: number
  hosts: number
  alerts_created: number
  truncated: boolean
  results: { hosts?: HostHit[]; matches?: RuleMatch[]; log_types?: string[] | null } | null
  error: string | null
  created_at: string
  finished_at: string | null
}

const IOC_TYPES = [
  ['ip', 'IP address'], ['domain', 'Domain'], ['hash', 'File hash (MD5/SHA1/SHA256)'], ['url', 'URL'], ['text', 'Any text'],
] as const

const TRIGGER: Record<string, string> = {
  manual: 'started by an analyst', ip_block: 'IP added to blocklist', web_block: 'domain blocked',
  malware_hash: 'hash added to malware hashes',
}

const input = 'bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary'

function apiError(err: unknown): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d)) return d.map(x => (x as { msg?: string }).msg ?? '').join('; ')
  return 'Could not start the retro-hunt.'
}

function when(ts: string | null) {
  return ts ? format(new Date(ts), 'dd MMM yyyy HH:mm') : '—'
}

function StatusPill({ h }: { h: RetroHunt }) {
  const tone = h.status === 'failed' ? 'text-destructive border-destructive/50'
    : h.status === 'done' ? (h.matched > 0 ? 'text-red-400 border-red-400/50' : 'text-emerald-400 border-emerald-400/50')
    : 'text-muted-foreground border-border'
  const text = h.status === 'done' ? (h.matched > 0 ? `found · ${h.matched.toLocaleString()}` : 'not seen') : h.status
  return (
    <span className={`inline-flex items-center gap-1 text-[11px] uppercase tracking-wide px-1.5 py-0.5 rounded border ${tone}`}>
      {(h.status === 'pending' || h.status === 'running') && <Loader2 size={11} className="animate-spin" />}
      {text}
    </span>
  )
}

function Detail({ h }: { h: RetroHunt }) {
  if (h.status === 'failed') return <p className="text-xs text-destructive">{h.error}</p>
  if (h.status !== 'done') return <p className="text-xs text-muted-foreground">Searching the stored logs…</p>
  if (h.kind === 'ioc') {
    const hosts = h.results?.hosts ?? []
    if (!hosts.length) return <p className="text-xs text-emerald-400">Not seen in the last {h.days} days.</p>
    return (
      <div className="space-y-3">
        {hosts.map(host => (
          <div key={host.agent_id ?? host.hostname} className="space-y-1">
            <div className="flex flex-wrap gap-x-3 text-xs">
              <b>{host.hostname}</b>
              <span className="text-muted-foreground">{host.count.toLocaleString()} lines</span>
              <span className="text-muted-foreground">first {when(host.first_seen)} · last {when(host.last_seen)}</span>
            </div>
            {host.samples.map(s => (
              <div key={s.event_id} className="text-[11px] font-mono text-muted-foreground break-all pl-3 border-l border-border">
                <span className="text-foreground/70">{s.log_type}</span> {s.line}
              </div>
            ))}
          </div>
        ))}
      </div>
    )
  }
  const matches = h.results?.matches ?? []
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">
        Evaluated {h.scanned.toLocaleString()} events{h.results?.log_types ? ` of ${h.results.log_types.join(', ')}` : ''}
        {h.truncated ? ' (stopped at the limit)' : ''}. {h.matched ? `${h.matched} matched on ${h.hosts} hosts.` : 'Nothing matched.'}
      </p>
      {matches.slice(0, 50).map(m => (
        <div key={m.event_id} className="text-[11px] font-mono break-all pl-3 border-l border-border">
          <span className="text-muted-foreground">{when(m.created_at)} · {m.hostname ?? '?'} · {m.log_type}</span>
          <div>{m.line}</div>
        </div>
      ))}
    </div>
  )
}

export default function RetroHuntPage() {
  const qc = useQueryClient()
  const [kind, setKind] = useState<'ioc' | 'rule'>('ioc')
  const [iocType, setIocType] = useState('ip')
  const [value, setValue] = useState('')
  const [ruleQuery, setRuleQuery] = useState('')
  const [ruleId, setRuleId] = useState('')
  const [days, setDays] = useState(30)
  const [alerts, setAlerts] = useState(true)
  const [open, setOpen] = useState<string | null>(null)

  const hunts = useQuery<RetroHunt[]>({
    queryKey: ['retro-hunts'],
    queryFn: () => api.get('/api/retro-hunts', { params: { limit: 50 } }).then(r => r.data),
    refetchInterval: q => (q.state.data ?? []).some(h => h.status === 'pending' || h.status === 'running') ? 3000 : 20000,
  })
  const rules = useQuery<{ items: { id: string; title: string; level: string }[] }>({
    queryKey: ['retro-hunt-rules', ruleQuery],
    queryFn: () => api.get('/api/rules', { params: { q: ruleQuery || undefined, page_size: 20 } }).then(r => r.data),
    enabled: kind === 'rule',
  })
  const start = useMutation({
    mutationFn: () => api.post('/api/retro-hunts', kind === 'ioc'
      ? { kind, ioc_type: iocType, ioc_value: value.trim(), days, create_alerts: alerts }
      : { kind, rule_id: ruleId, days, create_alerts: alerts }).then(r => r.data as RetroHunt),
    onSuccess: h => { setOpen(h.id); setValue(''); qc.invalidateQueries({ queryKey: ['retro-hunts'] }) },
  })
  const ready = kind === 'ioc' ? value.trim().length > 0 : ruleId !== ''

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <History size={18} />
        <h1 className="text-xl font-bold">Retro-hunt</h1>
      </div>
      <p className="text-xs text-muted-foreground max-w-3xl">
        Search the stored logs for an indicator learnt today, or run a rule over the past to see what it would have caught.
        Adding an IP to the IP blocklist, a domain to Web Protection or a hash to Malware hashes starts one automatically
        (Settings → retro_hunt_on_block). Every host that saw the indicator gets one alert.
      </p>

      <div className="rounded-lg border border-border bg-card p-4 space-y-3">
        <div className="flex gap-1 text-sm">
          {(['ioc', 'rule'] as const).map(k => (
            <button key={k} onClick={() => setKind(k)} aria-pressed={kind === k}
              className={`px-3 py-1.5 rounded border ${kind === k ? 'border-primary text-primary' : 'border-border text-muted-foreground'}`}>
              {k === 'ioc' ? 'Indicator' : 'Rule'}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-end gap-3">
          {kind === 'ioc' ? <>
            <label className="space-y-1">
              <span className="block text-xs text-muted-foreground">Type</span>
              <select id="retro-ioc-type" value={iocType} onChange={e => setIocType(e.target.value)} className={input}>
                {IOC_TYPES.map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </label>
            <label className="space-y-1 flex-1 min-w-[220px]">
              <span className="block text-xs text-muted-foreground">Value</span>
              <input id="retro-ioc-value" value={value} onChange={e => setValue(e.target.value)}
                placeholder={iocType === 'ip' ? '45.129.56.138' : iocType === 'domain' ? 'c2.example.net' : ''}
                className={`${input} w-full font-mono`} />
            </label>
          </> : <>
            <label className="space-y-1">
              <span className="block text-xs text-muted-foreground">Find a rule</span>
              <input id="retro-rule-search" value={ruleQuery} onChange={e => setRuleQuery(e.target.value)}
                placeholder="webshell, kerberoast…" className={`${input} w-56`} />
            </label>
            <label className="space-y-1 flex-1 min-w-[240px]">
              <span className="block text-xs text-muted-foreground">Rule</span>
              <select id="retro-rule" value={ruleId} onChange={e => setRuleId(e.target.value)} className={`${input} w-full`}>
                <option value="">Choose a rule…</option>
                {(rules.data?.items ?? []).map(r => <option key={r.id} value={r.id}>{r.title} ({r.level})</option>)}
              </select>
            </label>
          </>}
          <label className="space-y-1">
            <span className="block text-xs text-muted-foreground">Days back</span>
            <input id="retro-days" type="number" min={1} max={365} value={days}
              onChange={e => setDays(Math.max(1, Math.min(365, Number(e.target.value) || 1)))} className={`${input} w-24`} />
          </label>
          <label className="flex items-center gap-1.5 text-sm cursor-pointer select-none pb-2">
            <input id="retro-alerts" type="checkbox" checked={alerts} onChange={e => setAlerts(e.target.checked)} />
            Raise alerts
          </label>
          <button onClick={() => start.mutate()} disabled={!ready || start.isPending}
            className="flex items-center gap-1.5 px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
            {start.isPending ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />} Hunt
          </button>
        </div>
        {start.isError && <p className="text-xs text-destructive">{apiError(start.error)}</p>}
      </div>

      {hunts.isLoading ? <Loader2 size={16} className="animate-spin" />
        : hunts.isError ? <p className="text-sm text-destructive">Could not load the retro-hunts.</p>
        : !(hunts.data ?? []).length ? <p className="text-sm text-muted-foreground">No retro-hunts yet.</p> : (
          <div className="rounded-lg border border-border divide-y divide-border">
            {hunts.data!.map(h => (
              <div key={h.id}>
                <button onClick={() => setOpen(open === h.id ? null : h.id)}
                  className="w-full flex items-center gap-3 px-3 py-2 text-left text-sm hover:bg-muted/40">
                  {open === h.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  <span className="font-mono truncate min-w-0 flex-1">
                    {h.kind === 'ioc' ? `${h.ioc_type}: ${h.ioc_value}` : `rule: ${h.rule_title}`}
                  </span>
                  <span className="text-xs text-muted-foreground hidden sm:inline">{TRIGGER[h.trigger] ?? h.trigger}</span>
                  <span className="text-xs text-muted-foreground">{h.days}d · {when(h.created_at)}</span>
                  {h.alerts_created > 0 && <span className="text-xs text-red-400">{h.alerts_created} alerts</span>}
                  <StatusPill h={h} />
                </button>
                {open === h.id && <div className="px-9 pb-3"><Detail h={h} /></div>}
              </div>
            ))}
          </div>
        )}
    </div>
  )
}
