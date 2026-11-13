import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2, Plus, Trash2 } from 'lucide-react'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { emitToast } from '@/hooks/useToast'

interface IpBlock {
  id: string
  cidr: string
  group_id: string
  source: string
  status: string
  reason: string
  alert_id: string | null
  created_at: string | null
  expires_at: string | null
}

interface IpBlockList { total: number; mode: 'off' | 'detect' | 'block'; items: IpBlock[] }

const SOURCE_LABEL: Record<string, string> = { manual: 'Manual', soar: 'SOAR', alert: 'Alert', feed: 'Feed' }
const MODE_LABEL: Record<IpBlockList['mode'], string> = {
  block: 'Block: agents drop traffic to and from these addresses',
  detect: 'Detect: agents only alert on connections',
  off: 'Off: agents ignore this list',
}
const input = 'bg-muted border border-border rounded px-2 py-1.5 text-sm'
const button = 'text-xs px-2 py-1 rounded border border-border hover:bg-muted disabled:opacity-40 disabled:cursor-not-allowed'
const PAGE = 50

function apiError(e: unknown): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : 'Request failed'
}

function expiresAt(days: string): string | undefined {
  const n = Number(days)
  if (!days.trim() || !Number.isInteger(n) || n < 1) return undefined
  return new Date(Date.now() + n * 86400_000).toISOString()
}

export default function IpBlocklistPage() {
  const user = useAuthStore(s => s.user)
  const superadmin = user?.role === 'superadmin'
  const qc = useQueryClient()
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('active')
  const [offset, setOffset] = useState(0)
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')
  const [days, setDays] = useState('')
  const [group, setGroup] = useState('default')

  const { data, isLoading, isError } = useQuery<IpBlockList>({
    queryKey: ['ip-blocks', q, status, offset],
    queryFn: () => api.get('/api/ip-blocks', { params: { q, status, limit: PAGE, offset } }).then(r => r.data),
  })
  const refresh = () => qc.invalidateQueries({ queryKey: ['ip-blocks'] })
  const add = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/api/ip-blocks', body).then(r => r.data as IpBlock),
    onSuccess: row => {
      emitToast(`${row.cidr} blocked: agents pick it up within a minute`, 'success')
      setValue(''); setReason(''); setDays('')
      refresh()
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/ip-blocks/${id}`),
    onSuccess: () => { emitToast('Removed from the blocklist', 'success'); refresh() },
    onError: e => emitToast(apiError(e), 'error'),
  })

  const submit = () => add.mutate({
    value: value.trim(), reason: reason.trim(), expires_at: expiresAt(days),
    ...(superadmin ? { group_id: group.trim() || 'default' } : {}),
  })

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-xl font-bold">IP Blocklist</h1>
        <p className="text-sm text-muted-foreground">
          IP indicators of compromise your endpoints drop or report in real time. SOAR playbooks add to it with the Block IOC node.
        </p>
      </div>

      {data && (
        <div className="rounded-lg border border-border p-3 text-sm flex flex-wrap items-center gap-2">
          <span className="font-medium">{superadmin ? 'Default group' : 'Your group'}:</span>
          <span className={data.mode === 'block' ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground'}>{MODE_LABEL[data.mode]}</span>
          <Link to="/policies" className="ml-auto text-xs underline">Change in Policies (IP IoC blocklist)</Link>
        </div>
      )}

      <form onSubmit={e => { e.preventDefault(); if (value.trim()) submit() }}
        className="rounded-lg border border-border p-4 flex flex-wrap items-end gap-3">
        <label className="space-y-1">
          <span className="block text-xs text-muted-foreground">Address or CIDR</span>
          <input value={value} onChange={e => setValue(e.target.value)} placeholder="203.0.113.7 or 2001:db8::/48"
            className={`${input} w-56 font-mono`} />
        </label>
        <label className="space-y-1 flex-1 min-w-48">
          <span className="block text-xs text-muted-foreground">Reason</span>
          <input value={reason} onChange={e => setReason(e.target.value)} placeholder="Cobalt Strike C2 from case #42"
            className={`${input} w-full`} />
        </label>
        <label className="space-y-1">
          <span className="block text-xs text-muted-foreground">Expires after (days, empty: never)</span>
          <input type="number" min={1} value={days} onChange={e => setDays(e.target.value)} className={`${input} w-28`} />
        </label>
        {superadmin && (
          <label className="space-y-1">
            <span className="block text-xs text-muted-foreground">Group (* = all groups)</span>
            <input value={group} onChange={e => setGroup(e.target.value)} className={`${input} w-32`} />
          </label>
        )}
        <button type="submit" disabled={!value.trim() || add.isPending}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
          <Plus size={13} /> Block
        </button>
        {add.isError && <p className="w-full text-xs text-destructive">{apiError(add.error)}</p>}
        <p className="w-full text-xs text-muted-foreground">
          Networks broader than /16 (IPv4) or /48 (IPv6), loopback and link-local space are refused. Agents never block the SIEM server or their gateway.
        </p>
      </form>

      <div className="flex flex-wrap items-center gap-2">
        <input value={q} onChange={e => { setQ(e.target.value); setOffset(0) }} placeholder="Search addresses"
          className={`${input} w-56`} />
        <select value={status} onChange={e => { setStatus(e.target.value); setOffset(0) }} className={input}>
          <option value="active">Active</option>
          <option value="removed">Removed</option>
          <option value="">All</option>
        </select>
        {data && <span className="text-xs text-muted-foreground">{data.total} entries</span>}
      </div>

      {isLoading && <Loader2 size={16} className="animate-spin" />}
      {isError && <p className="text-sm text-destructive">Could not load the blocklist.</p>}
      {data && (
        <div className="rounded-lg border border-border overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 text-xs">
              <tr>
                <th className="text-left px-3 py-2">Address</th>
                {superadmin && <th className="text-left px-3 py-2">Group</th>}
                <th className="text-left px-3 py-2">Source</th>
                <th className="text-left px-3 py-2">Reason</th>
                <th className="text-left px-3 py-2">Expires</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {data.items.length === 0 && (
                <tr><td colSpan={6} className="px-3 py-6 text-center text-muted-foreground">No entries.</td></tr>
              )}
              {data.items.map(b => {
                const removable = b.status === 'active' && (superadmin || b.group_id !== '*')
                return (
                  <tr key={b.id} className="border-t border-border">
                    <td className="px-3 py-2 font-mono">{b.cidr.endsWith('/32') || b.cidr.endsWith('/128') ? b.cidr.split('/')[0] : b.cidr}</td>
                    {superadmin && <td className="px-3 py-2 text-xs">{b.group_id === '*' ? 'all groups' : b.group_id}</td>}
                    <td className="px-3 py-2 text-xs">
                      {SOURCE_LABEL[b.source] ?? b.source}
                      {b.alert_id && <Link to={`/alerts/${b.alert_id}`} className="ml-1 underline">alert</Link>}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground max-w-md truncate" title={b.reason}>{b.reason || '-'}</td>
                    <td className="px-3 py-2 text-xs">{b.expires_at ? new Date(b.expires_at).toLocaleDateString() : 'Never'}</td>
                    <td className="px-3 py-2 text-right">
                      {removable && (
                        <button onClick={() => remove.mutate(b.id)} disabled={remove.isPending} className={button}
                          title="Remove from the blocklist">
                          <Trash2 size={12} />
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      {data && data.total > PAGE && (
        <div className="flex items-center gap-2 text-xs">
          <button className={button} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
          <span>{offset + 1}-{Math.min(offset + PAGE, data.total)} of {data.total}</span>
          <button className={button} disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>Next</button>
        </div>
      )}
    </div>
  )
}
