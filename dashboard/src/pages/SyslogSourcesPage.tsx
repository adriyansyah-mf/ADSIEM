import { useMemo, useState } from 'react'
import { Plus, ToggleLeft, ToggleRight, Trash2 } from 'lucide-react'
import { useDecoders } from '@/hooks/useDecoders'
import {
  useCreateSyslogSource, useDeleteSyslogSource, useSyslogSources, useUnknownSyslogSenders, useUpdateSyslogSource,
} from '@/hooks/useSyslogSources'
import { useAuthStore } from '@/stores/auth'

const EMPTY = { name: '', cidr: '', logType: '', customType: '' }

function ago(iso: string | null): string {
  if (!iso) return 'never'
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 90) return `${s}s ago`
  if (s < 5400) return `${Math.round(s / 60)}m ago`
  if (s < 129600) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

export default function SyslogSourcesPage() {
  const isSuperadmin = useAuthStore(s => s.hasRole('superadmin'))
  const canManage = useAuthStore(s => s.hasRole('admin'))
  const { data: sources, isLoading } = useSyslogSources()
  const { data: unknown } = useUnknownSyslogSenders(isSuperadmin)
  const create = useCreateSyslogSource()
  const update = useUpdateSyslogSource()
  const remove = useDeleteSyslogSource()
  const [form, setForm] = useState(EMPTY)
  const [error, setError] = useState('')

  const { data: decoderPages } = useDecoders(1, 200)
  const logTypes = useMemo(() => {
    const types = new Set((decoderPages?.items ?? []).filter(d => d.is_enabled).map(d => d.log_type))
    return [...types].sort((a, b) => a.localeCompare(b))
  }, [decoderPages])

  const logType = form.logType === 'custom' ? form.customType.trim() : form.logType
  const set = (patch: Partial<typeof EMPTY>) => setForm(f => ({ ...f, ...patch }))

  const submit = () => {
    if (!form.name.trim() || !form.cidr.trim() || !logType) {
      setError('Name, address and log type are required')
      return
    }
    setError('')
    create.mutate({ name: form.name.trim(), cidr: form.cidr.trim(), log_type: logType },
      { onSuccess: () => setForm(EMPTY) })
  }

  return (
    <div className="max-w-5xl">
      <div className="mb-6">
        <h1 className="text-xl font-bold">Syslog devices</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Firewalls, switches and appliances that can't run an agent. Point them at this server on
          port <span className="font-mono">514</span> (UDP or TCP; RFC 3164, RFC 5424 or CEF). Messages from
          addresses that aren't registered here are dropped.
        </p>
      </div>

      {canManage && (
        <div className="rounded-lg border border-border bg-card p-4 mb-6">
          <h2 className="text-sm font-semibold mb-3">Register a device</h2>
          <div className="grid gap-2 sm:grid-cols-[1fr_1fr_1fr_auto]">
            <label className="text-xs">
              <span className="block mb-1 text-muted-foreground">Name</span>
              <input value={form.name} onChange={e => set({ name: e.target.value })} placeholder="FortiGate HQ"
                className="w-full px-3 py-2 rounded border border-border bg-background text-sm" />
            </label>
            <label className="text-xs">
              <span className="block mb-1 text-muted-foreground">Sender address or network</span>
              <input value={form.cidr} onChange={e => set({ cidr: e.target.value })} placeholder="10.0.5.1 or 10.0.5.0/24"
                className="w-full px-3 py-2 rounded border border-border bg-background text-sm font-mono" />
            </label>
            <label className="text-xs">
              <span className="block mb-1 text-muted-foreground">Log type (picks the decoders)</span>
              <select value={form.logType} onChange={e => set({ logType: e.target.value })}
                className="w-full px-3 py-2 rounded border border-border bg-background text-sm">
                <option value="">Choose…</option>
                {logTypes.map(t => <option key={t} value={t}>{t}</option>)}
                <option value="custom">Other (type it)</option>
              </select>
              {form.logType === 'custom' && (
                <input value={form.customType} onChange={e => set({ customType: e.target.value })} placeholder="my_device"
                  className="mt-2 w-full px-3 py-2 rounded border border-border bg-background text-sm font-mono" />
              )}
            </label>
            <div className="flex items-end">
              <button onClick={submit} disabled={create.isPending}
                className="flex items-center gap-1 px-3 py-2 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50">
                <Plus size={14} /> Register
              </button>
            </div>
          </div>
          {error && <p className="text-xs text-destructive mt-2">{error}</p>}
          <p className="text-xs text-muted-foreground mt-2">
            FortiGate: <span className="font-mono">fortigate_traffic</span> · any CEF sender: <span className="font-mono">cef</span> ·
            Suricata eve.json: <span className="font-mono">suricata</span> · Zeek JSON: <span className="font-mono">zeek</span> ·
            Linux rsyslog forwarding: <span className="font-mono">linux_auth</span>
          </p>
        </div>
      )}

      <div className="rounded-lg border border-border overflow-x-auto mb-6">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 text-xs text-muted-foreground">
            <tr>
              <th className="text-left px-3 py-2 font-medium">Name</th>
              <th className="text-left px-3 py-2 font-medium">Address</th>
              <th className="text-left px-3 py-2 font-medium">Log type</th>
              {isSuperadmin && <th className="text-left px-3 py-2 font-medium">Group</th>}
              <th className="text-right px-3 py-2 font-medium">Messages</th>
              <th className="text-left px-3 py-2 font-medium">Last message</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {isLoading && <tr><td colSpan={7} className="px-3 py-6 text-center text-muted-foreground">Loading…</td></tr>}
            {!isLoading && !sources?.length && (
              <tr><td colSpan={7} className="px-3 py-6 text-center text-muted-foreground">No syslog devices registered yet.</td></tr>
            )}
            {sources?.map(s => (
              <tr key={s.id} className={`border-t border-border ${s.enabled ? '' : 'opacity-60'}`}>
                <td className="px-3 py-2">{s.name}</td>
                <td className="px-3 py-2 font-mono text-xs">{s.cidr}</td>
                <td className="px-3 py-2 font-mono text-xs">{s.log_type}</td>
                {isSuperadmin && <td className="px-3 py-2 text-xs">{s.group_id}</td>}
                <td className="px-3 py-2 text-right tabular-nums">{s.message_count.toLocaleString()}</td>
                <td className="px-3 py-2 text-xs text-muted-foreground">{ago(s.last_seen_at)}</td>
                <td className="px-3 py-2">
                  {canManage && (
                    <div className="flex items-center justify-end gap-2">
                      <button onClick={() => update.mutate({ id: s.id, enabled: !s.enabled })}
                        aria-label={s.enabled ? `Disable ${s.name}` : `Enable ${s.name}`}
                        className="text-muted-foreground hover:text-foreground">
                        {s.enabled ? <ToggleRight size={18} className="text-primary" /> : <ToggleLeft size={18} />}
                      </button>
                      <button onClick={() => remove.mutate(s.id)} aria-label={`Remove ${s.name}`}
                        className="text-destructive hover:opacity-70">
                        <Trash2 size={14} />
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {isSuperadmin && !!unknown?.length && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h2 className="text-sm font-semibold">Unregistered senders</h2>
          <p className="text-xs text-muted-foreground mb-3">Dropped in the last 7 days. Register one to start ingesting it.</p>
          <ul className="divide-y divide-border">
            {unknown.map(u => (
              <li key={u.ip} className="py-2 flex flex-col gap-1 sm:flex-row sm:items-center sm:gap-3">
                <span className="font-mono text-sm w-40 shrink-0">{u.ip}</span>
                <span className="text-xs text-muted-foreground w-36 shrink-0">
                  {u.count.toLocaleString()} msgs · {ago(u.last_seen)}
                </span>
                <span className="font-mono text-xs text-muted-foreground truncate min-w-0 flex-1" title={u.sample}>{u.sample}</span>
                <button onClick={() => set({ cidr: u.ip, name: form.name || u.ip })}
                  className="text-xs px-2 py-1 rounded border border-border hover:bg-muted shrink-0">
                  Use address
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
