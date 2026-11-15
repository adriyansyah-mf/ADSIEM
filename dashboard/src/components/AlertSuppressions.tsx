import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldOff, X } from 'lucide-react'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { QueryState } from '@/components/Workspace'

interface Suppression {
  readonly id: string
  readonly entity_type: string
  readonly entity_value: string
  readonly reason: string | null
  readonly expires_at: string | null
  readonly hit_count: number
  readonly last_hit_at: string | null
}

function shortDate(value: string | null) {
  return value ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—'
}

export function AlertSuppressions() {
  const client = useQueryClient()
  const canManage = useAuthStore(state => state.hasRole('analyst'))
  const [form, setForm] = useState({ entity_type: 'ip', entity_value: '', reason: '', expires_in_days: '' })
  const query = useQuery<Suppression[]>({
    queryKey: ['suppressions'],
    queryFn: () => api.get('/api/suppressions').then(response => response.data),
  })
  const add = useMutation({
    mutationFn: () => api.post('/api/suppressions', { ...form, expires_in_days: form.expires_in_days ? Number(form.expires_in_days) : null }),
    onSuccess: () => { void client.invalidateQueries({ queryKey: ['suppressions'] }); setForm(value => ({ ...value, entity_value: '', reason: '' })) },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/suppressions/${id}`),
    onSuccess: () => { void client.invalidateQueries({ queryKey: ['suppressions'] }) },
  })
  return (
    <details className="panel">
      <summary className="control-cluster p-4 font-medium">
        <ShieldOff size={16} aria-hidden="true" /> Suppression rules
        {query.data && <span className="text-muted-foreground text-xs">{query.data.length}</span>}
      </summary>
      <div className="panel__body">
        <p className="text-muted-foreground mb-4">Manage known noise separately from the investigation queue.</p>
        {canManage && <form className="control-cluster items-end mb-4" onSubmit={event => { event.preventDefault(); if (form.entity_value.trim()) add.mutate() }}>
          <label className="field"><span>Match type</span><select className="ui-input" value={form.entity_type}
            onChange={event => setForm(value => ({ ...value, entity_type: event.target.value }))}>
            <option value="ip">IP address</option><option value="hostname">Hostname</option>
            <option value="user">User</option><option value="rule_title">Rule title</option>
          </select></label>
          <label className="field"><span>Value</span><input className="ui-input" required value={form.entity_value}
            onChange={event => setForm(value => ({ ...value, entity_value: event.target.value }))} /></label>
          <label className="field"><span>Reason (optional)</span><input className="ui-input" value={form.reason}
            onChange={event => setForm(value => ({ ...value, reason: event.target.value }))} /></label>
          <label className="field"><span>Ends after</span><select className="ui-input" value={form.expires_in_days}
            onChange={event => setForm(value => ({ ...value, expires_in_days: event.target.value }))}>
            <option value="">Never</option><option value="1">1 day</option><option value="7">7 days</option>
            <option value="30">30 days</option><option value="90">90 days</option>
          </select></label>
          <button className="ui-button" disabled={add.isPending || !form.entity_value.trim()}>{add.isPending ? 'Adding…' : 'Add suppression'}</button>
        </form>}
        {(add.isError || remove.isError) && <p role="alert" className="text-destructive mb-4">Could not save suppression changes. Check your permissions and try again.</p>}
        {query.isPending ? <QueryState kind="loading" title="Loading suppression rules…" />
          : query.isError ? <QueryState kind="error" title="Could not load suppression rules" onRetry={() => { void query.refetch() }} />
          : query.data.length === 0 ? <p className="text-muted-foreground">No suppression rules configured.</p>
          : <div className="table-scroll"><table className="data-table">
            <thead><tr>{['Type', 'Value', 'Reason', 'Hidden', 'Last hit', 'Ends', ''].map((title, index) => <th className="p-3" key={index}>{title}</th>)}</tr></thead>
            <tbody>{query.data.map(item => <tr key={item.id}>
              <td className="p-3">{item.entity_type}</td><td className="p-3 font-mono">{item.entity_value}</td>
              <td className="p-3">{item.reason ?? '—'}</td>
              <td className="p-3 tabular-nums">{item.hit_count.toLocaleString()}</td>
              <td className="p-3">{shortDate(item.last_hit_at)}</td>
              <td className="p-3">{item.expires_at
                ? (new Date(item.expires_at) < new Date() ? <span className="text-muted-foreground">ended</span> : shortDate(item.expires_at))
                : 'never'}</td>
              <td className="p-3">{canManage && <button className="ui-icon-button" disabled={remove.isPending}
                aria-label={`Remove suppression for ${item.entity_value}`} onClick={() => remove.mutate(item.id)}><X size={14} /></button>}</td>
            </tr>)}</tbody>
          </table></div>}
      </div>
    </details>
  )
}
