import { useEffect, useRef, useState } from 'react'
import { Loader2, Plus, Trash2 } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import {
  BLOCK_PAGE, type BlockFilter, type WebPolicy, apiError, useAddAllowRule, useAgentWebHealth, useAllowlist, useBlockWeb,
  useDeleteAllowRule, usePreviewPage, useSaveWebPolicy, useUnblockWeb, useUpdateAllowRule, useWebBlocks, useWebPolicy,
} from '@/hooks/useWebProtection'

type Tab = 'blocklist' | 'allowlist' | 'page' | 'agents'
const SOURCE_LABEL: Record<string, string> = { manual: 'Manual', alert: 'Alert', urlhaus: 'URLhaus', phishtank: 'PhishTank' }
const input = 'bg-muted border border-border rounded px-2 py-1.5 text-sm'
const button = 'text-xs px-2 py-1 rounded border border-border hover:bg-muted disabled:opacity-40 disabled:cursor-not-allowed'

function PolicySwitch({ group }: { group: string }) {
  const { data: policy, isError } = useWebPolicy(group)
  const save = useSaveWebPolicy(group)
  if (isError) return <p className="text-sm text-destructive">Could not load the policy.</p>
  if (!policy) return <Loader2 size={14} className="animate-spin" />
  const toggle = () => save.mutate({ ...policy, enabled: !policy.enabled, page_html: policy.custom_page ? policy.page_html : null })
  return (
    <div className="rounded-lg border border-border p-4 flex flex-wrap items-center gap-3">
      <div className="min-w-0">
        <div className="text-sm font-semibold">Web Protection for group {group}: {policy.enabled ? 'on' : 'off'}</div>
        <div className="text-xs text-muted-foreground">
          When on, agents redirect blocked domains to the block page. Agents also install a local certificate authority so the page shows on HTTPS sites.
        </div>
      </div>
      <button onClick={toggle} disabled={save.isPending}
        className={`ml-auto px-3 py-1.5 rounded text-sm font-medium ${policy.enabled ? 'border border-border hover:bg-muted' : 'bg-primary text-primary-foreground'}`}>
        {policy.enabled ? 'Turn off' : 'Turn on'}
      </button>
      {save.isError && <p className="w-full text-xs text-destructive">{apiError(save.error, 'Could not save.')}</p>}
    </div>
  )
}

function Blocklist({ group, superadmin }: { group: string; superadmin: boolean }) {
  const [filter, setFilter] = useState<BlockFilter>({ q: '', source: '', status: 'active', offset: 0 })
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')
  const { data, isLoading, isError } = useWebBlocks(filter)
  const block = useBlockWeb()
  const unblock = useUnblockWeb()
  const update = (patch: Partial<BlockFilter>) => setFilter(f => ({ ...f, offset: 0, ...patch }))
  const submit = () => block.mutate({ value: value.trim(), reason: reason.trim(), ...(superadmin ? { group_id: group } : {}) }, { onSuccess: () => { setValue(''); setReason('') } })

  return (
    <div className="space-y-3">
      {group ? <PolicySwitch group={group} /> : <p className="text-sm text-muted-foreground">Enter a group to manage its policy and block page.</p>}
      <form onSubmit={e => { e.preventDefault(); submit() }} className="flex flex-wrap items-end gap-2">
        <label className="space-y-1">
          <span className="block text-xs text-muted-foreground">Domain or URL</span>
          <input value={value} onChange={e => setValue(e.target.value)} placeholder="malicious.example"
            className={`${input} w-64 max-w-full font-mono`} />
        </label>
        <label className="space-y-1">
          <span className="block text-xs text-muted-foreground">Reason</span>
          <input value={reason} onChange={e => setReason(e.target.value)} className={`${input} w-64 max-w-full`} />
        </label>
        <button type="submit" disabled={!value.trim() || block.isPending || (superadmin && !group)}
          className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm font-medium inline-flex items-center gap-1 disabled:opacity-50">
          <Plus size={14} /> Block
        </button>
      </form>
      {block.isError && <p className="text-xs text-destructive">{apiError(block.error, 'Could not block.')}</p>}

      <div className="flex flex-wrap items-center gap-2">
        <input value={filter.q} onChange={e => update({ q: e.target.value })} placeholder="Search domain"
          aria-label="Search domain" className={`${input} w-56 max-w-full`} />
        <select value={filter.source} onChange={e => update({ source: e.target.value })} aria-label="Source" className={input}>
          <option value="">Any source</option>
          {Object.entries(SOURCE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select value={filter.status} onChange={e => update({ status: e.target.value })} aria-label="Status" className={input}>
          <option value="active">Blocked</option>
          <option value="removed">Unblocked</option>
          <option value="suppressed">Allowlisted</option>
        </select>
        <span className="text-xs text-muted-foreground ml-auto">{data ? `${data.total.toLocaleString()} domains` : ''}</span>
      </div>

      {isError ? <p className="text-sm text-destructive">Could not load the blocklist.</p>
        : isLoading ? <Loader2 size={16} className="animate-spin" />
        : !data?.items.length ? <p className="text-sm text-muted-foreground">No domains here.</p> : (
          <div className="rounded-lg border border-border overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 text-xs text-muted-foreground uppercase">
                <tr>
                  <th className="text-left px-3 py-2">Domain</th>
                  {superadmin && <th className="text-left px-3 py-2">Group</th>}
                  <th className="text-left px-3 py-2">Source</th>
                  <th className="text-left px-3 py-2">Reason</th>
                  <th className="text-left px-3 py-2">Expires</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {data.items.map(b => (
                  <tr key={b.id} className="border-t border-border">
                    <td className="px-3 py-2 font-mono text-xs break-all">{b.domain}
                      {b.group_id === '*' && <span className="ml-1 text-muted-foreground">(all groups)</span>}</td>
                    {superadmin && <td className="px-3 py-2 text-xs">{b.group_id === '*' ? 'all groups' : b.group_id}</td>}
                    <td className="px-3 py-2 text-xs">{SOURCE_LABEL[b.source] ?? b.source}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{b.reason || '—'}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">{b.expires_at ? new Date(b.expires_at).toLocaleString() : 'never'}</td>
                    <td className="px-3 py-2 text-right">
                      {b.status === 'active' && (
                        <button className={button} disabled={unblock.isPending} onClick={() => unblock.mutate(b.id)}>
                          {b.group_id === '*' ? 'Allow for my group' : 'Unblock'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      {unblock.isError && <p className="text-xs text-destructive">{apiError(unblock.error, 'Could not unblock.')}</p>}
      {data && data.total > BLOCK_PAGE && (
        <div className="flex items-center gap-2 text-xs">
          <button className={button} disabled={filter.offset === 0}
            onClick={() => setFilter(f => ({ ...f, offset: Math.max(0, f.offset - BLOCK_PAGE) }))}>Previous</button>
          <span className="text-muted-foreground">{filter.offset + 1}–{Math.min(filter.offset + BLOCK_PAGE, data.total)} of {data.total}</span>
          <button className={button} disabled={filter.offset + BLOCK_PAGE >= data.total}
            onClick={() => setFilter(f => ({ ...f, offset: f.offset + BLOCK_PAGE }))}>Next</button>
        </div>
      )}
    </div>
  )
}

function Allowlist({ group, superadmin }: { group: string; superadmin: boolean }) {
  const { data, isLoading, isError } = useAllowlist()
  const add = useAddAllowRule()
  const updateRule = useUpdateAllowRule()
  const remove = useDeleteAllowRule()
  const [domain, setDomain] = useState('')
  const [subdomains, setSubdomains] = useState(true)
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">Domains on this list are never blocked, even when a feed or an alert lists them.</p>
      <form onSubmit={e => { e.preventDefault(); updateRule.reset(); remove.reset()
        add.mutate({ domain: domain.trim(), include_subdomains: subdomains, ...(superadmin ? { group_id: group } : {}) }, { onSuccess: () => setDomain('') }) }}
        className="flex flex-wrap items-center gap-2">
        <input value={domain} onChange={e => setDomain(e.target.value)} placeholder="intranet.example" aria-label="Domain to allow"
          className={`${input} w-64 max-w-full font-mono`} />
        <label className="text-xs inline-flex items-center gap-1">
          <input type="checkbox" checked={subdomains} onChange={e => setSubdomains(e.target.checked)} /> Include subdomains
        </label>
        <button type="submit" disabled={!domain.trim() || add.isPending || (superadmin && !group)} className={button}>Allow</button>
      </form>
      {(add.isError || updateRule.isError || remove.isError) && (
        <p className="text-xs text-destructive">{apiError(add.error ?? updateRule.error ?? remove.error, 'Could not save.')}</p>
      )}
      {isError ? <p className="text-sm text-destructive">Could not load the allowlist.</p>
        : isLoading ? <Loader2 size={16} className="animate-spin" /> : (
          <div className="rounded-lg border border-border overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 text-xs text-muted-foreground uppercase">
                <tr><th className="text-left px-3 py-2">Domain</th>{superadmin && <th className="text-left px-3 py-2">Group</th>}<th className="text-left px-3 py-2">Scope</th><th className="px-3 py-2" /></tr>
              </thead>
              <tbody>
                {data?.items.map(r => {
                  const editable = r.group_id !== '*' || superadmin
                  return (
                    <tr key={r.id} className={`border-t border-border ${r.enabled ? '' : 'opacity-60'}`}>
                      <td className="px-3 py-2 font-mono text-xs">{r.domain}{r.include_subdomains ? ' + subdomains' : ''}</td>
                      {superadmin && <td className="px-3 py-2 text-xs">{r.group_id === '*' ? 'all groups' : r.group_id}</td>}
                      <td className="px-3 py-2 text-xs text-muted-foreground">{r.builtin ? 'Built-in' : r.group_id === '*' ? 'All groups' : 'This group'}</td>
                      <td className="px-3 py-2 text-right space-x-1 whitespace-nowrap">
                        {editable && (
                          <button className={button} disabled={updateRule.isPending}
                            onClick={() => { add.reset(); remove.reset(); updateRule.mutate({ id: r.id, enabled: !r.enabled }) }}>{r.enabled ? 'Disable' : 'Enable'}</button>
                        )}
                        {editable && !r.builtin && (
                          <button className={button} aria-label={`Delete ${r.domain}`} disabled={remove.isPending}
                            onClick={() => { add.reset(); updateRule.reset(); remove.mutate(r.id) }}><Trash2 size={12} /></button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
    </div>
  )
}

function BlockPageEditor({ group }: { group: string }) {
  const { data: policy, isError } = useWebPolicy(group)
  const save = useSaveWebPolicy(group)
  const preview = usePreviewPage(group)
  const [html, setHtml] = useState('')
  const [contact, setContact] = useState('')
  const htmlRef = useRef('')
  htmlRef.current = policy?.page_html ?? ''
  useEffect(() => {
    if (policy) { setHtml(policy.page_html); setContact(policy.contact) }
  }, [policy])
  const loaded = !!policy
  useEffect(() => {
    if (loaded) preview.mutate(htmlRef.current)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loaded, group])
  if (isError) return <p className="text-sm text-destructive">Could not load the policy.</p>
  if (!policy) return <Loader2 size={16} className="animate-spin" />
  const body = (page: string | null): Omit<WebPolicy, 'group_id' | 'custom_page' | 'page_html'> & { page_html: string | null } =>
    ({ enabled: policy.enabled, feed_enabled: policy.feed_enabled, alert_enabled: policy.alert_enabled,
       alert_block_days: policy.alert_block_days, max_entries: policy.max_entries, contact, page_html: page })
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="space-y-2 min-w-0">
        <p className="text-xs text-muted-foreground">
          HTML and CSS only. Scripts, forms and external images are removed when you save. Variables: {'{{domain}} {{reason}} {{source}} {{time}} {{hostname}} {{contact}}'}.
        </p>
        <textarea value={html} onChange={e => setHtml(e.target.value)} rows={18} aria-label="Block page HTML"
          className="w-full bg-muted border border-border rounded px-3 py-2 text-xs font-mono" />
        <label className="block space-y-1">
          <span className="text-xs text-muted-foreground">Contact shown as {'{{contact}}'}</span>
          <input value={contact} onChange={e => setContact(e.target.value)} className={`${input} w-full`} />
        </label>
        <div className="flex flex-wrap gap-2">
          <button className={button} disabled={preview.isPending} onClick={() => preview.mutate(html)}>Preview</button>
          <button className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50"
            disabled={save.isPending} onClick={() => save.mutate(body(html))}>Save</button>
          <button className={button} disabled={save.isPending || !policy.custom_page} onClick={() => save.mutate(body(null))}>Reset to built-in</button>
        </div>
        {save.isError && <p className="text-xs text-destructive">{apiError(save.error, 'Could not save.')}</p>}
        {preview.isError && <p className="text-xs text-destructive">{apiError(preview.error, 'Could not render the preview.')}</p>}
      </div>
      <div className="min-w-0">
        <div className="text-xs text-muted-foreground mb-1">Preview with sample values</div>
        <iframe title="Block page preview" sandbox="" srcDoc={preview.data ?? ''}
          className="w-full h-96 rounded border border-border bg-white" />
      </div>
    </div>
  )
}

function AgentsTab({ superadmin }: { superadmin: boolean }) {
  const { data, isLoading, isError } = useAgentWebHealth()
  if (isError) return <p className="text-sm text-destructive">Could not load agent health.</p>
  if (isLoading) return <Loader2 size={16} className="animate-spin" />
  if (!data?.items.length) return <p className="text-sm text-muted-foreground">No approved agents.</p>
  return (
    <div className="rounded-lg border border-border overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-muted/40 text-xs text-muted-foreground uppercase">
          <tr>
            <th className="text-left px-3 py-2">Host</th>
            {superadmin && <th className="text-left px-3 py-2">Group</th>}
            <th className="text-left px-3 py-2">Status</th>
            <th className="text-left px-3 py-2">Entries</th>
            <th className="text-left px-3 py-2">CA</th>
            <th className="text-left px-3 py-2">Block page server</th>
            <th className="text-left px-3 py-2">Hosts file</th>
            <th className="text-left px-3 py-2">Last error</th>
            <th className="text-left px-3 py-2">Reported</th>
          </tr>
        </thead>
        <tbody>
          {data.items.map(a => {
            const h = a.health
            return (
              <tr key={a.agent_id} className="border-t border-border">
                <td className="px-3 py-2 text-xs">{a.hostname}{!a.online && <span className="ml-1 text-muted-foreground">(offline)</span>}</td>
                {superadmin && <td className="px-3 py-2 text-xs">{a.group_id}</td>}
                {h ? (
                  <>
                    <td className="px-3 py-2 text-xs">{h.enabled ? 'Enabled' : 'Off'}</td>
                    <td className="px-3 py-2 text-xs">{h.entries.toLocaleString()}</td>
                    <td className="px-3 py-2 text-xs font-mono">
                      {h.ca_installed ? `Installed ${h.ca_fingerprint.slice(0, 12)}` : 'Not installed'}</td>
                    <td className={`px-3 py-2 text-xs ${h.page_server.startsWith('page_unavailable') ? 'text-red-500' : ''}`}>
                      {h.page_server || '—'}</td>
                    <td className={`px-3 py-2 text-xs ${h.hosts_tampered ? 'text-red-500' : ''}`}>
                      {h.hosts_tampered ? 'Tampered' : 'OK'}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground break-all">{h.last_error || '—'}</td>
                  </>
                ) : (
                  <td colSpan={6} className="px-3 py-2 text-xs text-muted-foreground">No health reported yet</td>
                )}
                <td className="px-3 py-2 text-xs text-muted-foreground">
                  {a.health_at ? new Date(a.health_at).toLocaleString() : '—'}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export default function WebProtectionPage() {
  const user = useAuthStore(s => s.user)
  const superadmin = user?.role === 'superadmin'
  const initial = superadmin ? 'default' : user?.group_id ?? 'default'
  const [group, setGroup] = useState(initial)
  const [draft, setDraft] = useState(initial)
  const applyGroup = () => { const g = draft.trim(); setDraft(g); setGroup(g) }
  const [tab, setTab] = useState<Tab>('blocklist')
  const noGroup = <p className="text-sm text-muted-foreground">Enter a group to manage its policy and block page.</p>
  return (
    <div className="p-6 space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <h1 className="text-xl font-bold">Web Protection</h1>
          <p className="text-sm text-muted-foreground">Block domains on your endpoints and choose the page users see.</p>
        </div>
        {superadmin && (
          <form className="ml-auto text-xs space-y-1" onSubmit={e => { e.preventDefault(); applyGroup() }}>
            <label className="block space-y-1">
              <span className="block text-muted-foreground">Group</span>
              <input value={draft} onChange={e => setDraft(e.target.value)} onBlur={applyGroup} className={`${input} w-40`} />
            </label>
          </form>
        )}
      </div>
      <div className="flex flex-wrap gap-1 border-b border-border">
        {([['blocklist', 'Blocklist'], ['allowlist', 'Allowlist'], ['page', 'Block page'], ['agents', 'Agents']] as const).map(([key, label]) => (
          <button key={key} aria-pressed={tab === key} onClick={() => setTab(key)}
            className={`px-3 py-1.5 text-sm border-b-2 -mb-px ${tab === key ? 'border-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
            {label}
          </button>
        ))}
      </div>
      {tab === 'blocklist' && <Blocklist group={group} superadmin={superadmin} />}
      {tab === 'allowlist' && <Allowlist group={group} superadmin={superadmin} />}
      {tab === 'agents' && <AgentsTab superadmin={superadmin} />}
      {tab === 'page' && (group ? <BlockPageEditor key={group} group={group} /> : noGroup)}
    </div>
  )
}
