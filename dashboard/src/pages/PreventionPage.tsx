import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNowStrict } from 'date-fns'
import { api } from '@/api/client'
import { CanvasHeader, CanvasPage, Empty } from '@/components/canvas/Canvas'
import { Ban, Eye, Loader2, Pencil, Plus, ToggleLeft, ToggleRight, Trash2 } from 'lucide-react'
import {
  type PreventionAction, type PreventionRule, type PreventionRuleType,
  useDeletePreventionRule, usePreventionRules, useSavePreventionRule, useTogglePreventionRule,
} from '@/hooks/usePrevention'

const TYPES: { value: PreventionRuleType; label: string; valueLabel: string; placeholder: string }[] = [
  { value: 'dir', label: 'Directory', valueLabel: 'Directory (anything below it)', placeholder: '/dev/shm' },
  { value: 'path', label: 'Executable path', valueLabel: 'Absolute path', placeholder: '/opt/legacy/bin/tool' },
  { value: 'hash', label: 'SHA-256', valueLabel: 'SHA-256 of the file', placeholder: '64 hex characters' },
  { value: 'parent', label: 'Parent → child', valueLabel: 'Child executables (comma separated)', placeholder: 'sh, dash, bash, python3' },
  { value: 'signer', label: 'Signer (Windows)', valueLabel: 'Publisher as the signature names it (agent/cmd/authsig shows it)', placeholder: 'Psiphon Inc.' },
]

const typeLabel = (t: PreventionRuleType) => TYPES.find(x => x.value === t)?.label ?? t

function apiError(e: unknown): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map(d => (d as { msg?: string }).msg ?? String(d)).join('; ')
  return 'Could not save the rule'
}

interface FormState {
  id?: string
  name: string
  description: string
  rule_type: PreventionRuleType
  value: string
  parent: string
  action: PreventionAction
}

const emptyForm: FormState = { name: '', description: '', rule_type: 'dir', value: '', parent: '', action: 'detect' }

/** Totals of the other protection layers, for the side summary. */
function useLayers() {
  const total = (url: string) => () => api.get(url, { params: { limit: 1 } }).then(r => Number(r.data.total) || 0)
  const ips = useQuery({ queryKey: ['protection-layers', 'ips'], queryFn: total('/api/ip-blocks'), retry: false, staleTime: 60_000 })
  const web = useQuery({ queryKey: ['protection-layers', 'web'], queryFn: total('/api/web-blocks'), retry: false, staleTime: 60_000 })
  const hashes = useQuery({
    queryKey: ['protection-layers', 'hashes'], retry: false, staleTime: 60_000,
    queryFn: () => api.get('/api/malware-hashes', { params: { limit: 1 } }).then(r =>
      ((r.data.counts ?? []) as { status: string; count: number }[]).filter(c => c.status === 'active').reduce((n, c) => n + c.count, 0)),
  })
  const yara = useQuery({ queryKey: ['protection-layers', 'yara'], retry: false, staleTime: 60_000,
    queryFn: () => api.get('/api/yara-rules').then(r => Array.isArray(r.data) ? r.data.length : Number(r.data?.total) || 0) })
  return { ips: ips.data ?? null, web: web.data ?? null, hashes: hashes.data ?? null, yara: yara.data ?? null }
}

export default function PreventionPage() {
  const layers = useLayers()
  const { data: rules = [], isLoading } = usePreventionRules()
  const save = useSavePreventionRule()
  const toggle = useTogglePreventionRule()
  const remove = useDeletePreventionRule()
  const [form, setForm] = useState<FormState | null>(null)
  const [error, setError] = useState('')

  const edit = (r?: PreventionRule) => {
    setError('')
    setForm(r ? { id: r.id, name: r.name, description: r.description ?? '', rule_type: r.rule_type, value: r.value, parent: r.parent, action: r.action } : emptyForm)
  }

  const submit = async () => {
    if (!form) return
    try {
      await save.mutateAsync({ ...form, description: form.description || undefined })
      setForm(null)
    } catch (e) {
      setError(apiError(e))
    }
  }

  const switchAction = (r: PreventionRule) =>
    save.mutate({ id: r.id, name: r.name, description: r.description ?? undefined, rule_type: r.rule_type,
      value: r.value, parent: r.parent, action: r.action === 'block' ? 'detect' : 'block' })

  const meta = TYPES.find(t => t.value === form?.rule_type) ?? TYPES[0]

  const setMode = (r: PreventionRule, mode: 'off' | PreventionAction) => {
    if (mode === 'off') { if (r.is_enabled) toggle.mutate(r.id); return }
    if (!r.is_enabled) toggle.mutate(r.id)
    if (r.action !== mode) switchAction(r)
  }

  return (
    <CanvasPage>
      <CanvasHeader
        title="Protection policies"
        sub="What agents stop before it runs, and what only raises an alert · start in Detect, review, then Block"
        counts={{ '/malware-hashes': layers.hashes, '/ip-blocklist': layers.ips, '/yara': layers.yara }}
        actions={<button type="button" className="cv-btn cv-btn--primary" onClick={() => edit()}>New rule</button>}
      />
      <div className="cv-split">
        <section className="cv-pane" aria-label="Prevention rules">
          <div className="cv-tablewrap">
            <table className="cv-table" style={{ minWidth: 720 }}>
              <thead><tr><th>Rule</th><th>Mode</th><th>Type</th><th>Matches</th><th>Created</th><th><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {rules.map(r => {
                  const mode = !r.is_enabled ? 'off' : r.action
                  return (
                    <tr key={r.id}>
                      <td>
                        <div className="cv-stack">
                          <span style={{ fontWeight: 500 }}>{r.name}</span>
                          {r.description && <span className="cv-muted cv-small">{r.description}</span>}
                        </div>
                      </td>
                      <td>
                        <div className="cv-mode" role="group" aria-label={`Mode for ${r.name}`}>
                          {(['off', 'detect', 'block'] as const).map(m => (
                            <button key={m} type="button" aria-pressed={mode === m} className={`cv-mode--${m}`}
                              disabled={save.isPending || toggle.isPending} onClick={() => setMode(r, m)}>
                              {m === 'off' ? 'Off' : m === 'detect' ? 'Detect' : 'Block'}
                            </button>
                          ))}
                        </div>
                      </td>
                      <td className="cv-dim">{typeLabel(r.rule_type)}</td>
                      <td className="cv-mono" style={{ maxWidth: 320, overflowWrap: 'anywhere' }}>{r.rule_type === 'parent' ? <>{r.parent} → {r.value}</> : r.value}</td>
                      <td className="cv-dim cv-small" style={{ whiteSpace: 'nowrap' }}>{formatDistanceToNowStrict(new Date(r.created_at))} ago</td>
                      <td>
                        <span className="cv-row" style={{ gap: 4, flexWrap: 'nowrap' }}>
                          <button type="button" className="cv-btn cv-btn--sm" onClick={() => edit(r)}>Edit</button>
                          <button type="button" className="cv-btn cv-btn--sm cv-btn--danger" aria-label={`Delete ${r.name}`}
                            onClick={() => { if (window.confirm(`Delete rule “${r.name}”?`)) remove.mutate(r.id) }}>Delete</button>
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {isLoading && <Empty>Loading rules…</Empty>}
            {!isLoading && rules.length === 0 && <Empty>No rules yet. A common first rule: Directory /dev/shm, Detect.</Empty>}
          </div>
          <p className="cv-muted cv-small" style={{ margin: 0, maxWidth: 820 }}>
            Linux agents check every program before it starts. The agent never blocks itself, init, systemd, the shells or sshd, whatever a rule says.
            Directory, path and parent rules are decided in the kernel on hosts with BPF LSM; hash rules (and everything on other kernels) by the agent's fanotify helper.
          </p>
        </section>
        <aside className="cv-list" aria-label="Protection layers" style={{ flex: '1 1 300px', maxWidth: 360, borderRight: 0, borderLeft: '1px solid #222733', padding: 16, gap: 12 }}>
          <h2 className="cv-h2">Protection layers</h2>
          {[
            { to: '/malware-hashes', name: 'Known-bad file hashes', detail: 'Feeds and analyst IoCs, blocked on execution', value: layers.hashes },
            { to: '/yara', name: 'YARA rules', detail: 'File and memory matches', value: layers.yara },
            { to: '/web-protection', name: 'Web protection', detail: 'Phishing and malware domains', value: layers.web },
            { to: '/ip-blocklist', name: 'IP blocklist', detail: 'Inbound and outbound', value: layers.ips },
            { to: '/policies', name: 'Agent policies', detail: 'Per-group agent configuration', value: null },
          ].map(layer => (
            <Link key={layer.to} to={layer.to} className="cv-card cv-evidence" style={{ color: 'inherit' }}>
              <span className="cv-row cv-row--between"><strong>{layer.name}</strong>{layer.value != null && <span className="cv-mono">{layer.value.toLocaleString('en-US')}</span>}</span>
              <span className="cv-small cv-muted">{layer.detail}</span>
            </Link>
          ))}
        </aside>
      </div>

      {form && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-card border border-border rounded-lg w-full max-w-xl space-y-4 p-5">
            <h2 className="font-bold">{form.id ? 'Edit rule' : 'New rule'}</h2>
            <div className="grid grid-cols-2 gap-3">
              <label className="space-y-1">
                <span className="text-xs text-muted-foreground">Name *</span>
                <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                  className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary" />
              </label>
              <label className="space-y-1">
                <span className="text-xs text-muted-foreground">Type</span>
                <select value={form.rule_type} onChange={e => setForm({ ...form, rule_type: e.target.value as PreventionRuleType })}
                  className="w-full bg-muted border border-border rounded px-3 py-2 text-sm">
                  {TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
              </label>
            </div>
            {form.rule_type === 'parent' && (
              <label className="block space-y-1">
                <span className="text-xs text-muted-foreground">Parent executables (comma separated)</span>
                <input value={form.parent} onChange={e => setForm({ ...form, parent: e.target.value })} placeholder="nginx, apache2, php-fpm8.2, java"
                  className="w-full bg-muted border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary" />
                <span className="text-xs text-muted-foreground">Names of the executable files: symlinks are resolved, so list dash next to sh.</span>
              </label>
            )}
            <label className="block space-y-1">
              <span className="text-xs text-muted-foreground">{meta.valueLabel} *</span>
              <input value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} placeholder={meta.placeholder}
                className="w-full bg-muted border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary" />
            </label>
            <label className="block space-y-1">
              <span className="text-xs text-muted-foreground">Description</span>
              <input value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
                className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary" />
            </label>
            <div className="flex gap-4 text-sm">
              {(['detect', 'block'] as const).map(a => (
                <label key={a} className="flex items-center gap-1.5">
                  <input type="radio" checked={form.action === a} onChange={() => setForm({ ...form, action: a })} />
                  {a === 'detect' ? 'Detect (alert only)' : 'Block'}
                </label>
              ))}
            </div>
            {error && <p className="text-xs text-destructive">{error}</p>}
            <div className="flex gap-2 justify-end">
              <button onClick={() => setForm(null)} className="px-4 py-2 rounded border border-border text-sm hover:bg-muted">Cancel</button>
              <button onClick={submit} disabled={!form.name || !form.value || save.isPending}
                className="px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
                {save.isPending ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </CanvasPage>
  )
}
