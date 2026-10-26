import { useState } from 'react'
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

export default function PreventionPage() {
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

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Ban size={18} className="text-primary" />
          <h1 className="text-xl font-bold">Execution prevention</h1>
        </div>
        <button onClick={() => edit()} className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={13} /> New rule
        </button>
      </div>
      <p className="text-xs text-muted-foreground max-w-3xl">
        Linux agents check every program before it starts. A <span className="font-semibold">detect</span> rule only
        raises an alert; a <span className="font-semibold">block</span> rule stops the program. Start new rules in detect
        mode, review the alerts, then switch them to block. The agent never blocks itself, init, systemd, the shells or
        sshd, whatever a rule says. Directory, path and parent rules are decided in the kernel on hosts with BPF LSM;
        hash rules (and everything on other kernels) by the agent's fanotify helper.
      </p>

      {isLoading ? <Loader2 size={16} className="animate-spin" /> : rules.length === 0 ? (
        <p className="text-sm text-muted-foreground">No rules yet. A common first rule: Directory /dev/shm, detect.</p>
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs text-muted-foreground uppercase">
              <tr>
                <th className="text-left px-3 py-2">Name</th>
                <th className="text-left px-3 py-2">Type</th>
                <th className="text-left px-3 py-2">Matches</th>
                <th className="text-left px-3 py-2">Action</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {rules.map(r => (
                <tr key={r.id} className={`border-t border-border ${r.is_enabled ? '' : 'opacity-50'}`}>
                  <td className="px-3 py-2">
                    <div className="font-medium">{r.name}</div>
                    {r.description && <div className="text-xs text-muted-foreground">{r.description}</div>}
                  </td>
                  <td className="px-3 py-2 text-xs">{typeLabel(r.rule_type)}</td>
                  <td className="px-3 py-2 font-mono text-xs break-all">
                    {r.rule_type === 'parent' ? <>{r.parent} → {r.value}</> : r.value}
                  </td>
                  <td className="px-3 py-2">
                    <button onClick={() => switchAction(r)} title="Switch between detect and block"
                      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold border ${
                        r.action === 'block' ? 'border-red-700 bg-red-900/30 text-red-300' : 'border-amber-700 bg-amber-900/20 text-amber-300'}`}>
                      {r.action === 'block' ? <Ban size={11} /> : <Eye size={11} />} {r.action}
                    </button>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex gap-1 justify-end">
                      <button onClick={() => toggle.mutate(r.id)} title={r.is_enabled ? 'Disable' : 'Enable'} className="p-1 rounded hover:bg-muted">
                        {r.is_enabled ? <ToggleRight size={16} className="text-primary" /> : <ToggleLeft size={16} className="text-muted-foreground" />}
                      </button>
                      <button onClick={() => edit(r)} title="Edit" className="p-1 rounded hover:bg-muted"><Pencil size={14} /></button>
                      <button onClick={() => remove.mutate(r.id)} title="Delete" className="p-1 rounded hover:bg-muted text-destructive"><Trash2 size={14} /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

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
    </div>
  )
}
