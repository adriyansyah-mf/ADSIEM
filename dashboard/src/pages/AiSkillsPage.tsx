import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, Edit2, Loader2, Plus, Sparkles, ToggleLeft, ToggleRight, Trash2 } from 'lucide-react'
import { api } from '@/api/client'
import MarkdownNote from '@/components/MarkdownNote'
import { useAuthStore } from '@/stores/auth'

// The procedures the AI investigator loads when a case matches them
// (server-api/app/services/ai_skills.py): it sees each enabled skill's name
// and description and calls load_skill for the full text.

interface AiSkill {
  id: string
  name: string
  description: string
  content: string
  is_enabled: boolean
  origin: 'builtin' | 'custom'
  updated_at: string | null
}

const KEY = ['ai-skills']
const NAME_RE = /^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$/
const TEMPLATE = `# Phishing investigation

## 1. Scope
- Every recipient of the same sender or subject (search_events on the mail logs).
- Who clicked: proxy or DNS events for the link's domain.

## 2. On each host that clicked
- run_artifact Windows.Sys.Pslist and Windows.Network.Netstat
- Downloads: Windows.Search.FileFinder on C:/Users/*/Downloads/**

## Verdict
- True positive: ...
- False positive: ...

## Report must cover
...
`

function apiError(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map(d => (d as { msg?: string }).msg ?? '').join('; ') || fallback
  return fallback
}

function useSkills() {
  return useQuery<AiSkill[]>({ queryKey: KEY, queryFn: () => api.get('/api/ai-skills').then(r => r.data) })
}

export default function AiSkillsPage() {
  const qc = useQueryClient()
  const { hasRole } = useAuthStore()
  const canManage = hasRole('admin')
  const { data: skills = [], isLoading, isError } = useSkills()
  const [open, setOpen] = useState<string | null>(null)
  const [form, setForm] = useState<{ id?: string; name: string; description: string; content: string } | null>(null)

  const invalidate = () => qc.invalidateQueries({ queryKey: KEY })
  const toggle = useMutation({
    mutationFn: (s: AiSkill) => api.patch(`/api/ai-skills/${s.id}`, { is_enabled: !s.is_enabled }),
    onSuccess: invalidate,
  })
  const remove = useMutation({ mutationFn: (id: string) => api.delete(`/api/ai-skills/${id}`), onSuccess: invalidate })
  const save = useMutation({
    mutationFn: (f: NonNullable<typeof form>) => f.id
      ? api.patch(`/api/ai-skills/${f.id}`, { description: f.description, content: f.content })
      : api.post('/api/ai-skills', { name: f.name, description: f.description, content: f.content }),
    onSuccess: () => { setForm(null); invalidate() },
  })

  const nameOk = form ? (form.id ? true : NAME_RE.test(form.name.trim().toLowerCase())) : false
  const enabled = skills.filter(s => s.is_enabled).length

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Sparkles size={18} />
          <h1 className="text-xl font-bold">AI skills</h1>
        </div>
        {canManage && (
          <button onClick={() => setForm({ name: '', description: '', content: TEMPLATE })}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm font-medium">
            <Plus size={13} /> New skill
          </button>
        )}
      </div>
      <p className="text-xs text-muted-foreground max-w-3xl">
        Procedures for kinds of attack. In <b>Investigate with AI</b> the investigator is shown every enabled skill's
        name and description, loads the ones that fit the case (shown as "Loaded skill" in the run's Activity), and
        follows them while still citing evidence for every claim. Built-in skills are updated with the platform: turn
        one off, or save a copy to change it. {skills.length ? `${enabled} of ${skills.length} enabled.` : ''}
      </p>

      {form && (
        <div className="rounded-lg border border-border bg-card p-4 space-y-3">
          <p className="text-xs text-muted-foreground uppercase font-semibold">{form.id ? `Edit ${form.name}` : 'New skill'}</p>
          {!form.id && (
            <label className="block space-y-1">
              <span className="text-xs text-muted-foreground">Name (lowercase, hyphens), what the AI calls it by</span>
              <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="phishing-investigation"
                className="w-full max-w-md bg-muted border border-border rounded px-3 py-2 text-sm font-mono" />
              {form.name && !nameOk && <span className="text-xs text-destructive">3-80 lowercase letters, digits and hyphens</span>}
            </label>
          )}
          <label className="block space-y-1">
            <span className="text-xs text-muted-foreground">When to use it: the AI chooses skills by this text, so name the alerts and signs it covers</span>
            <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} rows={2}
              className="w-full bg-muted border border-border rounded px-3 py-2 text-sm" />
          </label>
          <label className="block space-y-1">
            <span className="text-xs text-muted-foreground">Instructions (Markdown): steps, which tools and artifacts to run, true/false positive criteria, what the report must cover</span>
            <textarea value={form.content} onChange={e => setForm({ ...form, content: e.target.value })} rows={16}
              className="w-full bg-muted border border-border rounded px-3 py-2 text-xs font-mono" />
          </label>
          {save.isError && <p className="text-xs text-destructive">{apiError(save.error, 'Could not save the skill.')}</p>}
          <div className="flex gap-2">
            <button onClick={() => save.mutate({ ...form, name: form.name.trim().toLowerCase() })}
              disabled={save.isPending || !nameOk || form.description.trim().length < 10 || form.content.trim().length < 20}
              className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
              {save.isPending ? <Loader2 size={14} className="animate-spin" /> : 'Save'}
            </button>
            <button onClick={() => { setForm(null); save.reset() }} className="px-3 py-1.5 rounded border border-border text-sm">Cancel</button>
          </div>
        </div>
      )}

      {isError ? <p className="text-sm text-destructive">Could not load the skills.</p>
        : isLoading ? <Loader2 size={16} className="animate-spin" />
        : skills.length === 0 ? <p className="text-sm text-muted-foreground">No skills yet.</p> : (
          <div className="space-y-2">
            {skills.map(s => (
              <div key={s.id} className={`rounded-lg border border-border bg-card ${s.is_enabled ? '' : 'opacity-60'}`}>
                <div className="flex items-start gap-3 p-3">
                  <button onClick={() => setOpen(open === s.id ? null : s.id)} className="flex-1 min-w-0 text-left">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-sm font-semibold">{s.name}</span>
                      <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded border border-border text-muted-foreground">
                        {s.origin === 'builtin' ? 'built-in' : 'custom'}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{s.description}</p>
                  </button>
                  {canManage && (
                    <div className="flex items-center gap-1 shrink-0">
                      <button title={s.is_enabled ? 'Turn off' : 'Turn on'} disabled={toggle.isPending} onClick={() => toggle.mutate(s)}
                        className="p-1.5 rounded hover:bg-muted">
                        {s.is_enabled ? <ToggleRight size={18} className="text-emerald-400" /> : <ToggleLeft size={18} />}
                      </button>
                      {s.origin === 'builtin' ? (
                        <button title="Save a copy to change it" className="p-1.5 rounded hover:bg-muted"
                          onClick={() => setForm({ name: `${s.name}-custom`.slice(0, 80), description: s.description, content: s.content })}>
                          <Copy size={14} />
                        </button>
                      ) : (
                        <>
                          <button title="Edit" className="p-1.5 rounded hover:bg-muted"
                            onClick={() => setForm({ id: s.id, name: s.name, description: s.description, content: s.content })}>
                            <Edit2 size={14} />
                          </button>
                          <button title="Delete" className="p-1.5 rounded hover:bg-muted text-destructive" disabled={remove.isPending}
                            onClick={() => remove.mutate(s.id)}>
                            <Trash2 size={14} />
                          </button>
                        </>
                      )}
                    </div>
                  )}
                </div>
                {open === s.id && (
                  <div className="border-t border-border p-3 text-sm max-h-[480px] overflow-auto">
                    <MarkdownNote content={s.content} />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      {(toggle.isError || remove.isError) && (
        <p className="text-xs text-destructive">{apiError(toggle.error ?? remove.error, 'Could not change the skill.')}</p>
      )}
    </div>
  )
}
