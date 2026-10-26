import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import KnowledgeVault from '@/components/KnowledgeVault'
import { format, formatDistanceToNow } from 'date-fns'
import { CheckCircle2, CircleDashed, Pencil, Plus, RefreshCw, Search, Trash2, X } from 'lucide-react'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'

interface Scope { ips: string[]; hosts: string[]; users: string[]; rules: string[] }
interface Note {
  id: string; group_id: string; title: string; content: string; scope: Partial<Scope>
  enabled: boolean; expires_at: string | null; created_at: string; updated_at: string | null; indexed: boolean
}
interface Source {
  id: string; name: string; url: string; license: string; entries: number; indexed: number
  status?: string; last_sync?: string; last_attempt?: string; error?: string
  added?: number; updated?: number; removed?: number
}
interface Learned {
  id: string; entity_type: string; entity_id: string; context: string; ai_verdict: string | null
  rating: string; correct_verdict: string | null; note: string | null; created_at: string; in_ai_memory: boolean
}
interface Preview {
  notes: { id: string; title: string; content: string; matched?: string[]; score?: number }[]
  references: { id: string; title: string; source_ref: string; text: string; score: number }[]
  semantic: boolean
}

const mono: React.CSSProperties = { fontFamily: 'Share Tech Mono, monospace' }
const label: React.CSSProperties = {
  fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', letterSpacing: '1.5px',
  textTransform: 'uppercase', color: 'var(--text-muted)',
}
const input: React.CSSProperties = {
  width: '100%', padding: '6px 8px', background: 'var(--bg-base)', color: 'var(--text-primary)',
  border: '1px solid var(--border)', borderRadius: '4px', fontSize: '13px',
}
const btn: React.CSSProperties = {
  display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 12px', borderRadius: '4px',
  fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '12px', letterSpacing: '1px', cursor: 'pointer',
  border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-primary)',
}
const card: React.CSSProperties = { border: '1px solid var(--border)', borderRadius: '4px', padding: '10px 12px' }

function detail(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof d === 'string' ? d : fallback
}

const split = (s: string) => s.split(/[,\n]/).map(x => x.trim()).filter(Boolean)
const SCOPE_KEYS: [keyof Scope, string][] = [['ips', 'IPs'], ['hosts', 'Hosts'], ['users', 'Users'], ['rules', 'Rule titles']]

type Draft = { id?: string; title: string; content: string; scope: Record<keyof Scope, string>; expires: string; enabled: boolean }
const emptyDraft = (): Draft => ({ title: '', content: '', scope: { ips: '', hosts: '', users: '', rules: '' }, expires: '', enabled: true })

function NoteForm({ draft, onClose }: { draft: Draft; onClose: () => void }) {
  const qc = useQueryClient()
  const [d, setD] = useState<Draft>(draft)
  const save = useMutation({
    mutationFn: () => {
      const body = {
        title: d.title, content: d.content, enabled: d.enabled,
        expires_at: d.expires ? new Date(d.expires).toISOString() : null,
        scope: Object.fromEntries(SCOPE_KEYS.map(([k]) => [k, split(d.scope[k])])),
      }
      return d.id ? api.put(`/api/knowledge/notes/${d.id}`, body) : api.post('/api/knowledge/notes', body)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['knowledge-notes'] }); onClose() },
    onError: (e) => emitToast(detail(e, 'Could not save the note'), 'error'),
  })
  return (
    <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '12px' }}>
      <div className="flex items-center justify-between">
        <span style={label}>{d.id ? 'Edit note' : 'New note'}</span>
        <button onClick={onClose}><X size={14} /></button>
      </div>
      <input style={input} placeholder="Title, e.g. 10.20.0.5 is our Nessus scanner" value={d.title}
        onChange={e => setD({ ...d, title: e.target.value })} />
      <textarea style={{ ...input, minHeight: '110px', ...mono }} value={d.content}
        placeholder="What the AI should know: what is normal here, why it alerts, when it would still be suspicious."
        onChange={e => setD({ ...d, content: e.target.value })} />
      <div className="text-xs text-muted-foreground">
        Scope (optional, comma separated): a note with a scope is always given to the AI for alerts on those
        IPs / hosts / users / rules. Without one it is found by meaning.
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px' }}>
        {SCOPE_KEYS.map(([k, name]) => (
          <div key={k}>
            <div style={label}>{name}</div>
            <input style={{ ...input, ...mono }} value={d.scope[k]} onChange={e => setD({ ...d, scope: { ...d.scope, [k]: e.target.value } })} />
          </div>
        ))}
      </div>
      <div className="flex items-center gap-4 flex-wrap">
        <label className="text-sm flex items-center gap-2">
          <span style={label}>Expires</span>
          <input type="date" style={{ ...input, width: 'auto' }} value={d.expires} onChange={e => setD({ ...d, expires: e.target.value })} />
        </label>
        <label className="text-sm flex items-center gap-2">
          <input type="checkbox" checked={d.enabled} onChange={e => setD({ ...d, enabled: e.target.checked })} /> Enabled
        </label>
        <button style={{ ...btn, marginLeft: 'auto', borderColor: 'var(--accent-cyan)', color: 'var(--accent-cyan)' }}
          disabled={save.isPending || d.title.length < 3 || d.content.length < 3} onClick={() => save.mutate()}>
          SAVE
        </button>
      </div>
    </div>
  )
}

function NotesTab({ draft, setDraft }: { draft: Draft | null; setDraft: (d: Draft | null) => void }) {
  const qc = useQueryClient()
  const [q, setQ] = useState('')
  const { data: notes = [], isLoading } = useQuery<Note[]>({
    queryKey: ['knowledge-notes', q],
    queryFn: () => api.get('/api/knowledge/notes', { params: { q } }).then(r => r.data),
    refetchInterval: 10000,
  })
  const del = useMutation({
    mutationFn: (id: string) => api.delete(`/api/knowledge/notes/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['knowledge-notes'] }),
    onError: (e) => emitToast(detail(e, 'Could not delete'), 'error'),
  })
  const edit = (n: Note) => setDraft({
    id: n.id, title: n.title, content: n.content, enabled: n.enabled,
    expires: n.expires_at ? n.expires_at.slice(0, 10) : '',
    scope: Object.fromEntries(SCOPE_KEYS.map(([k]) => [k, (n.scope[k] ?? []).join(', ')])) as Record<keyof Scope, string>,
  })
  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
        <input style={{ ...input, maxWidth: '320px' }} placeholder="Search notes…" value={q} onChange={e => setQ(e.target.value)} />
        <button style={{ ...btn, marginLeft: 'auto', borderColor: 'var(--accent-cyan)', color: 'var(--accent-cyan)' }}
          onClick={() => setDraft(emptyDraft())}><Plus size={13} /> NEW NOTE</button>
      </div>
      {draft && <NoteForm key={draft.id ?? 'new'} draft={draft} onClose={() => setDraft(null)} />}
      {isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
      {!isLoading && notes.length === 0 && (
        <div className="text-sm text-muted-foreground">
          No notes yet. Write down what is normal in this environment — known scanners, scheduled jobs, apps that
          look like attacks — and the AI will take it into account when triaging.
        </div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {notes.map(n => {
          const expired = n.expires_at && new Date(n.expires_at) < new Date()
          const scope = SCOPE_KEYS.flatMap(([k]) => (n.scope[k] ?? []).map(v => `${k.slice(0, -1)}:${v}`))
          return (
            <div key={n.id} style={{ ...card, opacity: n.enabled && !expired ? 1 : 0.55 }}>
              <div className="flex items-center gap-2">
                <b className="text-sm">{n.title}</b>
                {!n.enabled && <span style={{ ...label, fontSize: '10px' }}>disabled</span>}
                {expired && <span style={{ ...label, fontSize: '10px', color: 'var(--accent-yellow)' }}>expired</span>}
                <span title={n.indexed ? 'Embedded: found by meaning' : 'Waiting to be embedded (scope matches already work)'}
                  style={{ color: n.indexed ? 'var(--accent-green)' : 'var(--text-muted)', display: 'inline-flex' }}>
                  {n.indexed ? <CheckCircle2 size={13} /> : <CircleDashed size={13} />}
                </span>
                <span className="ml-auto text-xs text-muted-foreground">
                  {n.group_id === '*' ? 'all groups · ' : ''}{formatDistanceToNow(new Date(n.updated_at ?? n.created_at), { addSuffix: true })}
                </span>
                <button title="Edit" onClick={() => edit(n)}><Pencil size={13} /></button>
                <button title="Delete" onClick={() => del.mutate(n.id)}><Trash2 size={13} /></button>
              </div>
              <div className="text-sm" style={{ whiteSpace: 'pre-wrap', marginTop: '4px' }}>{n.content}</div>
              {(scope.length > 0 || n.expires_at) && (
                <div style={{ ...mono, fontSize: '11px', color: 'var(--accent-cyan)', marginTop: '6px' }}>
                  {scope.join('  ')}{n.expires_at && <span style={{ color: 'var(--text-muted)' }}>  until {format(new Date(n.expires_at), 'dd MMM yyyy')}</span>}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ReferenceTab() {
  const qc = useQueryClient()
  const [q, setQ] = useState('')
  const { data: src } = useQuery<{ sources: Source[] }>({
    queryKey: ['knowledge-sources'],
    queryFn: () => api.get('/api/knowledge/sources').then(r => r.data),
    refetchInterval: 5000,
  })
  const { data: refs } = useQuery<{ items: { id: string; title: string; source_ref: string; excerpt: string }[] }>({
    queryKey: ['knowledge-refs', q],
    queryFn: () => api.get('/api/knowledge/references', { params: { q, limit: 50 } }).then(r => r.data),
  })
  const sync = useMutation({
    mutationFn: () => api.post('/api/knowledge/sources/payloadsallthethings/sync'),
    onSuccess: () => { emitToast('Sync queued', 'success'); qc.invalidateQueries({ queryKey: ['knowledge-sources'] }) },
    onError: (e) => emitToast(detail(e, 'Could not start the sync'), 'error'),
  })
  const s = src?.sources?.[0]
  return (
    <div>
      {s && (
        <div style={{ ...card, marginBottom: '12px' }}>
          <div className="flex items-center gap-2 flex-wrap">
            <b>{s.name}</b>
            <a href={s.url} target="_blank" rel="noreferrer" className="text-xs" style={{ color: 'var(--accent-cyan)' }}>github</a>
            <span className="text-xs text-muted-foreground">{s.license}</span>
            <button style={{ ...btn, marginLeft: 'auto' }} disabled={sync.isPending} onClick={() => sync.mutate()}>
              <RefreshCw size={13} /> SYNC NOW
            </button>
          </div>
          <div className="text-sm mt-2" style={{ display: 'flex', gap: '18px', flexWrap: 'wrap' }}>
            <span>{s.entries} sections · {s.indexed} embedded</span>
            <span>status: <b>{s.status ?? 'never synced'}</b></span>
            {s.last_sync && <span>last sync {formatDistanceToNow(new Date(s.last_sync), { addSuffix: true })}</span>}
            {s.added != null && s.last_sync && <span className="text-muted-foreground">+{s.added} / ~{s.updated} / −{s.removed}</span>}
          </div>
          {s.error && <div className="text-sm mt-1" style={{ color: 'var(--accent-red)' }}>{s.error}</div>}
          <div className="text-xs text-muted-foreground mt-2">
            Payload techniques the AI compares web and injection alerts against, to tell real attempts from requests
            that only look similar. Refreshed weekly; the download URL is in Settings (knowledge_pat_url).
          </div>
        </div>
      )}
      <input style={{ ...input, maxWidth: '320px', marginBottom: '8px' }} placeholder="Search payload sections…"
        value={q} onChange={e => setQ(e.target.value)} />
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {(refs?.items ?? []).map(r => (
          <div key={r.id} style={card}>
            <div className="text-sm"><b>{r.title}</b></div>
            <pre style={{ ...mono, fontSize: '11px', whiteSpace: 'pre-wrap', margin: '4px 0 0', color: 'var(--text-muted)' }}>{r.excerpt}</pre>
          </div>
        ))}
      </div>
    </div>
  )
}

function LearnedTab({ makeNote }: { makeNote: (d: Draft) => void }) {
  const { data } = useQuery<{ items: Learned[] }>({
    queryKey: ['knowledge-learned'],
    queryFn: () => api.get('/api/knowledge/learned').then(r => r.data),
    refetchInterval: 15000,
  })
  const items = data?.items ?? []
  return (
    <div>
      <div className="text-sm text-muted-foreground mb-3">
        Ratings analysts gave AI verdicts on alerts and cases. The AI is reminded of similar ones when it triages —
        especially the ones marked wrong. Turn a correction into a note to make it explicit and scoped.
      </div>
      {items.length === 0 && <div className="text-sm text-muted-foreground">No feedback yet.</div>}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {items.map(f => (
          <div key={f.id} style={card}>
            <div className="flex items-center gap-2 flex-wrap text-sm">
              <span style={{ color: f.rating === 'incorrect' ? 'var(--accent-red)' : 'var(--accent-green)', fontWeight: 700 }}>
                {f.rating === 'incorrect' ? 'WRONG' : 'RIGHT'}
              </span>
              <span className="text-muted-foreground">{f.entity_type}</span>
              <span style={mono}>AI: {f.ai_verdict ?? '—'}{f.correct_verdict ? ` → should be ${f.correct_verdict}` : ''}</span>
              <span title={f.in_ai_memory ? 'Embedded: used in triage' : 'Not embedded yet (retried hourly)'}
                style={{ color: f.in_ai_memory ? 'var(--accent-green)' : 'var(--accent-yellow)', display: 'inline-flex', alignItems: 'center', gap: '3px', fontSize: '11px' }}>
                {f.in_ai_memory ? <CheckCircle2 size={12} /> : <CircleDashed size={12} />} {f.in_ai_memory ? 'in AI memory' : 'pending'}
              </span>
              <span className="ml-auto text-xs text-muted-foreground">{formatDistanceToNow(new Date(f.created_at), { addSuffix: true })}</span>
              <button style={{ ...btn, padding: '2px 8px' }} onClick={() => makeNote({
                ...emptyDraft(),
                title: f.context.split('\n')[0].slice(0, 200),
                content: `${f.rating === 'incorrect' ? `The AI said "${f.ai_verdict}", but it should be "${f.correct_verdict ?? '?'}".` : ''}${f.note ? `\n${f.note}` : ''}\n\nContext:\n${f.context}`.trim(),
              })}><Plus size={12} /> MAKE NOTE</button>
            </div>
            <div className="text-sm" style={{ marginTop: '4px', whiteSpace: 'pre-wrap' }}>{f.context}</div>
            {f.note && <div className="text-sm text-muted-foreground" style={{ marginTop: '2px' }}>Analyst: {f.note}</div>}
          </div>
        ))}
      </div>
    </div>
  )
}

function TestTab() {
  const [textValue, setText] = useState('')
  const run = useMutation({
    mutationFn: () => api.post('/api/knowledge/preview', { text: textValue }).then(r => r.data as Preview),
    onError: (e) => emitToast(detail(e, 'Preview failed'), 'error'),
  })
  const out = run.data
  return (
    <div>
      <div className="text-sm text-muted-foreground mb-2">
        Paste an alert (title, IP, host, request) to see which notes and payload reference the AI would get.
      </div>
      <textarea style={{ ...input, minHeight: '90px', ...mono }} value={textValue} onChange={e => setText(e.target.value)}
        placeholder="SQL Injection Attempt 45.9.20.1 GET /search?q=1' UNION SELECT username,password FROM users--" />
      <button style={{ ...btn, marginTop: '8px' }} disabled={textValue.length < 3 || run.isPending} onClick={() => run.mutate()}>
        <Search size={13} /> PREVIEW
      </button>
      {out && (
        <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {!out.semantic && <div className="text-sm" style={{ color: 'var(--accent-yellow)' }}>
            Embedding model not available: only notes matched by scope (IP, host, user, rule) are shown.
          </div>}
          <span style={label}>Notes ({out.notes.length})</span>
          {out.notes.map(n => (
            <div key={n.id} style={card}>
              <b className="text-sm">{n.title}</b>
              <span className="text-xs text-muted-foreground" style={{ marginLeft: '8px' }}>
                {n.matched?.length ? `matches ${n.matched.join(', ')}` : `similarity ${n.score}`}
              </span>
              <div className="text-sm" style={{ whiteSpace: 'pre-wrap' }}>{n.content}</div>
            </div>
          ))}
          <span style={label}>Payload reference ({out.references.length})</span>
          {out.references.map(r => (
            <div key={r.id} style={card}>
              <b className="text-sm">{r.title}</b><span className="text-xs text-muted-foreground" style={{ marginLeft: '8px' }}>similarity {r.score}</span>
              <pre style={{ ...mono, fontSize: '11px', whiteSpace: 'pre-wrap', margin: '4px 0 0' }}>{r.text}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

const TABS = [
  ['vault', 'Vault'], ['notes', 'Quick notes'], ['reference', 'Payload reference'], ['learned', 'Learned from feedback'],
  ['test', 'Test'],
] as const

export default function KnowledgePage() {
  // /knowledge?article=<id> is the canonical link the AI cites (worker/knowledge_query.py)
  const [params] = useSearchParams()
  const article = params.get('article')
  const [tab, setTab] = useState<(typeof TABS)[number][0]>('vault')
  const [draft, setDraft] = useState<Draft | null>(null)
  return (
    <div>
      <div className="mb-4">
        <h1 className="text-xl font-bold">Knowledge</h1>
        <p className="text-sm text-muted-foreground">
          What the AI knows about this environment and about attacks. It is given the relevant parts when it
          triages alerts and investigates cases, to cut false positives.
        </p>
      </div>
      <div className="flex gap-1 mb-4" style={{ borderBottom: '1px solid var(--border)' }}>
        {TABS.map(([id, name]) => (
          <button key={id} onClick={() => setTab(id)} style={{
            ...label, padding: '8px 12px', color: tab === id ? 'var(--accent-cyan)' : 'var(--text-muted)',
            borderBottom: tab === id ? '2px solid var(--accent-cyan)' : '2px solid transparent',
          }}>{name}</button>
        ))}
      </div>
      {tab === 'vault' && <KnowledgeVault initialId={article} />}
      {tab === 'notes' && <NotesTab draft={draft} setDraft={setDraft} />}
      {tab === 'reference' && <ReferenceTab />}
      {tab === 'learned' && <LearnedTab makeNote={d => { setDraft(d); setTab('notes') }} />}
      {tab === 'test' && <TestTab />}
    </div>
  )
}
