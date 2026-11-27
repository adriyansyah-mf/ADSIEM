import { useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { format } from 'date-fns'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { api } from '@/api/client'
import MarkdownNote from '@/components/MarkdownNote'
import { useArticle, useArticles, type Article, type ArticleSummary } from '@/hooks/useKnowledgeVault'
import { useAuthStore } from '@/stores/auth'
import { CanvasHeader, CanvasPage, Chip, Empty, SectionTitle, type Tone } from '@/components/canvas/Canvas'

interface SopDocument {
  id: string
  filename: string
  content_type: string
  status: 'pending' | 'indexed' | 'failed'
  uploaded_by: string | null
  created_at: string
}

const PLAYBOOK_TAG = 'playbook'
const TRUST: Record<ArticleSummary['trust'], { label: string; tone: Tone }> = {
  verified: { label: 'APPROVED', tone: 'good' },
  reviewed: { label: 'REVIEWED', tone: 'info' },
  draft: { label: 'DRAFT', tone: 'muted' },
  external: { label: 'EXTERNAL', tone: 'warn' },
}

interface Step { n: number; title: string; body: string }

/** Top-level numbered items become playbook steps: "1. **Contain the host** — Isolate…". */
function parseSteps(markdown: string): { intro: string; steps: Step[]; rest: string } {
  const lines = markdown.replace(/^---[\s\S]*?\n---\n/, '').split('\n')
  const steps: Step[] = []
  const intro: string[] = []
  const rest: string[] = []
  let current: Step | null = null
  for (const line of lines) {
    const item = /^(\d+)[.)]\s+(.*)$/.exec(line)
    if (item) {
      const text = item[2]
      const bold = /^\*\*(.+?)\*\*\s*[—:-]?\s*(.*)$/.exec(text)
      const split = bold ?? /^(.{3,80}?)\s+[—:-]\s+(.*)$/.exec(text)
      current = { n: Number(item[1]), title: split ? split[1] : text, body: split ? split[2] : '' }
      steps.push(current)
    } else if (current && (/^\s{2,}\S/.test(line) || line.trim() === '')) {
      current.body += `\n${line.replace(/^\s{2,4}/, '')}`
    } else if (current) {
      current = null
      rest.push(line)
    } else if (steps.length) {
      rest.push(line)
    } else {
      intro.push(line)
    }
  }
  return { intro: intro.join('\n').replace(/^#\s+.*\n?/, '').trim(), steps, rest: rest.join('\n').trim() }
}

function category(article: ArticleSummary) {
  const tag = article.tags.find(t => t.toLowerCase() !== PLAYBOOK_TAG)
  return tag ? tag.replace(/[-_]/g, ' ').replace(/^\w/, c => c.toUpperCase()) : 'General'
}

function sopId(article: ArticleSummary) {
  return article.slug?.toUpperCase().slice(0, 12) ?? `KB-${article.id.slice(0, 4).toUpperCase()}`
}

export default function SopPage() {
  const [params, setParams] = useSearchParams()
  const canEdit = useAuthStore(s => s.hasRole('analyst'))
  const [search, setSearch] = useState('')
  const playbooks = useArticles({ tag: PLAYBOOK_TAG, q: search || undefined })
  const allArticles = useArticles({})
  const skills = useQuery<unknown[]>({ queryKey: ['ai-skills'], queryFn: () => api.get('/api/ai-skills').then(r => r.data), retry: false, staleTime: 60_000 })
  const docs = useQuery<SopDocument[]>({
    queryKey: ['sop-documents'],
    queryFn: () => api.get('/api/sop-documents').then(r => r.data),
    refetchInterval: q => (q.state.data ?? []).some(d => d.status === 'pending') ? 5000 : 60_000,
  })

  // Articles tagged "playbook" are the library; without any, every published article is offered.
  const tagged = playbooks.data ?? []
  const library = tagged.length || search ? tagged : (allArticles.data ?? []).filter(a => a.status !== 'archived')
  const groups = useMemo(() => {
    const map = new Map<string, ArticleSummary[]>()
    for (const article of library) map.set(category(article), [...(map.get(category(article)) ?? []), article])
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [library])
  const selectedId = params.get('playbook') ?? library[0]?.id ?? null
  const article = useArticle(selectedId)
  const select = (id: string) => setParams(current => { const next = new URLSearchParams(current); next.set('playbook', id); return next }, { replace: true })

  return (
    <CanvasPage>
      <CanvasHeader
        title="Playbooks & knowledge"
        crumb={article.data ? <>Playbooks &amp; knowledge / {sopId(article.data)}</> : undefined}
        sub="Response procedures the team follows, and the documents the AI cites when it investigates"
        counts={{ '/sop': library.length || null, '/knowledge': allArticles.data?.length ?? null, '/ai-skills': skills.data?.length ?? null }}
        actions={<>
          <form className="cv-search" style={{ width: 280 }} onSubmit={e => e.preventDefault()}>
            <Search size={14} aria-hidden="true" />
            <label htmlFor="sop-search" className="sr-only">Search playbooks</label>
            <input id="sop-search" placeholder="Search playbooks and articles" value={search} onChange={e => setSearch(e.target.value)} />
          </form>
          {canEdit && <Link className="cv-btn cv-btn--primary" to="/knowledge">New playbook</Link>}
        </>}
      />
      <div className="cv-split">
        <aside className="cv-list" aria-label="Playbook library" style={{ flex: '1 1 260px', maxWidth: 300, padding: 12, gap: 14 }}>
          {groups.map(([name, items]) => (
            <div key={name} className="cv-stack" style={{ gap: 2 }}>
              <span className="cv-eyebrow" style={{ padding: '0 8px 4px' }}>{name}</span>
              {items.map(item => (
                <button key={item.id} type="button" className={`cv-navitem ${item.id === selectedId ? 'is-active' : ''}`}
                  style={{ height: 'auto', minHeight: 32, padding: '6px 8px', justifyContent: 'space-between' }} onClick={() => select(item.id)}>
                  <span style={{ overflowWrap: 'anywhere' }}>{item.title}</span>
                  <span className="cv-mono cv-muted" style={{ fontSize: 11, flex: 'none' }}>{item.slug ? sopId(item) : `v${item.version}`}</span>
                </button>
              ))}
            </div>
          ))}
          {(playbooks.isLoading || allArticles.isLoading) && <span className="cv-muted cv-small">Loading…</span>}
          {!playbooks.isLoading && !allArticles.isLoading && library.length === 0 && (
            <span className="cv-muted cv-small" style={{ padding: '0 8px' }}>
              {search ? 'Nothing matches.' : 'No playbooks yet. Write one in the knowledge base and tag it “playbook”.'}
            </span>
          )}
          {!tagged.length && library.length > 0 && !search && (
            <span className="cv-muted cv-small" style={{ padding: '0 8px' }}>Showing every article. Tag an article “playbook” to list only procedures here.</span>
          )}
        </aside>

        <article className="cv-pane" aria-label="Playbook">
          {article.data ? <PlaybookView article={article.data} canEdit={canEdit} />
            : article.isLoading ? <Empty>Loading the playbook…</Empty>
            : <Empty>Select a playbook from the library.</Empty>}
        </article>

        <aside className="cv-list" aria-label="Related" style={{ flex: '1 1 280px', maxWidth: 320, borderRight: 0, borderLeft: '1px solid #222733', padding: 16, gap: 16 }}>
          {article.data && <Related article={article.data} />}
          <SopDocuments docs={docs.data ?? []} loading={docs.isLoading} canEdit={canEdit} />
        </aside>
      </div>
    </CanvasPage>
  )
}

function PlaybookView({ article, canEdit }: { readonly article: Article; readonly canEdit: boolean }) {
  const { intro, steps, rest } = useMemo(() => parseSteps(article.markdown), [article.markdown])
  const trust = TRUST[article.trust] ?? TRUST.draft
  return <>
    <div className="cv-stack" style={{ gap: 6 }}>
      <span className="cv-row cv-small cv-muted" style={{ gap: 8 }}>
        <span className="cv-mono">{sopId(article)} · v{article.version}</span>
        <Chip tone={trust.tone}>{trust.label}</Chip>
        {article.status !== 'published' && <Chip tone="muted">{article.status.toUpperCase()}</Chip>}
        <span>
          {article.reviewed_at ? `reviewed ${format(new Date(article.reviewed_at), 'd MMM yyyy')}` : 'not reviewed yet'}
          {article.expires_at ? ` · next review ${format(new Date(article.expires_at), 'd MMM yyyy')}` : ''}
        </span>
      </span>
      <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>{article.title}</h2>
      {intro && <div className="cv-dim"><MarkdownNote content={intro} /></div>}
    </div>
    <div className="cv-row">
      <Link className="cv-btn" to="/cases">Start in a case</Link>
      {canEdit && <Link className="cv-btn" to={`/knowledge?article=${article.id}`}>Edit</Link>}
      <button type="button" className="cv-btn" onClick={() => window.print()}>Export PDF</button>
    </div>
    {steps.length > 0 ? (
      <ol className="cv-pbsteps">
        {steps.map(step => (
          <li key={step.n}>
            <span className="cv-pbsteps__n">{step.n}</span>
            <div className="cv-stack" style={{ gap: 4, flex: 1 }}>
              <strong style={{ fontSize: 14 }}>{step.title}</strong>
              {step.body.trim() && <div className="cv-dim"><MarkdownNote content={step.body.trim()} /></div>}
            </div>
          </li>
        ))}
      </ol>
    ) : null}
    {(rest || !steps.length) && <div className="cv-card"><MarkdownNote content={steps.length ? rest : article.markdown} /></div>}
    {article.warnings.length > 0 && <p className="cv-t-warn cv-small" style={{ margin: 0 }}>{article.warnings.join(' · ')}</p>}
  </>
}

function Related({ article }: { readonly article: Article }) {
  const links = (list: Article['outgoing']) => list.filter(l => l.entry_id || l.title)
  const sections = [
    { title: 'Links to', items: links(article.outgoing) },
    { title: 'Referenced by', items: links(article.backlinks) },
    { title: 'Related', items: links(article.related) },
  ].filter(section => section.items.length)
  return <>
    {sections.map(section => (
      <section key={section.title} className="cv-stack" style={{ gap: 6 }}>
        <SectionTitle>{section.title}</SectionTitle>
        {section.items.slice(0, 6).map((link, index) => link.entry_id
          ? <Link key={`${link.entry_id}-${index}`} to={`/sop?playbook=${link.entry_id}`}>{link.title ?? link.target}</Link>
          : <span key={`${link.target}-${index}`} className="cv-muted">{link.title ?? link.target}</span>)}
      </section>
    ))}
    <section className="cv-stack" style={{ gap: 6 }}>
      <SectionTitle>Version</SectionTitle>
      <span className="cv-dim cv-small">v{article.version}{article.updated_at ? ` · updated ${format(new Date(article.updated_at), 'd MMM yyyy')}` : ''}</span>
      {article.tags.length > 0 && <span className="cv-row" style={{ gap: 4 }}>{article.tags.map(tag => <Chip key={tag}>{tag}</Chip>)}</span>}
      <span className="cv-small cv-muted">{article.indexed ? 'Indexed for the AI investigator' : article.index_error ? `Not indexed: ${article.index_error}` : 'Waiting to be indexed'}</span>
    </section>
  </>
}

function SopDocuments({ docs, loading, canEdit }: { readonly docs: SopDocument[]; readonly loading: boolean; readonly canEdit: boolean }) {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [error, setError] = useState('')
  const upload = useMutation({
    mutationFn: (file: File) => {
      const form = new FormData()
      form.append('file', file)
      return api.post('/api/sop-documents', form, { headers: { 'Content-Type': 'multipart/form-data' } })
    },
    onSuccess: () => { setError(''); void qc.invalidateQueries({ queryKey: ['sop-documents'] }) },
    onError: (err: unknown) => setError((err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Upload failed'),
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/sop-documents/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sop-documents'] }),
  })
  const tone: Record<SopDocument['status'], Tone> = { pending: 'warn', indexed: 'good', failed: 'bad' }
  return (
    <section className="cv-stack" style={{ gap: 8 }}>
      <SectionTitle action={canEdit && (
        <button type="button" className="cv-btn cv-btn--sm" disabled={upload.isPending} onClick={() => fileRef.current?.click()}>
          {upload.isPending ? 'Uploading…' : 'Upload'}
        </button>
      )}>SOP documents · {docs.length}</SectionTitle>
      <input ref={fileRef} type="file" accept=".pdf,.docx,.txt" hidden onChange={e => {
        const file = e.target.files?.[0]
        if (file) upload.mutate(file)
        e.target.value = ''
      }} />
      <span className="cv-small cv-muted">PDF, DOCX or TXT. The AI investigator reads them as reference; they do not become playbooks.</span>
      {error && <span className="cv-t-bad cv-small">{error}</span>}
      {loading && <span className="cv-muted cv-small">Loading…</span>}
      {docs.map(doc => (
        <div key={doc.id} className="cv-row cv-row--between" style={{ flexWrap: 'nowrap', borderTop: '1px solid #1E222B', paddingTop: 6 }}>
          <span className="cv-stack" style={{ minWidth: 0 }}>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={doc.filename}>{doc.filename}</span>
            <span className="cv-small cv-muted">{format(new Date(doc.created_at), 'd MMM yyyy')}</span>
          </span>
          <span className="cv-row" style={{ flexWrap: 'nowrap', gap: 6 }}>
            <Chip tone={tone[doc.status]}>{doc.status}</Chip>
            {canEdit && <button type="button" className="cv-btn cv-btn--sm" aria-label={`Delete ${doc.filename}`} disabled={remove.isPending}
              onClick={() => { if (window.confirm(`Delete ${doc.filename}?`)) remove.mutate(doc.id) }}>×</button>}
          </span>
        </div>
      ))}
    </section>
  )
}
