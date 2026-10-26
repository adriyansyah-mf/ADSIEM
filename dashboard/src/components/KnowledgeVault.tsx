import { useEffect, useRef, useState } from 'react'
import { formatDistanceToNow } from 'date-fns'
import {
  AlertTriangle, CheckCircle2, CircleDashed, Eye, FileUp, History, Link2, PenLine, Plus, Search, Upload, X,
} from 'lucide-react'
import MarkdownNote from '@/components/MarkdownNote'
import {
  type ArticleSummary, type ImportReport, useArticle, useArticles, useArticleTitles, useRevisions,
  useVaultMutations, vaultError,
} from '@/hooks/useKnowledgeVault'

// Knowledge vault: DFIR articles and environment notes the AI investigator retrieves and cites.

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
  display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '5px 10px', borderRadius: '4px',
  fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '12px', letterSpacing: '1px', cursor: 'pointer',
  border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-primary)',
}
const card: React.CSSProperties = { border: '1px solid var(--border)', borderRadius: '4px', padding: '10px 12px' }

const STATUS_COLOR: Record<string, string> = {
  draft: 'var(--accent-yellow)', published: 'var(--accent-green)', archived: 'var(--text-muted)',
}
const TRUST_COLOR: Record<string, string> = {
  draft: 'var(--text-muted)', reviewed: 'var(--accent-cyan)', verified: 'var(--accent-green)', external: 'var(--accent-orange)',
}

const TEMPLATE = `---
title: Investigating suspicious PowerShell
tags: [windows, powershell]
platforms: [windows]
mitre: [T1059.001]
type: dfir_article
---

# Triage

What to check first, and why. Link related notes with [[Note title]].

# Containment
`

function Tag({ text, color }: { text: string; color: string }) {
  return (
    <span style={{ ...label, fontSize: '10px', letterSpacing: '1px', color, border: `1px solid ${color}`, padding: '0 5px', borderRadius: '3px', whiteSpace: 'nowrap' }}>
      {text}
    </span>
  )
}

function IndexState({ a }: { a: ArticleSummary }) {
  if (a.status !== 'published') return <span style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)' }}>not visible to the AI ({a.status})</span>
  if (a.index_error) return <span style={{ ...mono, fontSize: '11px', color: 'var(--accent-red)' }} title={a.index_error}><AlertTriangle size={11} /> index failed: previous version stays live</span>
  return a.indexed
    ? <span style={{ ...mono, fontSize: '11px', color: 'var(--accent-green)' }}><CheckCircle2 size={11} /> indexed</span>
    : <span style={{ ...mono, fontSize: '11px', color: 'var(--accent-yellow)' }}><CircleDashed size={11} /> indexing…</span>
}

/** Obsidian links as bold text in the preview (react-markdown doesn't know them). */
function previewMarkdown(markdown: string): string {
  const body = markdown.replace(/^---\n[\s\S]*?\n---\n?/, '')
  return body.replace(/!?\[\[([^\]|#\n]*)(?:#([^\]|\n]+))?(?:\|([^\]\n]+))?\]\]/g,
    (_m, target: string, heading?: string, alias?: string) => `**${alias || target}${heading && !alias ? ` › ${heading}` : ''}**`)
}

function Editor({ id, onCreated }: { id: string | null; onCreated: (id: string) => void }) {
  const { data: article } = useArticle(id)
  const [text, setText] = useState(id ? '' : TEMPLATE)
  const [loadedVersion, setLoadedVersion] = useState<string | null>(null)
  const [problems, setProblems] = useState<{ message: string; problems: string[] } | null>(null)
  const [preview, setPreview] = useState(false)
  const [history, setHistory] = useState(false)
  const [linkQuery, setLinkQuery] = useState<string | null>(null)
  const area = useRef<HTMLTextAreaElement>(null)
  const { data: suggestions = [] } = useArticleTitles(linkQuery)
  const { data: revisions = [] } = useRevisions(id, history)
  const m = useVaultMutations(a => { setProblems(null); if (!id) onCreated(a.id) })

  // load the server's version once per article version (don't clobber typing on refetch)
  useEffect(() => {
    if (article && loadedVersion !== `${article.id}:${article.version}`) {
      setText(article.markdown)
      setLoadedVersion(`${article.id}:${article.version}`)
    }
  }, [article, loadedVersion])

  const dirty = article ? text !== article.markdown : text !== TEMPLATE
  const onType = (value: string) => {
    setText(value)
    const caret = area.current?.selectionStart ?? value.length
    const open = /\[\[([^\]\n|#]*)$/.exec(value.slice(0, caret))
    setLinkQuery(open ? open[1] : null)
  }
  const insertLink = (title: string) => {
    const el = area.current
    const caret = el?.selectionStart ?? text.length
    const before = text.slice(0, caret).replace(/\[\[([^\]\n|#]*)$/, `[[${title}]]`)
    setText(before + text.slice(caret))
    setLinkQuery(null)
    requestAnimationFrame(() => { el?.focus(); el?.setSelectionRange(before.length, before.length) })
  }
  const save = (status?: 'draft' | 'published') =>
    m.save.mutate({ id: id ?? undefined, markdown: text, status }, { onError: e => setProblems(vaultError(e, 'Could not save')) })

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 260px', gap: '12px', alignItems: 'start' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', minWidth: 0 }}>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
          {article ? <span style={{ fontSize: '15px', fontWeight: 600 }}>{article.title}</span> : <span style={label}>New article</span>}
          <span style={{ flex: 1 }} />
          <button style={btn} onClick={() => setPreview(p => !p)}>{preview ? <PenLine size={12} /> : <Eye size={12} />}{preview ? 'EDIT' : 'PREVIEW'}</button>
          <button style={btn} disabled={m.save.isPending || (!dirty && !!article)} onClick={() => save(article ? undefined : 'draft')}>
            {article ? 'SAVE' : 'SAVE DRAFT'}
          </button>
          {(!article || article.status !== 'published') && (
            <button style={{ ...btn, borderColor: 'var(--accent-green)', color: 'var(--accent-green)' }}
              disabled={m.save.isPending || m.publish.isPending}
              onClick={() => (dirty || !article ? save('published') : m.publish.mutate(article.id))}>
              PUBLISH
            </button>
          )}
          {article && article.status !== 'archived' && (
            <button style={btn} onClick={() => m.archive.mutate(article.id)}>ARCHIVE</button>
          )}
        </div>
        {problems && (
          <div style={{ ...card, borderColor: 'var(--accent-red)', fontSize: '12px', color: 'var(--accent-red)' }}>
            {problems.message}
            {problems.problems.map(p => <div key={p} style={mono}>· {p}</div>)}
          </div>
        )}
        {article?.warnings?.map(w => <div key={w} style={{ ...mono, fontSize: '11px', color: 'var(--accent-yellow)' }}>{w}</div>)}
        {preview ? (
          <div style={{ ...card, minHeight: '420px' }}>
            <MarkdownNote content={previewMarkdown(text)} style={{ fontFamily: 'Exo 2, sans-serif', fontSize: '13px', color: 'var(--text-primary)' }} />
          </div>
        ) : (
          <div style={{ position: 'relative' }}>
            <textarea ref={area} value={text} onChange={e => onType(e.target.value)} spellCheck={false}
              onKeyDown={e => { if (e.key === 'Escape') setLinkQuery(null) }}
              style={{ ...input, ...mono, minHeight: '460px', lineHeight: 1.5, resize: 'vertical' }} />
            {linkQuery !== null && suggestions.length > 0 && (
              <div style={{ position: 'absolute', left: '8px', bottom: '8px', zIndex: 5, minWidth: '260px', maxHeight: '180px', overflow: 'auto', background: 'var(--bg-surface, var(--bg-base))', border: '1px solid var(--accent-cyan)', borderRadius: '4px' }}>
                <div style={{ ...label, padding: '4px 8px' }}>Link to</div>
                {suggestions.map(s => (
                  <button key={s.id} onMouseDown={e => { e.preventDefault(); insertLink(s.title) }}
                    style={{ display: 'block', width: '100%', textAlign: 'left', padding: '4px 8px', fontSize: '12px', color: 'var(--text-primary)' }}>
                    {s.title}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
        <div style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)' }}>
          Frontmatter: title, tags, platforms, mitre, type, trust, expires, scope (groups, ips, hosts, users, rules).
          Type [[ to link a note. Credentials are refused; drafts never reach the AI.
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {article && (
          <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
              <Tag text={article.status} color={STATUS_COLOR[article.status]} />
              <Tag text={article.trust} color={TRUST_COLOR[article.trust]} />
              <Tag text={`v${article.version}`} color="var(--text-muted)" />
            </div>
            <IndexState a={article} />
            {article.path && <div style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)' }}>{article.path}</div>}
            <div style={{ display: 'flex', gap: '5px' }}>
              <button style={btn} onClick={() => m.review.mutate({ id: article.id, trust: 'reviewed' })}>REVIEWED</button>
              <button style={btn} onClick={() => m.review.mutate({ id: article.id, trust: 'verified' })}>VERIFIED</button>
            </div>
          </div>
        )}
        {article && article.headings.length > 0 && (
          <div style={card}>
            <div style={label}>Outline</div>
            {article.headings.map((h, i) => (
              <div key={i} style={{ fontSize: '12px', paddingLeft: `${(h.level - 1) * 10}px`, color: 'var(--text-primary)' }}>{h.text}</div>
            ))}
          </div>
        )}
        {article && (article.outgoing.length > 0 || article.backlinks.length > 0 || article.related.length > 0) && (
          <div style={{ ...card, fontSize: '12px' }}>
            {article.outgoing.length > 0 && <div style={label}><Link2 size={11} /> Links</div>}
            {article.outgoing.map(l => (
              <div key={`${l.target}#${l.heading}`} style={{ color: l.resolved ? 'var(--text-primary)' : 'var(--accent-red)' }}
                title={l.resolved ? undefined : 'No article with this title yet'}>
                {l.target}{l.heading ? ` › ${l.heading}` : ''}{l.resolved ? '' : ' (missing)'}
              </div>
            ))}
            {article.backlinks.length > 0 && <div style={{ ...label, marginTop: '6px' }}>Linked from</div>}
            {article.backlinks.map(l => <div key={l.entry_id}>{l.title}</div>)}
            {article.related.length > 0 && <div style={{ ...label, marginTop: '6px' }}>Same tags</div>}
            {article.related.map(l => <div key={l.entry_id}>{l.title}</div>)}
          </div>
        )}
        {article && (
          <div style={card}>
            <button style={{ ...label, display: 'inline-flex', gap: '4px', alignItems: 'center' }} onClick={() => setHistory(h => !h)}>
              <History size={11} /> History {history ? '▾' : '▸'}
            </button>
            {history && revisions.map(r => (
              <div key={r.version} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', marginTop: '4px' }}>
                <span style={mono}>v{r.version}</span>
                <span style={{ color: 'var(--text-muted)', flex: 1 }}>
                  {formatDistanceToNow(new Date(r.created_at), { addSuffix: true })}{r.note ? ` · ${r.note}` : ''}
                </span>
                {r.version !== article.version && (
                  <button style={{ ...btn, padding: '1px 6px', fontSize: '10px' }}
                    onClick={() => m.restore.mutate({ id: article.id, version: r.version })}>RESTORE</button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function ImportDialog({ onClose }: { onClose: () => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [publish, setPublish] = useState(false)
  const [report, setReport] = useState<ImportReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { importVault } = useVaultMutations()
  const run = (dryRun: boolean) => {
    if (!file) return
    setError(null)
    importVault.mutate({ file, dryRun, publish }, {
      onSuccess: setReport, onError: e => setError(vaultError(e, 'Import failed').message),
    })
  }
  const list = (title: string, items: string[], color = 'var(--text-primary)') => items.length > 0 && (
    <div style={{ marginTop: '6px' }}>
      <div style={label}>{title} ({items.length})</div>
      <div style={{ ...mono, fontSize: '11px', color, maxHeight: '120px', overflow: 'auto' }}>{items.map(i => <div key={i}>{i}</div>)}</div>
    </div>
  )
  return (
    <div style={{ ...card, marginBottom: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div className="flex items-center justify-between">
        <span style={label}>Import an Obsidian vault (zip)</span>
        <button onClick={onClose}><X size={14} /></button>
      </div>
      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
        One-way: Markdown notes are added or updated by path, with frontmatter and [[links]]. Hidden folders
        (.obsidian) and attachments are ignored. Check with a dry run first.
      </div>
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="file" accept=".zip" onChange={e => { setFile(e.target.files?.[0] ?? null); setReport(null) }} style={{ fontSize: '12px' }} />
        <label style={{ fontSize: '12px', display: 'inline-flex', gap: '4px', alignItems: 'center' }}>
          <input type="checkbox" checked={publish} onChange={e => setPublish(e.target.checked)} /> publish imported notes
        </label>
        <button style={btn} disabled={!file || importVault.isPending} onClick={() => run(true)}><Search size={12} />DRY RUN</button>
        <button style={{ ...btn, borderColor: 'var(--accent-cyan)', color: 'var(--accent-cyan)' }}
          disabled={!file || importVault.isPending || !report?.dry_run} onClick={() => run(false)}><Upload size={12} />IMPORT</button>
      </div>
      {error && <div style={{ fontSize: '12px', color: 'var(--accent-red)' }}>{error}</div>}
      {report && (
        <div style={{ fontSize: '12px' }}>
          <div>{report.dry_run ? 'Dry run' : 'Imported'}: {report.files} notes · {report.added.length} new · {report.updated.length} changed · {report.unchanged.length} unchanged</div>
          {list('New', report.added)}
          {list('Changed', report.updated)}
          {list('Errors', report.errors.map(e => `${e.path}: ${e.error}${e.problems.length ? ` (${e.problems.join('; ')})` : ''}`), 'var(--accent-red)')}
          {list('Links to notes that do not exist', report.unresolved_links.map(l => `${l.path} → [[${l.target}]]`), 'var(--accent-yellow)')}
          {list('Skipped', report.skipped.map(s => `${s.path}: ${s.reason}`), 'var(--text-muted)')}
        </div>
      )}
    </div>
  )
}

export default function KnowledgeVault({ initialId = null }: { initialId?: string | null }) {
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('')
  const [selected, setSelected] = useState<string | null>(initialId)
  const [creating, setCreating] = useState(false)
  const [importing, setImporting] = useState(false)
  const { data: articles = [] } = useArticles({ q: q || undefined, status: status || undefined })
  return (
    <div>
      {importing && <ImportDialog onClose={() => setImporting(false)} />}
      <div style={{ display: 'grid', gridTemplateColumns: '300px minmax(0, 1fr)', gap: '14px', alignItems: 'start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', gap: '6px' }}>
            <button style={{ ...btn, borderColor: 'var(--accent-cyan)', color: 'var(--accent-cyan)' }}
              onClick={() => { setSelected(null); setCreating(true) }}><Plus size={12} />NEW</button>
            <button style={btn} onClick={() => setImporting(true)}><FileUp size={12} />IMPORT</button>
          </div>
          <input style={input} placeholder="Search title, text or path" value={q} onChange={e => setQ(e.target.value)} />
          <select style={input} value={status} onChange={e => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            <option value="published">Published</option>
            <option value="draft">Drafts</option>
            <option value="archived">Archived</option>
          </select>
          <div style={{ border: '1px solid var(--border)', borderRadius: '4px', maxHeight: '600px', overflow: 'auto' }}>
            {articles.length === 0 && <div style={{ ...mono, fontSize: '12px', color: 'var(--text-muted)', padding: '10px' }}>No articles</div>}
            {articles.map(a => (
              <button key={a.id} onClick={() => { setCreating(false); setSelected(a.id) }}
                style={{ display: 'block', width: '100%', textAlign: 'left', padding: '7px 10px', borderBottom: '1px solid var(--border)',
                  background: selected === a.id ? 'rgba(0,212,255,0.06)' : 'transparent' }}>
                <div style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{a.title}</div>
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '3px' }}>
                  <Tag text={a.status} color={STATUS_COLOR[a.status]} />
                  <Tag text={a.trust} color={TRUST_COLOR[a.trust]} />
                  {a.tags.slice(0, 3).map(t => <Tag key={t} text={`#${t}`} color="var(--text-muted)" />)}
                </div>
              </button>
            ))}
          </div>
        </div>
        <div>
          {creating && <Editor key="new" id={null} onCreated={id => { setCreating(false); setSelected(id) }} />}
          {!creating && selected && <Editor key={selected} id={selected} onCreated={() => undefined} />}
          {!creating && !selected && (
            <div style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
              Write DFIR articles and environment notes in Markdown, or import your Obsidian vault. Published
              articles are indexed automatically; the AI investigator retrieves them by meaning, words, tags and
              links, and cites them as <span style={mono}>Knowledge: title#heading</span>. Knowledge guides an
              investigation but never counts as evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
