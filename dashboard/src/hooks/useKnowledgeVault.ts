import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'

// The knowledge vault (server-api routes/knowledge.py, services/knowledge_vault.py):
// Markdown articles with frontmatter, [[wikilinks]], revisions and a one-way Obsidian import.

export type ArticleStatus = 'draft' | 'published' | 'archived'

export interface ArticleSummary {
  id: string
  group_id: string
  kind: string
  source: string
  slug: string | null
  path: string | null
  title: string
  tags: string[]
  content_type: string
  trust: 'draft' | 'reviewed' | 'verified' | 'external'
  status: ArticleStatus
  version: number
  enabled: boolean
  expires_at: string | null
  reviewed_at: string | null
  updated_at: string | null
  indexed: boolean
  index_error: string | null
  excerpt: string
}

export interface ArticleLink {
  target?: string
  heading: string | null
  resolved?: boolean
  entry_id: string | null
  title: string | null
  slug: string | null
}

export interface Article extends ArticleSummary {
  markdown: string
  scope: Record<string, string[]>
  owner_id: string | null
  reviewed_by: string | null
  headings: { level: number; text: string; anchor: string }[]
  outgoing: ArticleLink[]
  backlinks: ArticleLink[]
  related: ArticleLink[]
  warnings: string[]
}

export interface Revision {
  version: number
  title: string
  status: string
  author_id: string | null
  note: string | null
  created_at: string
  markdown: string
}

export interface ImportReport {
  dry_run: boolean
  files: number
  added: string[]
  updated: string[]
  unchanged: string[]
  skipped: { path: string; reason: string }[]
  errors: { path: string; error: string; problems: string[] }[]
  unresolved_links: { path: string; target: string }[]
}

/** The server explains a refused save as {message, problems}; flatten it for a toast or a panel. */
export function vaultError(err: unknown, fallback: string): { message: string; problems: string[] } {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof d === 'string') return { message: d, problems: [] }
  if (d && typeof d === 'object' && 'message' in d) {
    const o = d as { message: string; problems?: string[] }
    return { message: o.message, problems: o.problems ?? [] }
  }
  return { message: fallback, problems: [] }
}

export function useArticles(filters: { q?: string; status?: string; tag?: string }) {
  return useQuery<ArticleSummary[]>({
    queryKey: ['knowledge-articles', filters],
    queryFn: () => api.get('/api/knowledge/articles', { params: filters }).then(r => r.data),
    refetchInterval: 15_000, // index status changes in the background
  })
}

export function useArticle(id: string | null) {
  return useQuery<Article>({
    queryKey: ['knowledge-article', id],
    queryFn: () => api.get(`/api/knowledge/articles/${id}`).then(r => r.data),
    enabled: !!id,
  })
}

export function useRevisions(id: string | null, open: boolean) {
  return useQuery<Revision[]>({
    queryKey: ['knowledge-article', id, 'revisions'],
    queryFn: () => api.get(`/api/knowledge/articles/${id}/revisions`).then(r => r.data),
    enabled: !!id && open,
  })
}

export function useArticleTitles(q: string | null) {
  return useQuery<{ id: string; title: string; slug: string }[]>({
    queryKey: ['knowledge-titles', q],
    queryFn: () => api.get('/api/knowledge/articles/titles', { params: { q } }).then(r => r.data),
    enabled: q !== null,
    staleTime: 10_000,
  })
}

export function useVaultMutations(onSaved?: (a: Article) => void) {
  const qc = useQueryClient()
  const refresh = (a?: Article) => {
    qc.invalidateQueries({ queryKey: ['knowledge-articles'] })
    if (a) qc.setQueryData(['knowledge-article', a.id], a)
    qc.invalidateQueries({ queryKey: ['knowledge-article'] })
  }
  const done = (msg: string) => (a: Article) => { emitToast(msg, 'success'); refresh(a); onSaved?.(a) }
  const fail = (fallback: string) => (e: unknown) => emitToast(vaultError(e, fallback).message, 'error')
  return {
    save: useMutation({
      mutationFn: ({ id, markdown, status }: { id?: string; markdown: string; status?: ArticleStatus }) =>
        (id ? api.put(`/api/knowledge/articles/${id}`, { markdown, status })
          : api.post('/api/knowledge/articles', { markdown, status })).then(r => r.data as Article),
      onSuccess: done('Saved'),
      // the editor shows the problems itself
    }),
    publish: useMutation({
      mutationFn: (id: string) => api.post(`/api/knowledge/articles/${id}/publish`).then(r => r.data as Article),
      onSuccess: done('Published: indexing for the AI'), onError: fail('Could not publish'),
    }),
    archive: useMutation({
      mutationFn: (id: string) => api.post(`/api/knowledge/articles/${id}/archive`).then(r => r.data as Article),
      onSuccess: done('Archived: the AI no longer sees it'), onError: fail('Could not archive'),
    }),
    review: useMutation({
      mutationFn: ({ id, trust }: { id: string; trust: 'reviewed' | 'verified' }) =>
        api.post(`/api/knowledge/articles/${id}/review`, { trust }).then(r => r.data as Article),
      onSuccess: done('Review recorded'), onError: fail('Could not record the review'),
    }),
    restore: useMutation({
      mutationFn: ({ id, version }: { id: string; version: number }) =>
        api.post(`/api/knowledge/articles/${id}/revisions/${version}/restore`).then(r => r.data as Article),
      onSuccess: done('Restored as a new version'), onError: fail('Could not restore'),
    }),
    importVault: useMutation({
      mutationFn: ({ file, dryRun, publish }: { file: File; dryRun: boolean; publish: boolean }) => {
        const form = new FormData()
        form.append('file', file)
        return api.post('/api/knowledge/import', form, { params: { dry_run: dryRun, publish } })
          .then(r => r.data as ImportReport)
      },
      onSuccess: (r) => { if (!r.dry_run) { emitToast('Vault imported', 'success'); refresh() } },
    }),
  }
}
