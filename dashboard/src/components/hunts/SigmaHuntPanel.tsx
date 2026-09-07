import { useState } from 'react'
import { Code2, Loader2, PlayCircle } from 'lucide-react'
import { useSigmaHunt } from '@/hooks/useHunts'
import type { SigmaHuntResponse } from '@/types'
import { SIGMA_EXAMPLE, errorMessage } from './constants'

export function SigmaHuntPanel() {
  const sigmaHunt = useSigmaHunt()
  const [content, setContent] = useState(SIGMA_EXAMPLE)
  const [result, setResult] = useState<SigmaHuntResponse | null>(null)
  const [error, setError] = useState('')

  const run = (searchAfter?: Array<string | number | boolean | null>) => {
    if (!content.trim()) {
      setError('Paste a Sigma rule before running the hunt')
      return
    }
    setError('')
    sigmaHunt.mutate({ content, size: 100, search_after: searchAfter }, {
      onSuccess: (next) => setResult(previous => searchAfter && previous
        ? { ...next, matches: [...previous.matches, ...next.matches] }
        : next),
      onError: (requestError) => setError(errorMessage(requestError, 'Sigma hunt failed')),
    })
  }

  return (
    <div className="enterprise-panel rounded-lg border border-border bg-card p-5 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide flex items-center gap-2">
            <Code2 size={15} /> Sigma Hunt
          </h2>
          <p className="text-xs text-muted-foreground mt-1">Compile a Sigma rule to Lucene and search events in your group.</p>
        </div>
        <span className="text-[11px] text-muted-foreground border border-border rounded px-2 py-1">PySigma compatible</span>
      </div>
      <label className="block text-xs font-medium text-muted-foreground" htmlFor="sigma-hunt-rule">Sigma YAML</label>
      <textarea
        id="sigma-hunt-rule"
        value={content}
        onChange={event => {
          setContent(event.target.value)
          setResult(null)
          setError('')
        }}
        spellCheck={false}
        className="min-h-[220px] w-full resize-y rounded border border-border bg-muted px-3 py-3 font-mono text-xs leading-relaxed text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        aria-describedby="sigma-hunt-help"
      />
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => run()}
          disabled={sigmaHunt.isPending}
          className="flex min-h-11 items-center gap-2 rounded bg-primary px-4 py-2 text-sm font-medium text-primary-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary disabled:opacity-50"
        >
          {sigmaHunt.isPending ? <Loader2 size={14} className="animate-spin" /> : <PlayCircle size={14} />}
          Run Sigma hunt
        </button>
        <span id="sigma-hunt-help" className="text-xs text-muted-foreground">Up to 100 events per page.</span>
      </div>
      {error && <p className="text-xs text-destructive" role="alert">{error}</p>}
      {result && (
        <div className="space-y-3 border-t border-border pt-4">
          <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span className="font-medium">{result.total.toLocaleString()} matching events</span>
            {result.next_cursor && (
            <button type="button" onClick={() => run(result.next_cursor ?? undefined)} disabled={sigmaHunt.isPending}
                className="min-h-11 rounded border border-border px-3 py-2 text-xs text-muted-foreground hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary disabled:opacity-50">
                Load more
              </button>
            )}
          </div>
          <details className="rounded border border-border bg-muted/40">
            <summary className="min-h-11 cursor-pointer px-3 py-2 text-xs font-medium text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">View compiled Lucene query</summary>
            <pre className="max-h-40 overflow-auto border-t border-border px-3 py-3 font-mono text-[11px] leading-relaxed text-primary whitespace-pre-wrap">{result.lucene_query}</pre>
          </details>
          {result.matches.length === 0 ? (
            <p className="rounded border border-dashed border-border px-3 py-6 text-center text-sm text-muted-foreground">No events matched this rule.</p>
          ) : (
            <div className="space-y-2" aria-live="polite">
              {result.matches.map((match, index) => (
                <details key={`${index}-${String(match.id ?? 'event')}`} className="rounded border border-border bg-muted/20">
                  <summary className="min-h-11 cursor-pointer px-3 py-2 font-mono text-xs text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">Event {index + 1}: {String(match.event_action ?? match.event_category ?? match.id ?? 'decoded event')}</summary>
                  <pre className="max-h-64 overflow-auto border-t border-border px-3 py-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap">{JSON.stringify(match, null, 2)}</pre>
                </details>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
