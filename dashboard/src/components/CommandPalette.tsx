import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Bell, CornerDownLeft, FileText, FolderOpen, Search } from 'lucide-react'
import { api } from '@/api/client'
import { ALL_SECTIONS, useVisiblePages } from '@/components/AppSidebar'
import type { Alert, Case } from '@/types'

interface SearchResults {
  readonly alerts: readonly Pick<Alert, 'id' | 'title'>[]
  readonly cases: readonly Pick<Case, 'id' | 'title'>[]
}

interface Entry {
  readonly key: string
  readonly kind: 'page' | 'alert' | 'case'
  readonly label: string
  readonly hint: string
  readonly to: string
}

export interface CommandPaletteHandle { open: () => void }

const KIND_ICON = { page: FileText, alert: Bell, case: FolderOpen } as const

/** Ctrl/⌘ K: jump to any page (including ones that are tabs, not sidebar entries), alert or case. */
const CommandPalette = forwardRef<CommandPaletteHandle>(function CommandPalette(_, ref) {
  const dialog = useRef<HTMLDialogElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  const visible = useVisiblePages()
  const [text, setText] = useState('')
  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState(0)

  useImperativeHandle(ref, () => ({
    open: () => {
      if (!dialog.current?.open) dialog.current?.showModal()
      window.setTimeout(() => input.current?.select(), 0)
    },
  }))

  useEffect(() => {
    const timer = window.setTimeout(() => setQuery(text.trim()), 200)
    return () => window.clearTimeout(timer)
  }, [text])
  useEffect(() => setCursor(0), [query])

  const results = useQuery<SearchResults>({
    queryKey: ['global-search', query],
    queryFn: () => api.get('/api/search', { params: { q: query, limit: 5 } }).then(response => response.data),
    enabled: query.length >= 2,
  })

  const entries = useMemo<Entry[]>(() => {
    const needle = text.trim().toLowerCase()
    const pages: Entry[] = ALL_SECTIONS.flatMap(section => visible(section).map(page => ({
      key: `page:${page.to}`, kind: 'page' as const, label: page.label,
      hint: page.label === section.label ? 'Page' : section.label, to: page.to,
    })))
      .filter(entry => !needle || entry.label.toLowerCase().includes(needle) || entry.hint.toLowerCase().includes(needle))
      .slice(0, needle ? 8 : 6)
    const found = query.length >= 2 && results.data ? [
      ...results.data.alerts.map(item => ({ key: `alert:${item.id}`, kind: 'alert' as const, label: item.title, hint: 'Alert', to: `/alerts/${item.id}` })),
      ...results.data.cases.map(item => ({ key: `case:${item.id}`, kind: 'case' as const, label: item.title, hint: 'Case', to: `/cases/${item.id}` })),
    ] : []
    return [...pages, ...found]
  }, [text, query, results.data, visible])

  const go = (entry: Entry | undefined) => {
    if (!entry) return
    dialog.current?.close()
    setText('')
    navigate(entry.to)
  }

  return (
    <dialog ref={dialog} className="command-palette" aria-label="Search or jump to"
      onClick={event => { if (event.target === dialog.current) dialog.current?.close() }}>
      <div className="command-palette__field">
        <Search size={16} aria-hidden="true" />
        <input ref={input} value={text} onChange={event => setText(event.target.value)}
          placeholder="Search pages, alerts and cases…" aria-label="Search pages, alerts and cases"
          aria-controls="command-palette-results" aria-activedescendant={entries[cursor] ? `cp-${cursor}` : undefined}
          onKeyDown={event => {
            if (event.key === 'ArrowDown') { event.preventDefault(); setCursor(value => Math.min(value + 1, entries.length - 1)) }
            if (event.key === 'ArrowUp') { event.preventDefault(); setCursor(value => Math.max(value - 1, 0)) }
            if (event.key === 'Enter') { event.preventDefault(); go(entries[cursor]) }
          }} />
        <kbd>Esc</kbd>
      </div>
      <ul className="command-palette__results" id="command-palette-results" role="listbox" aria-label="Results">
        {entries.map((entry, index) => {
          const Icon = KIND_ICON[entry.kind]
          return (
            <li key={entry.key} id={`cp-${index}`} role="option" aria-selected={index === cursor}>
              <button type="button" className={index === cursor ? 'is-active' : ''}
                onMouseEnter={() => setCursor(index)} onClick={() => go(entry)}>
                <Icon size={15} aria-hidden="true" />
                <span className="command-palette__label">{entry.label}</span>
                <span className="command-palette__hint">{entry.hint}</span>
                {index === cursor && <CornerDownLeft size={13} aria-hidden="true" />}
              </button>
            </li>
          )
        })}
      </ul>
      {query.length >= 2 && results.isPending && <p className="command-palette__status" role="status">Searching alerts and cases…</p>}
      {query.length >= 2 && results.isError && <p className="command-palette__status" role="alert">Alert and case search is unavailable. Pages still work.</p>}
      {entries.length === 0 && !(query.length >= 2 && results.isPending) &&<p className="command-palette__status">Nothing matches “{text.trim()}”.</p>}
    </dialog>
  )
})

export default CommandPalette
