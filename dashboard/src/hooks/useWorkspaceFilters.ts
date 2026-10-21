import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'

/** Keep list views shareable, including when navigating browser history. */
export function useWorkspaceFilters() {
  const [params, setParams] = useSearchParams()
  const search = params.get('search') ?? ''
  const [searchInput, setSearchInput] = useState(search)
  const update = useCallback((values: Readonly<Record<string, string>>) => {
    setParams(current => {
      const next = new URLSearchParams(current)
      for (const [key, value] of Object.entries(values)) {
        if (value) next.set(key, value)
        else next.delete(key)
      }
      return next
    })
  }, [setParams])
  useEffect(() => { setSearchInput(search) }, [search])
  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (searchInput.trim() !== search) update({ search: searchInput.trim() })
    }, 400)
    return () => window.clearTimeout(timer)
  }, [searchInput, search, update])
  const clear = () => { setSearchInput(''); setParams({}) }
  return { params, searchInput, setSearchInput, update, clear }
}
