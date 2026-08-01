import { useCallback, useRef, useState } from 'react'

/**
 * Sequential Prev/Next pagination backed by Elasticsearch search_after cursors
 * instead of page offsets — ES rejects from+size past 10,000 results, which
 * real log/event volume (millions of docs) reaches within a few hundred pages.
 * Cursors are only known one step ahead (from the previous page's response), so
 * this only supports stepping to an adjacent page, which is all DataTable's
 * Prev/Next buttons ever request.
 */
export function useCursorPagination(initialPageSize = 25) {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSizeState] = useState(initialPageSize)
  const cursors = useRef<Record<number, string | null>>({ 1: null })

  const after = cursors.current[page] ?? null

  const onPageData = useCallback((nextAfter: string | null | undefined) => {
    if (nextAfter) cursors.current[page + 1] = nextAfter
  }, [page])

  const goToPage = useCallback((p: number) => {
    if (Object.prototype.hasOwnProperty.call(cursors.current, p)) setPage(p)
  }, [])

  const reset = useCallback(() => {
    cursors.current = { 1: null }
    setPage(1)
  }, [])

  const changePageSize = useCallback((size: number) => {
    cursors.current = { 1: null }
    setPageSizeState(size)
    setPage(1)
  }, [])

  return { page, pageSize, after, goToPage, onPageData, reset, changePageSize }
}
