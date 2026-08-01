import { useState, useEffect } from 'react'
import { SlidersHorizontal } from 'lucide-react'
import DataTable from '@/components/DataTable'
import QueryBuilder, { EMPTY_GROUP, isEmptyTree, type Group } from '@/components/QueryBuilder'
import { useEvents } from '@/hooks/useEvents'
import { useCursorPagination } from '@/hooks/useCursorPagination'
import { format } from 'date-fns'
import type { Event } from '@/types'

const FIELDS = ['event_category', 'event_action', 'source_ip', 'user_name', 'group_id', 'created_at', 'decoded_fields.source.ip', 'decoded_fields.user.name']

export default function EventsPage() {
  const [search, setSearch] = useState('')
  const [showBuilder, setShowBuilder] = useState(false)
  const [builderTree, setBuilderTree] = useState<Group>(EMPTY_GROUP)
  const [appliedTree, setAppliedTree] = useState<Group>(EMPTY_GROUP)
  const { page, pageSize, after, goToPage, onPageData, reset, changePageSize } = useCursorPagination(25)
  const filterTree = isEmptyTree(appliedTree) ? undefined : JSON.stringify(appliedTree)
  const { data, isLoading } = useEvents(pageSize, after, search || undefined, filterTree)

  useEffect(() => { onPageData(data?.next_after) }, [data?.next_after, onPageData])

  const columns = [
    { key: 'time', header: 'Time', render: (r: Event) => format(new Date(r.created_at), 'yyyy-MM-dd HH:mm:ss') },
    { key: 'category', header: 'Category', render: (r: Event) => r.event_category ?? '—' },
    { key: 'action', header: 'Action', render: (r: Event) => <span className="font-mono text-xs">{r.event_action ?? '—'}</span> },
    { key: 'source_ip', header: 'Source IP', render: (r: Event) => r.source_ip ?? '—' },
    { key: 'user', header: 'User', render: (r: Event) => r.user_name ?? '—' },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Events</h1>
        <button
          onClick={() => setShowBuilder((x) => !x)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded border text-xs font-medium transition-colors ${
            showBuilder ? 'bg-primary text-primary-foreground border-primary' : 'border-border hover:bg-muted'
          }`}
        >
          <SlidersHorizontal size={13} /> Advanced Filters
        </button>
      </div>

      {showBuilder && (
        <div className="mb-4 rounded-lg border border-border bg-card p-4 space-y-3">
          <QueryBuilder node={builderTree} onChange={setBuilderTree} fields={FIELDS} />
          <div className="flex gap-2">
            <button
              onClick={() => { setAppliedTree(builderTree); reset() }}
              className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-xs font-medium"
            >
              Apply
            </button>
            <button
              onClick={() => { setBuilderTree(EMPTY_GROUP); setAppliedTree(EMPTY_GROUP); reset() }}
              className="px-3 py-1.5 rounded border border-border text-xs font-medium hover:bg-muted"
            >
              Clear
            </button>
          </div>
        </div>
      )}

      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={pageSize} onPageChange={goToPage}
          onPageSizeChange={changePageSize}
          onSearch={(q) => { setSearch(q); reset() }}
          searchPlaceholder='Lucene syntax: event_action:login_failed AND user_name:root' />
      )}
    </div>
  )
}
