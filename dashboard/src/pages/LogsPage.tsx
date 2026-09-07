import { useState, useEffect } from 'react'
import { SlidersHorizontal } from 'lucide-react'
import DataTable from '@/components/DataTable'
import { PageHeader } from '@/components/ui/PageHeader'
import QueryBuilder, { EMPTY_GROUP, isEmptyTree, type Group } from '@/components/QueryBuilder'
import { useLogs } from '@/hooks/useLogs'
import { useCursorPagination } from '@/hooks/useCursorPagination'
import { format } from 'date-fns'
import type { RawLog } from '@/types'

const FIELDS = ['log_type', 'raw_message', 'agent_id', 'created_at', 'decoded_fields.source.ip', 'decoded_fields.user.name']

export default function LogsPage() {
  const [search, setSearch] = useState('')
  const [showBuilder, setShowBuilder] = useState(false)
  const [builderTree, setBuilderTree] = useState<Group>(EMPTY_GROUP)
  const [appliedTree, setAppliedTree] = useState<Group>(EMPTY_GROUP)
  const { page, pageSize, after, goToPage, onPageData, reset, changePageSize } = useCursorPagination(25)
  const filterTree = isEmptyTree(appliedTree) ? undefined : JSON.stringify(appliedTree)
  const { data, isLoading } = useLogs(pageSize, after, search || undefined, filterTree)

  useEffect(() => { onPageData(data?.next_after) }, [data?.next_after, onPageData])

  const columns = [
    { key: 'time', header: 'Time', render: (r: RawLog) => format(new Date(r.received_at), 'yyyy-MM-dd HH:mm:ss') },
    { key: 'type', header: 'Type', render: (r: RawLog) => <span className="font-mono text-xs">{r.log_type}</span> },
    { key: 'message', header: 'Message', render: (r: RawLog) =>
      <span className="font-mono text-xs truncate max-w-xl block">{r.raw_message}</span>
    },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <PageHeader title="Raw Logs" className="!mb-0" />
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
        <div className="mb-4 enterprise-panel rounded-lg border border-border bg-card p-4 space-y-3">
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
          searchPlaceholder='Lucene syntax: log_type:linux_auth AND raw_message:"Failed password"' />
      )}
    </div>
  )
}
