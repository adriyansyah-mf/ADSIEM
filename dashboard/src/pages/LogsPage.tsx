import { useState, useEffect } from 'react'
import DataTable from '@/components/DataTable'
import { useLogs } from '@/hooks/useLogs'
import { useCursorPagination } from '@/hooks/useCursorPagination'
import { format } from 'date-fns'
import type { RawLog } from '@/types'

export default function LogsPage() {
  const [search, setSearch] = useState('')
  const { page, pageSize, after, goToPage, onPageData, reset, changePageSize } = useCursorPagination(25)
  const { data, isLoading } = useLogs(pageSize, after, search || undefined)

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
      <h1 className="text-xl font-bold mb-6">Raw Logs</h1>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={pageSize} onPageChange={goToPage}
          onPageSizeChange={changePageSize}
          onSearch={(q) => { setSearch(q); reset() }} searchPlaceholder="Search logs..." />
      )}
    </div>
  )
}
