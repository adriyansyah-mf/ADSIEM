import { useState } from 'react'
import DataTable from '@/components/DataTable'
import { useLogs } from '@/hooks/useLogs'
import { format } from 'date-fns'
import type { RawLog } from '@/types'

export default function LogsPage() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const { data, isLoading } = useLogs(page, 25, search || undefined)

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
          page={page} pageSize={25} onPageChange={setPage}
          onSearch={(q) => { setSearch(q); setPage(1) }} searchPlaceholder="Search logs..." />
      )}
    </div>
  )
}
