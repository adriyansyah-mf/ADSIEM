import { useState } from 'react'
import DataTable from '@/components/DataTable'
import { useEvents } from '@/hooks/useEvents'
import { format } from 'date-fns'
import type { Event } from '@/types'

export default function EventsPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useEvents(page)

  const columns = [
    { key: 'time', header: 'Time', render: (r: Event) => format(new Date(r.created_at), 'yyyy-MM-dd HH:mm:ss') },
    { key: 'category', header: 'Category', render: (r: Event) => r.event_category ?? '—' },
    { key: 'action', header: 'Action', render: (r: Event) => <span className="font-mono text-xs">{r.event_action ?? '—'}</span> },
    { key: 'source_ip', header: 'Source IP', render: (r: Event) => r.source_ip ?? '—' },
    { key: 'user', header: 'User', render: (r: Event) => r.user_name ?? '—' },
  ]

  return (
    <div>
      <h1 className="text-xl font-bold mb-6">Events</h1>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} />
      )}
    </div>
  )
}
