import { useMemo, useState } from 'react'
import { Radio, Trash2, Pause, Play } from 'lucide-react'
import DataTable from '@/components/DataTable'
import { useLiveEvents, type LiveEvent } from '@/hooks/useLiveEvents'

export default function LiveEventsTable({ height }: { height?: number }) {
  const [streaming, setStreaming] = useState(true)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [query, setQuery] = useState('')
  const { events, status, received, clear } = useLiveEvents(streaming, 500)

  const filtered = useMemo(() => {
    if (!query.trim()) return events
    const q = query.toLowerCase()
    return events.filter(e =>
      [e.log_type, e.event_action, e.event_category, e.source_ip, e.user_name]
        .some(v => (v ?? '').toLowerCase().includes(q)) ||
      JSON.stringify(e.fields).toLowerCase().includes(q)
    )
  }, [events, query])

  const pageRows = useMemo(() => {
    const start = (page - 1) * pageSize
    return filtered.slice(start, start + pageSize)
  }, [filtered, page, pageSize])

  const statusColor =
    status === 'open' ? 'var(--accent-green)'
      : status === 'connecting' ? 'var(--accent-yellow)'
        : status === 'error' ? 'var(--accent-red)'
          : 'var(--text-muted)'

  const columns = [
    {
      key: 'created_at',
      header: 'Time',
      sortable: false,
      exportValue: (r: LiveEvent) => r.created_at,
      render: (r: LiveEvent) => (
        <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 11, color: 'var(--text-secondary)' }}>
          {new Date(r.created_at).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: 'log_type',
      header: 'Source',
      exportValue: (r: LiveEvent) => r.log_type ?? '',
      render: (r: LiveEvent) => (
        <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 11, color: 'var(--accent-cyan)' }}>
          {r.log_type ?? '—'}
        </span>
      ),
    },
    {
      key: 'event_action',
      header: 'Action',
      exportValue: (r: LiveEvent) => r.event_action ?? '',
      render: (r: LiveEvent) => (
        <span style={{ fontSize: 12, color: 'var(--text-primary)' }}>{r.event_action ?? '—'}</span>
      ),
    },
    {
      key: 'event_category',
      header: 'Category',
      exportValue: (r: LiveEvent) => r.event_category ?? '',
      render: (r: LiveEvent) => (
        <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{r.event_category ?? '—'}</span>
      ),
    },
    {
      key: 'source_ip',
      header: 'Source IP',
      exportValue: (r: LiveEvent) => r.source_ip ?? '',
      render: (r: LiveEvent) => (
        <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 11, color: 'var(--accent-orange)' }}>
          {r.source_ip ?? '—'}
        </span>
      ),
    },
    {
      key: 'user_name',
      header: 'User',
      hiddenByDefault: true,
      exportValue: (r: LiveEvent) => r.user_name ?? '',
      render: (r: LiveEvent) => (
        <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{r.user_name ?? '—'}</span>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, fontSize: 11 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: statusColor, fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          <Radio size={12} />
          {status}
        </span>
        <span style={{ color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace' }}>
          {received} received · {filtered.length} shown
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
          <button
            onClick={() => setStreaming(s => !s)}
            style={{
              display: 'flex', alignItems: 'center', gap: 4, padding: '3px 8px', fontSize: 11,
              borderRadius: 3, border: '1px solid var(--border)', background: 'transparent',
              color: streaming ? 'var(--accent-green)' : 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            {streaming ? <Pause size={11} /> : <Play size={11} />}
            {streaming ? 'Pause' : 'Resume'}
          </button>
          <button
            onClick={() => { clear(); setPage(1) }}
            style={{
              display: 'flex', alignItems: 'center', gap: 4, padding: '3px 8px', fontSize: 11,
              borderRadius: 3, border: '1px solid var(--border)', background: 'transparent',
              color: 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            <Trash2 size={11} />
            Clear
          </button>
        </div>
      </div>

      <DataTable<LiveEvent>
        columns={columns}
        data={pageRows}
        total={filtered.length}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        onSearch={q => { setQuery(q); setPage(1) }}
        searchPlaceholder="Filter events (source, action, ip, user, fields)…"
        expandable
        renderExpanded={row => (
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, fontFamily: 'Rajdhani, sans-serif', letterSpacing: '0.5px' }}>
              DECODED FIELDS
            </div>
            <pre
              style={{
                margin: 0, padding: 10, borderRadius: 4, background: 'var(--bg-panel)',
                border: '1px solid var(--border)', fontSize: 10, maxHeight: height ?? 240,
                overflow: 'auto', fontFamily: 'Share Tech Mono, monospace',
                color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              }}
            >
              {JSON.stringify(row.fields, null, 2)}
            </pre>
          </div>
        )}
        exportFilename="live-events.csv"
      />
    </div>
  )
}
