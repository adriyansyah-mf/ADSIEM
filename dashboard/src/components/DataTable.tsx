import { useState } from 'react'

interface Column<T> {
  key: string
  header: string
  render: (row: T) => React.ReactNode
  sortable?: boolean
}

interface Props<T> {
  columns: Column<T>[]
  data: T[]
  total: number
  page: number
  pageSize: number
  onPageChange: (page: number) => void
  onSearch?: (q: string) => void
  searchPlaceholder?: string
  onRowClick?: (row: T) => void
}

export default function DataTable<T extends { id: string }>({
  columns, data, total, page, pageSize,
  onPageChange, onSearch, searchPlaceholder = 'Search...', onRowClick,
}: Props<T>) {
  const [search, setSearch] = useState('')
  const totalPages = Math.ceil(total / pageSize)

  const handleSearch = (v: string) => {
    setSearch(v)
    onSearch?.(v)
  }

  return (
    <div className="space-y-3">
      {onSearch && (
        <input
          value={search}
          onChange={(e) => handleSearch(e.target.value)}
          placeholder={searchPlaceholder}
          className="w-full px-3 py-2 rounded border border-border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary"
        />
      )}
      <div className="rounded border border-border overflow-auto">
        <table className="w-full text-sm">
          <thead className="bg-muted text-muted-foreground">
            <tr>
              {columns.map((col) => (
                <th key={col.key} className="px-4 py-2 text-left font-medium whitespace-nowrap">
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.length === 0 ? (
              <tr><td colSpan={columns.length} className="text-center py-8 text-muted-foreground">No data</td></tr>
            ) : data.map((row) => (
              <tr
                key={row.id}
                onClick={() => onRowClick?.(row)}
                className={`border-t border-border hover:bg-muted/50 transition-colors ${onRowClick ? 'cursor-pointer' : ''}`}
              >
                {columns.map((col) => (
                  <td key={col.key} className="px-4 py-2">{col.render(row)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span>{total} total</span>
        <div className="flex gap-2">
          <button disabled={page <= 1} onClick={() => onPageChange(page - 1)}
            className="px-3 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted">Prev</button>
          <span className="px-2 py-1">{page} / {totalPages || 1}</span>
          <button disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}
            className="px-3 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted">Next</button>
        </div>
      </div>
    </div>
  )
}
