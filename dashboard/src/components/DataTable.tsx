import { useState } from 'react'
import { ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react'

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
  onPageSizeChange?: (size: number) => void
  onSearch?: (q: string) => void
  onSort?: (key: string, dir: 'asc' | 'desc') => void
  onDateRange?: (from: string, to: string) => void
  searchPlaceholder?: string
  onRowClick?: (row: T) => void
}

const PAGE_SIZES = [25, 50, 100]

export default function DataTable<T extends { id: string }>({
  columns, data, total, page, pageSize,
  onPageChange, onPageSizeChange, onSearch, onSort, onDateRange,
  searchPlaceholder = 'Search...', onRowClick,
}: Props<T>) {
  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')

  const totalPages = Math.ceil(total / pageSize)

  const handleSearch = (v: string) => {
    setSearch(v)
    onSearch?.(v)
  }

  const handleSort = (col: Column<T>) => {
    if (!col.sortable) return
    const newDir = sortKey === col.key && sortDir === 'asc' ? 'desc' : 'asc'
    setSortKey(col.key)
    setSortDir(newDir)
    onSort?.(col.key, newDir)
  }

  const handleDateRange = (from: string, to: string) => {
    setDateFrom(from)
    setDateTo(to)
    onDateRange?.(from, to)
  }

  const SortIcon = ({ col }: { col: Column<T> }) => {
    if (!col.sortable) return null
    if (sortKey !== col.key) return <ChevronsUpDown size={12} className="ml-1 opacity-40 inline" />
    return sortDir === 'asc'
      ? <ChevronUp size={12} className="ml-1 inline" />
      : <ChevronDown size={12} className="ml-1 inline" />
  }

  return (
    <div className="space-y-3">
      {/* Search + date range toolbar */}
      <div className="flex flex-wrap gap-2 items-center">
        {onSearch && (
          <input
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            placeholder={searchPlaceholder}
            className="flex-1 min-w-[180px] px-3 py-2 rounded border border-border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary"
          />
        )}
        {onDateRange && (
          <>
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => handleDateRange(e.target.value, dateTo)}
              className="px-3 py-2 rounded border border-border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <span className="text-muted-foreground text-sm">–</span>
            <input
              type="date"
              value={dateTo}
              onChange={(e) => handleDateRange(dateFrom, e.target.value)}
              className="px-3 py-2 rounded border border-border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </>
        )}
      </div>

      <div className="rounded border border-border overflow-auto">
        <table className="w-full text-sm">
          <thead className="bg-muted text-muted-foreground">
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  onClick={() => handleSort(col)}
                  className={`px-4 py-2 text-left font-medium whitespace-nowrap select-none
                    ${col.sortable ? 'cursor-pointer hover:text-foreground' : ''}`}
                >
                  {col.header}
                  <SortIcon col={col} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="text-center py-8 text-muted-foreground">
                  No data
                </td>
              </tr>
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

      {/* Pagination footer */}
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <div className="flex items-center gap-2">
          <span>{total} total</span>
          {onPageSizeChange && (
            <select
              value={pageSize}
              onChange={(e) => { onPageSizeChange(Number(e.target.value)); onPageChange(1) }}
              className="px-2 py-1 rounded border border-border bg-background text-sm focus:outline-none"
            >
              {PAGE_SIZES.map((s) => (
                <option key={s} value={s}>{s} / page</option>
              ))}
            </select>
          )}
        </div>
        <div className="flex gap-2">
          <button
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
            className="px-3 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted"
          >
            Prev
          </button>
          <span className="px-2 py-1">{page} / {totalPages || 1}</span>
          <button
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
            className="px-3 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  )
}
