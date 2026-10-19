import { useMemo, useState } from 'react'
import { ChevronUp, ChevronDown, ChevronsUpDown, ChevronRight, Download, Columns3, Rows3, Rows4 } from 'lucide-react'

interface Column<T> {
  key: string
  header: string
  render: (row: T) => React.ReactNode
  sortable?: boolean
  hiddenByDefault?: boolean
  exportValue?: (row: T) => string | number
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
  initialSearch?: string
  onSort?: (key: string, dir: 'asc' | 'desc') => void
  onDateRange?: (from: string, to: string) => void
  searchPlaceholder?: string
  onRowClick?: (row: T) => void
  rowKey?: (row: T) => string
  expandable?: boolean
  renderExpanded?: (row: T) => React.ReactNode
  exportFilename?: string
  toolbarExtra?: React.ReactNode
}

const PAGE_SIZES = [25, 50, 100]
type Density = 'compact' | 'normal' | 'comfortable'

const DENSITY_PAD: Record<Density, string> = {
  compact: 'px-3 py-1',
  normal: 'px-4 py-2',
  comfortable: 'px-4 py-3',
}

function toCsv<T>(columns: Column<T>[], rows: T[]): string {
  const esc = (v: unknown) => {
    const s = String(v ?? '')
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const header = columns.map(c => esc(c.header)).join(',')
  const body = rows.map(r =>
    columns.map(c => esc(c.exportValue ? c.exportValue(r) : '')).join(',')
  )
  return [header, ...body].join('\n')
}

export default function DataTable<T extends { id: string }>({
  columns, data, total, page, pageSize,
  onPageChange, onPageSizeChange, onSearch, initialSearch = '', onSort, onDateRange,
  searchPlaceholder = 'Search...', onRowClick, rowKey,
  expandable = false, renderExpanded,
  exportFilename = 'export.csv', toolbarExtra,
}: Props<T>) {
  const [search, setSearch] = useState(initialSearch)
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [density, setDensity] = useState<Density>('normal')
  const [hidden, setHidden] = useState<Set<string>>(
    () => new Set(columns.filter(c => c.hiddenByDefault).map(c => c.key))
  )
  const [colsOpen, setColsOpen] = useState(false)

  const visible = useMemo(() => columns.filter(c => !hidden.has(c.key)), [columns, hidden])
  const totalPages = Math.ceil(total / pageSize)
  const keyOf = (row: T) => (rowKey ? rowKey(row) : row.id)

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
    onPageChange(1)
  }

  const toggleRow = (row: T) => {
    const k = keyOf(row)
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(k)) next.delete(k)
      else next.add(k)
      return next
    })
  }

  const toggleColumn = (key: string) => {
    setHidden(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const handleExport = () => {
    const csv = toCsv(visible, data)
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = exportFilename
    a.click()
    URL.revokeObjectURL(url)
  }

  const SortIcon = ({ col }: { col: Column<T> }) => {
    if (!col.sortable) return null
    if (sortKey !== col.key) return <ChevronsUpDown size={12} className="ml-1 opacity-40 inline" />
    return sortDir === 'asc'
      ? <ChevronUp size={12} className="ml-1 inline" />
      : <ChevronDown size={12} className="ml-1 inline" />
  }

  const pad = DENSITY_PAD[density]

  return (
    <div className="space-y-3">
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

        {toolbarExtra}

        <div className="ml-auto flex items-center gap-1">
          <button
            onClick={() => setDensity(d => d === 'compact' ? 'normal' : d === 'normal' ? 'comfortable' : 'compact')}
            title={`Row density: ${density}`}
            className="p-2 rounded border border-border hover:bg-muted text-muted-foreground"
          >
            {density === 'compact' ? <Rows4 size={14} /> : density === 'normal' ? <Rows3 size={14} /> : <Rows3 size={16} />}
          </button>

          <div className="relative">
            <button
              onClick={() => setColsOpen(o => !o)}
              title="Show/hide columns"
              className="p-2 rounded border border-border hover:bg-muted text-muted-foreground"
            >
              <Columns3 size={14} />
            </button>
            {colsOpen && (
              <div className="absolute right-0 mt-1 z-20 min-w-[160px] rounded border border-border bg-card shadow-lg p-2 space-y-1">
                {columns.map(c => (
                  <label key={c.key} className="flex items-center gap-2 px-1 py-0.5 text-xs cursor-pointer hover:bg-muted rounded">
                    <input
                      type="checkbox"
                      checked={!hidden.has(c.key)}
                      onChange={() => toggleColumn(c.key)}
                    />
                    {c.header}
                  </label>
                ))}
              </div>
            )}
          </div>

          <button
            onClick={handleExport}
            disabled={data.length === 0}
            title="Export current page to CSV"
            className="p-2 rounded border border-border hover:bg-muted text-muted-foreground disabled:opacity-40"
          >
            <Download size={14} />
          </button>
        </div>
      </div>

      <div className="rounded border border-border bg-card overflow-auto shadow-[0_0_0_1px_hsl(var(--primary)/0.06)] max-h-[70vh]">
        <table className="w-full text-sm">
          <thead className="bg-muted text-muted-foreground sticky top-0 z-10">
            <tr>
              {expandable && <th className="w-8" />}
              {visible.map((col) => (
                <th
                  key={col.key}
                  onClick={() => handleSort(col)}
                  className={`${pad} text-left font-semibold uppercase tracking-wider text-[11px] whitespace-nowrap select-none
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
                <td colSpan={visible.length + (expandable ? 1 : 0)} className="text-center py-8 text-muted-foreground">
                  No data
                </td>
              </tr>
            ) : data.map((row) => {
              const k = keyOf(row)
              const isOpen = expanded.has(k)
              return (
                <RowGroup
                  key={k}
                  row={row}
                  isOpen={isOpen}
                  expandable={expandable}
                  renderExpanded={renderExpanded}
                  onToggle={() => toggleRow(row)}
                  onRowClick={onRowClick}
                  visible={visible}
                  pad={pad}
                />
              )
            })}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <div className="flex items-center gap-2 font-mono tabular-nums">
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

function RowGroup<T extends { id: string }>({
  row, isOpen, expandable, renderExpanded, onToggle, onRowClick, visible, pad,
}: {
  row: T
  isOpen: boolean
  expandable: boolean
  renderExpanded?: (row: T) => React.ReactNode
  onToggle: () => void
  onRowClick?: (row: T) => void
  visible: Column<T>[]
  pad: string
}) {
  return (
    <>
      <tr
        onClick={() => onRowClick?.(row)}
        className={`border-t border-border transition-colors ${onRowClick ? 'cursor-pointer hover:bg-white/[0.06] hover:border-l-2 hover:border-l-cyan-500/40' : 'hover:bg-white/[0.03]'}`}
      >
        {expandable && (
          <td className="w-8 px-1">
            <button
              onClick={(e) => { e.stopPropagation(); onToggle() }}
              className="p-1 rounded hover:bg-muted text-muted-foreground"
              title={isOpen ? 'Collapse' : 'Expand'}
            >
              <ChevronRight size={13} className={isOpen ? 'rotate-90 transition-transform' : 'transition-transform'} />
            </button>
          </td>
        )}
        {visible.map((col) => (
          <td key={col.key} className={pad}>{col.render(row)}</td>
        ))}
      </tr>
      {expandable && isOpen && (
        <tr className="bg-black/20">
          <td colSpan={visible.length + 1} className="px-6 py-3">
            {renderExpanded ? renderExpanded(row) : null}
          </td>
        </tr>
      )}
    </>
  )
}
