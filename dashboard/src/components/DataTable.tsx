import { useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { ChevronDown, ChevronRight, ChevronsUpDown, ChevronUp, Download } from 'lucide-react'

export interface Column<T> {
  readonly key: string
  readonly header: string
  readonly render: (row: T) => ReactNode
  readonly sortable?: boolean
  readonly hiddenByDefault?: boolean
  readonly exportValue?: (row: T) => string | number
}

interface Props<T> {
  readonly columns: readonly Column<T>[]
  readonly data: readonly T[]
  readonly total: number
  readonly page: number
  readonly pageSize: number
  readonly onPageChange: (page: number) => void
  readonly onPageSizeChange?: (size: number) => void
  readonly onSearch?: (query: string) => void
  readonly initialSearch?: string
  readonly onSort?: (key: string, direction: 'asc' | 'desc') => void
  readonly onDateRange?: (from: string, to: string) => void
  readonly searchPlaceholder?: string
  readonly onRowClick?: (row: T) => void
  readonly rowKey?: (row: T) => string
  readonly expandable?: boolean
  readonly renderExpanded?: (row: T) => ReactNode
  readonly exportFilename?: string
  readonly toolbarExtra?: ReactNode
  readonly emptyTitle?: string
  readonly emptyDescription?: string
  readonly showToolbar?: boolean
  readonly showPagination?: boolean
}

type Density = 'compact' | 'normal' | 'comfortable'
const PADDING: Readonly<Record<Density, string>> = {
  compact: 'px-4 py-2', normal: 'px-4 py-3', comfortable: 'px-4 py-4',
}
const DENSITIES: readonly Density[] = ['compact', 'normal', 'comfortable']

export default function DataTable<T extends { id: string }>({
  columns, data, total, page, pageSize, onPageChange, onPageSizeChange, onSearch,
  initialSearch = '', onSort, onDateRange, searchPlaceholder = 'Search…',
  onRowClick, rowKey, expandable = false, renderExpanded,
  exportFilename = 'export.csv', toolbarExtra,
  emptyTitle = 'No records to display', emptyDescription = 'Records will appear here when available. Try adjusting your filters.',
  showToolbar = true, showPagination = true,
}: Props<T>) {
  const [search, setSearch] = useState(initialSearch)
  const [sort, setSort] = useState<{ key: string; direction: 'asc' | 'desc' }>()
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set())
  const [density, setDensity] = useState<Density>('normal')
  const [hidden, setHidden] = useState<ReadonlySet<string>>(() => new Set(columns.filter(column => column.hiddenByDefault).map(column => column.key)))
  const columnMenu = useRef<HTMLDetailsElement>(null)
  const visible = useMemo(() => columns.filter(column => !hidden.has(column.key)), [columns, hidden])
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const padding = PADDING[density]
  const toggleColumn = (key: string) => setHidden(current => {
    const next = new Set(current)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    return next
  })
  const toggleRow = (id: string) => setExpanded(current => {
    const next = new Set(current)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    return next
  })
  const exportPage = () => {
    const escape = (value: unknown) => '"' + String(value ?? '').replace(/"/g, '""') + '"'
    const exported = visible.filter(column => column.header)
    const csv = [
      exported.map(column => escape(column.header)).join(','),
      ...data.map(row => exported.map(column => escape(column.exportValue ? column.exportValue(row) : Reflect.get(row, column.key))).join(',')),
    ].join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }))
    const link = document.createElement('a')
    link.href = url
    link.download = exportFilename
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-3">
      {showToolbar && <div className="control-cluster">
        {onSearch && <label className="field flex-1">
          <span>Search records</span>
          <input value={search} onChange={event => { setSearch(event.target.value); onSearch(event.target.value) }}
            placeholder={searchPlaceholder} className="ui-input" />
        </label>}
        {onDateRange && <div className="control-cluster">
          <label className="field"><span>From date</span><input type="date" value={from} className="ui-input"
            onChange={event => { setFrom(event.target.value); onDateRange(event.target.value, to); onPageChange(1) }} /></label>
          <label className="field"><span>To date</span><input type="date" value={to} className="ui-input"
            onChange={event => { setTo(event.target.value); onDateRange(from, event.target.value); onPageChange(1) }} /></label>
        </div>}
        {toolbarExtra}
        <div className="control-cluster ml-auto">
          <select aria-label="Row density" className="ui-input w-auto" value={density}
            onChange={event => { const value = DENSITIES.find(item => item === event.target.value); if (value) setDensity(value) }}>
            {DENSITIES.map(value => <option key={value} value={value}>{value.charAt(0).toUpperCase() + value.slice(1)} rows</option>)}
          </select>
          <details className="relative" ref={columnMenu}
            onKeyDown={event => { if (event.key === 'Escape' && columnMenu.current) { columnMenu.current.open = false; columnMenu.current.querySelector('summary')?.focus() } }}>
            <summary className="ui-button">Columns <ChevronDown size={14} aria-hidden="true" /></summary>
            <div className="table-column-menu">
              {columns.filter(column => column.header).map(column => (
                <label key={column.key} className="control-cluster">
                  <input type="checkbox" checked={!hidden.has(column.key)}
                    disabled={!hidden.has(column.key) && visible.filter(item => item.header).length === 1}
                    onChange={() => toggleColumn(column.key)} />
                  {column.header}
                </label>
              ))}
            </div>
          </details>
          <button onClick={exportPage} disabled={data.length === 0} className="ui-button" title="Export the rows on this page">
            <Download size={14} aria-hidden="true" /> Export page
          </button>
        </div>
      </div>}
      <div className="table-scroll" role="region" aria-label="Results table" tabIndex={0}>
        <table className="data-table">
          <thead><tr>
            {expandable && <th className="w-10"><span className="sr-only">Expand</span></th>}
            {visible.map(column => <th key={column.key} scope="col" className={padding}
              aria-sort={column.sortable && onSort ? sort?.key === column.key ? sort.direction === 'asc' ? 'ascending' : 'descending' : 'none' : undefined}>
              {column.sortable && onSort ? <button className="control-cluster" onClick={() => {
                const direction = sort?.key === column.key && sort.direction === 'asc' ? 'desc' : 'asc'
                setSort({ key: column.key, direction }); onSort(column.key, direction)
              }}>
                {column.header}
                {sort?.key !== column.key ? <ChevronsUpDown size={12} /> : sort.direction === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              </button> : column.header}
            </th>)}
          </tr></thead>
          <tbody>
            {data.length === 0 ? <tr><td colSpan={visible.length + (expandable ? 1 : 0)}>
              <div className="query-state"><h3>{emptyTitle}</h3><p>{emptyDescription}</p></div>
            </td></tr> : data.map(row => {
              const key = rowKey ? rowKey(row) : row.id
              const open = expanded.has(key)
              return <RowGroup key={key} row={row} open={open} visible={visible} padding={padding}
                expandable={expandable} onToggle={() => toggleRow(key)} onRowClick={onRowClick} renderExpanded={renderExpanded} />
            })}
          </tbody>
        </table>
      </div>
      {showPagination && <div className="table-pagination">
        <span className="tabular-nums">{total === 0 ? '0 results' : `${((page - 1) * pageSize + 1).toLocaleString()}–${Math.min(page * pageSize, total).toLocaleString()} of ${total.toLocaleString()} results`}</span>
        <div className="control-cluster">
          {onPageSizeChange && <select aria-label="Results per page" value={pageSize} className="ui-input w-auto"
            onChange={event => { onPageSizeChange(Number(event.target.value)); onPageChange(1) }}>
            {[25, 50, 100].map(size => <option key={size} value={size}>{size} / page</option>)}
          </select>}
          <button disabled={page <= 1} onClick={() => onPageChange(page - 1)} className="ui-button">Previous</button>
          <span className="tabular-nums">{page} / {pages}</span>
          <button disabled={page >= pages} onClick={() => onPageChange(page + 1)} className="ui-button">Next</button>
        </div>
      </div>}
    </div>
  )
}

function RowGroup<T>({ row, open, expandable, onToggle, onRowClick, renderExpanded, visible, padding }: {
  readonly row: T
  readonly open: boolean
  readonly expandable: boolean
  readonly onToggle: () => void
  readonly onRowClick?: (row: T) => void
  readonly renderExpanded?: (row: T) => ReactNode
  readonly visible: readonly Column<T>[]
  readonly padding: string
}) {
  return <>
    <tr onClick={() => onRowClick?.(row)} tabIndex={onRowClick ? 0 : undefined}
      onKeyDown={event => {
        if (onRowClick && event.target === event.currentTarget && event.key === 'Enter') {
          event.preventDefault()
          onRowClick(row)
        }
      }} className={onRowClick ? 'cursor-pointer' : undefined}>
      {expandable && <td className="w-10 px-1">
        <button className="ui-icon-button" onClick={event => { event.stopPropagation(); onToggle() }}
          aria-expanded={open} aria-label={open ? 'Collapse record' : 'Expand record'}>
          <ChevronRight size={14} className={open ? 'rotate-90' : undefined} />
        </button>
      </td>}
      {visible.map(column => <td key={column.key} className={padding}>{column.render(row)}</td>)}
    </tr>
    {expandable && open && <tr><td colSpan={visible.length + 1} className="p-5">{renderExpanded?.(row)}</td></tr>}
  </>
}
