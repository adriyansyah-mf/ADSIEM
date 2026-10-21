import { useState } from 'react'
import { format } from 'date-fns'
import { RefreshCw, Search } from 'lucide-react'
import DataTable, { type Column } from '@/components/DataTable'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import { PageHeader, Panel, QueryState } from '@/components/Workspace'
import { HuntDetails } from '@/components/HuntDetails'
import { HuntSchedules, IOC_TYPES } from '@/components/HuntSchedules'
import { useHunts, useStartHunt } from '@/hooks/useHunts'
import { huntError } from '@/hooks/useHuntSchedules'
import type { ThreatHunt } from '@/types'

export default function HuntsPage() {
  const query = useHunts()
  const start = useStartHunt()
  const [iocType, setIocType] = useState('ip')
  const [iocValue, setIocValue] = useState('')
  const [validation, setValidation] = useState('')
  const [message, setMessage] = useState('')
  const [selected, setSelected] = useState<ThreatHunt | null>(null)
  const columns: readonly Column<ThreatHunt>[] = [
    { key: 'ioc_value', header: 'Indicator', render: row => <div className="table-primary font-mono text-xs">{row.ioc_value}<div className="table-secondary">{row.ioc_type.toUpperCase()}</div></div> },
    { key: 'status', header: 'Status', render: row => <StatusBadge status={row.status} /> },
    { key: 'risk_level', header: 'Risk', render: row => <SeverityBadge severity={row.risk_level ?? 'unknown'} /> },
    { key: 'alert_count', header: 'Evidence', render: row => row.status === 'pending' || row.status === 'running' ? <span className="text-muted-foreground">Collecting…</span>
      : <span className="whitespace-nowrap tabular-nums">{row.alert_count} alerts · {row.event_count} events · {row.fim_count} FIM</span>,
      exportValue: row => `${row.alert_count} alerts · ${row.event_count} events · ${row.fim_count} FIM` },
    { key: 'created_at', header: 'Created', render: row => <time className="whitespace-nowrap" dateTime={row.created_at}>{format(new Date(row.created_at), 'dd MMM, HH:mm')}</time> },
    { key: 'group_id', header: 'Group', hiddenByDefault: true, render: row => row.group_id },
  ]
  return <div className="workspace">
    <PageHeader eyebrow="Investigation workspace" title="Threat hunting" description="Trace an indicator across endpoint history and review its evidence-backed assessment."
      actions={<button className="ui-button" disabled={query.isFetching} onClick={() => { void query.refetch() }}><RefreshCw size={14} /> Refresh history</button>} />
    <Panel title="New hunt" description="Investigate an IP address, hostname, username, or SHA256 hash.">
      <form onSubmit={event => {
        event.preventDefault()
        if (start.isPending) return
        const value = iocValue.trim()
        if (!value) { setValidation('Enter an indicator value.'); return }
        setValidation(''); setMessage('')
        start.mutate({ ioc_type: iocType, ioc_value: value }, {
          onSuccess: () => { setIocValue(''); setMessage('Hunt queued. Progress appears in recent hunts below.') },
        })
      }}>
        <fieldset className="hunt-search" disabled={start.isPending}>
          <label className="field"><span>Indicator type</span><select className="ui-input" value={iocType} onChange={event => setIocType(event.target.value)}>{IOC_TYPES.map(type => <option key={type.value} value={type.value}>{type.label}</option>)}</select></label>
          <label className="field"><span>Indicator value</span><input className="ui-input font-mono" required value={iocValue} onChange={event => setIocValue(event.target.value)}
            placeholder={iocType === 'ip' ? '192.0.2.42' : iocType === 'hostname' ? 'finance-server' : iocType === 'user' ? 'alex.morgan' : 'SHA256 hash'} aria-describedby="hunt-help" /></label>
          <button className="ui-button ui-button--primary" type="submit" disabled={start.isPending}><Search size={14} />{start.isPending ? 'Starting…' : 'Start hunt'}</button>
        </fieldset>
        <p id="hunt-help" className="text-xs text-muted-foreground mt-3 mb-0">AI analyzes related alert and event history. Verify its assessment before taking response actions.</p>
        {(validation || start.isError) && <p role="alert" className="text-destructive mt-3 mb-0">{validation || huntError(start.error)}</p>}
        {message && <p role="status" className="text-sm mt-3 mb-0">{message}</p>}
      </form>
    </Panel>
    <HuntSchedules />
    <section className="space-y-4 min-w-0" aria-label="Hunt history">
      <header><h2 className="text-[15px] font-semibold mb-1">Recent hunts</h2><p className="panel__description">Latest 50 investigations · refreshes every 8 seconds · Open a row for analysis and the full timeline</p></header>
      {query.isPending ? <section className="panel"><QueryState kind="loading" title="Loading hunt history…" /></section>
        : query.isError ? <section className="panel"><QueryState kind="error" title="Could not load hunt history" description="Existing investigations are not changed. Try again when the connection is available." onRetry={() => { void query.refetch() }} /></section>
          : <DataTable columns={columns} data={query.data} total={query.data.length} page={1} pageSize={50} onPageChange={() => {}} showPagination={false}
            onRowClick={setSelected} exportFilename="hunts-recent.csv" emptyTitle="No hunts yet" emptyDescription="Enter an indicator above to start your first investigation." />}
    </section>
    {selected && <HuntDetails hunt={query.data?.find(hunt => hunt.id === selected.id) ?? selected} onClose={() => setSelected(null)} />}
  </div>
}
