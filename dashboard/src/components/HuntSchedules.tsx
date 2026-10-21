import { useRef, useState } from 'react'
import { Pause, Play, Plus, Trash2 } from 'lucide-react'
import { format } from 'date-fns'
import DataTable, { type Column } from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { Panel, QueryState } from '@/components/Workspace'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { huntError, useCreateHuntSchedule, useHuntScheduleAction, useHuntSchedules, type HuntSchedule } from '@/hooks/useHuntSchedules'

export const IOC_TYPES = [
  { value: 'ip', label: 'IP address' }, { value: 'hostname', label: 'Hostname' },
  { value: 'user', label: 'Username' }, { value: 'hash', label: 'File hash (SHA256)' },
] as const

export function HuntSchedules() {
  const query = useHuntSchedules()
  const toggle = useHuntScheduleAction('toggle')
  const [showForm, setShowForm] = useState(false)
  const [deleting, setDeleting] = useState<HuntSchedule | null>(null)
  const createButton = useRef<HTMLButtonElement>(null)
  const columns: readonly Column<HuntSchedule>[] = [
    { key: 'name', header: 'Schedule', render: row => <div className="table-primary">{row.name}</div> },
    { key: 'ioc_value', header: 'Indicator', render: row => <div className="font-mono text-xs break-all min-w-32">{row.ioc_value}<div className="table-secondary">{row.ioc_type.toUpperCase()}</div></div> },
    { key: 'is_enabled', header: 'Status', render: row => <StatusBadge status={row.is_enabled ? 'enabled' : 'paused'} /> },
    { key: 'interval_hours', header: 'Interval', render: row => <span className="whitespace-nowrap">Every {row.interval_hours}h</span> },
    { key: 'last_run_at', header: 'Last run', render: row => row.last_run_at ? <time className="whitespace-nowrap" dateTime={row.last_run_at}>{format(new Date(row.last_run_at), 'dd MMM, HH:mm')}</time> : 'Never' },
    { key: 'actions', header: 'Actions', render: row => <div className="control-cluster flex-nowrap">
      <button className="ui-icon-button" aria-label={`${row.is_enabled ? 'Pause' : 'Resume'} ${row.name}`} disabled={toggle.isPending} onClick={() => toggle.mutate(row.id)}>{row.is_enabled ? <Pause size={14} /> : <Play size={14} />}</button>
      <button className="ui-icon-button" aria-label={`Delete ${row.name}`} onClick={() => setDeleting(row)}><Trash2 size={14} /></button>
    </div> },
  ]
  return <Panel title="Scheduled hunts" description="Run recurring indicator investigations. Pausing keeps the schedule and its history."
    actions={<button ref={createButton} className="ui-button" aria-expanded={showForm} aria-controls="hunt-schedule-form" onClick={() => setShowForm(value => !value)}><Plus size={14} /> New schedule</button>}>
    {showForm && <ScheduleForm />}
    {toggle.isError && <p role="alert" className="text-destructive">{huntError(toggle.error)}</p>}
    {query.isPending ? <QueryState kind="loading" title="Loading schedules…" />
      : query.isError ? <QueryState kind="error" title="Could not load schedules" onRetry={() => { void query.refetch() }} />
        : query.data.length === 0 ? <QueryState kind="empty" title="No scheduled hunts" description="Create a schedule to investigate an indicator at a regular interval." />
          : <DataTable columns={columns} data={query.data} total={query.data.length} page={1} pageSize={query.data.length} onPageChange={() => {}} showToolbar={false} showPagination={false} />}
    {deleting && <DeleteSchedule schedule={deleting} onClose={() => setDeleting(null)} onDeleted={() => { setDeleting(null); createButton.current?.focus() }} />}
  </Panel>
}

function ScheduleForm() {
  const create = useCreateHuntSchedule()
  const [form, setForm] = useState({ name: '', ioc_type: 'ip', ioc_value: '', interval_hours: '24' })
  const [message, setMessage] = useState('')
  const [validation, setValidation] = useState('')
  return <form id="hunt-schedule-form" className="hunt-schedule-form mb-5" onSubmit={event => {
    event.preventDefault()
    if (create.isPending) return
    const name = form.name.trim(), value = form.ioc_value.trim(), interval = Number(form.interval_hours)
    if (!name || !value || !Number.isInteger(interval) || interval < 1 || interval > 168) { setValidation('Enter a name, indicator, and a whole interval from 1 to 168 hours.'); return }
    setValidation(''); setMessage('')
    create.mutate({ name, ioc_type: form.ioc_type, ioc_value: value, interval_hours: interval }, {
      onSuccess: () => { setForm({ name: '', ioc_type: 'ip', ioc_value: '', interval_hours: '24' }); setMessage('Schedule created.') },
    })
  }}>
    <fieldset className="hunt-form-grid" disabled={create.isPending}>
      <label className="field"><span>Schedule name</span><input className="ui-input" required value={form.name} onChange={event => setForm({ ...form, name: event.target.value })} /></label>
      <label className="field"><span>Scheduled indicator type</span><select className="ui-input" value={form.ioc_type} onChange={event => setForm({ ...form, ioc_type: event.target.value })}>{IOC_TYPES.map(type => <option key={type.value} value={type.value}>{type.label}</option>)}</select></label>
      <label className="field"><span>Scheduled indicator value</span><input className="ui-input font-mono" required value={form.ioc_value} onChange={event => setForm({ ...form, ioc_value: event.target.value })} /></label>
      <label className="field"><span>Interval (hours)</span><input className="ui-input" type="number" required min={1} max={168} step={1} value={form.interval_hours} onChange={event => setForm({ ...form, interval_hours: event.target.value })} /></label>
    </fieldset>
    {(validation || create.isError) && <p role="alert" className="text-destructive">{validation || huntError(create.error)}</p>}
    {message && <p role="status" className="text-sm">{message}</p>}
    <button className="ui-button mt-3" type="submit" disabled={create.isPending}>{create.isPending ? 'Creating…' : 'Create schedule'}</button>
  </form>
}

function DeleteSchedule({ schedule, onClose, onDeleted }: { readonly schedule: HuntSchedule; readonly onClose: () => void; readonly onDeleted: () => void }) {
  const remove = useHuntScheduleAction('delete')
  return <WorkspaceDialog title={`Delete ${schedule.name}?`} description={`${schedule.ioc_type.toUpperCase()} · ${schedule.ioc_value}`} busy={remove.isPending} onClose={onClose}>
    <p>This permanently removes the recurring schedule. Existing hunt results are kept. Pause the schedule instead if you may need it again.</p>
    {remove.isError && <p role="alert" className="text-destructive">{huntError(remove.error)}</p>}
    <div className="control-cluster justify-end"><button className="ui-button" disabled={remove.isPending} onClick={onClose}>Cancel</button>
      <button className="ui-button ui-button--danger" disabled={remove.isPending} onClick={() => remove.mutate(schedule.id, { onSuccess: onDeleted })}>{remove.isPending ? 'Deleting…' : 'Delete schedule'}</button></div>
  </WorkspaceDialog>
}
