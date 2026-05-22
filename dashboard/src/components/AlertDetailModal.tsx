import { useState } from 'react'
import type { Alert } from '@/types'
import SeverityBadge from './SeverityBadge'
import StatusBadge from './StatusBadge'
import { useUpdateAlert, useAddAlertNote } from '@/hooks/useAlerts'
import { format } from 'date-fns'
import { X } from 'lucide-react'

interface Props { alert: Alert; onClose: () => void }

const STATUS_OPTIONS = ['new', 'in_progress', 'resolved', 'false_positive']

export default function AlertDetailModal({ alert, onClose }: Props) {
  const [note, setNote] = useState('')
  const updateAlert = useUpdateAlert()
  const addNote = useAddAlertNote()

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-lg border border-border bg-card p-6 shadow-2xl max-h-[90vh] overflow-auto"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold">{alert.title}</h2>
            <div className="flex gap-2 mt-1">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
            </div>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X size={20} /></button>
        </div>

        <div className="grid grid-cols-2 gap-3 text-sm mb-4">
          <div><span className="text-muted-foreground">Source IP:</span> {alert.source_ip ?? '—'}</div>
          <div><span className="text-muted-foreground">Hostname:</span> {alert.hostname ?? '—'}</div>
          <div><span className="text-muted-foreground">Created:</span> {format(new Date(alert.created_at), 'yyyy-MM-dd HH:mm:ss')}</div>
          <div><span className="text-muted-foreground">Group:</span> {alert.group_id}</div>
        </div>

        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">Update Status</label>
          <select
            value={alert.status}
            onChange={(e) => updateAlert.mutate({ id: alert.id, data: { status: e.target.value } })}
            className="px-3 py-1.5 rounded border border-border bg-background text-sm"
          >
            {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
          </select>
        </div>

        <div className="mb-4">
          <h3 className="text-sm font-medium mb-2">Notes ({alert.notes.length})</h3>
          <div className="space-y-2 max-h-48 overflow-auto">
            {alert.notes.map((n) => (
              <div key={n.id} className="p-3 rounded bg-muted text-sm">
                <div className="text-xs text-muted-foreground mb-1">{format(new Date(n.created_at), 'yyyy-MM-dd HH:mm')}</div>
                {n.content}
              </div>
            ))}
          </div>
          <div className="flex gap-2 mt-2">
            <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note..."
              className="flex-1 px-3 py-1.5 rounded border border-border bg-background text-sm" />
            <button
              onClick={() => { addNote.mutate({ id: alert.id, content: note }); setNote('') }}
              disabled={!note} className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50">
              Add
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
