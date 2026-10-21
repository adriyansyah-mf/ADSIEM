import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import type { Event, RawLog } from '@/types'

export type TelemetryRecord = RawLog | Event

export function TelemetryDetails({ record, onClose }: {
  readonly record: TelemetryRecord
  readonly onClose: () => void
}) {
  const raw = 'raw_message' in record
  const timestamp = raw ? record.received_at : record.created_at
  const fields = raw ? [['Log type', record.log_type], ['Agent ID', record.agent_id]]
    : [['Category', record.event_category], ['Action', record.event_action], ['Source IP', record.source_ip], ['User', record.user_name], ['Group', record.group_id], ['Agent ID', record.agent_id]]
  return <WorkspaceDialog title={raw ? 'Raw log details' : 'Event details'} description="Read-only evidence · original values are preserved" onClose={onClose} wide>
    <dl className="evidence-metadata">
      <div><dt>Record ID</dt><dd>{record.id}</dd></div>
      <div><dt>{raw ? 'Received' : 'Created'}</dt><dd><time dateTime={timestamp}>{timestamp}</time></dd></div>
      {fields.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? '—'}</dd></div>)}
    </dl>
    <section className="mt-6"><h3 className="text-sm font-semibold mb-3">{raw ? 'Original message' : 'Decoded fields'}</h3>
      <pre className="evidence-content">{raw ? record.raw_message : JSON.stringify(record.decoded_fields, null, 2)}</pre>
    </section>
  </WorkspaceDialog>
}
