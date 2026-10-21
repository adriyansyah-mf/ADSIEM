import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { QueryState } from '@/components/Workspace'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import MarkdownNote from '@/components/MarkdownNote'
import type { ThreatHunt } from '@/types'

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseAnalysis(value: string | null): Record<string, unknown> | null {
  try { const parsed: unknown = JSON.parse(value ?? 'null'); return record(parsed) ? parsed : null }
  catch { return null }
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

export function HuntDetails({ hunt, onClose }: { readonly hunt: ThreatHunt; readonly onClose: () => void }) {
  const analysis = parseAnalysis(hunt.analysis)
  const narrative = typeof analysis?.attack_narrative === 'string' ? analysis.attack_narrative : null
  const techniques = strings(analysis?.mitre_techniques)
  const actions = strings(analysis?.recommended_actions)
  const pending = hunt.status === 'pending' || hunt.status === 'running'
  return <WorkspaceDialog title={`Hunt · ${hunt.ioc_value}`} description={`${hunt.ioc_type.toUpperCase()} · ${hunt.group_id} · Read-only investigation results`} onClose={onClose} wide>
    <div className="control-cluster mb-5"><StatusBadge status={hunt.status} /><SeverityBadge severity={hunt.risk_level ?? 'unknown'} />
      <span className="text-xs text-muted-foreground">{hunt.alert_count} alerts · {hunt.event_count} events · {hunt.fim_count} FIM records</span></div>
    <dl className="evidence-metadata mb-6">
      <div><dt>Created</dt><dd><time dateTime={hunt.created_at}>{hunt.created_at}</time></dd></div>
      <div><dt>Completed</dt><dd>{hunt.completed_at ? <time dateTime={hunt.completed_at}>{hunt.completed_at}</time> : 'Not completed'}</dd></div>
    </dl>
    {pending && <QueryState kind="loading" title={hunt.status === 'pending' ? 'Waiting in queue…' : 'Hunt in progress…'} description="Results update automatically while this dialog is open." />}
    {hunt.status === 'failed' && <p role="alert" className="text-destructive">{narrative ?? 'This hunt failed. Start a new hunt to try again.'}</p>}
    {hunt.status === 'done' && <section className="hunt-analysis space-y-4" aria-label="Hunt analysis">
      <div><h3 className="text-sm font-semibold mb-2">AI analysis</h3>
        {narrative ? <MarkdownNote content={narrative} /> : <p className="text-muted-foreground">No narrative was returned.</p>}
        <p className="text-xs text-muted-foreground mt-3">AI-generated assessment · verify against the evidence before taking action.</p></div>
      <dl className="evidence-metadata">
        {techniques.length > 0 && <div><dt>MITRE techniques</dt><dd>{techniques.join(', ')}</dd></div>}
        {(['kill_chain_phase', 'campaign_assessment'] as const).map(key => typeof analysis?.[key] === 'string' &&
          <div key={key}><dt>{key === 'kill_chain_phase' ? 'Kill chain phase' : 'Campaign assessment'}</dt><dd>{analysis[key].replace(/_/g, ' ')}</dd></div>)}
      </dl>
      {actions.length > 0 && <div><h3 className="text-sm font-semibold mb-2">Recommended actions</h3><ul className="list-disc pl-5 space-y-2">{actions.map((action, index) => <li key={index}>{action}</li>)}</ul></div>}
      {hunt.alert_count === 0 && hunt.event_count === 0 && hunt.fim_count === 0 && <p className="text-muted-foreground">No related history was found for this indicator.</p>}
    </section>}
    {hunt.analysis && !analysis && <section className="mt-5"><h3 className="text-sm font-semibold mb-2">Unstructured analysis</h3>
      <p className="text-xs text-muted-foreground">The analysis could not be read as a structured object. Original content is shown below.</p><pre className="evidence-content">{hunt.analysis}</pre></section>}
    {!!hunt.timeline?.length && <section className="mt-6" aria-label="Hunt evidence timeline">
      <h3 className="text-sm font-semibold mb-3">Evidence timeline · {hunt.timeline.length} {hunt.timeline.length === 1 ? 'entry' : 'entries'}</h3>
      <ol className="hunt-timeline">{hunt.timeline.map((entry, index) => <li key={`${entry.id}-${index}`}>
        <div className="control-cluster text-xs"><time dateTime={entry.time} className="text-muted-foreground">{entry.time}</time>
          <span>{entry.type === 'alert' ? 'Alert' : 'Event'}</span>{entry.severity && <SeverityBadge severity={entry.severity} />}</div>
        <p className="mb-0 mt-2">{entry.type === 'alert' ? entry.title : `${entry.category ?? 'Uncategorized'} / ${entry.action ?? 'Unknown activity'} · User: ${entry.user ?? '—'}`}</p>
        {(entry.hostname || entry.source_ip) && <p className="font-mono text-xs text-muted-foreground mt-2 mb-0">{[entry.hostname, entry.source_ip].filter(Boolean).join(' · ')}</p>}
      </li>)}</ol>
    </section>}
  </WorkspaceDialog>
}
