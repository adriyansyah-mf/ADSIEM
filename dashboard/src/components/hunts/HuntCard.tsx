import { useState } from 'react'
import { format } from 'date-fns'
import { CheckCircle, ChevronDown, ChevronRight, Clock, Loader2, XCircle } from 'lucide-react'
import type { ThreatHunt } from '@/types'
import MarkdownNote from '@/components/MarkdownNote'
import { RISK_COLORS } from './constants'

function StatusIcon({ status }: { status: string }) {
  if (status === 'done') return <CheckCircle size={14} className="text-emerald-400" />
  if (status === 'failed') return <XCircle size={14} className="text-red-400" />
  if (status === 'running') return <Loader2 size={14} className="text-blue-400 animate-spin" />
  return <Clock size={14} className="text-muted-foreground" />
}

export function HuntCard({ hunt }: { hunt: ThreatHunt }) {
  const [expanded, setExpanded] = useState(hunt.status === 'done' && (hunt.alert_count ?? 0) > 0)
  const analysis = (() => {
    try { return hunt.analysis ? JSON.parse(hunt.analysis) : null } catch { return null }
  })()

  const riskClass = RISK_COLORS[hunt.risk_level ?? 'unknown'] ?? RISK_COLORS.unknown

  return (
    <div className="enterprise-panel rounded-lg border border-border bg-card overflow-hidden">
      {/* Header */}
      <button
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors text-left"
        onClick={() => setExpanded(x => !x)}
      >
        <StatusIcon status={hunt.status} />
        <span className="font-mono text-sm font-medium">{hunt.ioc_type.toUpperCase()}</span>
        <span className="font-mono text-sm text-primary">{hunt.ioc_value}</span>
        {hunt.risk_level && hunt.risk_level !== 'unknown' && (
          <span className={`text-xs px-2 py-0.5 rounded border font-medium ${riskClass}`}>
            {hunt.risk_level.toUpperCase()}
          </span>
        )}
        <div className="flex items-center gap-3 ml-auto text-xs text-muted-foreground">
          {hunt.status === 'done' && (
            <>
              <span>{hunt.alert_count} alerts</span>
              <span>{hunt.event_count} events</span>
            </>
          )}
          <span>{format(new Date(hunt.created_at), 'MM-dd HH:mm')}</span>
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-border px-4 py-4 space-y-4">
          {hunt.status === 'pending' || hunt.status === 'running' ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 size={14} className="animate-spin" />
              {hunt.status === 'pending' ? 'Waiting in queue…' : 'AI is tracing…'}
            </div>
          ) : hunt.status === 'failed' ? (
            <p className="text-sm text-destructive">{analysis?.attack_narrative ?? 'Hunt failed.'}</p>
          ) : (
            <>
              {/* AI Narrative */}
              {analysis?.attack_narrative && (
                <div className="rounded bg-muted/30 border border-border p-3 space-y-1">
                  <p className="text-xs text-muted-foreground uppercase font-medium">AI Analysis</p>
                  <MarkdownNote content={analysis.attack_narrative} className="text-sm" />
                </div>
              )}

              {/* MITRE + Kill Chain */}
              <div className="flex flex-wrap gap-4 text-xs">
                {analysis?.mitre_techniques?.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">MITRE: </span>
                    {analysis.mitre_techniques.map((t: string) => (
                      <span key={t} className="mr-1 px-1.5 py-0.5 bg-muted rounded font-mono">{t}</span>
                    ))}
                  </div>
                )}
                {analysis?.kill_chain_phase && (
                  <div>
                    <span className="text-muted-foreground">Kill Chain: </span>
                    <span className="font-medium">{analysis.kill_chain_phase.replace('_', ' ')}</span>
                  </div>
                )}
                {analysis?.campaign_assessment && (
                  <div>
                    <span className="text-muted-foreground">Campaign: </span>
                    <span className="font-medium">{analysis.campaign_assessment.replace('_', ' ')}</span>
                  </div>
                )}
              </div>

              {/* Recommended actions */}
              {analysis?.recommended_actions?.length > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground uppercase font-medium mb-1">Recommended Actions</p>
                  <ul className="text-sm space-y-0.5">
                    {analysis.recommended_actions.map((a: string, i: number) => (
                      <li key={i} className="flex gap-2"><span className="text-muted-foreground">•</span>{a}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Timeline */}
              {hunt.timeline && hunt.timeline.length > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground uppercase font-medium mb-2">Timeline ({hunt.timeline.length} entries)</p>
                  <div className="space-y-1 max-h-60 overflow-y-auto">
                    {hunt.timeline.map((e, i) => (
                      <div key={i} className="flex gap-2 text-xs font-mono">
                        <span className="text-muted-foreground whitespace-nowrap">{(e.time ?? '').slice(0, 16)}</span>
                        <span className={`px-1.5 rounded ${e.type === 'alert' ? 'bg-red-900/30 text-red-400' : 'bg-blue-900/30 text-blue-400'}`}>
                          {e.type.toUpperCase()}
                        </span>
                        {e.type === 'alert' ? (
                          <span className="truncate">[{e.severity?.toUpperCase()}] {e.title}</span>
                        ) : (
                          <span className="truncate">{e.category}/{e.action} user={e.user ?? '—'}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(hunt.alert_count === 0 && hunt.event_count === 0) && (
                <p className="text-sm text-muted-foreground">No history found for this IoC in alerts/events.</p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
