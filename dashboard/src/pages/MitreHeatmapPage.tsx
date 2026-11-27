import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { CanvasHeader, CanvasPage, Empty, Seg } from '@/components/canvas/Canvas'

interface CoverageCell { technique_id: string; technique_name: string; tactic: string; rules: number; detections: number }
interface Coverage {
  period_days: number
  techniques_total: number
  techniques_covered: number
  techniques_detected: number
  detected_without_rule: number
  disabled_rule_mappings: number
  tactics: { tactic: string; techniques: CoverageCell[] }[]
}
interface HeatmapCell { technique_id: string; technique_name: string; tactic: string; count: number }
interface Heatmap { period_days: number; max_count: number; total_technique_hits: number; tactics: { tactic: string; techniques: HeatmapCell[] }[] }

type Mode = 'coverage' | 'detections'

const TABS = [
  { to: '/threat-iocs', label: 'Indicators' },
  { to: '/malware-hashes', label: 'Malware hashes' },
  { to: '/mitre-heatmap', label: 'MITRE coverage' },
]
const DAY_OPTIONS = [7, 30, 90, 180, 365]
// none, 1 rule, 2 rules, 3+ rules (canvas legend)
const LEVELS = ['cv-att--0', 'cv-att--1', 'cv-att--2', 'cv-att--3']
// detections: sequential ramp on the same blue hue
const HEAT = ['cv-att--1', 'cv-att--2', 'cv-att--3', 'cv-att--4']

function download(name: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  URL.revokeObjectURL(url)
}

export default function MitreHeatmapPage() {
  const [mode, setMode] = useState<Mode>('coverage')
  const [days, setDays] = useState(30)
  const coverage = useQuery<Coverage>({
    queryKey: ['mitre', 'coverage', days],
    queryFn: () => api.get('/api/mitre/coverage', { params: { days } }).then(r => r.data),
    refetchInterval: 120_000,
  })
  const heatmap = useQuery<Heatmap>({
    queryKey: ['mitre', 'heatmap', days],
    queryFn: () => api.get('/api/mitre/heatmap', { params: { days } }).then(r => r.data),
    enabled: mode === 'detections',
  })

  const data = coverage.data
  const pct = data && data.techniques_total ? Math.round((data.techniques_covered / data.techniques_total) * 100) : 0
  const tactics = mode === 'coverage'
    ? (data?.tactics ?? []).filter(t => t.techniques.length)
    : (heatmap.data?.tactics ?? []).filter(t => t.techniques.length)
  const maxHeat = heatmap.data?.max_count ?? 1

  const exportLayer = () => {
    if (!data) return
    download('adsiem-attack-coverage.json', {
      name: 'AD-SIEM detection coverage', domain: 'enterprise-attack',
      versions: { layer: '4.5', navigator: '5.1.0' },
      description: `Enabled rules per technique; detections over the last ${data.period_days} days in the comment.`,
      gradient: { colors: ['#1C2740', '#3D6FD6'], minValue: 0, maxValue: 3 },
      techniques: data.tactics.flatMap(t => t.techniques).map(cell => ({
        techniqueID: cell.technique_id, score: Math.min(cell.rules, 3),
        comment: `${cell.rules} rule(s), ${cell.detections} detection(s)`, enabled: true,
      })),
    })
  }

  return (
    <CanvasPage>
      <CanvasHeader
        title="ATT&CK coverage"
        crumb="MITRE coverage"
        sub="Enterprise matrix · coverage from enabled detection rules, with detections seen in the window"
        tabs={TABS}
        actions={<>
          <Seg label="Matrix mode" value={mode} onChange={setMode} options={[{ value: 'coverage', label: 'Rule coverage' }, { value: 'detections', label: 'Detections' }]} />
          <select className="cv-select" aria-label="Window" value={days} onChange={event => setDays(Number(event.target.value))}>
            {DAY_OPTIONS.map(value => <option key={value} value={value}>Last {value} days</option>)}
          </select>
          <button type="button" className="cv-btn" disabled={!data} onClick={exportLayer}>Export Navigator layer</button>
        </>}
      />
      <div className="cv-body cv-body--wide">
        <div className="cv-row" style={{ gap: 28, alignItems: 'baseline' }}>
          <span><span className="cv-muted">Techniques covered</span> <strong style={{ fontSize: 15 }}>{data ? `${data.techniques_covered} of ${data.techniques_total} mapped (${pct}%)` : '–'}</strong></span>
          <span><span className="cv-muted">Seen in last {days} days</span> <strong style={{ fontSize: 15 }}>{data ? `${data.techniques_detected} techniques` : '–'}</strong></span>
          <span><span className="cv-muted">Detected without a rule</span> <strong className={data?.detected_without_rule ? 'cv-t-warn' : undefined} style={{ fontSize: 15 }}>{data?.detected_without_rule ?? '–'}</strong></span>
          <span className="cv-legend" style={{ marginLeft: 'auto' }}>
            {mode === 'coverage' ? <>
              <span><i className="cv-att--0" /> None</span>
              <span><i className="cv-att--1" /> 1 rule</span>
              <span><i className="cv-att--2" /> 2 rules</span>
              <span><i className="cv-att--3" /> 3+ rules</span>
              <span><i className="cv-att__hot" style={{ position: 'static' }} /> Detected in {days} days</span>
            </> : <>
              <span><i className="cv-att--1" /> Fewer</span>
              <span><i className="cv-att--4" /> More detections</span>
            </>}
          </span>
        </div>

        <div className="cv-matrix" role="table" aria-label="ATT&CK matrix">
          {tactics.map(tactic => {
            const cells = tactic.techniques as (CoverageCell | HeatmapCell)[]
            const covered = mode === 'coverage' ? (cells as CoverageCell[]).filter(c => c.rules > 0).length : null
            return (
              <div key={tactic.tactic} className="cv-matrix__col" role="rowgroup">
                <div className="cv-matrix__head">
                  <strong>{tactic.tactic}</strong>
                  <span className="cv-muted cv-small">{covered != null ? `${covered} of ${cells.length} covered` : `${cells.length} techniques`}</span>
                </div>
                {cells.map(cell => {
                  const level = 'rules' in cell
                    ? LEVELS[Math.min(cell.rules, 3)]
                    : HEAT[Math.min(HEAT.length - 1, Math.floor(((cell.count - 1) / Math.max(1, maxHeat - 1)) * HEAT.length))]
                  const tip = 'rules' in cell
                    ? `${cell.technique_id} · ${cell.rules} rule(s) · ${cell.detections} detection(s)`
                    : `${cell.technique_id} · ${cell.count} detection(s)`
                  return (
                    <Link key={cell.technique_id} role="cell" className={`cv-att ${level}`} title={tip}
                      to={'rules' in cell && cell.rules === 0 ? `/rules?q=${encodeURIComponent(cell.technique_id)}&import=1` : `/rules?q=${encodeURIComponent(cell.technique_id.toLowerCase())}`}>
                      <span className="cv-att__id">{cell.technique_id}</span>
                      <span className="cv-att__name">{cell.technique_name}</span>
                      {'detections' in cell && cell.detections > 0 && <span className="cv-att__hot" aria-label={`Detected ${cell.detections} times in the last ${days} days`} />}
                      {'count' in cell && <span className="cv-att__count">{cell.count}</span>}
                    </Link>
                  )
                })}
              </div>
            )
          })}
        </div>
        {(mode === 'coverage' ? coverage : heatmap).isPending && <Empty>Loading the matrix…</Empty>}
        {(mode === 'coverage' ? coverage : heatmap).isError && <Empty>Could not load ATT&CK data.</Empty>}
        {!coverage.isPending && tactics.length === 0 && <Empty>No rule or detection maps to an ATT&CK technique yet. Rules gain coverage from their attack.* tags.</Empty>}
        <p className="cv-muted cv-small" style={{ margin: 0 }}>
          Select a technique to open the rules that cover it. Gaps (dashed) open the rule library filtered to that technique so you can import or write one.
          {data?.disabled_rule_mappings ? ` ${data.disabled_rule_mappings} technique mappings belong to disabled rules and are not counted.` : ''}
        </p>
      </div>
    </CanvasPage>
  )
}
