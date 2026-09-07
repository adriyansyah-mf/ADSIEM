import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Grid3x3 } from 'lucide-react'
import { PageHeader } from '@/components/ui/PageHeader'

interface TechniqueEntry {
  technique_id: string
  technique_name: string
  tactic: string
  count: number
}

interface HeatmapResponse {
  period_days: number
  total_alerts_with_mitre: number
  total_technique_hits: number
  max_count: number
  tactics: { tactic: string; techniques: TechniqueEntry[] }[]
}

// Sequential blue ramp, light -> dark (references/palette.md in the dataviz skill).
const RAMP = ['#cde2fb', '#9ec5f4', '#5598e7', '#2a78d6', '#184f95', '#0d366b']

function colorForCount(count: number, max: number): { bg: string; fg: string } {
  if (max <= 1) return { bg: RAMP[3], fg: '#fff' }
  const ratio = (count - 1) / (max - 1)
  const idx = Math.min(RAMP.length - 1, Math.round(ratio * (RAMP.length - 1)))
  return { bg: RAMP[idx], fg: idx >= 3 ? '#fff' : '#0d172a' }
}

const DAY_OPTIONS = [
  { label: '7 days', value: 7 },
  { label: '30 days', value: 30 },
  { label: '90 days', value: 90 },
  { label: '180 days', value: 180 },
  { label: '365 days', value: 365 },
]

export default function MitreHeatmapPage() {
  const [days, setDays] = useState(90)
  const { data, isLoading } = useQuery<HeatmapResponse>({
    queryKey: ['mitre-heatmap', days],
    queryFn: () => api.get('/api/mitre/heatmap', { params: { days } }).then(r => r.data),
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <PageHeader
          title={<><Grid3x3 aria-hidden="true" size={20} /> MITRE ATT&amp;CK Heatmap</>}
          subtitle="Technique frequency across triaged alerts; darker cells were seen more often."
          className="!mb-0"
        />
        <select
          value={days}
          onChange={e => setDays(Number(e.target.value))}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm"
        >
          {DAY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </div>

      {isLoading ? (
        <div className="text-muted-foreground mt-4">Loading...</div>
      ) : !data || data.total_technique_hits === 0 ? (
        <div className="mt-6 p-8 rounded border border-border text-center text-muted-foreground text-sm">
          No MITRE techniques recorded by the AI analyst in this period yet.
        </div>
      ) : (
        <>
          <div className="flex items-center gap-4 text-xs text-muted-foreground mb-4 mt-3">
            <span>{data.total_alerts_with_mitre} alerts with technique data</span>
            <span>·</span>
            <span>{data.total_technique_hits} technique hits</span>
            <div className="flex items-center gap-1 ml-auto">
              <span>Fewer</span>
              {RAMP.map(c => (
                <div key={c} style={{ width: 14, height: 10, background: c, borderRadius: 2 }} />
              ))}
              <span>More</span>
            </div>
          </div>

          <div className="flex gap-2 overflow-x-auto pb-2">
            {data.tactics.map(col => (
              <div key={col.tactic} className="flex-shrink-0 w-44">
                <div className="text-xs font-semibold px-2 py-1.5 rounded-t bg-muted border border-border text-center">
                  {col.tactic}
                  <div className="text-[10px] font-normal text-muted-foreground">
                    {col.techniques.length} technique{col.techniques.length === 1 ? '' : 's'}
                  </div>
                </div>
                <div className="border border-t-0 border-border rounded-b overflow-hidden">
                  {col.techniques.length === 0 ? (
                    <div className="px-2 py-3 text-center text-[11px] text-muted-foreground">No data</div>
                  ) : (
                    col.techniques.map(t => {
                      const { bg, fg } = colorForCount(t.count, data.max_count)
                      return (
                        <div
                          key={t.technique_id}
                          title={`${t.technique_id}: ${t.technique_name}\n${t.count} alert${t.count === 1 ? '' : 's'}`}
                          className="px-2 py-1.5 text-[11px] border-t border-border/60 first:border-t-0 flex items-center justify-between cursor-default"
                          style={{ background: bg, color: fg }}
                        >
                          <span className="truncate font-mono">{t.technique_id}</span>
                          <span className="font-semibold ml-1">{t.count}</span>
                        </div>
                      )
                    })
                  )}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
