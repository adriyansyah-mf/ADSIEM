export const TIME_PRESETS = [
  { label: 'All time', value: '' },
  { label: 'Last 1 hour', value: '1h' },
  { label: 'Last 24 hours', value: '24h' },
  { label: 'Last 7 days', value: '7d' },
  { label: 'Last 30 days', value: '30d' },
]

const PRESET_MS: Record<string, number> = {
  '1h': 3600_000,
  '24h': 86_400_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
}

export function presetToStartTime(preset: string): string | undefined {
  const ms = PRESET_MS[preset]
  return ms ? new Date(Date.now() - ms).toISOString() : undefined
}

export function TimeRangeSelect({
  value, onChange, className, style,
}: { value: string; onChange: (v: string) => void; className?: string; style?: React.CSSProperties }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)} className={className} style={style}>
      {TIME_PRESETS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
    </select>
  )
}
