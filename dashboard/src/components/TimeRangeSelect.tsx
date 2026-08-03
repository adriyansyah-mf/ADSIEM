import { useState } from 'react'

export interface TimeRange {
  start_time?: string
  end_time?: string
}

const PRESETS = [
  { label: 'All time', value: '' },
  { label: 'Last 1 hour', value: '1h' },
  { label: 'Last 24 hours', value: '24h' },
  { label: 'Last 7 days', value: '7d' },
  { label: 'Last 30 days', value: '30d' },
  { label: 'Custom range…', value: 'custom' },
]

const PRESET_MS: Record<string, number> = {
  '1h': 3_600_000,
  '24h': 86_400_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
}

// datetime-local inputs give "YYYY-MM-DDTHH:mm" in local time with no
// timezone info — new Date() on that string parses it as local time already,
// so a plain .toISOString() call is all that's needed to get UTC for the API.
const localInputToIso = (v: string): string | undefined => (v ? new Date(v).toISOString() : undefined)

/**
 * Preset dropdown (1h/24h/7d/30d) plus an optional custom from/to range.
 * Presets are resolved to a fixed ISO timestamp at selection time (not on
 * every render) so the resulting `value` is stable and safe to use directly
 * in a react-query queryKey/params without causing refetch loops.
 */
export function TimeRangeFilter({
  value, onChange, selectStyle, inputStyle, selectClassName, inputClassName,
}: {
  value: TimeRange
  onChange: (r: TimeRange) => void
  selectStyle?: React.CSSProperties
  inputStyle?: React.CSSProperties
  selectClassName?: string
  inputClassName?: string
}) {
  const [preset, setPreset] = useState('')

  const handlePreset = (p: string) => {
    setPreset(p)
    if (p === 'custom') return
    if (!p) { onChange({}); return }
    const ms = PRESET_MS[p]
    onChange({ start_time: new Date(Date.now() - ms).toISOString(), end_time: undefined })
  }

  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
      <select value={preset} onChange={e => handlePreset(e.target.value)} style={selectStyle} className={selectClassName}>
        {PRESETS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
      </select>
      {preset === 'custom' && (
        <>
          <input
            type="datetime-local"
            style={inputStyle}
            className={inputClassName}
            onChange={e => onChange({ ...value, start_time: localInputToIso(e.target.value) })}
          />
          <span style={{ fontSize: 11, opacity: 0.6 }}>to</span>
          <input
            type="datetime-local"
            style={inputStyle}
            className={inputClassName}
            onChange={e => onChange({ ...value, end_time: localInputToIso(e.target.value) })}
          />
        </>
      )}
    </div>
  )
}
