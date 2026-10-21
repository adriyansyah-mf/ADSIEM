import type { CSSProperties } from 'react'

const COLORS: Readonly<Record<string, string>> = {
  critical: 'var(--accent-red)',
  high: 'var(--accent-orange)',
  medium: 'var(--accent-yellow)',
  low: 'var(--accent-green)',
  info: 'var(--accent-cyan)',
}

export default function SeverityBadge({ severity }: { readonly severity: string }) {
  const color = COLORS[severity] ?? 'var(--text-muted)'
  const style: CSSProperties & { '--badge-color': string } = { '--badge-color': color }
  return (
    <span className="semantic-badge" style={style}>
      <span className="semantic-badge__dot" aria-hidden="true" />
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  )
}
