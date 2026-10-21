import type { CSSProperties } from 'react'

const COLORS: Readonly<Record<string, string>> = {
  new: 'var(--accent-cyan)', open: 'var(--accent-cyan)',
  in_progress: 'var(--accent-yellow)', in_review: 'var(--accent-yellow)',
  escalated: 'var(--accent-orange)',
  pending_approval: 'var(--accent-yellow)', isolated: 'var(--accent-red)',
  resolved: 'var(--accent-green)', online: 'var(--accent-green)',
  closed: 'var(--text-muted)', false_positive: 'var(--text-muted)', offline: 'var(--text-muted)',
}

export default function StatusBadge({ status }: { readonly status: string }) {
  const color = COLORS[status] ?? 'var(--text-muted)'
  const style: CSSProperties & { '--badge-color': string } = { '--badge-color': color }
  const label = status.replace(/_/g, ' ')
  return (
    <span className="semantic-badge" style={style}>
      <span className="semantic-badge__dot" aria-hidden="true" />
      {label.charAt(0).toUpperCase() + label.slice(1)}
    </span>
  )
}
