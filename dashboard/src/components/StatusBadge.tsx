const COLOR: Record<string, string> = {
  new: 'var(--accent-blue)',
  in_progress: 'var(--accent-yellow)',
  resolved: 'var(--accent-green)',
  false_positive: 'var(--text-muted)',
  online: 'var(--accent-green)',
  offline: 'var(--text-muted)',
}

export default function StatusBadge({ status }: { status: string }) {
  const c = COLOR[status] ?? 'var(--text-muted)'
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: 4,
        border: `1px solid ${c}`,
        background: `color-mix(in srgb, ${c} 12%, transparent)`,
        color: c,
        fontWeight: 600,
        fontSize: 11,
        letterSpacing: '0.02em',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      {status.replace('_', ' ')}
    </span>
  )
}
