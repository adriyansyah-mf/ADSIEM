import { TrendingDown, TrendingUp } from 'lucide-react'
import type { ReactNode } from 'react'

type TrendDirection = 'up' | 'down'

type StatCardProps = {
  readonly label: string
  readonly value: ReactNode
  readonly context?: ReactNode
  readonly trend?: {
    readonly value: string
    readonly direction: TrendDirection
  }
  readonly favorableDirection?: TrendDirection
  readonly sparkline?: ReactNode
  readonly onClick?: () => void
}

export function StatCard({
  label,
  value,
  context,
  trend,
  favorableDirection = 'up',
  sparkline,
  onClick,
}: StatCardProps) {
  const isFavorable = trend?.direction === favorableDirection
  const TrendIcon = trend?.direction === 'down' ? TrendingDown : TrendingUp
  const content = (
    <>
      <div className="text-xs font-semibold tracking-[0.02em] text-[var(--text-secondary)]">{label}</div>
      <div className="mt-2 flex items-end justify-between gap-3">
        <div className="min-w-0 text-[1.75rem] font-bold leading-none tabular-nums text-[var(--text-primary)]">{value}</div>
        {trend !== undefined && (
          <div
            className="flex items-center gap-1 pb-0.5 text-xs font-semibold"
            style={{ color: isFavorable ? 'var(--accent-green)' : 'var(--accent-red)' }}
            aria-label={`${trend.direction} ${trend.value}`}
          >
            <TrendIcon aria-hidden="true" size={14} strokeWidth={2} />
            {trend.value}
          </div>
        )}
      </div>
      {context !== undefined && <div className="mt-2 text-xs text-[var(--text-muted)]">{context}</div>}
      {sparkline !== undefined && <div className="mt-3">{sparkline}</div>}
    </>
  )

  const classes = 'w-full rounded-lg border border-[var(--glass-border)] bg-[var(--glass-bg)] p-4 text-left shadow-[0_8px_24px_rgba(0,0,0,0.18),inset_0_1px_0_rgba(255,255,255,0.04)] backdrop-blur-xl'

  if (onClick !== undefined) {
    return (
      <button type="button" onClick={onClick} className={`${classes} min-h-11 cursor-pointer transition-[border-color,background-color,transform] duration-150 hover:border-[var(--accent-blue)] hover:bg-[var(--glass-bg-strong)] active:scale-[0.99]`}>
        {content}
      </button>
    )
  }

  return <section className={classes}>{content}</section>
}
