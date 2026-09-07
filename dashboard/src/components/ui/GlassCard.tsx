import type { ReactNode } from 'react'

type GlassCardProps = {
  readonly title?: ReactNode
  readonly actions?: ReactNode
  readonly className?: string
  readonly children: ReactNode
}

export function GlassCard({ title, actions, className = '', children }: GlassCardProps) {
  return (
    <section className={`overflow-hidden rounded-lg border border-[var(--glass-border)] bg-[var(--glass-bg)] shadow-[0_8px_24px_rgba(0,0,0,0.18),inset_0_1px_0_rgba(255,255,255,0.04)] backdrop-blur-xl ${className}`}>
      {(title !== undefined || actions !== undefined) && (
        <header className="flex min-h-11 items-center justify-between gap-3 border-b border-[var(--glass-border)] px-4 py-3">
          {title !== undefined && <h2 className="m-0 text-sm font-semibold text-[var(--text-primary)]">{title}</h2>}
          {actions !== undefined && <div className="flex flex-wrap items-center justify-end gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}
