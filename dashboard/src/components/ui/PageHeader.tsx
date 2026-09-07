import type { ReactNode } from 'react'

type PageHeaderProps = {
  readonly title: ReactNode
  readonly subtitle?: ReactNode
  readonly breadcrumb?: ReactNode
  readonly actions?: ReactNode
  readonly className?: string
}

export function PageHeader({ title, subtitle, breadcrumb, actions, className = '' }: PageHeaderProps) {
  return (
    <header className={`mb-5 flex flex-wrap items-start justify-between gap-4 ${className}`}>
      <div className="min-w-0">
        {breadcrumb !== undefined && (
          <div className="mb-1 text-xs font-medium text-[var(--text-muted)]">{breadcrumb}</div>
        )}
        <h1 className="m-0 flex min-w-0 items-center gap-2 text-[1.375rem] font-bold leading-tight text-[var(--text-primary)]">
          {title}
        </h1>
        {subtitle !== undefined && (
          <p className="mb-0 mt-1 max-w-[72ch] text-[0.8125rem] leading-relaxed text-[var(--text-secondary)]">{subtitle}</p>
        )}
      </div>
      {actions !== undefined && <div className="flex flex-wrap items-center justify-end gap-2">{actions}</div>}
    </header>
  )
}
