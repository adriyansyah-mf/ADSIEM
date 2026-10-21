import type { ReactNode } from 'react'
import { AlertCircle, Inbox, Loader2 } from 'lucide-react'

export function PageHeader({ eyebrow, title, description, actions }: {
  readonly eyebrow?: string
  readonly title: string
  readonly description?: string
  readonly actions?: ReactNode
}) {
  return (
    <header className="page-header">
      <div className="page-header__copy">
        {eyebrow && <span className="page-eyebrow">{eyebrow}</span>}
        <h1>{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  )
}

export function Panel({ title, description, actions, children }: {
  readonly title: string
  readonly description?: string
  readonly actions?: ReactNode
  readonly children: ReactNode
}) {
  return (
    <section className="panel">
      <header className="panel__header">
        <div>
          <h2>{title}</h2>
          {description && <p className="panel__description">{description}</p>}
        </div>
        {actions}
      </header>
      <div className="panel__body">{children}</div>
    </section>
  )
}

export function QueryState({ kind, title, description, onRetry }: {
  readonly kind: 'loading' | 'error' | 'empty'
  readonly title: string
  readonly description?: string
  readonly onRetry?: () => void
}) {
  const Icon = kind === 'error' ? AlertCircle : kind === 'loading' ? Loader2 : Inbox
  return (
    <div className={`query-state query-state--${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <Icon size={24} aria-hidden="true" />
      <h3>{title}</h3>
      {description && <p>{description}</p>}
      {onRetry && <button className="ui-button" onClick={onRetry}>Try again</button>}
    </div>
  )
}
