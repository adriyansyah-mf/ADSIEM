import { useEffect, useId, useRef } from 'react'
import type { ReactNode } from 'react'
import { X } from 'lucide-react'

export function WorkspaceDialog({ title, description, children, onClose, busy = false, wide = false }: {
  readonly title: string
  readonly description?: string
  readonly children: ReactNode
  readonly onClose: () => void
  readonly busy?: boolean
  readonly wide?: boolean
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const id = useId()
  useEffect(() => {
    const dialog = ref.current
    const previous = document.activeElement
    dialog?.showModal()
    return () => {
      dialog?.close()
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus()
    }
  }, [])
  return <dialog ref={ref} className={`workspace-dialog ${wide ? 'workspace-dialog--wide' : ''}`}
    aria-labelledby={`${id}-title`} aria-describedby={description ? `${id}-description` : undefined}
    aria-busy={busy} onCancel={event => { event.preventDefault(); if (!busy) onClose() }}>
    <header className="panel__header">
      <div className="min-w-0"><h2 id={`${id}-title`}>{title}</h2>
        {description && <p id={`${id}-description`} className="panel__description">{description}</p>}</div>
      <button className="ui-icon-button" aria-label="Close dialog" disabled={busy} onClick={onClose}><X size={16} /></button>
    </header>
    <div className="panel__body">{children}</div>
  </dialog>
}
