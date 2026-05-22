import { useEffect, useRef, type ReactNode } from 'react'
import { EditorState } from '@codemirror/state'
import { EditorView, basicSetup } from 'codemirror'
import { yaml } from '@codemirror/lang-yaml'
import { oneDark } from '@codemirror/theme-one-dark'
import { X } from 'lucide-react'

interface Props {
  title: string
  value: string
  onChange: (v: string) => void
  onSave: () => void
  onClose: () => void
  extraAction?: { label: string; onClick: () => void }
  footer?: ReactNode
}

export default function YamlEditor({ title, value, onChange, onSave, onClose, extraAction, footer }: Props) {
  const editorRef = useRef<HTMLDivElement>(null)
  const viewRef = useRef<EditorView | null>(null)

  useEffect(() => {
    if (!editorRef.current) return
    const state = EditorState.create({
      doc: value,
      extensions: [
        basicSetup,
        yaml(),
        oneDark,
        EditorView.updateListener.of((u) => {
          if (u.docChanged) onChange(u.state.doc.toString())
        }),
      ],
    })
    const view = new EditorView({ state, parent: editorRef.current })
    viewRef.current = view
    return () => view.destroy()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-lg border border-border bg-card shadow-2xl"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h2 className="font-semibold">{title}</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X size={18} /></button>
        </div>
        <div ref={editorRef} className="h-96 overflow-auto text-sm" />
        {footer}
        <div className="flex gap-2 justify-end px-4 py-3 border-t border-border">
          {extraAction && (
            <button onClick={extraAction.onClick}
              className="px-4 py-1.5 rounded border border-border text-sm hover:bg-muted">
              {extraAction.label}
            </button>
          )}
          <button onClick={onClose} className="px-4 py-1.5 rounded border border-border text-sm hover:bg-muted">Cancel</button>
          <button onClick={onSave} className="px-4 py-1.5 rounded bg-primary text-primary-foreground text-sm">Save</button>
        </div>
      </div>
    </div>
  )
}
