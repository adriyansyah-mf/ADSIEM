import { useEffect, useState } from 'react'
import { subscribeToast } from '@/hooks/useToast'
import { X } from 'lucide-react'

interface Toast {
  id: number
  message: string
  type: 'success' | 'error' | 'info'
}

export default function Toaster() {
  const [toasts, setToasts] = useState<Toast[]>([])

  useEffect(() => {
    return subscribeToast((t) => {
      setToasts((prev) => [...prev, t])
      setTimeout(() => {
        setToasts((prev) => prev.filter((x) => x.id !== t.id))
      }, 4000)
    })
  }, [])

  if (toasts.length === 0) return null

  return (
    <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 w-80">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`flex items-start gap-3 rounded border px-4 py-3 text-sm shadow-lg transition-all
            ${t.type === 'success' ? 'border-green-600 bg-green-950 text-green-200' : ''}
            ${t.type === 'error' ? 'border-red-600 bg-red-950 text-red-200' : ''}
            ${t.type === 'info' ? 'border-border bg-card text-foreground' : ''}
          `}
        >
          <span className="flex-1">{t.message}</span>
          <button
            onClick={() => setToasts((prev) => prev.filter((x) => x.id !== t.id))}
            className="text-muted-foreground hover:text-foreground flex-shrink-0"
          >
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  )
}
