import { useCallback } from 'react'

type ToastType = 'success' | 'error' | 'info'

interface ToastEvent {
  message: string
  type: ToastType
  id: number
}

// Simple event-based toast system that doesn't require React context
const listeners: Array<(t: ToastEvent) => void> = []
let counter = 0

export function emitToast(message: string, type: ToastType = 'info') {
  const event: ToastEvent = { message, type, id: ++counter }
  listeners.forEach((l) => l(event))
}

export function subscribeToast(listener: (t: ToastEvent) => void) {
  listeners.push(listener)
  return () => {
    const idx = listeners.indexOf(listener)
    if (idx >= 0) listeners.splice(idx, 1)
  }
}

export function useToast() {
  const success = useCallback((message: string) => emitToast(message, 'success'), [])
  const error = useCallback((message: string) => emitToast(message, 'error'), [])
  const info = useCallback((message: string) => emitToast(message, 'info'), [])
  return { success, error, info }
}
