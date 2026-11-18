import { createContext, useContext, useState, useCallback, useEffect, useRef, useMemo, type ReactNode } from 'react'

interface Toast {
  id: number
  message: string
  type: 'info' | 'success' | 'error'
}

interface ToastContextType {
  addToast: (message: string, type?: Toast['type']) => void
}

const ToastContext = createContext<ToastContextType>({ addToast: () => {} })

let nextId = 0

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const timersRef = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map())

  const addToast = useCallback((message: string, type: Toast['type'] = 'info') => {
    const id = nextId++
    setToasts((prev) => [...prev, { id, message, type }])
    const timer = setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
      timersRef.current.delete(id)
    }, 4000)
    timersRef.current.set(id, timer)
  }, [])

  useEffect(() => {
    const timers = timersRef.current
    return () => { timers.forEach((t) => clearTimeout(t)); timers.clear() }
  }, [])

  useEffect(() => {
    const handler = () => addToast('Your session has expired. Please sign in again.', 'error')
    window.addEventListener('session-expired', handler)
    return () => window.removeEventListener('session-expired', handler)
  }, [addToast])

  const contextValue = useMemo(() => ({ addToast }), [addToast])

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      <div className="fixed bottom-4 right-4 flex flex-col gap-2 z-50" aria-live="polite" aria-atomic="true" role="status">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`px-4 py-2 rounded-lg text-sm shadow-lg animate-slide-in ${
              toast.type === 'error'
                ? 'bg-danger text-white'
                : toast.type === 'success'
                  ? 'bg-success text-white'
                  : 'bg-surface border border-border text-text'
            }`}
          >
            {toast.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components -- context hook co-located with its provider; HMR falls back to a full reload here
export function useToast() {
  return useContext(ToastContext)
}
