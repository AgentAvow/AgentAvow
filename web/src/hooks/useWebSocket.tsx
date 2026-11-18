import { useEffect, useRef, useMemo, useState, useSyncExternalStore } from 'react'

type MessageHandler = (data: Record<string, unknown>) => void

interface UseWebSocketOptions {
  channels?: string[]
  onMessage?: MessageHandler
  enabled?: boolean
}

const BASE_DELAY = 1000
const MAX_DELAY = 30000

// Close WebSocket when tab is hidden to avoid background CPU/network usage
function subscribeVisibility(cb: () => void) {
  document.addEventListener('visibilitychange', cb)
  return () => document.removeEventListener('visibilitychange', cb)
}
function getTabVisible() { return !document.hidden }

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const { channels = ['feed', 'notifications'], onMessage, enabled = true } = options
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const connectTimeout = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const mountedRef = useRef(true)
  const onMessageRef = useRef(onMessage)
  const retriesRef = useRef(0)
  const [connected, setConnected] = useState(false)
  const tabVisible = useSyncExternalStore(subscribeVisibility, getTabVisible, () => true)

  // Stabilize channels reference — only change when the actual values change
  const channelKey = channels.join(',')
  const stableChannels = useMemo(() => channels, [channelKey]) // eslint-disable-line react-hooks/exhaustive-deps

  // Keep onMessage ref current without triggering reconnects
  // eslint-disable-next-line react-hooks/refs -- latest-callback ref: keeps the handler current without reconnecting; moving it to an effect would change delivery timing
  onMessageRef.current = onMessage

  // Only connect when tab is visible — disconnects when hidden, reconnects when visible
  const effectiveEnabled = enabled && tabVisible

  useEffect(() => {
    mountedRef.current = true

    const connect = () => {
      const token = localStorage.getItem('token')
      if (!token || !effectiveEnabled || !mountedRef.current) return

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const host = window.location.host
      const channelStr = stableChannels.join(',')
      // Connect without token in URL — send auth as first message
      const url = `${protocol}//${host}/api/v1/ws?channels=${channelStr}`

      const ws = new WebSocket(url)
      wsRef.current = ws

      // Connection timeout — close and retry if stuck in CONNECTING
      connectTimeout.current = setTimeout(() => {
        if (ws.readyState === WebSocket.CONNECTING) {
          ws.close()
        }
      }, 10000)

      ws.onopen = () => {
        clearTimeout(connectTimeout.current)
        // Send auth token as first message instead of query param
        ws.send(JSON.stringify({ type: 'auth', token }))
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          if (data.type === 'ping') {
            ws.send(JSON.stringify({ type: 'pong' }))
            return
          }
          if (data.type === 'auth_ok') {
            retriesRef.current = 0
            setConnected(true)
            return
          }
          if (data.type === 'auth_failed') {
            ws.close()
            return
          }
          onMessageRef.current?.(data)
        } catch {
          // ignore non-JSON messages
        }
      }

      ws.onclose = () => {
        clearTimeout(connectTimeout.current)
        setConnected(false)
        wsRef.current = null
        if (mountedRef.current && effectiveEnabled) {
          // Exponential backoff with jitter
          const delay = Math.min(BASE_DELAY * 2 ** retriesRef.current, MAX_DELAY)
          const jitter = delay * 0.5 * Math.random()
          retriesRef.current++
          reconnectTimer.current = setTimeout(connect, delay + jitter)
        }
      }

      ws.onerror = () => {
        ws.close()
      }
    }

    connect()
    return () => {
      mountedRef.current = false
      clearTimeout(reconnectTimer.current)
      clearTimeout(connectTimeout.current)
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [stableChannels, effectiveEnabled])

  return { connected }
}
