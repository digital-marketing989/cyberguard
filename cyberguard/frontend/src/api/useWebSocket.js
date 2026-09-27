/**
 * WebSocket hook for live attack timeline feed
 * — Exponential backoff reconnect (1s → 2s → 4s → 8s → 30s max)
 */
import { useEffect, useRef, useState, useCallback } from 'react'

const MAX_BACKOFF = 30000

export function useWebSocket(url, { onMessage, maxEvents = 50 } = {}) {
  const [events, setEvents] = useState([])
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState(null)
  const [reconnectAttempt, setReconnectAttempt] = useState(0)
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)
  const mountedRef = useRef(true)
  const attemptRef = useRef(0)

  const connect = useCallback(() => {
    if (!mountedRef.current) return

    try {
      const wsUrl = url.startsWith('ws')
        ? url
        : `ws://${window.location.host}${url}`

      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        if (!mountedRef.current) return
        setConnected(true)
        setError(null)
        // Reset backoff on successful connect
        attemptRef.current = 0
        setReconnectAttempt(0)
      }

      ws.onmessage = (evt) => {
        if (!mountedRef.current) return
        try {
          const data = JSON.parse(evt.data)
          setEvents(prev => [data, ...prev].slice(0, maxEvents))
          onMessage?.(data)
        } catch (e) {
          console.warn('WS parse error:', e)
        }
      }

      ws.onclose = () => {
        if (!mountedRef.current) return
        setConnected(false)
        // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s max
        const delay = Math.min(1000 * Math.pow(2, attemptRef.current), MAX_BACKOFF)
        attemptRef.current += 1
        setReconnectAttempt(attemptRef.current)
        reconnectTimer.current = setTimeout(connect, delay)
      }

      ws.onerror = () => {
        if (!mountedRef.current) return
        setError('WebSocket connection error — retrying…')
        setConnected(false)
      }
    } catch (e) {
      setError(String(e))
    }
  }, [url, maxEvents, onMessage])

  useEffect(() => {
    mountedRef.current = true
    attemptRef.current = 0
    connect()
    return () => {
      mountedRef.current = false
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  return { events, connected, error, reconnectAttempt }
}
