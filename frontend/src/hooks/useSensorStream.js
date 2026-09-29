import { useCallback, useEffect, useRef, useState } from 'react'
import { connectSensor, subscribe } from '@services/realtimeTransportClient'

const HISTORY_POINTS = 180   // 3 minutes of 1 s samples
const MAX_FLOWS = 150

const flowKey = (f) => `${f.flow_id}|${f.ts}`

function mergeFlows(batch, prev) {
  const seen = new Set(prev.map(flowKey))
  const fresh = batch.filter((f) => !seen.has(flowKey(f)))
  return [...fresh, ...prev].slice(0, MAX_FLOWS)
}

/**
 * Live feed from the passive sensor: capabilities (hello), throughput history,
 * the observed-flow sample, and traffic-lab scenario runs.
 */
export default function useSensorStream() {
  const [connected, setConnected] = useState(false)
  const [meta, setMeta] = useState(null)
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState([])
  const [flows, setFlows] = useState([])
  const [runs, setRuns] = useState([])
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(false)

  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  useEffect(() => {
    connectSensor()
    const unsubs = [
      subscribe('connect', () => setConnected(true)),
      subscribe('disconnect', () => setConnected(false)),
      subscribe('connect_error', () => setConnected(false)),
      subscribe('hello', (h) => {
        setMeta(h)
        if (Array.isArray(h.active_runs)) setRuns(h.active_runs)
      }),
      subscribe('flow_stats', (s) => {
        setStats(s)
        setHistory((prev) => [...prev, {
          t: Math.round((s.ts || Date.now() / 1000) * 1000),
          fps: s.flows_per_s,
          mbps: s.mbps,
          p95: s.latency?.p95_ms ?? null,
        }].slice(-HISTORY_POINTS))
      }),
      subscribe('flows_snapshot', (list) => setFlows(Array.isArray(list) ? list.slice(0, MAX_FLOWS) : [])),
      subscribe('flows_batch', (batch) => {
        if (!pausedRef.current && Array.isArray(batch)) setFlows((prev) => mergeFlows(batch, prev))
      }),
      subscribe('scenario', (run) => setRuns((prev) => [run, ...prev.filter((r) => r.id !== run.id)].slice(0, 30))),
    ]
    return () => unsubs.forEach((u) => u())
  }, [])

  const peak = Math.max(stats?.peak_flows_per_s || 0, ...history.map((h) => h.fps || 0))
  const togglePause = useCallback(() => setPaused((p) => !p), [])
  const clearFlows = useCallback(() => setFlows([]), [])

  return { connected, meta, stats, history, peak, flows, runs, paused, togglePause, clearFlows }
}
