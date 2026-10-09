import { useCallback, useEffect, useRef, useState } from 'react'
import { connectSensor, subscribe } from '@services/realtimeTransportClient'

const HISTORY_POINTS = 180   // 3 minutes of 1 s samples
const MAX_FLOWS = 150
const MAX_RUNS = 30

const flowKey = (f) => `${f.flow_id}|${f.ts}`

function mergeFlows(batch, prev) {
  const seen = new Set(prev.map(flowKey))
  const fresh = batch.filter((f) => !seen.has(flowKey(f)))
  return [...fresh, ...prev].slice(0, MAX_FLOWS)
}

/**
 * Live feed from the passive sensor: capabilities (hello), throughput history,
 * per-source ingest counters, the observed-flow sample, and traffic-lab scenario runs.
 */
export default function useSensorStream() {
  const [connected, setConnected] = useState(false)
  const [meta, setMeta] = useState(null)
  const [stats, setStats] = useState(null)
  const [sources, setSources] = useState([])
  const [history, setHistory] = useState([])
  const [flows, setFlows] = useState([])
  const [runs, setRuns] = useState([])
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(false)
  const bootRef = useRef(null)

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
        // A different boot id means the sensor restarted: the previous run's history,
        // flow sample and scenario runs no longer describe it. A plain reconnect keeps them.
        const restarted = bootRef.current !== null && h.boot_id !== bootRef.current
        bootRef.current = h.boot_id ?? null
        if (restarted) {
          setStats(null)
          setHistory([])
          setFlows([])
        }
        setMeta(h)
        setSources(Array.isArray(h.sources) ? h.sources : [])
        const active = Array.isArray(h.active_runs) ? h.active_runs : []
        setRuns((prev) => {
          const base = restarted ? [] : prev
          const fresh = active.filter((a) => !base.some((r) => r.id === a.id))
          return [...fresh, ...base].sort((a, b) => (b.start_wall || 0) - (a.start_wall || 0)).slice(0, MAX_RUNS)
        })
      }),
      subscribe('flow_stats', (s) => {
        setStats(s)
        if (Array.isArray(s.sources)) setSources(s.sources)
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
      subscribe('scenario', (run) => setRuns((prev) => [run, ...prev.filter((r) => r.id !== run.id)].slice(0, MAX_RUNS))),
    ]
    return () => unsubs.forEach((u) => u())
  }, [])

  const peak = Math.max(stats?.peak_flows_per_s || 0, ...history.map((h) => h.fps || 0))
  const togglePause = useCallback(() => setPaused((p) => !p), [])
  const clearFlows = useCallback(() => setFlows([]), [])

  return { connected, meta, stats, sources, history, peak, flows, runs, paused, togglePause, clearFlows }
}
