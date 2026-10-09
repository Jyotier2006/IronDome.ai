import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { subscribe } from '@services/realtimeTransportClient'
import { CLASS_ORDER, SEVERITY } from '@/constants/threatModel'

const MAX_INCIDENTS = 400
const MAX_CLEARED = 1000
const TRIAGE_KEY = 'irondome.triage'

// Triage state (acknowledged / cleared) is kept per sensor run in this browser: a page
// reload keeps it, a sensor restart - whose incidents are all new - starts clean.
function loadTriage(bootId) {
  try {
    const t = JSON.parse(localStorage.getItem(TRIAGE_KEY) || 'null')
    if (t && t.boot_id === bootId) return { acked: t.acked || {}, cleared: t.cleared || [] }
  } catch { /* storage blocked or corrupt: start clean */ }
  return { acked: {}, cleared: [] }
}

function saveTriage(bootId, acked, cleared) {
  try {
    localStorage.setItem(TRIAGE_KEY, JSON.stringify({ boot_id: bootId, acked, cleared }))
  } catch { /* storage blocked: triage still works until the page is reloaded */ }
}

const byNewest = (a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)

/**
 * Incident feed. The sensor already correlates raw per-window alerts into one
 * incident per (threat class, entity); updates bump occurrences / confidence.
 * Acknowledgement is an analyst-side workflow state only - nothing is sent
 * back toward the monitored network.
 */
export default function useIncidentStore() {
  const [incidents, setIncidents] = useState([])
  const [acked, setAcked] = useState({})
  const [cleared, setCleared] = useState([])                   // incident ids removed with "Clear ack'd"
  const [bootId, setBootId] = useState(undefined)              // undefined until the first hello
  const [lastNew, setLastNew] = useState(null)                 // latest newly raised incident (never a snapshot)
  const [statusFilter, setStatusFilter] = useState('all')      // all | open | acknowledged
  const [classFilter, setClassFilter] = useState(null)         // threat_class id | null
  const [severityFilter, setSeverityFilter] = useState(null)   // severity | null
  const [selectedId, setSelectedId] = useState(null)
  const bootRef = useRef(undefined)
  const clearedRef = useRef(new Set())

  useEffect(() => {
    const unsubs = [
      subscribe('hello', (h) => {
        const id = h.boot_id ?? null
        if (id === bootRef.current) return                     // reconnected to the same sensor run
        const restarted = bootRef.current !== undefined
        bootRef.current = id
        const triage = loadTriage(id)
        clearedRef.current = new Set(triage.cleared)
        setBootId(id)
        setAcked(triage.acked)
        setCleared(triage.cleared)
        if (restarted) {
          setIncidents([])
          setSelectedId(null)
          setLastNew(null)
        }
      }),
      subscribe('incidents_snapshot', (list) => {
        if (!Array.isArray(list)) return
        setIncidents((prev) => {
          const byId = new Map(prev.map((i) => [i.incident_id, i]))
          list.forEach((i) => { if (!clearedRef.current.has(i.incident_id)) byId.set(i.incident_id, i) })
          return [...byId.values()].sort(byNewest).slice(0, MAX_INCIDENTS)
        })
      }),
      subscribe('alert', (inc) => {
        setIncidents((prev) => [inc, ...prev.filter((i) => i.incident_id !== inc.incident_id)].slice(0, MAX_INCIDENTS))
        setLastNew(inc)
      }),
      subscribe('alert_update', (u) => {
        setIncidents((prev) => prev.map((i) => (i.incident_id === u.incident_id ? { ...i, ...u } : i)))
      }),
    ]
    return () => unsubs.forEach((u) => u())
  }, [])

  useEffect(() => {
    if (bootId !== undefined) saveTriage(bootId, acked, cleared)
  }, [bootId, acked, cleared])

  const isAcked = useCallback((id) => Boolean(acked[id]), [acked])

  const filtered = useMemo(() => incidents.filter((i) => {
    if (statusFilter === 'open' && acked[i.incident_id]) return false
    if (statusFilter === 'acknowledged' && !acked[i.incident_id]) return false
    if (classFilter && i.threat_class !== classFilter) return false
    if (severityFilter && i.severity !== severityFilter) return false
    return true
  }), [incidents, acked, statusFilter, classFilter, severityFilter])

  const stats = useMemo(() => {
    const bySeverity = Object.fromEntries(Object.keys(SEVERITY).map((s) => [s, 0]))
    const byClass = Object.fromEntries(CLASS_ORDER.map((c) => [c, { count: 0, open: 0, last: null, maxConf: 0, techniques: {}, occurrences: 0 }]))
    let open = 0
    for (const i of incidents) {
      const isOpen = !acked[i.incident_id]
      if (isOpen) {
        open += 1
        bySeverity[i.severity] = (bySeverity[i.severity] || 0) + 1
      }
      const c = byClass[i.threat_class]
      if (!c) continue
      c.count += 1
      c.open += isOpen ? 1 : 0
      c.occurrences += i.occurrences || 1
      c.maxConf = Math.max(c.maxConf, i.confidence || 0)
      c.techniques[i.technique_label || i.technique] = (c.techniques[i.technique_label || i.technique] || 0) + 1
      if (!c.last || Date.parse(i.last_seen || i.timestamp) > Date.parse(c.last)) c.last = i.last_seen || i.timestamp
    }
    return { total: incidents.length, open, bySeverity, byClass }
  }, [incidents, acked])

  const acknowledge = useCallback((id) => setAcked((a) => ({ ...a, [id]: new Date().toISOString() })), [])
  const acknowledgeAll = useCallback(() => {
    const now = new Date().toISOString()
    setAcked((a) => {
      const next = { ...a }
      incidents.forEach((i) => { if (!next[i.incident_id]) next[i.incident_id] = now })
      return next
    })
  }, [incidents])
  const clearAcknowledged = useCallback(() => {
    const ids = incidents.filter((i) => acked[i.incident_id]).map((i) => i.incident_id)
    if (!ids.length) return
    // remembered so a reconnect snapshot does not bring the cleared incidents back
    const next = [...cleared, ...ids].slice(-MAX_CLEARED)
    clearedRef.current = new Set(next)
    setCleared(next)
    setIncidents((prev) => prev.filter((i) => !acked[i.incident_id]))
  }, [incidents, acked, cleared])

  const selected = useMemo(() => incidents.find((i) => i.incident_id === selectedId) || null, [incidents, selectedId])

  return {
    incidents, filtered, stats, acked, isAcked, lastNew,
    statusFilter, setStatusFilter, classFilter, setClassFilter, severityFilter, setSeverityFilter,
    selected, setSelectedId, acknowledge, acknowledgeAll, clearAcknowledged,
  }
}
