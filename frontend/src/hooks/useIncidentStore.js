import { useCallback, useEffect, useMemo, useState } from 'react'
import { subscribe } from '@services/realtimeTransportClient'
import { CLASS_ORDER, SEVERITY } from '@/constants/threatModel'

const MAX_INCIDENTS = 400

/**
 * Incident feed. The sensor already correlates raw per-window alerts into one
 * incident per (threat class, entity); updates bump occurrences / confidence.
 * Acknowledgement is an analyst-side workflow state only - nothing is sent
 * back toward the monitored network.
 */
export default function useIncidentStore() {
  const [incidents, setIncidents] = useState([])
  const [acked, setAcked] = useState({})
  const [statusFilter, setStatusFilter] = useState('all')      // all | open | acknowledged
  const [classFilter, setClassFilter] = useState(null)         // threat_class id | null
  const [severityFilter, setSeverityFilter] = useState(null)   // severity | null
  const [selectedId, setSelectedId] = useState(null)

  useEffect(() => {
    const unsubs = [
      subscribe('incidents_snapshot', (list) => {
        if (!Array.isArray(list)) return
        setIncidents((prev) => {
          const byId = new Map(prev.map((i) => [i.incident_id, i]))
          list.forEach((i) => byId.set(i.incident_id, i))
          return [...byId.values()].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, MAX_INCIDENTS)
        })
      }),
      subscribe('alert', (inc) => {
        setIncidents((prev) => [inc, ...prev.filter((i) => i.incident_id !== inc.incident_id)].slice(0, MAX_INCIDENTS))
      }),
      subscribe('alert_update', (u) => {
        setIncidents((prev) => prev.map((i) => (i.incident_id === u.incident_id ? { ...i, ...u } : i)))
      }),
    ]
    return () => unsubs.forEach((u) => u())
  }, [])

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
    setIncidents((prev) => prev.filter((i) => !acked[i.incident_id]))
  }, [acked])

  const selected = useMemo(() => incidents.find((i) => i.incident_id === selectedId) || null, [incidents, selectedId])

  return {
    incidents, filtered, stats, acked, isAcked,
    statusFilter, setStatusFilter, classFilter, setClassFilter, severityFilter, setSeverityFilter,
    selected, setSelectedId, acknowledge, acknowledgeAll, clearAcknowledged,
  }
}
