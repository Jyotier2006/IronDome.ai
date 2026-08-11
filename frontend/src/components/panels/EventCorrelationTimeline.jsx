import { useState, useEffect, useMemo, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const eventTypes = {
  network: { color: 'text-accent-purple', label: 'Blocked' },
  alert: { color: 'text-status-warning', label: 'Alert' },
  error: { color: 'text-status-critical', label: 'Critical' },
}

const EventIcon = ({ type }) => {
  const icons = {
    network: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>,
    alert: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>,
    error: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>,
  }
  return icons[type] || icons.alert
}

const formatAttackType = (type) => type?.replace(/_/g, ' ') || 'traffic'

export default function TimelinePanel({ alerts = [], droppedPackets = [] }) {
  const [isPaused, setIsPaused] = useState(false)
  const [pausedSnapshot, setPausedSnapshot] = useState(null)
  const [isHovered, setIsHovered] = useState(false)
  const scrollRef = useRef(null)

  const liveEvents = useMemo(() => {
    const fromAlerts = alerts.map((alert) => ({
      id: `alert-${alert.id}`,
      type: alert.severity === 'critical' ? 'error' : 'alert',
      message: alert.title,
      source: alert.source || 'Detection Engine',
      timestamp: new Date(alert.timestamp).getTime() || Date.now(),
    }))

    const fromDropped = droppedPackets.map((packet, i) => ({
      id: `dropped-${packet.timestamp}-${i}`,
      type: 'network',
      message: `Blocked ${formatAttackType(packet.attack_type)} from ${packet.source_ip || 'unknown IP'}`,
      source: 'Response Engine',
      timestamp: new Date(packet.timestamp).getTime() || Date.now(),
    }))

    return [...fromAlerts, ...fromDropped]
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 50)
  }, [alerts, droppedPackets])

  const events = isPaused && pausedSnapshot ? pausedSnapshot : liveEvents

  const handleTogglePause = () => {
    setIsPaused((prev) => {
      const next = !prev
      setPausedSnapshot(next ? liveEvents : null)
      return next
    })
  }

  useEffect(() => {
    if (scrollRef.current && !isHovered && !isPaused) {
      scrollRef.current.scrollTop = 0
    }
  }, [events, isHovered, isPaused])

  const getRelativeTime = (timestamp) => {
    const seconds = Math.floor((Date.now() - timestamp) / 1000)
    if (seconds < 0) return 'just now'
    if (seconds < 60) return `${seconds}s ago`
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
    return `${Math.floor(seconds / 3600)}h ago`
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-section font-medium text-text-primary flex items-center gap-2">
          <svg className="w-5 h-5 text-accent-cyan" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          Live Timeline
        </h3>
        <div className="flex items-center gap-2">
          <span className="text-caption text-text-muted">{events.length} events</span>
          <button
            onClick={handleTogglePause}
            className={`p-1.5 rounded-glass transition-colors ${
              isPaused
                ? 'bg-status-warning/20 text-status-warning'
                : 'hover:bg-surface-glass-hover text-text-secondary'
            }`}
            title={isPaused ? 'Resume Feed' : 'Pause Feed'}
          >
            {isPaused ? <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> : <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
          </button>
        </div>
      </div>

      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto space-y-1 pr-1"
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
      >
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-text-muted opacity-50">
            <svg className="w-8 h-8 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
            <span className="text-caption">No alerts or blocked traffic yet</span>
          </div>
        ) : (
          <AnimatePresence>
            {events.map((event) => {
              const config = eventTypes[event.type] || eventTypes.alert
              return (
                <motion.div
                  key={event.id}
                  initial={{ opacity: 0, y: -20, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  transition={{ duration: 0.2 }}
                  className="glass-card-hover p-2.5 cursor-pointer"
                >
                  <div className="flex items-start gap-2">
                    <span className={`mt-0.5 ${config.color}`}><EventIcon type={event.type} /></span>
                    <div className="flex-1 min-w-0">
                      <p className="text-body text-text-primary truncate">{event.message}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className={`text-caption ${config.color}`}>{config.label}</span>
                        <span className="text-caption text-text-muted">•</span>
                        <span className="text-caption text-text-muted">{event.source}</span>
                        <span className="text-caption text-text-muted ml-auto font-mono">
                          {getRelativeTime(event.timestamp)}
                        </span>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )
            })}
          </AnimatePresence>
        )}
      </div>

      <div className="mt-3 pt-3 border-t border-white/5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <motion.span
            className={`w-2 h-2 rounded-full ${isPaused ? 'bg-status-warning' : 'bg-status-normal'}`}
            animate={isPaused ? {} : { opacity: [1, 0.5, 1] }}
            transition={{ duration: 1, repeat: Infinity }}
          />
          <span className="text-caption text-text-muted">
            {isPaused ? 'Feed paused' : 'Live'}
          </span>
        </div>
        <span className="text-caption text-text-muted">Alerts + blocked traffic, merged</span>
      </div>
    </div>
  )
}
