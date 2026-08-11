import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import CountUp from '@/components/common/AnimatedMetricCounter'

const DomeMark = () => (
  <svg width="20" height="20" viewBox="0 0 64 64" className="shrink-0">
    <path d="M10 50 H54" stroke="white" strokeWidth="4.5" strokeLinecap="round" />
    <path d="M14 50 A18 18 0 0 1 50 50" fill="none" stroke="white" strokeWidth="4.5" strokeLinecap="round" />
    <circle cx="32" cy="21" r="3.4" fill="white" />
    <path d="M32 9 V15 M32 27 V31 M18 21 H24 M40 21 H46" stroke="white" strokeWidth="3" strokeLinecap="round" />
  </svg>
)

const StatPill = ({ label, value, tone = 'text-text-secondary', suffix = '', decimals = 0 }) => (
  <div className="flex items-center gap-1.5">
    <span className="text-text-muted">{label}</span>
    <span className={`font-mono font-medium ${tone}`}>
      <CountUp value={value} decimals={decimals} />{suffix}
    </span>
  </div>
)

export default function Topbar({ connectionStatus = 'connected', stats, isPaused = false, onTogglePause, onOpenPalette }) {
  const [currentTime, setCurrentTime] = useState(new Date())

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000)
    return () => clearInterval(timer)
  }, [])

  const formatTime = (date) => {
    return date.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })
  }

  const formatDate = (date) => {
    return date.toLocaleDateString('en-US', {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    })
  }

  const statusConfig = {
    connected: { color: 'bg-status-normal', text: 'Connected', glow: 'shadow-glow-green' },
    degraded: { color: 'bg-status-warning', text: 'Degraded', glow: 'shadow-glow-amber' },
    disconnected: { color: 'bg-status-critical', text: 'Disconnected', glow: 'shadow-glow-red' },
  }

  const status = statusConfig[connectionStatus] || statusConfig.connected
  const eventsDisplay = stats?.eventsRate > 999 ? Math.round(stats.eventsRate / 100) / 10 : Math.round(stats?.eventsRate || 0)
  const eventsSuffix = stats?.eventsRate > 999 ? 'k/min' : '/min'

  return (
    <header className="h-14 px-4 flex items-center justify-between border-b border-white/[0.06] bg-background-secondary/70 backdrop-blur-lg relative z-10">
      <div className="flex items-center gap-3">
        <motion.div
          className="w-8 h-8 rounded-lg bg-gradient-to-br from-accent-cyan to-accent-purple flex items-center justify-center shadow-glow-cyan"
          whileHover={{ scale: 1.06, rotate: -3 }}
          transition={{ type: 'spring', stiffness: 300, damping: 15 }}
        >
          <DomeMark />
        </motion.div>
        <div>
          <h1 className="font-display text-body font-semibold text-text-primary tracking-wide leading-none flex items-baseline gap-1.5">
            IronDome<span className="text-accent-cyan">.ai</span>
          </h1>
          <p className="text-caption text-text-muted -mt-0.5">Security Operations Center</p>
        </div>
      </div>

      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-surface-glass border border-white/[0.07]">
          <motion.span
            className={`w-2 h-2 rounded-full ${status.color} ${status.glow}`}
            animate={{ opacity: [1, 0.5, 1] }}
            transition={{ duration: 2, repeat: Infinity }}
          />
          <span className="text-caption text-text-secondary">{status.text}</span>
        </div>

        <div className="hidden md:flex items-center gap-4 text-caption">
          <StatPill label="Events:" value={eventsDisplay} suffix={eventsSuffix} tone="text-status-normal" decimals={stats?.eventsRate > 999 ? 1 : 0} />
          <StatPill
            label="Alerts:"
            value={stats?.activeAlerts || 0}
            tone={stats?.activeAlerts > 0 ? 'text-status-warning' : 'text-text-secondary'}
          />
          <StatPill
            label="Blocked:"
            value={stats?.blockedCount || 0}
            tone={stats?.blockedCount > 0 ? 'text-status-critical' : 'text-text-secondary'}
          />
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="text-right hidden sm:block">
          <p className="text-body font-mono text-text-primary tabular-nums">{formatTime(currentTime)}</p>
          <p className="text-caption text-text-muted -mt-0.5">{formatDate(currentTime)}</p>
        </div>

        <div className="flex items-center gap-2">
          <motion.button
            onClick={onOpenPalette}
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-glass bg-surface-glass hover:bg-surface-glass-hover border border-white/[0.07] text-text-muted hover:text-text-secondary transition-colors"
            title="Command palette"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-4.35-4.35M17 11a6 6 0 11-12 0 6 6 0 0112 0z" /></svg>
            <span className="text-caption">Search</span>
            <kbd className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10">Ctrl K</kbd>
          </motion.button>
          <button
            onClick={onTogglePause}
            className={`p-2 rounded-glass transition-colors ${
              isPaused ? 'bg-status-warning/20 text-status-warning' : 'hover:bg-surface-glass-hover text-text-secondary'
            }`}
            title={isPaused ? 'Resume Feed' : 'Pause Feed'}
          >
            {isPaused ? (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            ) : (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            )}
          </button>
        </div>
      </div>
    </header>
  )
}
