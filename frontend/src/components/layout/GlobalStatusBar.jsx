import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import CountUp from '@/components/common/AnimatedMetricCounter'
import { Icon } from '@components/common/ui'
import { USE_MOCK } from '@services/realtimeTransportClient'

const DomeMark = () => (
  <svg width="20" height="20" viewBox="0 0 64 64" className="shrink-0" aria-hidden="true">
    <path d="M10 50 H54" stroke="white" strokeWidth="4.5" strokeLinecap="round" />
    <path d="M14 50 A18 18 0 0 1 50 50" fill="none" stroke="white" strokeWidth="4.5" strokeLinecap="round" />
    <circle cx="32" cy="21" r="3.4" fill="white" />
    <path d="M32 9 V15 M32 27 V31 M18 21 H24 M40 21 H46" stroke="white" strokeWidth="3" strokeLinecap="round" />
  </svg>
)

function Kpi({ label, value, unit, decimals = 0 }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="text-text-muted">{label}</span>
      <span className="font-mono font-medium text-text-primary">
        {Number.isFinite(value) ? <CountUp value={value} decimals={decimals} /> : '-'}
      </span>
      {unit && <span className="text-text-muted">{unit}</span>}
    </div>
  )
}

const POSTURE = [
  { icon: 'oneway', label: 'Receive-only', title: 'Ingest arrives through a one-way uplink; the sensor never transmits to the source' },
  { icon: 'eyeoff', label: 'No decryption', title: 'TLS / QUIC analysed from metadata only' },
  { icon: 'lock', label: 'No return path', title: 'No block / isolate / rate-limit action exists' },
]

export default function GlobalStatusBar({ connected, stats, openIncidents, autoAttacks = false, paused, onTogglePause, onOpenPalette }) {
  const [now, setNow] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const p95 = stats?.latency?.p95_ms

  return (
    <header className="h-14 px-4 flex items-center justify-between gap-4 border-b border-white/[0.06] bg-background-secondary/75 backdrop-blur-lg relative z-10">
      <div className="flex items-center gap-3 min-w-0">
        <motion.div className="w-8 h-8 rounded-lg bg-gradient-to-br from-accent-cyan to-accent-purple flex items-center justify-center shadow-glow-cyan shrink-0"
                    whileHover={{ scale: 1.06, rotate: -3 }} transition={{ type: 'spring', stiffness: 300, damping: 15 }}>
          <DomeMark />
        </motion.div>
        <div className="min-w-0">
          <h1 className="font-display text-body font-semibold text-text-primary tracking-wide leading-none">
            IronDome<span className="text-accent-cyan">.ai</span>
          </h1>
          <p className="text-[11px] text-text-muted truncate">Passive threat intelligence · unidirectional IP traffic</p>
        </div>
        <span className="hidden xl:inline-flex items-center gap-1.5 ml-1 px-2 py-1 rounded-md bg-white/[0.04] border border-white/10 text-[11px] text-text-secondary whitespace-nowrap"
              title="Smart India Hackathon - problem statement 26145 (National Technical Research Organisation)">
          SIH · PS 26145 · NTRO
        </span>
      </div>

      <div className="hidden lg:flex items-center gap-2">
        <span className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-white/[0.03] border border-white/[0.08] text-[11px] text-text-secondary">
          <motion.span className={`w-2 h-2 rounded-full ${connected ? 'bg-status-normal' : 'bg-status-critical'}`}
                       animate={{ opacity: [1, 0.45, 1] }} transition={{ duration: 2, repeat: Infinity }} />
          {USE_MOCK ? 'Demo data' : connected ? 'Sensor live' : 'Sensor offline'}
        </span>
        {autoAttacks && connected && (
          <span title="The sensor was started with IRONDOME_AUTO_SCENARIOS=on: the traffic lab injects a random attack every ~2 minutes"
                className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-status-warning/10 border border-status-warning/30 text-[11px] text-text-primary whitespace-nowrap">
            <Icon name="beaker" className="w-3.5 h-3.5" /> Auto attacks on
          </span>
        )}
        {POSTURE.map((p) => (
          <span key={p.label} title={p.title}
                className="hidden 2xl:inline-flex items-center gap-1 px-2 py-1 rounded-full bg-white/[0.03] border border-white/[0.08] text-[11px] text-text-secondary">
            <Icon name={p.icon} className="w-3.5 h-3.5" /> {p.label}
          </span>
        ))}
      </div>

      <div className="hidden md:flex items-center gap-4 text-[12px]">
        <Kpi label="Flows/s" value={stats?.flows_per_s} />
        <Kpi label="Mbps" value={stats?.mbps} decimals={1} />
        <Kpi label="p95" value={p95 != null ? p95 / 1000 : NaN} unit="s" decimals={1} />
        <Kpi label="Open" value={openIncidents} />
      </div>

      <div className="flex items-center gap-3 shrink-0">
        <div className="text-right hidden lg:block whitespace-nowrap">
          <p className="text-body font-mono text-text-primary tabular-nums leading-none">{now.toLocaleTimeString('en-GB', { hour12: false })}</p>
          <p className="text-[11px] text-text-muted">{now.toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' })}</p>
        </div>
        <button type="button" onClick={onOpenPalette}
                className="hidden sm:flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.08] text-text-muted hover:text-text-secondary"
                title="Command palette">
          <Icon name="search" className="w-3.5 h-3.5" />
          <kbd className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10 whitespace-nowrap">Ctrl K</kbd>
        </button>
        <button type="button" onClick={onTogglePause} title={paused ? 'Resume flow view' : 'Pause flow view'}
                className={`p-2 rounded-lg transition-colors ${paused ? 'bg-status-warning/20 text-text-primary' : 'hover:bg-white/[0.06] text-text-secondary'}`}>
          <Icon name={paused ? 'play' : 'pause'} className="w-5 h-5" />
        </button>
      </div>
    </header>
  )
}
