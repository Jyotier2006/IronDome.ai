import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const BOOT_LINES = [
  { label: 'Ingest Service', detail: 'telemetry uplink :8001' },
  { label: 'Detection Engine', detail: '7 rules + ML layer :8002' },
  { label: 'Alert Manager', detail: 'correlation pipeline :8003' },
  { label: 'Response Engine', detail: 'playbooks armed :8004' },
  { label: 'IronDome Model Service', detail: 'threat brains :8006' },
  { label: 'Socket Uplink', detail: 'dashboard realtime channel' },
]

const LINE_INTERVAL = 220
const LINES_DONE_AT = 400 + BOOT_LINES.length * LINE_INTERVAL
const EXIT_AT = LINES_DONE_AT + 650
const EXIT_DURATION = 500

export default function BootSequence({ onDone }) {
  const [visibleLines, setVisibleLines] = useState(0)
  const [phase, setPhase] = useState('booting') // booting -> ready -> exiting
  const [shouldRender, setShouldRender] = useState(true)

  // Drive the automatic boot timeline.
  useEffect(() => {
    const timers = BOOT_LINES.map((_, i) =>
      setTimeout(() => setVisibleLines(i + 1), 400 + i * LINE_INTERVAL)
    )
    timers.push(setTimeout(() => setPhase('ready'), LINES_DONE_AT))
    timers.push(setTimeout(() => setPhase('exiting'), EXIT_AT))
    return () => timers.forEach(clearTimeout)
  }, [])

  // Any transition into 'exiting' (auto or skipped) unmounts after the exit animation.
  useEffect(() => {
    if (phase !== 'exiting') return
    const t = setTimeout(() => {
      setShouldRender(false)
      onDone?.()
    }, EXIT_DURATION)
    return () => clearTimeout(t)
  }, [phase, onDone])

  const skip = () => setPhase((p) => (p === 'exiting' ? p : 'exiting'))

  useEffect(() => {
    window.addEventListener('keydown', skip)
    return () => window.removeEventListener('keydown', skip)
  }, [])

  const progress = Math.min(100, Math.round((visibleLines / BOOT_LINES.length) * 100))

  return (
    <AnimatePresence>
      {shouldRender && (
        <motion.div
          className="fixed inset-0 z-[100] flex items-center justify-center bg-[#05070d] cursor-pointer select-none"
          onClick={skip}
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, scale: 1.03 }}
          transition={{ duration: EXIT_DURATION / 1000, ease: 'easeInOut' }}
        >
          {/* ambient glow behind mark */}
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div
              className="absolute left-1/2 top-1/2 w-[600px] h-[600px] -translate-x-1/2 -translate-y-1/2 rounded-full opacity-30 blur-3xl"
              style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.5), rgba(139,92,246,0.25) 55%, transparent 75%)' }}
            />
          </div>

          <div className="relative flex flex-col items-center w-full max-w-md px-6">
            {/* Shield mark */}
            <motion.svg
              width="72" height="72" viewBox="0 0 64 64"
              initial={{ opacity: 0, scale: 0.7 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.6, ease: 'easeOut' }}
              className="mb-4"
            >
              <defs>
                <linearGradient id="bootG" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#06b6d4" />
                  <stop offset="100%" stopColor="#8b5cf6" />
                </linearGradient>
              </defs>
              <path d="M10 50 H54" stroke="url(#bootG)" strokeWidth="4.5" strokeLinecap="round" />
              <motion.path
                d="M14 50 A18 18 0 0 1 50 50"
                fill="none" stroke="url(#bootG)" strokeWidth="4.5" strokeLinecap="round"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 1, ease: 'easeInOut' }}
              />
              <circle cx="32" cy="21" r="3.4" fill="url(#bootG)" />
              <path d="M32 9 V15 M32 27 V31 M18 21 H24 M40 21 H46" stroke="url(#bootG)" strokeWidth="3" strokeLinecap="round" />
            </motion.svg>

            <motion.h1
              className="font-display text-3xl font-semibold tracking-[0.2em] text-gradient mb-1"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.25, duration: 0.5 }}
            >
              IRONDOME
            </motion.h1>
            <motion.p
              className="text-caption text-text-muted tracking-[0.3em] uppercase mb-8"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.4, duration: 0.5 }}
            >
              IronDome.ai Security Operations Center
            </motion.p>

            {/* Boot log */}
            <div className="w-full font-mono text-xs space-y-1.5 mb-6 min-h-[132px]">
              {BOOT_LINES.map((line, i) => (
                <motion.div
                  key={line.label}
                  initial={{ opacity: 0, x: -8 }}
                  animate={i < visibleLines ? { opacity: 1, x: 0 } : {}}
                  transition={{ duration: 0.25 }}
                  className="flex items-center justify-between text-text-secondary"
                >
                  <span className="flex items-center gap-2">
                    <span className={i < visibleLines ? 'text-accent-green' : 'text-text-muted'}>
                      {i < visibleLines ? 'OK' : '..'}
                    </span>
                    {line.label}
                  </span>
                  <span className="text-text-muted">{line.detail}</span>
                </motion.div>
              ))}
            </div>

            {/* Progress bar */}
            <div className="w-full h-[3px] rounded-full bg-white/5 overflow-hidden mb-3">
              <motion.div
                className="h-full bg-gradient-to-r from-accent-cyan to-accent-purple"
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>

            <AnimatePresence>
              {phase === 'ready' && (
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="text-caption font-mono tracking-[0.2em] text-accent-green uppercase"
                >
                  All systems operational
                </motion.p>
              )}
            </AnimatePresence>

            <span className="absolute -bottom-10 text-[10px] text-text-muted tracking-widest uppercase">
              Click or press any key to skip
            </span>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
