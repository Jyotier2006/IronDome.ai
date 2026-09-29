import { memo, useEffect, useMemo, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { ClassDot, Icon } from '@components/common/ui'
import { injectScenario } from '@services/httpApiClient'
import { toast } from '@utils/notificationEventBus'
import { CLASS_ORDER, classInfo } from '@/constants/threatModel'

/**
 * Traffic Lab - drives the *simulated IP data* (the production side of the diode).
 * Injecting a scenario changes what the simulated network does; the sensor still
 * only observes the resulting one-way flow stream and must detect it on its own.
 */
function TrafficLabController({ scenarios, runs, available }) {
  const [open, setOpen] = useState(false)
  const [intensity, setIntensity] = useState(1)
  const [busy, setBusy] = useState(null)
  const [, forceTick] = useState(0)

  useEffect(() => {
    const onOpen = () => setOpen(true)
    window.addEventListener('irondome:open-lab', onOpen)
    return () => window.removeEventListener('irondome:open-lab', onOpen)
  }, [])

  useEffect(() => {
    if (!open) return undefined
    const t = setInterval(() => forceTick((n) => n + 1), 1000)
    return () => clearInterval(t)
  }, [open])

  const grouped = useMemo(() => {
    const byClass = {}
    for (const s of scenarios || []) {
      const key = CLASS_ORDER.includes(s.threat_class) ? s.threat_class : 'multiple'
      ;(byClass[key] = byClass[key] || []).push(s)
    }
    return [...CLASS_ORDER, 'multiple'].filter((k) => byClass[k]).map((k) => [k, byClass[k]])
  }, [scenarios])

  const now = Date.now() / 1000
  const active = (runs || []).filter((r) => r.end_wall && r.end_wall > now)

  const inject = async (s) => {
    setBusy(s.id)
    try {
      await injectScenario(s.id, intensity)
      toast(`Traffic lab: ${s.title} injected - watch for the detection`, 'info', 3200)
    } catch (e) {
      toast(`Could not inject: ${e.message}`, 'warning', 3200)
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <button type="button" onClick={() => setOpen((o) => !o)}
              className={`fixed top-1/2 -translate-y-1/2 z-50 transition-all duration-300 ${open ? 'right-[360px]' : 'right-0'}`}
              aria-label="Traffic lab">
        <span className={`flex items-center gap-1 px-2 py-4 rounded-l-lg border border-r-0 border-white/10 ${open ? 'bg-white/[0.12] text-text-primary' : 'bg-[#141a29] text-text-secondary hover:text-text-primary'}`}>
          <Icon name="beaker" className="w-5 h-5" />
        </span>
      </button>

      <AnimatePresence>
        {open && (
          <motion.aside initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
                        transition={{ type: 'spring', damping: 26, stiffness: 300 }}
                        className="fixed top-0 right-0 h-full w-[360px] z-40 bg-[#0d111c] border-l border-white/10 shadow-2xl flex flex-col">
            <div className="p-4 border-b border-white/[0.07]">
              <div className="flex items-center justify-between">
                <h3 className="text-[15px] font-semibold text-text-primary flex items-center gap-2"><Icon name="beaker" /> Traffic lab</h3>
                <button type="button" onClick={() => setOpen(false)} className="p-1.5 rounded-lg hover:bg-white/[0.06] text-text-muted" aria-label="Close"><Icon name="x" /></button>
              </div>
              <p className="mt-1 text-[12px] text-text-secondary leading-snug">
                Injects labelled attacks into the <b className="text-text-primary font-medium">simulated network</b> (the production side of the diode).
                The sensor is not told - it must detect each one from the one-way flow stream.
              </p>
              <label className="mt-3 flex items-center gap-3 text-[12px] text-text-secondary">
                Intensity
                <input type="range" min="0.5" max="2" step="0.1" value={intensity} onChange={(e) => setIntensity(+e.target.value)}
                       className="flex-1 accent-slate-300" />
                <span className="w-9 text-right tabular text-text-primary">{intensity.toFixed(1)}×</span>
              </label>
            </div>

            {active.length > 0 && (
              <div className="px-4 py-3 border-b border-white/[0.07]">
                <p className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">Running now</p>
                {active.map((r) => (
                  <div key={r.id} className="flex items-center justify-between text-[12px] py-0.5">
                    <span className="text-text-primary truncate">{r.title}</span>
                    <span className="text-text-muted tabular">{Math.max(0, Math.round(r.end_wall - now))} s left</span>
                  </div>
                ))}
              </div>
            )}

            <div className="flex-1 overflow-y-auto p-4 space-y-4 thin-scrollbar">
              {!available && (
                <p className="text-[12px] text-text-secondary">The sensor's built-in traffic lab is off (IRONDOME_LAB=off). Replay captures into UDP/2055 with scripts/replay_capture.py instead.</p>
              )}
              {grouped.map(([cls, list]) => (
                <div key={cls}>
                  <p className="text-[11px] text-text-muted mb-1.5 flex items-center gap-1.5">
                    {cls !== 'multiple' && <ClassDot cls={cls} />}
                    {cls === 'multiple' ? 'Multi-stage' : `PS (${classInfo(cls).ps}) ${classInfo(cls).label}`}
                  </p>
                  <div className="space-y-1.5">
                    {list.map((s) => (
                      <button key={s.id} type="button" disabled={!available || busy === s.id} onClick={() => inject(s)}
                              className="w-full text-left p-2.5 rounded-lg bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.07] transition-colors disabled:opacity-50">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[12px] font-medium text-text-primary">{s.title}</span>
                          <span className="text-[10px] font-mono text-text-muted shrink-0">{s.duration}s</span>
                        </div>
                        <p className="text-[11px] text-text-muted font-mono mt-0.5">{s.tool}</p>
                        <p className="text-[11px] text-text-secondary mt-0.5 leading-snug">{s.description}</p>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            <p className="p-3 border-t border-white/[0.07] text-[11px] text-text-muted text-center">Simulated IP data · the sensor only observes</p>
          </motion.aside>
        )}
      </AnimatePresence>
    </>
  )
}

export default memo(TrafficLabController)
