import { memo, useMemo } from 'react'
import { ClassDot, Icon, SeverityBadge } from '@components/common/ui'
import { classInfo, clockTime, entityText } from '@/constants/threatModel'

/**
 * Chronological view: detections (incidents) interleaved with traffic-lab
 * scenario injections, so the delay from "attack started" to "alert raised"
 * is visible at a glance.
 */
function TimelinePanel({ incidents, runs, onOpenIncident }) {
  const events = useMemo(() => {
    const inc = incidents.map((i) => ({
      kind: 'incident', id: i.incident_id, t: Date.parse(i.timestamp), item: i,
    }))
    const lab = (runs || []).filter((r) => r.start_wall).map((r) => ({
      kind: 'run', id: `run-${r.id}`, t: r.start_wall * 1000, item: r,
    }))
    return [...inc, ...lab].sort((a, b) => b.t - a.t).slice(0, 120)
  }, [incidents, runs])

  // time from the most recent matching injection to each detection
  const ttd = useMemo(() => {
    const out = {}
    const starts = (runs || []).filter((r) => r.start_wall)
    for (const i of incidents) {
      const t = Date.parse(i.timestamp)
      const run = starts
        .filter((r) => (r.threat_class === i.threat_class || r.threat_class === 'multiple') && r.start_wall * 1000 <= t && t - r.start_wall * 1000 < 300000)
        .sort((a, b) => b.start_wall - a.start_wall)[0]
      if (run) out[i.incident_id] = (t - run.start_wall * 1000) / 1000
    }
    return out
  }, [incidents, runs])

  if (!events.length) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-text-muted">
        <Icon name="clock" className="w-8 h-8 mb-2 opacity-60" />
        <p className="text-caption text-text-secondary">No detections yet</p>
        <p className="text-[11px] mt-1">Inject a scenario from the Traffic Lab to see injection → detection on this timeline.</p>
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto pr-1 thin-scrollbar">
      <ol className="relative border-l border-white/[0.08] ml-2">
        {events.map((e) => {
          if (e.kind === 'run') {
            const r = e.item
            return (
              <li key={e.id} className="ml-4 mb-3">
                <span className="absolute -left-[5px] mt-1.5 w-2.5 h-2.5 rounded-full bg-[#111521] border border-white/40" />
                <div className="flex items-center gap-2 text-[12px]">
                  <span className="font-mono text-text-muted tabular">{clockTime(r.start_wall)}</span>
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-white/[0.05] border border-white/10 text-[10px] text-text-secondary">
                    <Icon name="beaker" className="w-3 h-3" /> Traffic lab {r.auto ? '(auto)' : ''}
                  </span>
                  <span className="text-text-primary">Injected: {r.title}</span>
                  <span className="text-text-muted">· PS ({r.ps_ref}) · {r.tool}</span>
                </div>
              </li>
            )
          }
          const i = e.item
          const info = classInfo(i.threat_class)
          return (
            <li key={e.id} className="ml-4 mb-3">
              <span className="absolute -left-[5px] mt-2 w-2.5 h-2.5 rounded-full" style={{ background: info.color }} />
              <button type="button" onClick={() => onOpenIncident?.(i.incident_id)}
                      className="w-full text-left glass-card-hover px-3 py-2">
                <div className="flex flex-wrap items-center gap-2 text-[12px]">
                  <span className="font-mono text-text-muted tabular">{clockTime(i.timestamp)}</span>
                  <ClassDot cls={i.threat_class} />
                  <span className="text-text-muted font-mono">({info.ps})</span>
                  <span className="text-text-primary font-medium">{i.technique_label}</span>
                  <SeverityBadge severity={i.severity} />
                  <span className="text-text-secondary">{(i.confidence * 100).toFixed(0)}% conf.</span>
                  {ttd[i.incident_id] != null && (
                    <span className="ml-auto text-[11px] text-text-secondary">detected {ttd[i.incident_id].toFixed(1)} s after injection</span>
                  )}
                </div>
                <p className="mt-0.5 text-[11px] text-text-muted font-mono truncate">{entityText(i)} · ×{i.occurrences || 1}</p>
              </button>
            </li>
          )
        })}
      </ol>
    </div>
  )
}

export default memo(TimelinePanel)
