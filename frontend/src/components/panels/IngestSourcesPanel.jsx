import { memo } from 'react'
import { ClassDot, Icon } from '@components/common/ui'
import { CLASS_ORDER, classInfo, fmtCompact, timeAgo } from '@/constants/threatModel'

const POSTURE = [
  { icon: 'oneway', title: 'Receive-only ingest', text: 'Flows arrive through a one-way uplink; the sensor never transmits to the source.' },
  { icon: 'eyeoff', title: 'No decryption', text: 'TLS / QUIC judged from handshake metadata and packet timing only.' },
  { icon: 'lock', title: 'No return path', text: 'No block, isolate or rate-limit action exists - intelligence only.' },
]

function IngestSourcesPanel({ meta, stats, connected, incidentStats, activeClass, onSelectClass }) {
  const sources = meta?.sources || []
  return (
    <div className="h-full flex flex-col gap-4 overflow-y-auto pr-1 thin-scrollbar">
      <section>
        <h3 className="text-[13px] font-semibold text-text-primary flex items-center gap-2 mb-2">
          <Icon name="oneway" className="w-4 h-4 text-text-secondary" /> Ingest sources
        </h3>
        <div className="space-y-2">
          {sources.map((s) => (
            <div key={s.id} className="glass-card p-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12px] text-text-primary font-medium truncate">{s.kind}</span>
                <span className={`w-2 h-2 rounded-full shrink-0 ${s.enabled && connected ? 'bg-status-normal' : 'bg-text-muted'}`}
                      title={s.enabled ? 'enabled' : 'disabled'} />
              </div>
              <p className="text-[11px] text-text-muted font-mono mt-0.5 truncate">{s.transport}</p>
              <p className="text-[11px] text-text-secondary mt-1">
                {fmtCompact(s.records)} flows
                {s.id === 'udp' && <> · {fmtCompact(s.datagrams)} datagrams{s.exporters ? ` · ${s.exporters} exporter(s)` : ''}</>}
              </p>
            </div>
          ))}
          {!sources.length && <p className="text-[11px] text-text-muted">{connected ? 'Loading…' : 'Sensor not connected'}</p>}
        </div>
        {stats?.baseline_learning && (
          <p className="mt-2 text-[11px] text-text-secondary flex gap-1.5">
            <Icon name="clock" className="w-3.5 h-3.5 mt-px shrink-0" />
            Learning estate baseline ({Math.round(stats.context_age_s)} s of history); prevalence-based detectors need strong evidence until it matures.
          </p>
        )}
      </section>

      <section>
        <h3 className="text-[13px] font-semibold text-text-primary flex items-center gap-2 mb-2">
          <Icon name="shield" className="w-4 h-4 text-text-secondary" /> Threat coverage (PS a-f)
        </h3>
        <div className="space-y-1">
          {CLASS_ORDER.map((c) => {
            const info = classInfo(c)
            const s = incidentStats?.byClass?.[c]
            const active = activeClass === c
            return (
              <button key={c} type="button" onClick={() => onSelectClass(active ? null : c)}
                      className={`w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-left transition-colors ${active ? 'bg-white/[0.08]' : 'hover:bg-white/[0.04]'}`}>
                <ClassDot cls={c} />
                <span className="text-[11px] font-mono text-text-muted w-3">{info.ps}</span>
                <span className="flex-1 text-[12px] text-text-primary truncate">{info.short}</span>
                <span className="text-[11px] text-text-secondary tabular">{s?.count || 0}</span>
                <span className="text-[10px] text-text-muted w-12 text-right">{s?.last ? timeAgo(s.last) : '—'}</span>
              </button>
            )
          })}
        </div>
      </section>

      <section className="mt-auto">
        <h3 className="text-[13px] font-semibold text-text-primary mb-2">Sensor posture</h3>
        <div className="space-y-2">
          {POSTURE.map((p) => (
            <div key={p.title} className="flex gap-2">
              <Icon name={p.icon} className="w-4 h-4 mt-0.5 text-text-secondary shrink-0" />
              <div>
                <p className="text-[12px] text-text-primary">{p.title}</p>
                <p className="text-[11px] text-text-muted leading-snug">{p.text}</p>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}

export default memo(IngestSourcesPanel)
