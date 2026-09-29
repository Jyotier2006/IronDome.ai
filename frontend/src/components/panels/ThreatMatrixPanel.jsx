import { memo } from 'react'
import { ClassDot, ConfidenceMeter, Icon } from '@components/common/ui'
import { CLASS_ORDER, classInfo, timeAgo } from '@/constants/threatModel'

const DETECTOR_OF = {
  volumetric_ddos: ['ddos'],
  c2_beaconing: ['c2_beacon'],
  dga_dns_tunnelling: ['dga_domain', 'dns_tunnel'],
  encrypted_malware: ['encrypted_malware'],
  recon_scan: ['recon_scan'],
  data_exfiltration: ['exfiltration'],
}

function ThreatMatrixPanel({ meta, incidentStats, activeClass, onSelectClass }) {
  const catalog = Object.fromEntries((meta?.threat_classes || []).map((t) => [t.id, t]))
  const modes = meta?.detector_modes || {}
  return (
    <div className="h-full overflow-y-auto pr-1 thin-scrollbar">
      <p className="text-[12px] text-text-secondary mb-3">
        The six threat classes named in problem statement 26145. Each is detected passively from flow, DNS and TLS metadata by
        its own calibrated model; select a class to filter the incident feed.
      </p>
      <div className="grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-3 gap-3">
        {CLASS_ORDER.map((c) => {
          const info = classInfo(c)
          const s = incidentStats?.byClass?.[c] || { count: 0, open: 0, maxConf: 0, techniques: {}, last: null, occurrences: 0 }
          const cat = catalog[c]
          const active = activeClass === c
          const techniques = cat?.techniques?.length ? cat.techniques : []
          return (
            <button
              key={c} type="button" onClick={() => onSelectClass?.(active ? null : c)}
              className={`glass-card p-4 text-left transition-colors border ${active ? 'border-white/30 bg-white/[0.06]' : 'border-white/[0.07] hover:bg-white/[0.04]'}`}
              style={{ boxShadow: `inset 3px 0 0 0 ${info.color}` }}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <ClassDot cls={c} size={10} />
                    <span className="text-[11px] font-mono text-text-muted">PS ({info.ps})</span>
                  </div>
                  <h4 className="mt-1 text-[15px] font-semibold text-text-primary">{info.label}</h4>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-2xl font-semibold text-text-primary leading-none">{s.count}</p>
                  <p className="text-[11px] text-text-muted mt-1">{s.open} open</p>
                </div>
              </div>
              <p className="mt-2 text-[12px] text-text-secondary leading-snug">{info.summary}</p>

              <div className="mt-3 flex flex-wrap gap-1">
                {techniques.map((t) => (
                  <span key={t.id} className="px-1.5 py-0.5 rounded bg-white/[0.05] border border-white/[0.08] text-[10px] text-text-secondary"
                        title={(t.mitre || []).join(', ')}>
                    {t.label}{s.techniques?.[t.label] ? ` · ${s.techniques[t.label]}` : ''}
                  </span>
                ))}
              </div>

              <div className="mt-3 pt-3 border-t border-white/[0.06] grid grid-cols-3 gap-2 text-[11px]">
                <div>
                  <p className="text-text-muted">Max confidence</p>
                  <div className="mt-1">{s.count ? <ConfidenceMeter value={s.maxConf} color={info.color} width="w-10" /> : <span className="text-text-secondary">-</span>}</div>
                </div>
                <div>
                  <p className="text-text-muted">Last seen</p>
                  <p className="mt-1 text-text-primary">{s.last ? timeAgo(s.last) : 'never'}</p>
                </div>
                <div>
                  <p className="text-text-muted">Detector</p>
                  <p className="mt-1 text-text-primary truncate flex items-center gap-1">
                    <Icon name="cpu" className="w-3 h-3" />
                    {(DETECTOR_OF[c] || []).map((d) => modes[d] || 'ml').join(' + ') || 'ml'}
                  </p>
                </div>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

export default memo(ThreatMatrixPanel)
