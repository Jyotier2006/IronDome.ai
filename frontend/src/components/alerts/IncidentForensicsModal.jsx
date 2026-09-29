import { memo, useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { ClassDot, ConfidenceMeter, Icon, SeverityBadge } from '@components/common/ui'
import { downloadJson } from '@services/httpApiClient'
import { classInfo, entityText, featureLabel } from '@/constants/threatModel'

const mitreUrl = (t) => {
  const [base, sub] = t.split('.')
  return `https://attack.mitre.org/techniques/${base}/${sub ? `${sub}/` : ''}`
}

const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString('en-GB', { hour12: false }) : '-')

function Section({ title, children }) {
  return (
    <section>
      <h4 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">{title}</h4>
      {children}
    </section>
  )
}

function KV({ k, v, mono = false }) {
  return (
    <div className="flex justify-between gap-3 py-0.5 text-[12px]">
      <span className="text-text-muted shrink-0">{k}</span>
      <span className={`text-text-primary text-right break-all ${mono ? 'font-mono' : ''}`}>{v}</span>
    </div>
  )
}

function ZBar({ z }) {
  const mag = Math.min(1, Math.abs(z) / 12)
  return (
    <span className="relative inline-block w-24 h-2 align-middle" aria-hidden="true">
      <span className="absolute inset-y-0 left-1/2 w-px bg-white/25" />
      <span className="absolute inset-y-0 rounded-full" style={{
        background: '#7d8aa5',
        width: `${mag * 50}%`,
        left: z >= 0 ? '50%' : `${50 - mag * 50}%`,
      }} />
    </span>
  )
}

function renderValue(v) {
  if (v == null) return '-'
  if (Array.isArray(v)) {
    if (!v.length) return '-'
    if (typeof v[0] === 'object') {
      return v.slice(0, 6).map((o) => Object.values(o).join(' · ')).join('\n')
    }
    return v.slice(0, 12).join(', ')
  }
  if (typeof v === 'object') {
    return Object.entries(v).map(([a, b]) => {
      // window bounds arrive as epoch seconds: show them as clock times
      if ((a === 'start' || a === 'end') && typeof b === 'number' && b > 1e9) {
        return `${a}: ${new Date(b * 1000).toLocaleTimeString('en-GB', { hour12: false })}`
      }
      if (typeof b === 'number') return `${a}: ${Number(b.toFixed(3))}`
      if (b && typeof b === 'object') return `${a}: ${JSON.stringify(b)}`
      return `${a}: ${b}`
    }).join(' · ')
  }
  if (typeof v === 'number') return Number.isInteger(v) ? v.toLocaleString('en-IN') : v.toFixed(3)
  return String(v)
}

function IncidentForensicsModal({ incident, isOpen, acked, onClose, onAcknowledge }) {
  const [showRaw, setShowRaw] = useState(false)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!isOpen) return undefined
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [isOpen, onClose])

  useEffect(() => { setShowRaw(false); setCopied(false) }, [incident?.incident_id])

  if (!incident) return null
  const info = classInfo(incident.threat_class)
  const ev = incident.evidence || {}
  const ctx = ev.context || {}
  const devs = ev.top_deviations || []
  const det = incident.detector || {}
  const flow = incident.flow || {}
  const extra = Object.entries(ev).filter(([k]) => !['features', 'top_deviations', 'context'].includes(k))

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(incident, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* clipboard unavailable */ }
  }

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}
                      className="fixed inset-0 bg-black/65 backdrop-blur-sm z-50" />
          {/* Centred by a flex wrapper: the motion transform would override translate-based centring */}
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
          <motion.div
            initial={{ opacity: 0, scale: 0.97, y: 16 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.97, y: 16 }}
            className="pointer-events-auto w-full h-full md:h-auto md:w-[760px] md:max-h-[86vh] flex flex-col glass-panel bg-[#0d111c]/95 overflow-hidden"
            role="dialog" aria-modal="true" aria-label={`Incident: ${incident.technique_label}`}
          >
            <header className="p-4 border-b border-white/[0.07]" style={{ boxShadow: `inset 0 3px 0 0 ${info.color}` }}>
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-[11px] text-text-muted">
                    <ClassDot cls={incident.threat_class} size={10} />
                    <span className="font-mono">PS ({info.ps})</span>
                    <span>{info.label}</span>
                  </div>
                  <h2 className="mt-1 text-xl font-semibold text-text-primary">{incident.technique_label || incident.technique}</h2>
                  <div className="mt-2 flex flex-wrap items-center gap-3">
                    <SeverityBadge severity={incident.severity} />
                    <span className="text-[12px] text-text-secondary flex items-center gap-2">Confidence <ConfidenceMeter value={incident.confidence} color={info.color} width="w-24" /></span>
                    {incident.occurrences > 1 && <span className="text-[12px] text-text-secondary">×{incident.occurrences} correlated sightings</span>}
                    {acked && <span className="text-[12px] text-text-secondary flex items-center gap-1"><Icon name="check" className="w-3 h-3" />Acknowledged</span>}
                  </div>
                </div>
                <button type="button" onClick={onClose} className="p-2 rounded-lg hover:bg-white/[0.06] text-text-muted" aria-label="Close">
                  <Icon name="x" />
                </button>
              </div>
            </header>

            <div className="flex-1 overflow-y-auto p-4 space-y-4 thin-scrollbar">
              <Section title="What was detected">
                <p className="text-[13px] text-text-primary leading-relaxed">{incident.description}</p>
              </Section>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Section title="Flow identity">
                  <div className="glass-card p-3">
                    <KV k="Flow ID (Community ID v1)" v={incident.flow_id} mono />
                    <KV k="5-tuple" v={`${flow.src_ip}:${flow.src_port ?? '-'} → ${flow.dst_ip}:${flow.dst_port ?? '-'} ${flow.protocol || ''}`} mono />
                    <KV k="Entity" v={entityText(incident)} mono />
                    <KV k="First seen" v={fmtTime(incident.first_seen)} />
                    <KV k="Last seen" v={fmtTime(incident.last_seen)} />
                    <KV k="Alert raised" v={fmtTime(incident.timestamp)} />
                    <KV k="Related flows" v={(incident.related_flow_ids || []).length} />
                  </div>
                </Section>
                <Section title="Classification & decision">
                  <div className="glass-card p-3">
                    <KV k="Threat class" v={`(${info.ps}) ${info.label}`} />
                    <KV k="Technique" v={incident.technique} mono />
                    <KV k="Detector" v={det.model || det.name} />
                    <KV k="Mode" v={det.mode === 'ml+intel' ? 'ML + threat intel' : det.mode === 'ml+behaviour' ? 'ML + NXDOMAIN behaviour' : det.mode} />
                    <KV k="Confidence vs threshold" v={`${(incident.confidence * 100).toFixed(1)}% ≥ ${((det.threshold ?? 0) * 100).toFixed(1)}%`} />
                    {incident.latency_ms != null && <KV k="Processing latency" v={`${(incident.latency_ms / 1000).toFixed(2)} s`} />}
                    <div className="flex justify-between gap-3 py-0.5 text-[12px]">
                      <span className="text-text-muted">MITRE ATT&CK</span>
                      <span className="flex flex-wrap justify-end gap-1">
                        {(incident.mitre_attack || []).map((t) => (
                          <a key={t} href={mitreUrl(t)} target="_blank" rel="noreferrer"
                             className="px-1.5 py-0.5 rounded bg-white/[0.05] border border-white/10 font-mono text-[11px] text-text-primary hover:bg-white/[0.10]">{t}</a>
                        ))}
                      </span>
                    </div>
                  </div>
                </Section>
              </div>

              {devs.length > 0 && (
                <Section title="Evidence - features furthest from the benign baseline">
                  <div className="glass-card p-3 overflow-x-auto">
                    <table className="w-full text-[12px]">
                      <thead className="text-text-muted text-[11px]">
                        <tr>
                          <th className="text-left font-medium pb-1">Feature</th>
                          <th className="text-right font-medium pb-1">Observed</th>
                          <th className="text-right font-medium pb-1">Benign mean</th>
                          <th className="text-right font-medium pb-1 pl-4">Deviation (σ)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {devs.map((d) => (
                          <tr key={d.feature} className="border-t border-white/[0.05]">
                            <td className="py-1 text-text-primary">{featureLabel(d.feature)}</td>
                            <td className="py-1 text-right tabular text-text-primary">{renderValue(d.value)}</td>
                            <td className="py-1 text-right tabular text-text-secondary">{renderValue(d.benign_mean)}</td>
                            <td className="py-1 text-right tabular text-text-secondary pl-4 whitespace-nowrap">
                              <ZBar z={d.z_score} /> <span className="ml-1">{d.z_score > 0 ? '+' : ''}{d.z_score}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}

              {(Object.keys(ctx).length > 0 || extra.length > 0) && (
                <Section title="Supporting context">
                  <div className="glass-card p-3">
                    {Object.entries(ctx).map(([k, v]) => <KV key={k} k={featureLabel(k)} v={<span className="whitespace-pre-line">{renderValue(v)}</span>} mono />)}
                    {extra.map(([k, v]) => <KV key={k} k={featureLabel(k)} v={<span className="whitespace-pre-line">{renderValue(v)}</span>} mono />)}
                  </div>
                </Section>
              )}

              <Section title="Recommended action (out-of-band)">
                <div className="glass-card p-3 text-[12px] text-text-primary leading-relaxed flex gap-2">
                  <Icon name="info" className="w-4 h-4 mt-px text-text-secondary shrink-0" />
                  <span>{incident.recommended_action} The sensor sits behind a one-way link and cannot act on the network itself.</span>
                </div>
              </Section>

              <Section title="Standard alert record">
                <div className="flex gap-2 mb-2">
                  <button type="button" onClick={() => setShowRaw((s) => !s)} className="btn-ghost !px-2.5 !py-1 !text-[12px] border border-white/10">
                    {showRaw ? 'Hide JSON' : 'Show JSON'}
                  </button>
                  <button type="button" onClick={copy} className="btn-ghost !px-2.5 !py-1 !text-[12px] border border-white/10 flex items-center gap-1.5">
                    <Icon name="copy" className="w-3.5 h-3.5" /> {copied ? 'Copied' : 'Copy'}
                  </button>
                  <button type="button" onClick={() => downloadJson(`alert-${incident.incident_id}.json`, incident)}
                          className="btn-ghost !px-2.5 !py-1 !text-[12px] border border-white/10 flex items-center gap-1.5">
                    <Icon name="download" className="w-3.5 h-3.5" /> Download
                  </button>
                </div>
                {showRaw && (
                  <pre className="max-h-72 overflow-auto thin-scrollbar rounded-lg bg-black/40 border border-white/[0.06] p-3 text-[11px] text-text-secondary font-mono">
                    {JSON.stringify(incident, null, 2)}
                  </pre>
                )}
              </Section>
            </div>

            <footer className="p-3 border-t border-white/[0.07] flex justify-end gap-2">
              {!acked && (
                <button type="button" onClick={() => onAcknowledge(incident.incident_id)} className="btn-primary !py-1.5 !text-[13px] flex items-center gap-1.5">
                  <Icon name="check" className="w-4 h-4" /> Acknowledge
                </button>
              )}
              <button type="button" onClick={onClose} className="btn-ghost !py-1.5 !text-[13px]">Close</button>
            </footer>
          </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  )
}

export default memo(IncidentForensicsModal)
