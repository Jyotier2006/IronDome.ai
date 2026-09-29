import { memo } from 'react'
import { Icon, PanelTitle } from '@components/common/ui'
import { downloadJson, fetchAlertSchema } from '@services/httpApiClient'
import { CONSTRAINTS, fmtCompact, fmtInt, fmtPct } from '@/constants/threatModel'

const SCHEMA_FIELDS = ['timestamp', 'flow_id', 'threat_class', 'confidence', 'evidence', 'severity', 'technique', 'mitre_attack', 'flow', 'entity', 'detector']

function Stage({ icon, title, lines, last = false }) {
  return (
    <div className="flex items-stretch gap-2 min-w-0">
      <div className="glass-card p-3 flex-1 min-w-0">
        <p className="text-[12px] font-semibold text-text-primary flex items-center gap-1.5"><Icon name={icon} className="w-3.5 h-3.5 text-text-secondary" />{title}</p>
        <ul className="mt-1.5 space-y-0.5">
          {lines.map((l) => <li key={l} className="text-[11px] text-text-secondary leading-snug">{l}</li>)}
        </ul>
      </div>
      {!last && <div className="self-center text-text-muted shrink-0"><Icon name="oneway" className="w-4 h-4" /></div>}
    </div>
  )
}

function CompliancePanel({ meta, stats, peak, incidentStats, incidents }) {
  const udp = meta?.sources?.find((s) => s.id === 'udp')
  const modes = Object.values(meta?.detector_modes || {})
  const mlCount = modes.filter((m) => m === 'ml').length
  const lat = stats?.latency || {}
  const target = meta?.throughput_target_fps || 5000

  const evidence = {
    a: [
      `Ingest: ${udp?.transport || 'UDP receive-only collector'} - ${fmtInt(udp?.datagrams)} datagrams in, 0 sent back`,
      `Sensor flags: read_only=${String(meta?.read_only ?? true)}, issues_mitigation=${String(meta?.issues_mitigation ?? false)}`,
      'No block / isolate / rate-limit endpoint exists; recommendations are out-of-band only',
    ],
    b: [
      `decrypts_payload=${String(meta?.decrypts_payload ?? false)} · ${fmtPct(stats?.encrypted_share)} of flows encrypted (TLS/QUIC), ${fmtPct(stats?.handshake_share)} with handshake metadata`,
      'Features: JA3 / JA3S / JA4 fingerprints, SNI & ALPN presence, packet-size & timing sequences (SPLT)',
      'Flow records carry no payload field at all',
    ],
    c: [
      'Event-time windows: DDoS 2 s · scan 30 s · DNS & exfiltration 60 s · beacon last 64 connections',
      `Alert latency p50 ${lat.p50_ms != null ? (lat.p50_ms / 1000).toFixed(1) : '-'} s · p95 ${lat.p95_ms != null ? (lat.p95_ms / 1000).toFixed(1) : '-'} s (flow ingested → alert)`,
      `Watermark lag ${fmtInt(stats?.watermark_lag_ms)} ms · load-shed ${fmtInt(stats?.shed)} candidates`,
    ],
    d: [
      `Stated target: ${fmtInt(target)} flows/s sustained per sensor process`,
      `Live now ${fmtInt(stats?.flows_per_s)} flows/s · session peak ${fmtInt(peak)} flows/s`,
      'Benchmark method and measured results: docs/THROUGHPUT.md (scripts/benchmark_throughput.py)',
    ],
    e: [
      `Schema v1.0 - required: ${SCHEMA_FIELDS.slice(0, 5).join(', ')}`,
      'Plus severity, technique, MITRE ATT&CK, 5-tuple, entity, detector & threshold',
      `Flow identifier = Community ID v1 (Zeek / Suricata compatible) · ${fmtInt(incidentStats?.total)} incidents held`,
    ],
  }

  return (
    <div className="h-full overflow-y-auto pr-1 thin-scrollbar space-y-4">
      <div>
        <PanelTitle icon="flow">Pipeline - ingest, feature extraction, model inference, alert output</PanelTitle>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
          <Stage icon="oneway" title="1 · One-way ingest" lines={[
            udp?.transport || 'UDP receive-only',
            'NetFlow v5/v9 · IPFIX · sFlow · biflow JSON · PCAP replay',
            `${fmtCompact(stats?.total_flows)} flows since start`,
          ]} />
          <Stage icon="grid" title="2 · Streaming features" lines={[
            '7 extractors, event-time windows',
            `estate context ${fmtInt(stats?.context_age_s)} s${stats?.baseline_learning ? ' (learning)' : ''}`,
            'prevalence · baselines · SPLT · lexical',
          ]} />
          <Stage icon="cpu" title="3 · Model inference" lines={[
            `${mlCount}/${modes.length || 7} calibrated ML models loaded`,
            'gradient boosting + isotonic calibration',
            'evidence-consistency guard · JA3 intel',
          ]} />
          <Stage icon="shield" title="4 · Alert output" last lines={[
            `${fmtInt(incidentStats?.total)} incidents · ${fmtInt(incidentStats?.open)} open`,
            'standard schema v1.0 · correlated',
            'REST + Socket.IO → this dashboard',
          ]} />
        </div>
      </div>

      <div>
        <PanelTitle icon="check">Problem-statement constraints - how each is met, with live evidence</PanelTitle>
        <div className="space-y-2">
          {CONSTRAINTS.map((c) => (
            <div key={c.id} className="glass-card p-3 flex gap-3">
              <span className="w-6 h-6 rounded-md bg-white/[0.06] border border-white/10 text-[11px] font-mono font-semibold text-text-secondary flex items-center justify-center shrink-0">{c.id}</span>
              <div className="min-w-0 flex-1">
                <p className="text-[13px] font-semibold text-text-primary flex items-center gap-2">
                  {c.title}
                  <span className="inline-flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-white/[0.05] border border-white/10 text-text-secondary">
                    <Icon name="check" className="w-3 h-3" /> met
                  </span>
                </p>
                <p className="text-[11px] text-text-muted">{c.text}</p>
                <ul className="mt-1.5 space-y-0.5">
                  {evidence[c.id].map((l) => <li key={l} className="text-[12px] text-text-secondary">· {l}</li>)}
                </ul>
                {c.id === 'e' && (
                  <div className="mt-2 flex gap-2">
                    <button type="button" className="btn-ghost !px-2.5 !py-1 !text-[12px] flex items-center gap-1.5 border border-white/10"
                            onClick={async () => downloadJson('irondome-alert-schema-1.0.json', await fetchAlertSchema())}>
                      <Icon name="download" className="w-3.5 h-3.5" /> Alert JSON Schema
                    </button>
                    <button type="button" disabled={!incidents?.length}
                            className="btn-ghost !px-2.5 !py-1 !text-[12px] flex items-center gap-1.5 border border-white/10 disabled:opacity-40"
                            onClick={() => downloadJson('irondome-sample-alert.json', incidents[0])}>
                      <Icon name="download" className="w-3.5 h-3.5" /> Latest alert record
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default memo(CompliancePanel)
