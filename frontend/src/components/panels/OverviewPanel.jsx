import { memo, useMemo } from 'react'
import ThroughputChart from '@components/charts/ThroughputChart'
import { ClassDot, Icon, PanelTitle, SeverityBadge } from '@components/common/ui'
import { CHART, CLASS_ORDER, classInfo, fmtCompact, fmtInt, fmtPct, SEVERITY } from '@/constants/threatModel'

const LATENCY_BOUND_MS = 3000   // alert latency budget shown against p95 (streaming, bounded latency)

function StatTile({ label, value, unit, note, children }) {
  return (
    <div className="glass-card p-3 min-w-0">
      <p className="text-[11px] text-text-secondary">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-text-primary leading-none">
        {value}
        {unit && <span className="text-[12px] font-normal text-text-secondary ml-1">{unit}</span>}
      </p>
      {note && <p className="mt-1.5 text-[11px] text-text-muted truncate">{note}</p>}
      {children}
    </div>
  )
}

function ShareBar({ label, share, color = CHART.neutral }) {
  const pct = Math.max(0, Math.min(1, share || 0)) * 100
  return (
    <div className="flex items-center gap-2 text-[11px]">
      <span className="w-16 text-text-secondary shrink-0">{label}</span>
      <span className="relative flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'rgba(125,138,165,0.18)' }}>
        <span className="absolute inset-y-0 left-0 rounded-r" style={{ width: `${pct}%`, background: color }} />
      </span>
      <span className="w-10 text-right text-text-primary tabular">{pct.toFixed(0)}%</span>
    </div>
  )
}

function OverviewPanel({ stats, history, peak, meta, incidentStats, runs, onSelectClass }) {
  const markers = useMemo(() => (runs || [])
    .filter((r) => r.start_wall)
    .map((r) => ({ t: r.start_wall * 1000, label: `(${r.ps_ref}) ${r.title}` })), [runs])

  const proto = useMemo(() => {
    const mix = stats?.protocol_mix || {}
    const total = Object.values(mix).reduce((a, b) => a + b, 0) || 1
    return ['TCP', 'UDP', 'ICMP'].map((p) => ({ p, share: (mix[p] || 0) / total }))
  }, [stats])

  const p95 = stats?.latency?.p95_ms
  const target = meta?.throughput_target_fps || stats?.target_flows_per_s || 5000
  const openBySev = incidentStats?.bySeverity || {}

  return (
    <div className="h-full overflow-y-auto pr-1 thin-scrollbar space-y-4">
      <div className="grid grid-cols-2 xl:grid-cols-5 gap-3">
        <StatTile label="Flows per second" value={fmtInt(stats?.flows_per_s)}
                  note={`peak ${fmtInt(peak)} · target ${fmtInt(target)}`} />
        <StatTile label="Monitored bandwidth" value={stats ? stats.mbps.toFixed(1) : '-'} unit="Mbps"
                  note={`${fmtCompact(stats?.total_flows)} flows · ${fmtCompact(stats?.pkts_per_s)} pkt/s`} />
        <StatTile label="Open incidents" value={fmtInt(incidentStats?.open ?? 0)}>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {Object.keys(SEVERITY).filter((s) => openBySev[s]).map((s) => (
              <span key={s} className="inline-flex items-center gap-1 text-[11px] text-text-secondary">
                <SeverityBadge severity={s} compact /> {openBySev[s]}
              </span>
            ))}
            {!incidentStats?.open && <span className="text-[11px] text-text-muted">none open</span>}
          </div>
        </StatTile>
        <StatTile label="Alert latency, p95" value={p95 != null ? (p95 / 1000).toFixed(1) : '-'} unit="s"
                  note={`budget ${(LATENCY_BOUND_MS / 1000).toFixed(0)} s, ingest to alert`}>
          <div className="mt-1.5 relative h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(34,184,207,0.2)' }}>
            <span className="absolute inset-y-0 left-0 rounded-full" style={{
              width: `${Math.min(100, ((p95 || 0) / LATENCY_BOUND_MS) * 100)}%`,
              background: (p95 || 0) > LATENCY_BOUND_MS ? SEVERITY.critical.color : '#22b8cf',
            }} />
          </div>
        </StatTile>
        <StatTile label="Encrypted traffic (TLS/QUIC)" value={fmtPct(stats?.encrypted_byte_share)}
                  note={`of bytes · ${fmtPct(stats?.encrypted_share)} of flows · ${fmtPct(stats?.handshake_share)} handshake seen`} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="glass-card p-3">
          <PanelTitle icon="pulse" right={<span className="text-[11px] text-text-muted">last 3 min · 1 s samples</span>}>
            Flow rate (flows per second)
          </PanelTitle>
          <ThroughputChart data={history} dataKey="fps" unit="flows/s" markers={markers}
                           ariaLabel="Flows observed per second over the last three minutes" />
        </div>
        <div className="glass-card p-3">
          <PanelTitle icon="chart" right={<span className="text-[11px] text-text-muted">monitored link</span>}>
            Monitored bandwidth (Mbps)
          </PanelTitle>
          <ThroughputChart data={history} dataKey="mbps" unit="Mbps" digits={1}
                           ariaLabel="Monitored bandwidth in megabits per second over the last three minutes" />
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="glass-card p-3 xl:col-span-2">
          <PanelTitle icon="shield" right={<span className="text-[11px] text-text-muted">click a class to filter incidents</span>}>
            Detections by threat class (PS a-f)
          </PanelTitle>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {CLASS_ORDER.map((c) => {
              const info = classInfo(c)
              const s = incidentStats?.byClass?.[c] || { count: 0, open: 0 }
              return (
                <button key={c} type="button" onClick={() => onSelectClass?.(c)}
                        className="flex items-center gap-2.5 px-2.5 py-2 rounded-lg bg-white/[0.02] hover:bg-white/[0.05] border border-white/[0.06] text-left transition-colors">
                  <ClassDot cls={c} size={10} />
                  <span className="text-[11px] font-mono text-text-muted w-3">{info.ps}</span>
                  <span className="flex-1 text-[12px] text-text-primary leading-tight">{info.label}</span>
                  <span className="text-[12px] text-text-primary font-semibold tabular">{s.count}</span>
                  <span className="text-[11px] text-text-muted w-14 text-right">{s.open} open</span>
                </button>
              )
            })}
          </div>
        </div>
        <div className="glass-card p-3">
          <PanelTitle icon="flow">Traffic composition</PanelTitle>
          <div className="space-y-2">
            {proto.map(({ p, share }) => <ShareBar key={p} label={p} share={share} />)}
          </div>
          <div className="mt-3 pt-3 border-t border-white/[0.06] space-y-2">
            <ShareBar label="Encrypted (TLS/QUIC)" share={stats?.encrypted_share} />
            <ShareBar label="Handshake seen" share={stats?.handshake_share} />
            <ShareBar label="DNS" share={stats?.dns_share} />
          </div>
          <p className="mt-3 text-[11px] text-text-muted flex items-start gap-1.5">
            <Icon name="lock" className="w-3.5 h-3.5 mt-px shrink-0" />
            Shares of flows seen by the passive sensor. Encrypted = TLS/QUIC by port or handshake; "handshake seen" = flows whose ClientHello metadata (JA3/JA4, SNI) was captured. Sessions are profiled from that metadata and packet sizes / timing only.
          </p>
        </div>
      </div>
    </div>
  )
}

export default memo(OverviewPanel)
