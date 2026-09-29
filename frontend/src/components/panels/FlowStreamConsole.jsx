import { memo } from 'react'
import { clockTime, fmtBytes } from '@/constants/threatModel'

const chip = (text, tone = 'rgba(255,255,255,0.06)') => (
  <span style={{ padding: '1px 7px', borderRadius: 4, background: tone, color: '#cbd5e1', fontSize: 11, whiteSpace: 'nowrap' }}>{text}</span>
)

function describe(f) {
  if (f.dns) return `DNS ${f.dns.qtype} ${f.dns.qname}${f.dns.rcode && f.dns.rcode !== 'NOERROR' ? ` [${f.dns.rcode}]` : ''}`
  if (f.tls) return `${f.tls.version || 'TLS'} sni=${f.tls.sni || '-'} ja3=${(f.tls.ja3 || '-').slice(0, 12)}`
  if (f.quic) return 'QUIC (metadata only)'
  return f.flags ? `flags=${f.flags}` : ''
}

function FlowStreamConsole({ flows, paused, onTogglePause, onClear, height, expanded, onToggleExpand }) {
  return (
    <div style={{ height, background: '#0b0f18', borderTop: '1px solid rgba(255,255,255,0.08)', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px', background: '#0f1420', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ color: '#94a3b8', fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}>flow.stream</span>
          <span style={{ color: '#64748b', fontSize: 11 }}>one-way uplink · sampled · {flows.length} shown</span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {[['pause', paused ? 'Resume' : 'Pause', onTogglePause], ['clear', 'Clear', onClear], ['size', expanded ? 'Collapse' : 'Expand', onToggleExpand]].map(([k, label, fn]) => (
            <button key={k} type="button" onClick={fn}
                    style={{ padding: '3px 10px', borderRadius: 4, fontSize: 11, background: k === 'pause' && paused ? 'rgba(250,178,25,0.18)' : 'rgba(255,255,255,0.06)', color: '#cbd5e1', border: 'none', cursor: 'pointer' }}>
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className="thin-scrollbar" style={{ flex: '1 1 auto', minHeight: 0, overflowY: 'auto', padding: '6px 12px', fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}>
        {flows.length === 0 ? (
          <div style={{ color: '#64748b', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>Waiting for flow records on the one-way uplink…</div>
        ) : flows.slice(0, 80).map((f) => (
          <div key={`${f.flow_id}-${f.ts}`} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '2px 0', whiteSpace: 'nowrap', overflow: 'hidden' }}>
            <span style={{ color: '#64748b' }}>{clockTime(f.ts)}</span>
            {chip(f.proto)}
            <span style={{ color: '#e2e8f0' }}>{f.src_ip}:{f.src_port}</span>
            <span style={{ color: '#64748b' }}>→</span>
            <span style={{ color: '#e2e8f0' }}>{f.dst_ip}:{f.dst_port}</span>
            {chip(fmtBytes(f.bytes))}
            <span style={{ color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis' }}>{describe(f)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default memo(FlowStreamConsole)
