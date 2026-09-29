import { memo, useMemo, useState } from 'react'
import { Icon } from '@components/common/ui'
import { clockTime, fmtBytes, fmtInt } from '@/constants/threatModel'

function Meta({ f }) {
  if (f.dns) {
    return (
      <span className="truncate">
        <span className="text-text-muted">DNS {f.dns.qtype}</span>{' '}
        <span className="text-text-primary">{f.dns.qname}</span>
        {f.dns.rcode && f.dns.rcode !== 'NOERROR' && <span className="text-text-muted"> · {f.dns.rcode}</span>}
      </span>
    )
  }
  if (f.tls) {
    return (
      <span className="truncate" title={`JA3 ${f.tls.ja3 || '-'}\nJA4 ${f.tls.ja4 || '-'}`}>
        <span className="text-text-muted">{f.tls.version || 'TLS'}</span>{' '}
        <span className="text-text-primary">{f.tls.sni || '(no SNI)'}</span>
        <span className="text-text-muted"> · JA3 {f.tls.ja3 ? f.tls.ja3.slice(0, 8) : '-'}</span>
      </span>
    )
  }
  if (f.quic) return <span className="text-text-muted">QUIC · encrypted, metadata only</span>
  return <span className="text-text-muted">{f.flags ? `flags ${f.flags}` : '-'}</span>
}

function FlowExplorerPanel({ flows, paused, onTogglePause }) {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('all')

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return flows.filter((f) => {
      if (kind === 'dns' && !f.dns) return false
      if (kind === 'tls' && !(f.tls || f.quic)) return false
      if (kind === 'other' && (f.dns || f.tls || f.quic)) return false
      if (!q) return true
      const hay = `${f.src_ip} ${f.dst_ip} ${f.dst_port} ${f.proto} ${f.dns?.qname || ''} ${f.tls?.sni || ''} ${f.tls?.ja3 || ''} ${f.flow_id}`.toLowerCase()
      return hay.includes(q)
    })
  }, [flows, query, kind])

  return (
    <div className="h-full flex flex-col min-h-0">
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <div className="relative">
          <Icon name="search" className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by IP, port, domain, SNI, JA3..."
            className="w-72 pl-8 pr-3 py-1.5 rounded-lg bg-white/[0.04] border border-white/10 text-[12px] text-text-primary placeholder:text-text-muted outline-none focus:border-white/25"
          />
        </div>
        {['all', 'dns', 'tls', 'other'].map((k) => (
          <button key={k} type="button" onClick={() => setKind(k)}
                  className={`px-2.5 py-1.5 rounded-lg text-[12px] border transition-colors ${kind === k ? 'bg-white/[0.10] border-white/25 text-text-primary' : 'bg-white/[0.03] border-white/10 text-text-secondary hover:text-text-primary'}`}>
            {k === 'all' ? 'All' : k === 'dns' ? 'DNS' : k === 'tls' ? 'TLS / QUIC' : 'Other'}
          </button>
        ))}
        <span className="ml-auto text-[11px] text-text-muted">{rows.length} of {flows.length} sampled flows</span>
        <button type="button" onClick={onTogglePause}
                className={`px-2.5 py-1.5 rounded-lg text-[12px] border flex items-center gap-1.5 ${paused ? 'bg-status-warning/15 border-status-warning/30 text-text-primary' : 'bg-white/[0.03] border-white/10 text-text-secondary hover:text-text-primary'}`}>
          <Icon name={paused ? 'play' : 'pause'} className="w-3.5 h-3.5" />
          {paused ? 'Resume' : 'Pause'}
        </button>
      </div>

      <div className="flex-1 min-h-0 overflow-auto thin-scrollbar rounded-lg border border-white/[0.06]">
        <table className="w-full text-[12px]">
          <thead className="sticky top-0 bg-[#0f1320] text-text-muted text-[11px]">
            <tr>
              <th className="text-left font-medium px-3 py-2">Time</th>
              <th className="text-left font-medium px-2 py-2">Proto</th>
              <th className="text-left font-medium px-2 py-2">Initiator</th>
              <th className="text-left font-medium px-2 py-2">Responder</th>
              <th className="text-right font-medium px-2 py-2">Bytes</th>
              <th className="text-right font-medium px-2 py-2">Pkts</th>
              <th className="text-left font-medium px-3 py-2">Passive metadata</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr key={`${f.flow_id}-${f.ts}`} className="border-t border-white/[0.04] hover:bg-white/[0.03]" title={`Community ID ${f.flow_id}`}>
                <td className="px-3 py-1.5 font-mono text-text-muted tabular whitespace-nowrap">{clockTime(f.ts)}</td>
                <td className="px-2 py-1.5 text-text-secondary">{f.proto}</td>
                <td className="px-2 py-1.5 font-mono text-text-primary whitespace-nowrap">{f.src_ip}<span className="text-text-muted">:{f.src_port}</span></td>
                <td className="px-2 py-1.5 font-mono text-text-primary whitespace-nowrap">{f.dst_ip}<span className="text-text-muted">:{f.dst_port}</span></td>
                <td className="px-2 py-1.5 text-right text-text-secondary tabular whitespace-nowrap">{fmtBytes(f.bytes)}</td>
                <td className="px-2 py-1.5 text-right text-text-secondary tabular">{fmtInt(f.pkts)}</td>
                <td className="px-3 py-1.5 max-w-[360px]"><Meta f={f} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <p className="text-center text-[12px] text-text-muted py-10">No flows match - waiting for the one-way feed.</p>}
      </div>
      <p className="mt-2 text-[11px] text-text-muted flex items-center gap-1.5">
        <Icon name="eyeoff" className="w-3.5 h-3.5" />
        A rolling sample of flow records as received through the one-way uplink. No payload is stored or shown - only headers, counters and handshake metadata.
      </p>
    </div>
  )
}

export default memo(FlowExplorerPanel)
