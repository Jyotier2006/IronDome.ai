// ============================================
// IronDome.ai - threat model shared by the whole dashboard
// SIH PS 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
// ============================================

// The six threat classes of the problem statement, items (a)-(f).
// Colours are the dark-mode categorical slots, assigned in fixed order and
// validated against the panel surface (#111521): worst adjacent CVD dE 8.4,
// normal-vision dE 19.3, all >= 3:1 contrast. Colour marks identity only;
// text always uses the text tokens, never the class colour.
export const THREAT_CLASSES = {
  volumetric_ddos: {
    ps: 'a',
    label: 'Volumetric / Protocol DDoS',
    short: 'DDoS',
    color: '#3987e5',
    summary: 'SYN floods, UDP reflection/amplification and spoofed-source floods from flow-level rates and source-IP entropy.',
  },
  c2_beaconing: {
    ps: 'b',
    label: 'Botnet C2 Beaconing',
    short: 'C2 beacon',
    color: '#d95926',
    summary: 'Periodicity and inter-arrival analysis on flows that repeat at regular intervals to few destinations.',
  },
  dga_dns_tunnelling: {
    ps: 'c',
    label: 'DGA Domains & DNS Tunnelling',
    short: 'DGA / DNS',
    color: '#199e70',
    summary: 'Entropy / n-gram analysis of DNS query names plus query-length and record-type anomalies.',
  },
  encrypted_malware: {
    ps: 'd',
    label: 'Malware in Encrypted Sessions',
    short: 'Encrypted malware',
    color: '#c98500',
    summary: 'TLS/QUIC metadata only - JA3/JA3S/JA4 fingerprints, packet-size and timing sequences. Never decrypted.',
  },
  recon_scan: {
    ps: 'e',
    label: 'Reconnaissance & Port Scanning',
    short: 'Recon / scan',
    color: '#d55181',
    summary: 'Fan-out from a single source across many destination ports or hosts.',
  },
  data_exfiltration: {
    ps: 'f',
    label: 'Data Exfiltration',
    short: 'Exfiltration',
    color: '#008300',
    summary: 'Asymmetric flow-volume anomalies and unusual outbound-to-inbound byte ratios.',
  },
}

export const CLASS_ORDER = [
  'volumetric_ddos',
  'c2_beaconing',
  'dga_dns_tunnelling',
  'encrypted_malware',
  'recon_scan',
  'data_exfiltration',
]

export const classInfo = (id) =>
  THREAT_CLASSES[id] || { ps: '?', label: id || 'Unknown', short: id || '?', color: '#7d8aa5', summary: '' }

// Severity is *status*, not identity: the fixed status palette, always shown
// with an icon + label so it never relies on colour alone.
export const SEVERITY = {
  critical: { label: 'Critical', color: '#d03b3b', rank: 4, icon: 'octagon' },
  high: { label: 'High', color: '#ec835a', rank: 3, icon: 'triangle' },
  medium: { label: 'Medium', color: '#fab219', rank: 2, icon: 'circle' },
  low: { label: 'Low', color: '#8b93a7', rank: 1, icon: 'dot' },
}

export const severityInfo = (s) => SEVERITY[s] || SEVERITY.low

// Neutral chart ink (one step off the surface; solid hairlines, never dashed)
export const CHART = {
  grid: 'rgba(255,255,255,0.06)',
  axis: 'rgba(255,255,255,0.14)',
  tick: '#8b93a7',
  neutral: '#7d8aa5',
  accent: '#3987e5',
}

// PS architectural constraints (a)-(e)
export const CONSTRAINTS = [
  { id: 'a', title: 'Read-only ingest', text: 'No return path, no live query to the source, no inline block.' },
  { id: 'b', title: 'No payload decryption', text: 'TLS/QUIC analysed from metadata only.' },
  { id: 'c', title: 'Streaming, not batch', text: 'Incremental processing with bounded alert latency.' },
  { id: 'd', title: 'Defined throughput target', text: 'Stated and demonstrated flows/sec sustained.' },
  { id: 'e', title: 'Standardized alert schema', text: 'Timestamp, flow identifier, threat class, confidence, evidence.' },
]

// ---------- formatting helpers ----------
export const fmtInt = (n) => (Number.isFinite(n) ? Math.round(n).toLocaleString('en-IN') : '-')

export const fmtCompact = (n) => {
  if (!Number.isFinite(n)) return '-'
  const a = Math.abs(n)
  if (a >= 1e9) return `${(n / 1e9).toFixed(1)}B`
  if (a >= 1e6) return `${(n / 1e6).toFixed(1)}M`
  if (a >= 1e3) return `${(n / 1e3).toFixed(1)}K`
  return `${Math.round(n)}`
}

export const fmtBytes = (b) => {
  if (!Number.isFinite(b)) return '-'
  if (b >= 1e9) return `${(b / 1e9).toFixed(2)} GB`
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`
  return `${b} B`
}

export const fmtPct = (x, digits = 0) => (Number.isFinite(x) ? `${(x * 100).toFixed(digits)}%` : '-')

export const timeAgo = (iso) => {
  const t = typeof iso === 'number' ? iso * 1000 : Date.parse(iso)
  if (!Number.isFinite(t)) return '-'
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export const clockTime = (iso) => {
  const t = typeof iso === 'number' ? iso * 1000 : Date.parse(iso)
  if (!Number.isFinite(t)) return '--:--:--'
  return new Date(t).toLocaleTimeString('en-GB', { hour12: false })
}

export const shortFlowId = (id) => (id ? `${id.slice(0, 10)}...` : '-')

export const entityText = (inc) => {
  const e = inc?.entity || {}
  switch (e.type) {
    case 'destination': return `victim ${e.ip}`
    case 'source': return `source ${e.ip}`
    case 'host_pair': return `${e.src_ip} -> ${e.dst_ip}${e.dst_port ? `:${e.dst_port}` : ''}`
    case 'host_domain': return `${e.ip} -> *.${e.domain}`
    case 'host': return `host ${e.ip}`
    case 'flow': return `${e.src_ip} -> ${e.dst_ip}:${e.dst_port}`
    default: {
      const f = inc?.flow || {}
      return f.src_ip ? `${f.src_ip} -> ${f.dst_ip}` : '-'
    }
  }
}

export const featureLabel = (name) => name.replace(/_/g, ' ')
