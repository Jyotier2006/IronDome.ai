// ============================================
// IronDome.ai - offline demo data (VITE_USE_MOCK=true)
// Emits exactly the sensor's socket / REST schema so the dashboard can be shown
// without the Python sensor running. Live mode never uses this file.
// ============================================
import { THREAT_CLASSES, CLASS_ORDER } from '@/constants/threatModel'

const rnd = (a, b) => a + Math.random() * (b - a)
const pick = (xs) => xs[Math.floor(Math.random() * xs.length)]
const ip = () => `${Math.floor(rnd(11, 223))}.${Math.floor(rnd(0, 255))}.${Math.floor(rnd(0, 255))}.${Math.floor(rnd(1, 254))}`
const host = () => `10.10.1.${Math.floor(rnd(10, 58))}`
const b64 = () => btoa(String.fromCharCode(...Array.from({ length: 20 }, () => Math.floor(rnd(0, 256)))))
const flowId = () => `1:${b64()}`
const hex = (n) => Array.from({ length: n }, () => '0123456789abcdef'[Math.floor(rnd(0, 16))]).join('')
const iso = (t = Date.now()) => new Date(t).toISOString()

export const MOCK_SCENARIOS = [
  { id: 'syn_flood', title: 'TCP SYN flood', tool: 'hping3 -S --flood', ps_ref: 'a', threat_class: 'volumetric_ddos', duration: 40, description: 'Bots send half-open SYNs to the public web server.' },
  { id: 'spoofed_flood', title: 'Spoofed-source SYN flood', tool: 'hping3 -S --rand-source', ps_ref: 'a', threat_class: 'volumetric_ddos', duration: 40, description: 'Every packet from a random forged source address.' },
  { id: 'udp_flood', title: 'UDP flood', tool: 'hping3 --udp --flood', ps_ref: 'a', threat_class: 'volumetric_ddos', duration: 40, description: 'A handful of hosts blast large UDP packets at random ports.' },
  { id: 'udp_amplification', title: 'DNS / NTP reflection-amplification', tool: 'reflector set', ps_ref: 'a', threat_class: 'volumetric_ddos', duration: 40, description: 'Open resolvers / NTP servers reflect oversized replies at the victim.' },
  { id: 'slowloris', title: 'Slowloris slow-HTTP exhaustion', tool: 'slowloris', ps_ref: 'a', threat_class: 'volumetric_ddos', duration: 90, description: 'Many half-sent HTTP requests held open.' },
  { id: 'c2_beacon', title: 'C2 beaconing', tool: 'sandboxed C2 emulator', ps_ref: 'b', threat_class: 'c2_beaconing', duration: 120, description: 'An infected workstation checks in over TLS at a regular interval with jitter.' },
  { id: 'dga', title: 'DGA domain burst', tool: 'DGArchive-style generator', ps_ref: 'c', threat_class: 'dga_dns_tunnelling', duration: 45, description: 'A host walks its domain-generation list; most lookups return NXDOMAIN.' },
  { id: 'dns_tunnel', title: 'DNS tunnel', tool: 'dnscat2 / iodine', ps_ref: 'c', threat_class: 'dga_dns_tunnelling', duration: 60, description: 'Encoded TXT/CNAME/NULL queries to one controlled domain.' },
  { id: 'encrypted_malware', title: 'Malware C2 over TLS', tool: 'implant TLS stack', ps_ref: 'd', threat_class: 'encrypted_malware', duration: 90, description: 'An implant opens irregular TLS sessions with its own client stack.' },
  { id: 'port_scan', title: 'Vertical port scan', tool: 'nmap -sS -p1-1024', ps_ref: 'e', threat_class: 'recon_scan', duration: 30, description: 'An external host SYN-scans a range of ports on the public servers.' },
  { id: 'host_sweep', title: 'Horizontal host sweep', tool: 'nmap -sS -p445,3389', ps_ref: 'e', threat_class: 'recon_scan', duration: 30, description: 'An internal host sweeps the workstation subnet for SMB and RDP.' },
  { id: 'exfiltration', title: 'Bulk data exfiltration', tool: 'scripted upload', ps_ref: 'f', threat_class: 'data_exfiltration', duration: 90, description: 'A workstation uploads a large volume to a never-before-seen server.' },
  { id: 'kill_chain', title: 'Full kill-chain', tool: 'combined', ps_ref: 'b-f', threat_class: 'multiple', duration: 190, description: 'Recon, C2 beacon, DGA, DNS tunnel and exfiltration in sequence.' },
]

const MITRE = {
  syn_flood: ['T1498.001', 'T1499.001'], udp_icmp_flood: ['T1498.001'], udp_amplification: ['T1498.002'],
  spoofed_flood: ['T1498.001'], slow_http: ['T1499.002'], periodic_beacon: ['T1071.001', 'T1573'],
  dga: ['T1568.002'], dns_tunnelling: ['T1071.004', 'T1572'], ja3_watchlist: ['T1573.002'],
  tls_behaviour: ['T1573.002', 'T1071.001'], vertical_scan: ['T1046'], horizontal_scan: ['T1046', 'T1595.001'],
  volume_asymmetry: ['T1041', 'T1048'],
}
const TECH_LABEL = {
  syn_flood: 'TCP SYN flood', udp_icmp_flood: 'UDP / ICMP flood', udp_amplification: 'UDP reflection / amplification',
  spoofed_flood: 'Spoofed-source flood', slow_http: 'Slow HTTP exhaustion (Slowloris)', periodic_beacon: 'Periodic C2 beacon',
  dga: 'Algorithmically generated domains (DGA)', dns_tunnelling: 'DNS tunnelling', ja3_watchlist: 'Watch-listed TLS client fingerprint',
  tls_behaviour: 'Anomalous encrypted-session behaviour', vertical_scan: 'Vertical port scan', horizontal_scan: 'Horizontal host sweep',
  volume_asymmetry: 'Asymmetric outbound transfer',
}
const ACTIONS = {
  volumetric_ddos: 'Notify the NOC / upstream ISP out-of-band so scrubbing or rate-limiting can be applied on the production side. The monitoring enclave has no return path and never pushes mitigations itself.',
  c2_beaconing: 'Raise an incident for the internal host; the endpoint team should isolate and image it through normal change control.',
  dga_dns_tunnelling: 'Report the queried base domain to the DNS team for sinkholing via the production-side change process.',
  encrypted_malware: 'Correlate the JA3/JA4 fingerprint and destination across the estate; hand the host to incident response. No decryption is performed or required.',
  recon_scan: 'Record the scanning source for threat-intel; watch for follow-on exploitation of the probed services.',
  data_exfiltration: 'Escalate to incident response and data-protection officers; preserve the alert record and its related flow records as evidence for forensics.',
}

const SCENARIO_TECH = {
  syn_flood: ['volumetric_ddos', 'syn_flood'], spoofed_flood: ['volumetric_ddos', 'spoofed_flood'],
  udp_flood: ['volumetric_ddos', 'udp_icmp_flood'], udp_amplification: ['volumetric_ddos', 'udp_amplification'],
  slowloris: ['volumetric_ddos', 'slow_http'], c2_beacon: ['c2_beaconing', 'periodic_beacon'],
  dga: ['dga_dns_tunnelling', 'dga'], dns_tunnel: ['dga_dns_tunnelling', 'dns_tunnelling'],
  encrypted_malware: ['encrypted_malware', 'tls_behaviour'], port_scan: ['recon_scan', 'vertical_scan'],
  host_sweep: ['recon_scan', 'horizontal_scan'], exfiltration: ['data_exfiltration', 'volume_asymmetry'],
}

function evidenceFor(tc, tech, ctx) {
  const dev = (feature, value, mean, z) => ({ feature, value, benign_mean: mean, z_score: z })
  switch (tc) {
    case 'volumetric_ddos':
      return {
        features: { flows_per_s: 742, syn_only_ratio: tech === 'syn_flood' ? 0.97 : 0.02, src_entropy_norm: 0.98, uniq_src: tech === 'spoofed_flood' ? 1480 : 40, amp_port_ratio: tech === 'udp_amplification' ? 1 : 0 },
        top_deviations: [dev('flows_per_s', 742, 38.2, 9.4), dev('syn_only_ratio', 0.97, 0.04, 12.1), dev('established_ratio', 0.02, 0.93, -8.7)],
        context: { window: { seconds: 2 }, flows: 1484, top_sources: [{ ip: ctx.attacker, flows: 61 }], top_dst_ports: [{ port: 443, flows: 1480 }] },
      }
    case 'c2_beaconing':
      return {
        features: { n_conns: 14, iat_median: 5.02, iat_cv: 0.09, iat_regularity: 0.92, dst_prevalence: 1 },
        top_deviations: [dev('iat_regularity', 0.92, 0.41, 3.1), dev('dst_prevalence', 1, 38, -2.8), dev('bytes_fwd_cv', 0.08, 0.9, -2.2)],
        context: { interval_s: 5.02, jitter_pct: 6.1 },
      }
    case 'dga_dns_tunnelling':
      return tech === 'dga'
        ? { features: { unique_domains: 41, nx_ratio: 0.93, malicious_domains: 36 }, top_deviations: [], malicious_domain_count: 36,
            example_domains: Array.from({ length: 5 }, () => ({ domain: `${hex(12).replace(/[0-9]/g, 'x')}.${pick(['info', 'xyz', 'top', 'ru'])}`, score: +rnd(0.9, 0.999).toFixed(3), rcode: 'NXDOMAIN' })),
            context: { nx_ratio: 0.93 } }
        : { features: { queries: 612, unique_ratio: 1, mean_sub_len: 71, txt_null_ratio: 0.94 },
            top_deviations: [dev('mean_sub_len', 71, 9.8, 11.3), dev('unique_ratio', 1, 0.31, 3.9), dev('txt_null_ratio', 0.94, 0.03, 8.2)],
            context: { base_domain: ctx.target, sample_queries: [`${hex(60)}.t.${ctx.target}`], qtypes: { TXT: 402, CNAME: 110, MX: 100 } } }
    case 'encrypted_malware':
      return {
        features: { ja3_prevalence: 1, dst_prevalence: 1, sni_present: 0, alpn_present: 0, bytes_bwd: 1420 },
        top_deviations: [dev('ja3_prevalence', 1, 64, -3.2), dev('splt_bwd_mean', 180, 1310, -4.4), dev('cipher_count', 59, 16, 5.1)],
        context: { version: 'TLS1.2', ja3: hex(32), ja4: `t12i590600_${hex(12)}_${hex(12)}` },
      }
    case 'recon_scan':
      return {
        features: { uniq_ports: tech === 'vertical_scan' ? 842 : 2, uniq_hosts: tech === 'vertical_scan' ? 3 : 212, failed_ratio: 0.97, no_payload_ratio: 1 },
        top_deviations: [dev('uniq_pairs', 842, 11, 14.2), dev('failed_ratio', 0.97, 0.06, 7.7)],
        context: { ports_total: 842, top_targets: [{ ip: '10.10.2.80', flows: 402 }] },
      }
    default:
      return {
        features: { bytes_out_mb: 184.2, bytes_in_mb: 0.41, out_in_ratio_log: 2.65, dst_prevalence: 1, host_out_zscore: 18.4 },
        top_deviations: [dev('bytes_out_mb', 184.2, 3.1, 16.8), dev('host_out_zscore', 18.4, 0.1, 9.2)],
        context: { bytes_out: 184200000, bytes_in: 410000, ratio: 449.3 },
      }
  }
}

export function mockIncident(scenarioId, ctx = {}) {
  const [tc, tech] = SCENARIO_TECH[scenarioId] || SCENARIO_TECH.syn_flood
  const info = THREAT_CLASSES[tc]
  const conf = +rnd(0.86, 0.999).toFixed(4)
  const now = Date.now()
  const c = { attacker: ctx.attacker || ip(), host: ctx.host || host(), target: ctx.target || `${hex(8)}.xyz` }
  const entity = {
    volumetric_ddos: { type: 'destination', ip: '10.10.2.80' },
    c2_beaconing: { type: 'host_pair', src_ip: c.host, dst_ip: c.attacker, dst_port: 443 },
    dga_dns_tunnelling: tech === 'dga' ? { type: 'host', ip: c.host } : { type: 'host_domain', ip: c.host, domain: c.target },
    encrypted_malware: { type: 'flow', src_ip: c.host, dst_ip: c.attacker, dst_port: 443 },
    recon_scan: { type: 'source', ip: tech === 'vertical_scan' ? c.attacker : c.host },
    data_exfiltration: { type: 'host_pair', src_ip: c.host, dst_ip: c.attacker },
  }[tc]
  const id = crypto.randomUUID()
  return {
    schema_version: '1.0',
    alert_id: id,
    incident_id: id,
    timestamp: iso(now),
    first_seen: iso(now - rnd(2000, 9000)),
    last_seen: iso(now - 500),
    flow_id: flowId(),
    related_flow_ids: [flowId(), flowId(), flowId()],
    flow: { src_ip: entity.src_ip || c.attacker, src_port: Math.floor(rnd(32768, 60999)), dst_ip: entity.dst_ip || entity.ip || '10.10.2.80', dst_port: entity.dst_port || 443, protocol: tc === 'dga_dns_tunnelling' ? 'UDP' : 'TCP' },
    entity,
    threat_class: tc,
    ps_ref: info.ps,
    threat_label: info.label,
    technique: tech,
    technique_label: TECH_LABEL[tech],
    mitre_attack: MITRE[tech] || [],
    confidence: conf,
    severity: { volumetric_ddos: 'critical', data_exfiltration: 'critical', recon_scan: 'medium' }[tc] || 'high',
    description: `${TECH_LABEL[tech]} observed passively from flow metadata (demo data).`,
    recommended_action: ACTIONS[tc],
    detector: { name: tc, model: `${info.short} classifier`, version: '2.0', mode: tech === 'ja3_watchlist' ? 'ml+intel' : 'ml', threshold: 0.5 },
    evidence: evidenceFor(tc, tech, c),
    source: { pipeline: 'sensor', mode: 'mock' },
    occurrences: 1,
    latency_ms: Math.round(rnd(600, 1700)),
  }
}

const DOMAINS = ['www.google.com', 'api.github.com', 'timesofindia.com', 'cdn.jsdelivr.net', 'irctc.co.in', 'onlinesbi.sbi', 'hb.telemetry-hub.com', 'update.os-vendor.com', `${hex(14)}.cloudfront.net`]

export function mockFlow() {
  const kind = Math.random()
  const f = {
    flow_id: flowId(), ts: Date.now() / 1000, src_ip: host(), src_port: Math.floor(rnd(32768, 60999)),
    dst_ip: ip(), dst_port: 443, proto: 'TCP', bytes: Math.floor(rnd(800, 90000)), pkts: Math.floor(rnd(6, 90)), flags: 'SAPF',
  }
  if (kind < 0.35) {
    f.dst_ip = '203.0.113.53'; f.dst_port = 53; f.proto = 'UDP'; f.bytes = Math.floor(rnd(120, 520)); f.pkts = 2; f.flags = ''
    f.dns = { qname: pick(DOMAINS), qtype: pick(['A', 'A', 'AAAA', 'HTTPS']), rcode: 'NOERROR' }
  } else if (kind < 0.85) {
    f.tls = { sni: pick(DOMAINS), ja3: pick(['cd08e31494f9531f560d64c695473da9', '579ccef312d18482fc42e2b822ca2430', hex(32)]), ja4: `t13d1516h2_8daaf6152771_${hex(12)}`, version: 'TLS1.3' }
  } else {
    f.proto = 'UDP'; f.quic = true
  }
  return f
}

export function mockHello() {
  return {
    service: 'irondome-sensor', core_version: '2.0.0', read_only: true, issues_mitigation: false, decrypts_payload: false,
    ingest: { udp_port: 2055, lab: true }, learning_seconds: 300, throughput_target_fps: 5000,
    threat_classes: CLASS_ORDER.map((id) => ({
      id, ps_ref: THREAT_CLASSES[id].ps, label: THREAT_CLASSES[id].label, summary: THREAT_CLASSES[id].summary, recommended_action: ACTIONS[id],
      techniques: Object.values(SCENARIO_TECH).filter(([tc]) => tc === id).map(([, tk]) => tk)
        .filter((tk, i, a) => a.indexOf(tk) === i).map((tk) => ({ id: tk, label: TECH_LABEL[tk], mitre: MITRE[tk] || [] })),
    })),
    scenarios: MOCK_SCENARIOS,
    detector_modes: { ddos: 'ml', recon_scan: 'ml', c2_beacon: 'ml', dga_domain: 'ml', dns_tunnel: 'ml', encrypted_malware: 'ml', exfiltration: 'ml' },
    sources: [
      { id: 'lab', kind: 'built-in traffic lab', transport: 'in-process', enabled: true, records: 0 },
      { id: 'udp', kind: 'flow collector (NetFlow v5 / JSON)', transport: 'UDP/2055 receive-only', enabled: true, records: 0, datagrams: 0, errors: 0, exporters: 0 },
      { id: 'http', kind: 'REST flow upload', transport: 'HTTP POST /api/ingest/flows', enabled: true, records: 0 },
    ],
    stats: {}, active_runs: [],
  }
}

export function mockModels() {
  const row = (det, tc, ps, algo, p, r, f1, fpr, sr, us, thr, feats) => ({
    detector: det, threat_class: tc, ps_ref: ps, title: algo, algorithm: 'HistGradientBoostingClassifier (250 iterations, 31 leaves, class-balanced) + isotonic probability calibration (3-fold)',
    threshold: thr, inference_us_per_row: us, features: Array.from({ length: feats }, (_, i) => ({ name: `feature_${i + 1}`, description: '' })),
    classes: ['benign', 'attack'], metrics: { test: { precision: p, recall: r, f1, false_positive_rate: fpr, roc_auc: 0.999 }, stress: { recall: sr, false_positive_rate: fpr } },
    importance: [], train: { samples: 4000 },
  })
  return {
    generated_at: new Date().toISOString(), sklearn: '1.8.0', quick: false,
    detectors: {
      ddos: row('ddos', 'volumetric_ddos', 'a', 'Volumetric / protocol DDoS classifier', 1, 0.999, 0.9995, 0, 0.911, 1.9, 0.68, 22),
      c2_beacon: row('c2_beacon', 'c2_beaconing', 'b', 'C2 beaconing (periodicity) classifier', 0.997, 0.996, 0.997, 0.003, 0.994, 1.6, 0.545, 16),
      dga_domain: row('dga_domain', 'dga_dns_tunnelling', 'c', 'DGA domain (lexical) classifier', 0.993, 0.952, 0.972, 0.007, 0.864, 1.7, 0.425, 14),
      dns_tunnel: row('dns_tunnel', 'dga_dns_tunnelling', 'c', 'DNS tunnelling classifier', 1, 1, 1, 0, 1, 1.6, 0.5, 15),
      encrypted_malware: row('encrypted_malware', 'encrypted_malware', 'd', 'Encrypted-session malware classifier', 0.996, 1, 0.998, 0.004, 1, 2.3, 0.145, 28),
      recon_scan: row('recon_scan', 'recon_scan', 'e', 'Reconnaissance / port-scan classifier', 1, 1, 1, 0, 0.992, 1.7, 0.705, 16),
      exfiltration: row('exfiltration', 'data_exfiltration', 'f', 'Data exfiltration (volume asymmetry) classifier', 1, 0.95, 0.974, 0, 0.96, 1.6, 0.75, 13),
    },
  }
}
