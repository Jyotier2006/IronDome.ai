// ============================================
// IronDome.ai - realtime feed from the passive sensor (Socket.IO)
// The dashboard only *receives*: hello, flow_stats, flows_batch, alert,
// alert_update, scenario. There is no command channel to the network.
// ============================================
import { io } from 'socket.io-client'
import { mockFlow, mockHello, mockIncident, MOCK_SCENARIOS } from '@mock/mockTrafficDataset'

export const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true'
export const SENSOR_URL = import.meta.env.VITE_SENSOR_URL || `http://${window.location.hostname || '127.0.0.1'}:3001`

// ---------- offline demo emitter (same event names and payloads) ----------
class MockSensor {
  constructor() {
    this.listeners = new Map()
    this.connected = false
    this.timers = []
    this.total = 0
    this.bytes = 0
    this.attack = null
  }

  on(ev, cb) {
    if (!this.listeners.has(ev)) this.listeners.set(ev, new Set())
    this.listeners.get(ev).add(cb)
    return this
  }

  off(ev, cb) {
    this.listeners.get(ev)?.delete(cb)
    return this
  }

  emitLocal(ev, data) {
    this.listeners.get(ev)?.forEach((cb) => cb(data))
  }

  // Like the live sensor, the demo starts with no incidents and never attacks on its own:
  // detections appear only for scenarios injected from the traffic lab.
  connect() {
    if (this.connected) return this
    this.connected = true
    setTimeout(() => {
      this.emitLocal('connect')
      this.emitLocal('hello', mockHello())
      this.emitLocal('incidents_snapshot', [])
      this.emitLocal('flows_snapshot', Array.from({ length: 30 }, mockFlow))
    }, 150)
    this.timers.push(setInterval(() => this.tick(), 1000))
    return this
  }

  disconnect() {
    this.connected = false
    this.timers.forEach(clearInterval)
    this.timers = []
    this.emitLocal('disconnect')
  }

  tick() {
    const boost = this.attack && this.attack.scenario.includes('flood') ? 5 : 1
    const fps = (220 + Math.random() * 90) * boost
    this.total += fps
    this.bytes += fps * 9000
    this.emitLocal('flow_stats', {
      ts: Date.now() / 1000, flows_per_s: +fps.toFixed(1), pkts_per_s: Math.round(fps * 14), mbps: +(fps * 0.072).toFixed(2),
      total_flows: Math.round(this.total), total_bytes: this.bytes, peak_flows_per_s: 0, target_flows_per_s: 5000,
      encrypted_share: 0.76, encrypted_byte_share: 0.9, handshake_share: 0.07, dns_share: 0.12, protocol_mix: { TCP: 0.66, UDP: 0.33, ICMP: 0.01 },
      latency: { p50_ms: 1150, p95_ms: 1680, max_ms: 1900, samples: 40 }, context_age_s: 900, baseline_learning: false,
      open_incidents: this.attack?.sent ? 1 : 0, shed: 0, uptime_s: 0,
      sources: mockHello().sources.map((s) => (s.id === 'lab' ? { ...s, records: Math.round(this.total) } : s)),
    })
    this.emitLocal('flows_batch', Array.from({ length: 8 }, mockFlow))
    if (this.attack && Date.now() > this.attack.alertAt && !this.attack.sent) {
      this.attack.sent = true
      this.emitLocal('alert', mockIncident(this.attack.scenario, this.attack))
    }
    if (this.attack && Date.now() > this.attack.end) this.attack = null
  }

  inject(scenario, auto = false) {
    const meta = MOCK_SCENARIOS.find((s) => s.id === scenario) || MOCK_SCENARIOS[0]
    const run = {
      id: Math.random().toString(16).slice(2, 14), scenario: meta.id, title: meta.title, tool: meta.tool,
      ps_ref: meta.ps_ref, threat_class: meta.threat_class, attacker: `198.51.100.${Math.floor(Math.random() * 250)}`,
      host: `10.10.1.${10 + Math.floor(Math.random() * 48)}`, target: '10.10.2.80', intensity: 1,
      start_wall: Date.now() / 1000, end_wall: Date.now() / 1000 + meta.duration,
    }
    this.attack = { ...run, alertAt: Date.now() + 2500 + Math.random() * 3000, end: Date.now() + meta.duration * 1000, sent: false }
    this.emitLocal('scenario', { event: 'start', auto, ...run })
    return run
  }
}

// ---------- connection management ----------
let socket = null

export function getSocket() {
  if (socket) return socket
  socket = USE_MOCK
    ? new MockSensor()
    : io(SENSOR_URL, { transports: ['websocket', 'polling'], reconnection: true, reconnectionDelay: 1000, autoConnect: false })
  return socket
}

export function connectSensor() {
  const s = getSocket()
  s.connect()
  return s
}

export function disconnectSensor() {
  if (socket) socket.disconnect()
}

export function subscribe(event, cb) {
  const s = getSocket()
  s.on(event, cb)
  return () => s.off(event, cb)
}

export function mockInject(scenario) {
  return USE_MOCK ? getSocket().inject(scenario) : null
}
