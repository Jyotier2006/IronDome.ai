// ============================================
// IronDome.ai - REST client for the passive sensor
// Read endpoints for alerts, models, validation and schema, plus the traffic-lab
// scenario injector (which drives the *simulated source*, not the sensor).
// There is intentionally no block / isolate / rate-limit call: the enclave is read-only.
// ============================================
import { SENSOR_URL, USE_MOCK, mockInject } from './realtimeTransportClient'
import { mockModels } from '@mock/mockTrafficDataset'

async function request(path, options = {}) {
  const res = await fetch(`${SENSOR_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try {
      detail = (await res.json()).detail || detail
    } catch { /* keep status text */ }
    throw new Error(detail)
  }
  return res.json()
}

export const fetchModels = () => (USE_MOCK ? Promise.resolve(mockModels()) : request('/api/models'))

export const fetchEvaluation = () => (USE_MOCK ? Promise.resolve({}) : request('/api/evaluation'))

export const fetchAlertSchema = () => (USE_MOCK ? Promise.resolve({ title: 'demo' }) : request('/api/schema/alert'))

export const fetchIncident = (id) => request(`/api/alerts/${encodeURIComponent(id)}`)

export function injectScenario(scenario, intensity = 1) {
  if (USE_MOCK) return Promise.resolve({ started: mockInject(scenario) })
  return request('/api/scenario', { method: 'POST', body: JSON.stringify({ scenario, intensity }) })
}

// Downloads are generated client-side from what the dashboard holds.
export function downloadJson(filename, data, jsonl = false) {
  const text = jsonl ? data.map((d) => JSON.stringify(d)).join('\n') + '\n' : JSON.stringify(data, null, 2)
  const blob = new Blob([text], { type: jsonl ? 'application/x-ndjson' : 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
