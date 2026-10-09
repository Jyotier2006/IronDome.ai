import { memo, useEffect, useState } from 'react'
import { ClassDot, Icon, PanelTitle } from '@components/common/ui'
import { fetchEvaluation, fetchModels } from '@services/httpApiClient'
import { USE_MOCK } from '@services/realtimeTransportClient'
import { classInfo, fmtPct } from '@/constants/threatModel'

const ORDER = ['ddos', 'c2_beacon', 'dga_domain', 'dns_tunnel', 'encrypted_malware', 'recon_scan', 'exfiltration']

function ModelRegistryPanel({ connected }) {
  const [cards, setCards] = useState(null)
  const [evaluation, setEvaluation] = useState(null)
  const [error, setError] = useState(null)
  const [open, setOpen] = useState(null)
  const [attempt, setAttempt] = useState(0)

  // (Re)load until the cards arrive: on mount, on Retry, and when the sensor (re)connects.
  useEffect(() => {
    if (cards) return undefined
    let alive = true
    setError(null)
    Promise.all([fetchModels(), fetchEvaluation().catch(() => ({}))])
      .then(([m, e]) => { if (alive) { setCards(m); setEvaluation(e) } })
      .catch((err) => { if (alive) setError(err.message) })
    return () => { alive = false }
  }, [attempt, connected]) // eslint-disable-line react-hooks/exhaustive-deps

  if (error) {
    return (
      <div className="text-[12px] text-text-secondary space-y-2">
        <p>Could not load model cards from the sensor: {error}</p>
        <button type="button" onClick={() => setAttempt((n) => n + 1)} className="btn-ghost !px-2.5 !py-1 !text-[12px] border border-white/10">
          Retry
        </button>
      </div>
    )
  }
  if (!cards) return <p className="text-[12px] text-text-muted">Loading model cards…</p>

  const dets = ORDER.filter((d) => cards.detectors?.[d])
  const scen = evaluation?.scenarios || []
  const benign = evaluation?.benign

  return (
    <div className="h-full overflow-y-auto pr-1 thin-scrollbar space-y-4">
      {USE_MOCK && (
        <p className="text-[11px] px-3 py-2 rounded-lg bg-status-warning/10 border border-status-warning/25 text-text-secondary">
          Demo mode: showing sample model cards. Start the sensor to load the cards written by the training pipeline.
        </p>
      )}
      <div className="glass-card p-3">
        <PanelTitle icon="cpu" right={<span className="text-[11px] text-text-muted">scikit-learn {cards.sklearn} · trained {cards.generated_at ? new Date(cards.generated_at).toLocaleString('en-GB') : '-'}</span>}>
          Detection models - held-out test and shifted "stress" results
        </PanelTitle>
        <div className="overflow-x-auto">
          <table className="w-full text-[12px]">
            <thead className="text-text-muted text-[11px]">
              <tr className="border-b border-white/[0.06]">
                <th className="text-left font-medium py-2 pr-2">PS</th>
                <th className="text-left font-medium py-2 pr-2">Detector</th>
                <th className="text-right font-medium py-2 px-2">Features</th>
                <th className="text-right font-medium py-2 px-2">Precision</th>
                <th className="text-right font-medium py-2 px-2">Recall</th>
                <th className="text-right font-medium py-2 px-2">F1</th>
                <th className="text-right font-medium py-2 px-2">FPR</th>
                <th className="text-right font-medium py-2 px-2">Stress recall</th>
                <th className="text-right font-medium py-2 px-2">Threshold</th>
                <th className="text-right font-medium py-2 pl-2">Inference</th>
              </tr>
            </thead>
            <tbody>
              {dets.map((d) => {
                const c = cards.detectors[d]
                const te = c.metrics?.test || {}
                const st = c.metrics?.stress || {}
                const isOpen = open === d
                return (
                  <tr key={d} className="border-b border-white/[0.04] hover:bg-white/[0.03] cursor-pointer" onClick={() => setOpen(isOpen ? null : d)}>
                    <td className="py-2 pr-2"><span className="inline-flex items-center gap-1.5"><ClassDot cls={c.threat_class} /><span className="font-mono text-text-muted">{c.ps_ref}</span></span></td>
                    <td className="py-2 pr-2 text-text-primary">
                      {c.title || d}
                      <span className="block text-[10px] text-text-muted font-mono">{d}</span>
                    </td>
                    <td className="py-2 px-2 text-right tabular text-text-secondary">{c.features?.length ?? '-'}</td>
                    <td className="py-2 px-2 text-right tabular text-text-primary">{fmtPct(te.precision, 1)}</td>
                    <td className="py-2 px-2 text-right tabular text-text-primary">{fmtPct(te.recall, 1)}</td>
                    <td className="py-2 px-2 text-right tabular text-text-primary">{te.f1?.toFixed(3) ?? '-'}</td>
                    <td className="py-2 px-2 text-right tabular text-text-secondary">{fmtPct(te.false_positive_rate, 2)}</td>
                    <td className="py-2 px-2 text-right tabular text-text-secondary">{fmtPct(st.recall, 1)}</td>
                    <td className="py-2 px-2 text-right tabular text-text-secondary">{c.threshold}</td>
                    <td className="py-2 pl-2 text-right tabular text-text-secondary whitespace-nowrap">{c.inference_us_per_row} µs/row</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        {open && cards.detectors[open] && (
          <div className="mt-3 p-3 rounded-lg bg-white/[0.03] border border-white/[0.06] text-[12px]">
            <p className="text-text-primary font-medium">{cards.detectors[open].algorithm}</p>
            <p className="text-text-muted mt-1">Classes: {cards.detectors[open].classes?.join(', ')} · decision: {cards.detectors[open].threshold_rule || 'P(attack) ≥ threshold'}</p>
            {cards.detectors[open].importance?.length > 0 && (
              <div className="mt-2">
                <p className="text-text-secondary mb-1">Most influential features (permutation importance)</p>
                <ul className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-0.5">
                  {cards.detectors[open].importance.slice(0, 8).map((f) => {
                    const doc = cards.detectors[open].features?.find((x) => x.name === f.feature)?.description
                    return (
                      <li key={f.feature} className="flex items-baseline gap-2">
                        <span className="font-mono text-text-primary">{f.feature}</span>
                        <span className="text-text-muted truncate">{doc}</span>
                      </li>
                    )
                  })}
                </ul>
              </div>
            )}
          </div>
        )}
        <p className="mt-2 text-[11px] text-text-muted">Click a row for its algorithm and most influential features. Methodology: the ML pipeline section of README.md; auto-generated metrics: docs/MODEL_REPORT.md.</p>
      </div>

      <div className="glass-card p-3">
        <PanelTitle icon="beaker">End-to-end replay evaluation (streaming pipeline vs ground truth)</PanelTitle>
        {scen.length ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-[12px]">
                <thead className="text-text-muted text-[11px]">
                  <tr className="border-b border-white/[0.06]">
                    <th className="text-left font-medium py-2 pr-2">PS</th>
                    <th className="text-left font-medium py-2 pr-2">Scenario</th>
                    <th className="text-right font-medium py-2 px-2">Detected</th>
                    <th className="text-right font-medium py-2 px-2">Median time-to-detect</th>
                    <th className="text-right font-medium py-2 pl-2">Replay throughput</th>
                  </tr>
                </thead>
                <tbody>
                  {scen.map((s) => (
                    <tr key={s.scenario} className="border-b border-white/[0.04]">
                      <td className="py-1.5 pr-2 font-mono text-text-muted">{s.ps_ref}</td>
                      <td className="py-1.5 pr-2 text-text-primary font-mono">{s.scenario}</td>
                      <td className="py-1.5 px-2 text-right tabular text-text-primary">{s.detected}/{s.runs}</td>
                      <td className="py-1.5 px-2 text-right tabular text-text-secondary">{s.median_ttd != null ? `${Math.max(0, s.median_ttd).toFixed(1)} s` : '-'}</td>
                      <td className="py-1.5 pl-2 text-right tabular text-text-secondary">{s.flows_per_s?.toLocaleString('en-IN')} flows/s</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {benign && (
              <p className="mt-2 text-[12px] text-text-secondary flex items-start gap-1.5">
                <Icon name="info" className="w-3.5 h-3.5 mt-px shrink-0" />
                Benign-only estate, {benign.minutes} min steady state: {benign.false_incidents ?? benign.false_alerts} false incident(s) ({benign.incidents_per_hour ?? benign.fp_per_hour}/hour).
              </p>
            )}
          </>
        ) : (
          <p className="text-[12px] text-text-muted">No evaluation results yet - run <span className="font-mono">python model_microservice/evaluate_pipeline.py</span>.</p>
        )}
      </div>

      <p className="text-[11px] text-text-muted">
        {classInfo('encrypted_malware').label}: alerts require a rare client fingerprint and an absent or suspicious server name, or a watch-listed JA3 - sessions are never decrypted.
      </p>
    </div>
  )
}

export default memo(ModelRegistryPanel)
