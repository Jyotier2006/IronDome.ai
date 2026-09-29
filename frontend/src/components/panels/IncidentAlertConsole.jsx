import { memo } from 'react'
import { AnimatePresence } from 'framer-motion'
import IncidentSummaryCard from '@components/alerts/IncidentSummaryCard'
import { ClassChip, Empty, Icon, SeverityBadge } from '@components/common/ui'
import { downloadJson } from '@services/httpApiClient'
import { CLASS_ORDER, SEVERITY } from '@/constants/threatModel'

/**
 * Incident feed - labelled alerts with confidence and evidence (PS output).
 * Read-only by design: the analyst can acknowledge and export, and every
 * recommended action is carried out out-of-band on the production side.
 */
function IncidentAlertConsole({ store }) {
  const {
    filtered, stats, isAcked, statusFilter, setStatusFilter, classFilter, setClassFilter,
    severityFilter, setSeverityFilter, setSelectedId, acknowledge, acknowledgeAll, clearAcknowledged, incidents,
  } = store

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-[15px] font-semibold text-text-primary flex items-center gap-2">
          <Icon name="shield" className="w-4 h-4 text-text-secondary" />
          Incidents
        </h3>
        <span className="text-[11px] text-text-muted">{stats.open} open · {stats.total} total</span>
      </div>

      <div className="grid grid-cols-4 gap-1.5 mb-2">
        {Object.keys(SEVERITY).map((s) => (
          <button key={s} type="button" onClick={() => setSeverityFilter(severityFilter === s ? null : s)}
                  className={`glass-card px-2 py-1.5 text-left border ${severityFilter === s ? 'border-white/30' : 'border-transparent'}`}>
            <p className="text-lg font-semibold text-text-primary leading-none">{stats.bySeverity[s] || 0}</p>
            <div className="mt-1"><SeverityBadge severity={s} /></div>
          </button>
        ))}
      </div>

      <div className="flex gap-1 mb-2 p-1 rounded-lg bg-white/[0.03]">
        {['all', 'open', 'acknowledged'].map((f) => (
          <button key={f} type="button" onClick={() => setStatusFilter(f)}
                  className={`flex-1 py-1 text-[12px] rounded-md capitalize transition-colors ${statusFilter === f ? 'bg-white/[0.10] text-text-primary' : 'text-text-muted hover:text-text-secondary'}`}>
            {f}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap gap-1 mb-2">
        {CLASS_ORDER.map((c) => (
          <ClassChip key={c} cls={c} active={classFilter === c} count={stats.byClass[c]?.count}
                     onClick={() => setClassFilter(classFilter === c ? null : c)} />
        ))}
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto pr-1 thin-scrollbar space-y-2">
        <AnimatePresence initial={false}>
          {filtered.map((inc) => (
            <IncidentSummaryCard key={inc.incident_id} incident={inc} acked={isAcked(inc.incident_id)}
                                 onOpen={() => setSelectedId(inc.incident_id)} onAcknowledge={acknowledge} />
          ))}
        </AnimatePresence>
        {!filtered.length && (
          <Empty icon="shield" title={incidents.length ? 'No incidents match the filters' : 'No incidents yet'}
                 hint="Detections appear here with threat class, confidence and evidence as the sensor raises them." />
        )}
      </div>

      <div className="pt-2 mt-2 border-t border-white/[0.06] grid grid-cols-3 gap-1.5">
        <button type="button" onClick={acknowledgeAll} disabled={!stats.open}
                className="btn-ghost !px-2 !py-1.5 !text-[12px] flex items-center justify-center gap-1 disabled:opacity-40">
          <Icon name="check" className="w-3.5 h-3.5" /> Ack all
        </button>
        <button type="button" onClick={clearAcknowledged} disabled={stats.total === stats.open}
                className="btn-ghost !px-2 !py-1.5 !text-[12px] flex items-center justify-center gap-1 disabled:opacity-40">
          <Icon name="trash" className="w-3.5 h-3.5" /> Clear ack'd
        </button>
        <button type="button" onClick={() => downloadJson(`irondome-incidents-${Date.now()}.jsonl`, filtered, true)} disabled={!filtered.length}
                className="btn-ghost !px-2 !py-1.5 !text-[12px] flex items-center justify-center gap-1 disabled:opacity-40">
          <Icon name="download" className="w-3.5 h-3.5" /> Export
        </button>
      </div>
    </div>
  )
}

export default memo(IncidentAlertConsole)
