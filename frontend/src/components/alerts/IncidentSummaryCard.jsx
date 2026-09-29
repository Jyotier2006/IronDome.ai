import { memo } from 'react'
import { motion } from 'framer-motion'
import { ClassDot, ConfidenceMeter, Icon, SeverityBadge } from '@components/common/ui'
import { classInfo, entityText, shortFlowId, timeAgo } from '@/constants/threatModel'

function IncidentSummaryCard({ incident, acked, onOpen, onAcknowledge }) {
  const info = classInfo(incident.threat_class)
  const replay = incident.source?.mode === 'replay'
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 16 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -16 }}
      transition={{ duration: 0.2 }}
      onClick={onOpen}
      className={`glass-card p-3 cursor-pointer hover:bg-white/[0.05] transition-colors ${acked ? 'opacity-55' : ''}`}
      style={{ boxShadow: `inset 3px 0 0 0 ${info.color}` }}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter') onOpen?.() }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-[11px] text-text-muted">
            <ClassDot cls={incident.threat_class} />
            <span className="font-mono">PS ({info.ps})</span>
            <span className="truncate">{info.short}</span>
            {replay && <span className="px-1 rounded bg-white/[0.06] border border-white/10 text-[10px]">replay</span>}
          </div>
          <p className="mt-0.5 text-[13px] font-semibold text-text-primary truncate">{incident.technique_label || incident.technique}</p>
        </div>
        <SeverityBadge severity={incident.severity} />
      </div>

      <p className="mt-1 text-[11px] text-text-secondary font-mono truncate">{entityText(incident)}</p>

      <div className="mt-2 flex items-center justify-between gap-2">
        <ConfidenceMeter value={incident.confidence} color={info.color} />
        <span className="text-[11px] text-text-muted flex items-center gap-2">
          {incident.occurrences > 1 && <span className="tabular">×{incident.occurrences}</span>}
          <span className="font-mono" title={incident.flow_id}>{shortFlowId(incident.flow_id)}</span>
          <span>{timeAgo(incident.last_seen || incident.timestamp)}</span>
        </span>
      </div>

      {!acked && (
        <div className="mt-2 flex justify-end" onClick={(e) => e.stopPropagation()}>
          <button type="button" onClick={() => onAcknowledge?.(incident.incident_id)}
                  className="px-2 py-0.5 rounded text-[11px] bg-white/[0.05] hover:bg-white/[0.10] border border-white/10 text-text-secondary flex items-center gap-1">
            <Icon name="check" className="w-3 h-3" /> Acknowledge
          </button>
        </div>
      )}
    </motion.div>
  )
}

export default memo(IncidentSummaryCard)
