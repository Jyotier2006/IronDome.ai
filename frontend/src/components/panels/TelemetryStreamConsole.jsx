import { useRef, useEffect, useState, memo } from 'react'

function TelemetryTerminal({
  events = [],
  isPaused = false,
  onTogglePause,
  onClear,
}) {
  const scrollRef = useRef(null)
  const [isHovered, setIsHovered] = useState(false)
  const [isExpanded, setIsExpanded] = useState(false)

  useEffect(() => {
    if (scrollRef.current && !isHovered && !isPaused) {
      scrollRef.current.scrollTop = 0
    }
  }, [events, isHovered, isPaused])

  const formatTimestamp = (isoString) => {
    const date = new Date(isoString)
    if (Number.isNaN(date.getTime())) return '--:--:--'
    return date.toLocaleTimeString('en-US', { hour12: false })
  }

  const chip = (bg, color, text) => (
    <span style={{
      padding: '2px 8px',
      borderRadius: 4,
      background: bg,
      color,
      fontSize: 12,
      whiteSpace: 'nowrap',
    }}>
      {text}
    </span>
  )

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: isExpanded ? 320 : 160,
      minHeight: isExpanded ? 320 : 160,
      background: '#0d1117',
      border: '1px solid rgba(255,255,255,0.08)',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '8px 12px',
        background: '#0f172a',
        borderBottom: '1px solid rgba(255,255,255,0.08)',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ display: 'flex', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444' }} />
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#f59e0b' }} />
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#22c55e' }} />
          </div>
          <span style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: 12 }}>telemetry.stream</span>
          <span style={{ color: '#64748b', fontSize: 12 }}>{events.length} events</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <button
            onClick={onTogglePause}
            style={{
              padding: '4px 10px',
              borderRadius: 4,
              fontSize: 12,
              background: isPaused ? 'rgba(245,158,11,0.2)' : 'rgba(255,255,255,0.06)',
              color: isPaused ? '#f59e0b' : '#94a3b8',
              border: 'none',
              cursor: 'pointer',
            }}
          >
            {isPaused ? 'Resume' : 'Pause'}
          </button>
          <button
            onClick={onClear}
            style={{
              padding: '4px 10px',
              borderRadius: 4,
              fontSize: 12,
              background: 'rgba(255,255,255,0.06)',
              color: '#94a3b8',
              border: 'none',
              cursor: 'pointer',
            }}
          >
            Clear
          </button>
          <button
            onClick={() => setIsExpanded((v) => !v)}
            style={{
              padding: '4px 10px',
              borderRadius: 4,
              fontSize: 12,
              background: 'rgba(255,255,255,0.06)',
              color: '#94a3b8',
              border: 'none',
              cursor: 'pointer',
            }}
          >
            {isExpanded ? 'Collapse' : 'Expand'}
          </button>
        </div>
      </div>

      {/* Body */}
      <div
        ref={scrollRef}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        style={{
          flex: '1 1 auto',
          minHeight: 0,
          overflowY: 'auto',
          padding: 8,
          fontFamily: 'monospace',
          fontSize: 12,
          background: '#0d1117',
        }}
      >
        {events.length === 0 ? (
          <div style={{ color: '#64748b', display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
            Waiting for telemetry data...
          </div>
        ) : (
          events.map((event) => (
            <div
              key={event.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: 8,
                padding: '4px 0',
              }}
            >
              <span style={{ color: '#64748b', flexShrink: 0 }}>{formatTimestamp(event.timestamp)}</span>
              {chip('rgba(6,182,212,0.12)', '#06b6d4', String(event.deviceId ?? 'unknown'))}
              {chip('rgba(34,197,94,0.12)', '#22c55e', `CPU ${(Number(event.metrics?.cpu) || 0).toFixed(1)}%`)}
              {chip('rgba(245,158,11,0.12)', '#f59e0b', `MEM ${(Number(event.metrics?.memory) || 0).toFixed(1)}%`)}
              {chip('rgba(59,130,246,0.12)', '#3b82f6', `NET ${(Number(event.metrics?.network) || 0).toFixed(0)}KB/s`)}
              {chip('rgba(139,92,246,0.12)', '#8b5cf6', `REQ ${event.metrics?.requests ?? 0}`)}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

export default memo(TelemetryTerminal)
