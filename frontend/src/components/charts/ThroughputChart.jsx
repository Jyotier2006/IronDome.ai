import { memo, useMemo } from 'react'
import { Area, AreaChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { CHART } from '@/constants/threatModel'

// Traffic ink: a neutral cyan, deliberately *not* one of the six threat-class hues,
// so the throughput series never reads as a threat identity.
const TRAFFIC = '#22b8cf'

function niceMax(v) {
  if (!Number.isFinite(v) || v <= 0) return 10
  const target = v * 1.1
  const pow = 10 ** Math.floor(Math.log10(target))
  // multiples whose quarters are round numbers, so the four gridlines land on clean ticks
  return [1, 2, 4, 5, 8, 10].find((m) => m * pow >= target) * pow
}

const tickTime = (t) => new Date(t).toLocaleTimeString('en-GB', { hour12: false, minute: '2-digit', second: '2-digit' })

function CrosshairTooltip({ active, payload, label, unit, digits }) {
  if (!active || !payload?.length) return null
  const v = payload[0].value
  return (
    <div className="rounded-lg border border-white/10 bg-[#0d111c]/95 px-3 py-2 shadow-lg">
      <div className="text-[15px] font-semibold text-text-primary">
        {Number.isFinite(v) ? v.toLocaleString('en-IN', { maximumFractionDigits: digits }) : '-'}
        <span className="text-[11px] font-normal text-text-secondary ml-1">{unit}</span>
      </div>
      <div className="text-[11px] text-text-muted tabular">{new Date(label).toLocaleTimeString('en-GB', { hour12: false })}</div>
    </div>
  )
}

function ThroughputChart({ data, dataKey, unit, digits = 0, height = 170, markers = [], ariaLabel }) {
  const domain = useMemo(() => {
    if (!data.length) {
      const now = Date.now()
      return [now - 180000, now]
    }
    return [data[0].t, data[data.length - 1].t]
  }, [data])

  const visibleMarkers = markers.filter((m) => m.t >= domain[0] && m.t <= domain[1]).slice(0, 4)
  const yMax = niceMax(Math.max(0, ...data.map((d) => d[dataKey] || 0)))
  const yTicks = [0, yMax / 4, yMax / 2, (3 * yMax) / 4, yMax]

  return (
    <div style={{ height }} role="img" aria-label={ariaLabel}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 14, right: 12, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id={`wash-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={TRAFFIC} stopOpacity={0.14} />
              <stop offset="100%" stopColor={TRAFFIC} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke={CHART.grid} vertical={false} />
          <XAxis
            dataKey="t" type="number" domain={domain} tickFormatter={tickTime} tickCount={5}
            stroke={CHART.axis} tick={{ fill: CHART.tick, fontSize: 10 }} tickLine={false} height={20}
          />
          <YAxis
            stroke={CHART.axis} tick={{ fill: CHART.tick, fontSize: 10 }} tickLine={false} axisLine={false} width={44}
            tickFormatter={(v) => v.toLocaleString('en-IN', { maximumFractionDigits: yMax < 10 ? 1 : 0 })}
            domain={[0, yMax]} ticks={yTicks}
          />
          <Tooltip
            content={<CrosshairTooltip unit={unit} digits={digits} />}
            cursor={{ stroke: 'rgba(255,255,255,0.35)', strokeWidth: 1 }}
            isAnimationActive={false}
          />
          {visibleMarkers.map((m) => (
            <ReferenceLine
              key={`${m.t}-${m.label}`} x={m.t} stroke="rgba(255,255,255,0.22)" strokeWidth={1}
              label={{ value: m.label, position: 'insideTopLeft', fill: CHART.tick, fontSize: 10 }}
            />
          ))}
          <Area
            type="monotone" dataKey={dataKey} stroke={TRAFFIC} strokeWidth={2} fill={`url(#wash-${dataKey})`}
            dot={false} activeDot={{ r: 4, stroke: '#111521', strokeWidth: 2, fill: TRAFFIC }} isAnimationActive={false}
            connectNulls
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

export default memo(ThroughputChart)
