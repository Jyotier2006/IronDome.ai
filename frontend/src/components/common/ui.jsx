import { classInfo, severityInfo } from '@/constants/threatModel'

const PATHS = {
  shield: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
  pulse: 'M3 12h4l3-8 4 16 3-8h4',
  grid: 'M4 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1V5zm10 0a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1v-4zm10 0a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z',
  list: 'M4 6h16M4 12h16M4 18h10',
  clock: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
  cpu: 'M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z',
  check: 'M5 13l4 4L19 7',
  x: 'M6 18L18 6M6 6l12 12',
  arrowRight: 'M14 5l7 7m0 0l-7 7m7-7H3',
  oneway: 'M13 7l5 5m0 0l-5 5m5-5H6',
  lock: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
  eyeoff: 'M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21',
  beaker: 'M9 3h6m-5 0v6.5L4.5 19a1.5 1.5 0 001.3 2.2h12.4a1.5 1.5 0 001.3-2.2L14 9.5V3',
  download: 'M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4',
  search: 'M21 21l-4.35-4.35M17 11a6 6 0 11-12 0 6 6 0 0112 0z',
  pause: 'M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z',
  play: 'M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
  trash: 'M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16',
  copy: 'M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z',
  chart: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
  flow: 'M4 7h11m0 0l-3-3m3 3l-3 3M20 17H9m0 0l3-3m-3 3l3 3',
  database: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4',
  info: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
}

export function Icon({ name, className = 'w-4 h-4', strokeWidth = 2 }) {
  const d = PATHS[name] || PATHS.info
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={strokeWidth} d={d} />
    </svg>
  )
}

// Severity glyphs differ in *shape* so severity never depends on colour alone.
function SeverityGlyph({ kind, color }) {
  const common = { width: 10, height: 10, viewBox: '0 0 10 10', 'aria-hidden': true }
  if (kind === 'octagon') return <svg {...common}><polygon points="3,0 7,0 10,3 10,7 7,10 3,10 0,7 0,3" fill={color} /></svg>
  if (kind === 'triangle') return <svg {...common}><polygon points="5,0 10,10 0,10" fill={color} /></svg>
  if (kind === 'circle') return <svg {...common}><circle cx="5" cy="5" r="4.5" fill={color} /></svg>
  return <svg {...common}><circle cx="5" cy="5" r="2.5" fill={color} /></svg>
}

export function SeverityBadge({ severity, compact = false }) {
  const s = severityInfo(severity)
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-white/[0.05] border border-white/10 text-[11px] font-medium text-text-primary whitespace-nowrap">
      <SeverityGlyph kind={s.icon} color={s.color} />
      {!compact && s.label}
    </span>
  )
}

export function ClassDot({ cls, size = 8 }) {
  return <span className="inline-block rounded-full shrink-0" style={{ width: size, height: size, background: classInfo(cls).color }} aria-hidden="true" />
}

export function PsBadge({ cls, ps }) {
  const letter = ps || classInfo(cls).ps
  return (
    <span className="inline-flex items-center justify-center w-5 h-5 rounded-md bg-white/[0.06] border border-white/10 text-[10px] font-semibold text-text-secondary font-mono" title={`Problem statement threat class (${letter})`}>
      {letter}
    </span>
  )
}

export function ClassChip({ cls, active = false, onClick, count }) {
  const info = classInfo(cls)
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md border text-[11px] transition-colors ${
        active ? 'bg-white/[0.10] border-white/25 text-text-primary' : 'bg-white/[0.03] border-white/10 text-text-secondary hover:text-text-primary'
      }`}
      title={info.label}
    >
      <ClassDot cls={cls} />
      <span className="font-mono">{info.ps}</span>
      <span>{info.short}</span>
      {count != null && <span className="text-text-muted tabular">{count}</span>}
    </button>
  )
}

// Single-ratio meter: the unfilled track is a lighter step of the same hue.
export function ConfidenceMeter({ value, color = '#3987e5', width = 'w-16' }) {
  const pct = Math.max(0, Math.min(1, value || 0)) * 100
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`relative ${width} h-1.5 rounded-full overflow-hidden`} style={{ background: `${color}33` }}>
        <span className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${pct}%`, background: color }} />
      </span>
      <span className="text-[11px] text-text-primary tabular font-medium">{pct.toFixed(0)}%</span>
    </span>
  )
}

export function PanelTitle({ icon, children, right }) {
  return (
    <div className="flex items-center justify-between mb-3">
      <h3 className="text-[15px] font-semibold text-text-primary flex items-center gap-2">
        {icon && <span className="text-text-secondary"><Icon name={icon} /></span>}
        {children}
      </h3>
      {right}
    </div>
  )
}

export function Empty({ icon = 'info', title, hint }) {
  return (
    <div className="flex flex-col items-center justify-center py-10 text-center text-text-muted">
      <Icon name={icon} className="w-8 h-8 mb-2 opacity-60" />
      <p className="text-caption text-text-secondary">{title}</p>
      {hint && <p className="text-[11px] mt-1 max-w-xs">{hint}</p>}
    </div>
  )
}
