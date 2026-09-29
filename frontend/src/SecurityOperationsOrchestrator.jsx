import { useCallback, useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'

import BootSequence from './components/SystemInitializationSequence'
import ErrorBoundary from './components/RuntimeFaultBoundary'
import CommandPalette from './components/OperatorCommandConsole'
import GlobalStatusBar from './components/layout/GlobalStatusBar'
import ToastHost from './components/common/NotificationDispatchHost'
import { Icon } from './components/common/ui'

import IngestSourcesPanel from './components/panels/IngestSourcesPanel'
import OverviewPanel from './components/panels/OverviewPanel'
import ThreatMatrixPanel from './components/panels/ThreatMatrixPanel'
import FlowExplorerPanel from './components/panels/FlowExplorerPanel'
import TimelinePanel from './components/panels/EventCorrelationTimeline'
import ModelRegistryPanel from './components/panels/ModelRegistryPanel'
import CompliancePanel from './components/panels/CompliancePanel'
import IncidentAlertConsole from './components/panels/IncidentAlertConsole'
import TrafficLabController from './components/panels/TrafficLabController'
import FlowStreamConsole from './components/panels/FlowStreamConsole'
import IncidentForensicsModal from './components/alerts/IncidentForensicsModal'

import useSensorStream from './hooks/useSensorStream'
import useIncidentStore from './hooks/useIncidentStore'
import { downloadJson } from './services/httpApiClient'
import { toast } from '@utils/notificationEventBus'
import { CLASS_ORDER, classInfo, entityText } from './constants/threatModel'

const TABS = [
  { id: 'overview', label: 'Overview', icon: 'chart' },
  { id: 'matrix', label: 'Threat matrix', icon: 'grid' },
  { id: 'flows', label: 'Flow explorer', icon: 'flow' },
  { id: 'timeline', label: 'Timeline', icon: 'clock' },
  { id: 'models', label: 'Models', icon: 'cpu' },
  { id: 'compliance', label: 'Pipeline & compliance', icon: 'shield' },
]

const tabFromHash = () => {
  const h = window.location.hash.replace('#', '').split('+')[0]
  return TABS.some((t) => t.id === h) ? h : 'overview'
}

export default function App() {
  const [booting, setBooting] = useState(true)
  const [tab, setTabState] = useState(tabFromHash)
  const setTab = useCallback((id) => {
    setTabState(id)
    window.history.replaceState(null, '', `#${id}`)   // deep-linkable views for demos
  }, [])
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [flash, setFlash] = useState(false)
  const [termExpanded, setTermExpanded] = useState(false)

  const sensor = useSensorStream()
  const store = useIncidentStore()
  const lastIncident = useRef(null)
  const TERMINAL_HEIGHT = termExpanded ? 300 : 150

  // Announce new incidents; pulse the viewport edge for critical ones.
  useEffect(() => {
    const top = store.incidents[0]
    if (!top || top.incident_id === lastIncident.current) return
    const first = lastIncident.current === null
    lastIncident.current = top.incident_id
    if (first) return
    const info = classInfo(top.threat_class)
    toast(`(${info.ps}) ${top.technique_label} - ${entityText(top)}`, top.severity === 'critical' ? 'warning' : 'info', 3600)
    if (top.severity === 'critical') {
      setFlash(false)
      requestAnimationFrame(() => setFlash(true))
    }
  }, [store.incidents])

  useEffect(() => {
    const onHash = () => setTabState(tabFromHash())
    window.addEventListener('hashchange', onHash)
    if (window.location.hash.includes('+lab')) setTimeout(() => window.dispatchEvent(new Event('irondome:open-lab')), 500)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const selectClass = useCallback((c) => {
    store.setClassFilter(c)
    if (c) toast(`Incidents filtered to ${classInfo(c).label}`, 'info')
  }, [store])

  const paletteActions = [
    ...TABS.map((t) => ({ id: `tab-${t.id}`, label: `Go to ${t.label}`, hint: 'View', icon: <Icon name={t.icon} />, run: () => setTab(t.id) })),
    ...CLASS_ORDER.map((c) => ({
      id: `cls-${c}`, label: `Filter incidents: (${classInfo(c).ps}) ${classInfo(c).label}`, hint: 'Filter', keywords: classInfo(c).short,
      icon: <Icon name="shield" />, run: () => selectClass(c),
    })),
    { id: 'cls-clear', label: 'Clear incident filters', icon: <Icon name="x" />, run: () => { store.setClassFilter(null); store.setSeverityFilter(null); store.setStatusFilter('all') } },
    { id: 'lab', label: 'Open traffic lab (inject a scenario)', icon: <Icon name="beaker" />, run: () => window.dispatchEvent(new Event('irondome:open-lab')) },
    { id: 'ack', label: 'Acknowledge all incidents', icon: <Icon name="check" />, run: () => { store.acknowledgeAll(); toast('All incidents acknowledged', 'success') } },
    { id: 'export', label: 'Export incidents (JSONL)', icon: <Icon name="download" />, run: () => downloadJson(`irondome-incidents-${Date.now()}.jsonl`, store.incidents, true) },
    { id: 'pause', label: sensor.paused ? 'Resume flow view' : 'Pause flow view', icon: <Icon name={sensor.paused ? 'play' : 'pause'} />, run: sensor.togglePause },
  ]

  return (
    <div className="h-screen grid grid-rows-[auto_1fr] overflow-hidden relative">
      <div className="ambient-bg" />
      {booting && <BootSequence onDone={() => setBooting(false)} />}
      {flash && <div className="fixed inset-0 z-40 pointer-events-none critical-flash" onAnimationEnd={() => setFlash(false)} />}

      <GlobalStatusBar
        connected={sensor.connected}
        stats={sensor.stats}
        openIncidents={store.stats.open}
        paused={sensor.paused}
        onTogglePause={sensor.togglePause}
        onOpenPalette={() => setPaletteOpen(true)}
      />

      <main className="flex overflow-hidden min-h-0" style={{ paddingBottom: TERMINAL_HEIGHT }}>
        <aside className="w-72 xl:w-80 border-r border-white/5 p-4 overflow-hidden flex-shrink-0 hidden lg:block">
          <IngestSourcesPanel
            meta={sensor.meta} stats={sensor.stats} connected={sensor.connected}
            incidentStats={store.stats} activeClass={store.classFilter} onSelectClass={selectClass}
          />
        </aside>

        <section className="flex-1 p-4 overflow-hidden min-w-0">
          <div className="h-full glass-panel p-4 flex flex-col">
            <nav className="flex items-center gap-1 mb-4 pb-3 border-b border-white/5 overflow-x-auto" aria-label="Views">
              {TABS.map((t) => {
                const active = tab === t.id
                return (
                  <button key={t.id} type="button" onClick={() => setTab(t.id)}
                          className={`relative px-3 py-1.5 rounded-glass text-[12px] font-medium whitespace-nowrap transition-colors ${active ? 'text-text-primary' : 'text-text-muted hover:text-text-secondary'}`}>
                    {active && <motion.span layoutId="activeTab" className="absolute inset-0 rounded-glass bg-white/[0.08]" transition={{ type: 'spring', stiffness: 420, damping: 32 }} />}
                    <span className="relative z-10 inline-flex items-center gap-1.5"><Icon name={t.icon} className="w-3.5 h-3.5" />{t.label}</span>
                  </button>
                )
              })}
            </nav>
            <div className="flex-1 min-h-0">
              <ErrorBoundary compact>
                {tab === 'overview' && (
                  <OverviewPanel stats={sensor.stats} history={sensor.history} peak={sensor.peak} meta={sensor.meta}
                                 incidentStats={store.stats} runs={sensor.runs}
                                 onSelectClass={(c) => { selectClass(c); setTab('matrix') }} />
                )}
                {tab === 'matrix' && (
                  <ThreatMatrixPanel meta={sensor.meta} incidentStats={store.stats} activeClass={store.classFilter} onSelectClass={selectClass} />
                )}
                {tab === 'flows' && <FlowExplorerPanel flows={sensor.flows} paused={sensor.paused} onTogglePause={sensor.togglePause} />}
                {tab === 'timeline' && <TimelinePanel incidents={store.incidents} runs={sensor.runs} onOpenIncident={store.setSelectedId} />}
                {tab === 'models' && <ModelRegistryPanel />}
                {tab === 'compliance' && (
                  <CompliancePanel meta={sensor.meta} stats={sensor.stats} peak={sensor.peak} incidentStats={store.stats} incidents={store.incidents} />
                )}
              </ErrorBoundary>
            </div>
          </div>
        </section>

        <aside className="w-[380px] xl:w-[430px] border-l border-white/5 pt-3 px-4 pb-4 overflow-hidden flex-shrink-0 hidden md:block">
          <IncidentAlertConsole store={store} />
        </aside>
      </main>

      <div style={{ position: 'fixed', bottom: 0, left: 0, right: 0, zIndex: 30 }}>
        <ErrorBoundary compact>
          <FlowStreamConsole flows={sensor.flows} paused={sensor.paused} onTogglePause={sensor.togglePause}
                             onClear={sensor.clearFlows} height={TERMINAL_HEIGHT} expanded={termExpanded}
                             onToggleExpand={() => setTermExpanded((v) => !v)} />
        </ErrorBoundary>
      </div>

      <TrafficLabController scenarios={sensor.meta?.scenarios} runs={sensor.runs} available={sensor.meta?.ingest?.lab !== false} />
      <IncidentForensicsModal
        incident={store.selected}
        isOpen={!!store.selected}
        acked={store.selected ? store.isAcked(store.selected.incident_id) : false}
        onClose={() => store.setSelectedId(null)}
        onAcknowledge={store.acknowledge}
      />
      <ToastHost />
      <CommandPalette isOpen={paletteOpen} onClose={() => setPaletteOpen(false)} actions={paletteActions} />
    </div>
  )
}
