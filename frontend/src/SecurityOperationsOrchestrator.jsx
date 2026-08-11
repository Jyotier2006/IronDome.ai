import { useState, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'

import BootSequence from './components/SystemInitializationSequence'
import ErrorBoundary from './components/RuntimeFaultBoundary'
import CommandPalette from './components/OperatorCommandConsole'
import Topbar from './components/layout/GlobalStatusBar'
import ToastHost from './components/common/NotificationDispatchHost'

import ThreatMapPanel from './components/panels/NodeTopologyPanel'
import TimelinePanel from './components/panels/EventCorrelationTimeline'
import AlertsPanel from './components/panels/IncidentAlertConsole'
import TelemetryTerminal from './components/panels/TelemetryStreamConsole'
import DemoControlPanel from './components/panels/ScenarioSimulationController'
import IoTMapPanel from './components/panels/DeviceFleetTelemetryPanel'
import ResponseStatusPanel from './components/panels/AutomatedResponseLedger'
import DroppedPacketsPanel from './components/panels/PacketInterdictionLedger'

import TelemetryChart from './components/charts/MetricTimeSeriesChart'

import useTelemetry from './hooks/useTelemetryIngestionStream'
import useAlerts from './hooks/useIncidentAlertStore'
import useDroppedPackets from './hooks/usePacketInterdictionFeed'
import { toast } from '@utils/notificationEventBus'

const TABS = [
  {
    id: 'telemetry', label: 'Telemetry', tone: 'cyan',
    icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>,
  },
  {
    id: 'timeline', label: 'Timeline', tone: 'cyan',
    icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>,
  },
  {
    id: 'iot-fleet', label: 'IoT Fleet', tone: 'cyan',
    icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" /></svg>,
  },
  {
    id: 'response', label: 'Response', tone: 'green',
    icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>,
  },
  {
    id: 'dropped', label: 'Dropped', tone: 'red',
    icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>,
  },
]

const TONE_TEXT = { cyan: 'text-accent-cyan', green: 'text-accent-green', red: 'text-status-critical' }
const TONE_PILL = { cyan: 'bg-accent-cyan/20', green: 'bg-accent-green/20', red: 'bg-status-critical/20' }

function App() {
  const [booting, setBooting] = useState(true)
  const [connectionStatus, setConnectionStatus] = useState('connected')
  const [activeView, setActiveView] = useState('telemetry')
  const [flashCritical, setFlashCritical] = useState(false)
  const [isPaletteOpen, setIsPaletteOpen] = useState(false)
  const prevCriticalRef = useRef(0)

  const {
    isConnected,
    isPaused,
    telemetryData,
    latestPoint,
    rawEvents,
    toggle,
    clearData,
    devices,
    activeDeviceId,
    setActiveDeviceId
  } = useTelemetry()

  const alertsData = useAlerts()
  const { stats: alertStats } = alertsData

  // Use dropped packets hook
  const { droppedPackets, droppedStats } = useDroppedPackets()

  // Calculate blocked count from dropped packets stats
  const blockedCount = droppedStats.total_dropped || 0

  const eventsRate = latestPoint ? latestPoint.requests : 0

  const topbarStats = {
    eventsRate: eventsRate,
    activeAlerts: alertStats.active,
    blockedCount: blockedCount
  }

  useEffect(() => {
    setConnectionStatus(isConnected ? 'connected' : 'disconnected')
  }, [isConnected])

  // Ctrl/Cmd+K opens the command palette from anywhere in the app.
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setIsPaletteOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  const handleTogglePause = () => {
    toast(isPaused ? 'Live feed resumed' : 'Live feed paused', isPaused ? 'success' : 'warning')
    toggle()
  }

  const handleSelectDevice = (deviceId) => {
    setActiveDeviceId(deviceId)
    const device = devices.find((d) => d.id === deviceId)
    if (device) toast(`Viewing telemetry for ${device.name}`, 'info')
  }

  // Pulse a red vignette across the viewport whenever a new critical alert lands.
  useEffect(() => {
    if (alertStats.critical > prevCriticalRef.current) {
      setFlashCritical(false)
      requestAnimationFrame(() => setFlashCritical(true))
    }
    prevCriticalRef.current = alertStats.critical
  }, [alertStats.critical])

  const TERMINAL_HEIGHT = 160

  const paletteActions = [
    ...TABS.map((tab) => ({
      id: `nav-${tab.id}`,
      label: `Go to ${tab.label}`,
      icon: tab.icon,
      hint: 'View',
      run: () => {
        setActiveView(tab.id)
        toast(`Switched to ${tab.label}`, 'info')
      },
    })),
    {
      id: 'toggle-pause',
      label: isPaused ? 'Resume Live Feed' : 'Pause Live Feed',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      ),
      run: handleTogglePause,
    },
    {
      id: 'clear-terminal',
      label: 'Clear Telemetry Terminal',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
      ),
      run: () => {
        clearData()
        toast('Terminal cleared', 'info')
      },
    },
    {
      id: 'ack-all',
      label: 'Acknowledge All Alerts',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
      ),
      run: () => {
        alertsData.acknowledgeAll()
        toast('All alerts acknowledged', 'success')
      },
    },
    {
      id: 'filter-active-alerts',
      label: 'Filter Alerts: Active',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" /></svg>
      ),
      run: () => {
        alertsData.setFilter('active')
        toast('Showing active alerts', 'info')
      },
    },
    {
      id: 'filter-all-alerts',
      label: 'Filter Alerts: All',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" /></svg>
      ),
      run: () => {
        alertsData.setFilter('all')
        toast('Showing all alerts', 'info')
      },
    },
    {
      id: 'open-demo-control',
      label: 'Open Demo Control Panel',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 5v2m0 4v2m0 4v2M5 5a2 2 0 00-2 2v3a2 2 0 110 4v3a2 2 0 002 2h14a2 2 0 002-2v-3a2 2 0 110-4V7a2 2 0 00-2-2H5z" /></svg>
      ),
      run: () => window.dispatchEvent(new Event('aegis:open-demo-control')),
    },
  ]

  return (
    <div className="h-screen grid grid-rows-[auto_1fr] overflow-hidden relative">
      <div className="ambient-bg" />

      {booting && <BootSequence onDone={() => setBooting(false)} />}

      {flashCritical && (
        <div
          className="fixed inset-0 z-40 pointer-events-none critical-flash"
          onAnimationEnd={() => setFlashCritical(false)}
        />
      )}

      <Topbar
        connectionStatus={connectionStatus}
        stats={topbarStats}
        isPaused={isPaused}
        onTogglePause={handleTogglePause}
        onOpenPalette={() => setIsPaletteOpen(true)}
      />

      <main className="flex overflow-hidden min-h-0" style={{ paddingBottom: TERMINAL_HEIGHT }}>
        <aside className="w-72 xl:w-80 border-r border-white/5 p-4 overflow-hidden flex-shrink-0 hidden lg:block">
          <ThreatMapPanel
            devices={devices}
            activeDeviceId={activeDeviceId}
            onSelectDevice={handleSelectDevice}
          />
        </aside>

        <section className="flex-1 p-4 overflow-hidden min-w-0">
          <div className="h-full glass-panel p-4 flex flex-col">
            <div className="flex items-center gap-2 mb-4 pb-3 border-b border-white/5">
              {TABS.map((tab) => {
                const isActive = activeView === tab.id
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveView(tab.id)}
                    className={`relative px-3 py-1.5 rounded-glass text-caption font-medium transition-colors ${
                      isActive ? TONE_TEXT[tab.tone] : 'text-text-muted hover:text-text-secondary'
                    }`}
                  >
                    {isActive && (
                      <motion.span
                        layoutId="activeTabPill"
                        className={`absolute inset-0 rounded-glass ${TONE_PILL[tab.tone]}`}
                        transition={{ type: 'spring', stiffness: 420, damping: 32 }}
                      />
                    )}
                    <span className="relative z-10 inline-flex items-center gap-1">
                      {tab.icon}
                      {tab.label}
                      {tab.id === 'dropped' && blockedCount > 0 && (
                        <span className="ml-1 px-1.5 py-0.5 rounded-full bg-status-critical/30 text-xs">{blockedCount}</span>
                      )}
                    </span>
                  </button>
                )
              })}
            </div>

            <div className="flex-1 min-h-0">
              {activeView === 'telemetry' ? (
                <TelemetryChart
                  data={telemetryData}
                  latestPoint={latestPoint}
                  isPaused={isPaused}
                  onTogglePause={handleTogglePause}
                  devices={devices}
                  activeDeviceId={activeDeviceId}
                  onSelectDevice={handleSelectDevice}
                />
              ) : activeView === 'iot-fleet' ? (
                <IoTMapPanel latestPoint={latestPoint} />
              ) : activeView === 'response' ? (
                <ResponseStatusPanel />
              ) : activeView === 'dropped' ? (
                <DroppedPacketsPanel
                  droppedPackets={droppedPackets}
                  stats={droppedStats}
                />
              ) : (
                <TimelinePanel alerts={alertsData.allAlerts} droppedPackets={droppedPackets} />
              )}
            </div>
          </div>
        </section>

        <aside className="w-[420px] xl:w-[500px] border-l border-white/5 pt-3 px-4 pb-4 overflow-hidden flex-shrink-0 hidden md:block">
          <AlertsPanel alertsData={alertsData} />
        </aside>
      </main>

      <div style={{ position: 'fixed', bottom: 0, left: 0, right: 0, zIndex: 30 }}>
        <ErrorBoundary compact>
          <TelemetryTerminal
            events={rawEvents}
            isPaused={isPaused}
            onTogglePause={handleTogglePause}
            onClear={clearData}
          />
        </ErrorBoundary>
      </div>

      <DemoControlPanel />
      <ToastHost />
      <CommandPalette isOpen={isPaletteOpen} onClose={() => setIsPaletteOpen(false)} actions={paletteActions} />
    </div>
  )
}

export default App
