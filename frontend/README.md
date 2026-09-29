# IronDome.ai dashboard

The SOC dashboard for the IronDome.ai passive sensor (SIH PS 26145). It shows live or
replayed detections from one-way traffic: incidents with severity, confidence and
evidence, the six PS threat classes, the flow stream, model metrics and a live view of
how each PS constraint is met. It is read-only by design: there is no block, isolate
or rate-limit action anywhere in the UI, because the enclave has no return path.

## Views

| Tab | What it shows |
|---|---|
| Overview | flow rate and monitored bandwidth, open incidents, p95 alert latency, encrypted share, detections per PS class |
| Threat matrix | the six PS classes (a)–(f) with their techniques, counts and highest confidence |
| Flow explorer | a rolling sample of flow records with DNS / TLS (JA3, SNI) / QUIC metadata; never any payload |
| Timeline | incidents and injected lab scenarios in time order, with time from injection to detection |
| Models | held-out and stress metrics per detector, plus end-to-end replay results |
| Pipeline & compliance | ingest → features → inference → alert output, and each PS constraint with live evidence |

Clicking an incident opens its forensics view: Community ID, decision against the
threshold, the features furthest from the benign baseline, MITRE ATT&CK IDs, the
recommended out-of-band action and the raw alert record (copy / download). The traffic
lab drawer (flask icon, or <kbd>Ctrl</kbd>+<kbd>K</kbd>) injects attacks into the simulated
network.

## Run

```bash
npm install
npm run dev          # http://localhost:5173, talks to the sensor on <page host>:3001
npm run dev:mock     # built-in sample data, no sensor needed
npm run build        # production bundle in dist/
```

| Variable | Default | Meaning |
|---|---|---|
| `VITE_SENSOR_URL` | `http://<page host>:3001` | sensor REST + Socket.IO base URL |
| `VITE_USE_MOCK` | `false` | `true` = run on built-in sample data (set by `npm run dev:mock`) |

The dashboard reads `GET /api/models`, `/api/evaluation`, `/api/schema/alert` and
`/api/alerts/{id}`, posts lab scenarios to `/api/scenario`, and listens on Socket.IO for
`hello`, `incidents_snapshot`, `flows_snapshot`, `alert`, `alert_update`, `flow_stats`,
`flows_batch` and `scenario`.

## Docker

```bash
docker build -t irondome-dashboard .
docker build --build-arg VITE_SENSOR_URL=http://irondome.local -t irondome-dashboard .   # behind an ingress
docker run --rm -p 8080:80 irondome-dashboard
```

## Structure

```
src/
├── SecurityOperationsOrchestrator.jsx   # layout, tabs, command palette
├── components/
│   ├── panels/        # Overview, ThreatMatrix, FlowExplorer, Timeline, ModelRegistry, Compliance, TrafficLab, ...
│   ├── alerts/        # incident card and forensics view
│   ├── charts/        # throughput chart
│   └── common/        # shared UI (icons, badges, meters, toasts)
├── hooks/             # useSensorStream (Socket.IO), useIncidentStore (filters, acknowledgements)
├── services/          # REST client and Socket.IO transport (mock-aware)
├── constants/         # PS threat-class model, colours, formatting
└── mock/              # sample data for demo mode
```

Built with React 18, Vite 5, Tailwind CSS, Recharts, Framer Motion and socket.io-client.
