# HQG AI-SOC Platform

```
soc-platform/
├── backend/
│   ├── main.py              ← FastAPI entry point (uvicorn)
│   ├── config.py            ← Settings (pydantic-settings + .env)
│   ├── requirements.txt
│   ├── .env.example         ← Copy to .env and fill in values
│   ├── services/
│   │   └── opensearch.py    ← All OpenSearch queries
│   ├── routers/
│   │   ├── api.py           ← REST endpoints (/api/alerts/*, /api/stats/*)
│   │   └── ws.py            ← WebSocket /ws + broadcast loop
│   └── ai/
│       └── engine.py        ← EWMA · CUSUM · Entropy · IsolationForest · Behavioral
└── static/
    ├── index.html           ← Single-page dashboard
    ├── css/main.css
    └── js/
        ├── api.js           ← fetch wrappers → window.socApi
        ├── ws.js            ← WebSocket client → dispatches soc:data events
        ├── charts.js        ← Chart.js instances → window.socCharts
        └── app.js           ← Navigation, table rendering, data binding
```

## Quick Start

```bash
# 1. Backend
cd backend
cp .env.example .env
# Edit .env with your OpenSearch URL + credentials

pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 2. Frontend (dev — open directly)
# Just open static/index.html in browser
# OR use live-server:
cd static && npx live-server --port=3000

# 3. Production (Nginx)
sudo cp nginx.conf /etc/nginx/sites-enabled/soc-platform
sudo nginx -t && sudo systemctl reload nginx
```

## WebSocket Events

Server pushes `soc:data` event every `WS_BROADCAST_INTERVAL` seconds:
```json
{
  "type": "snapshot",
  "kpis":            { "total_alerts_24h": 0, "critical_alerts": 0, ... },
  "recent_alerts":   [...],
  "suricata_alerts": [...],
  "ai_alerts":       [...],
  "top_ips":         [{ "ip": "1.2.3.4", "count": 42 }],
  "timeline":        [{ "time": "2025-01-01T00:00:00", "count": 5 }]
}
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/stats/kpis` | KPI counts for header bar |
| GET | `/api/stats/top-ips` | Top attacking IPs |
| GET | `/api/stats/timeline?hours=24` | Alert volume over time |
| GET | `/api/stats/mitre` | MITRE techniques + tactics |
| GET | `/api/stats/severity` | Alert count by rule level |
| GET | `/api/alerts/wazuh?min_level=7` | Wazuh alerts |
| GET | `/api/alerts/suricata` | Suricata IDS alerts |
| GET | `/api/alerts/ai` | AI anomaly alerts |
| POST | `/api/response/block-ip?ip=1.2.3.4` | Block IP via iptables |
| GET | `/api/reports/security-intelligence` | SOC-grade HTML Security Intelligence report |
| WS | `/ws` | Real-time push stream |
