# HQG AI-SOC Platform — Tài liệu kỹ thuật toàn diện

> **Phiên bản:** 2.0.0
> **Cập nhật:** 10/04/2026
> **Mục đích:** Hướng dẫn cho lập trình viên mới hiểu toàn bộ kiến trúc, source code, cách mở rộng & nâng cấp hệ thống.

---

## Mục lục

1. [Tổng quan hệ thống](#1-tổng-quan-hệ-thống)
2. [Kiến trúc tổng thể](#2-kiến-trúc-tổng-thể)
3. [Cấu trúc thư mục](#3-cấu-trúc-thư-mục)
4. [Hạ tầng triển khai (VPS)](#4-hạ-tầng-triển-khai-vps)
5. [Backend — FastAPI](#5-backend--fastapi)
   - 5.1 Cấu hình (config.py)
   - 5.2 Entry point (main.py)
   - 5.3 Routers (API endpoints)
   - 5.4 Services (Business logic)
   - 5.5 AI Module (Machine Learning)
   - 5.6 Response Module (Firewall)
6. [Frontend — SPA thuần JS](#6-frontend--spa-thuần-js)
   - 6.1 index.html (Layout & Pages)
   - 6.2 CSS & Theme System
   - 6.3 Các module JS
7. [Luồng dữ liệu (Data Flow)](#7-luồng-dữ-liệu-data-flow)
8. [Cơ sở dữ liệu](#8-cơ-sở-dữ-liệu)
9. [Xác thực & phân quyền](#9-xác-thực--phân-quyền)
10. [AI Engine — Chi tiết kỹ thuật](#10-ai-engine--chi-tiết-kỹ-thuật)
11. [WebSocket — Real-time](#11-websocket--real-time)
12. [SOAR Playbook Engine](#12-soar-playbook-engine)
13. [Cách chạy local (Development)](#13-cách-chạy-local-development)
14. [Triển khai Production](#14-triển-khai-production)
15. [Hướng dẫn nâng cấp & mở rộng](#15-hướng-dẫn-nâng-cấp--mở-rộng)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. Tổng quan hệ thống

**HQG AI-SOC** là nền tảng Security Operations Center (SOC) tích hợp AI, phục vụ:

- **Giám sát real-time** — Nhận cảnh báo từ Wazuh SIEM + Suricata IDS qua OpenSearch
- **AI phát hiện bất thường** — 3 mô hình ML (Isolation Forest, EWMA, CUSUM) chạy nền mỗi 60 giây
- **Tự động phản ứng** — Auto-block IP nguy hiểm qua iptables (local + SSH remote)
- **Quản lý vụ việc** — Tạo case, phân loại (TP/FP), timeline, triage workflow
- **SOAR Playbook** — Drag-drop builder với canvas editor, chạy mô phỏng/thực tế
- **Threat Intelligence** — Tra cứu AbuseIPDB, quản lý IOC, feed status
- **Báo cáo bảo mật** — Export HTML report với findings, CVSS, CWE, remediation roadmap

**Tech Stack:**

| Tầng | Công nghệ |
|------|-----------|
| Backend | Python 3.11+, FastAPI, Uvicorn |
| Frontend | HTML/CSS/JS thuần (SPA, không framework) |
| Data | OpenSearch (Wazuh index), SQLite (cases, users) |
| ML | scikit-learn, numpy, pandas, scipy |
| Web Server | Nginx reverse proxy |
| IDS/SIEM | Wazuh 4.x + Suricata |
| External API | AbuseIPDB |

---

## 2. Kiến trúc tổng thể

```
┌──────────────────────────────────────────────────────────────────┐
│                        INTERNET                                  │
└───────────────────────┬──────────────────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────────────────┐
│  VPS Suricata (103.98.152.197)                                   │
│  ├─ Suricata IDS → logs → Wazuh Agent                           │
│  └─ iptables AI_BLOCK chain (remote block qua SSH)               │
└───────────────────────┬──────────────────────────────────────────┘
                        │ (Wazuh Agent → Wazuh Manager)
┌───────────────────────▼──────────────────────────────────────────┐
│  VPS Dashboard (103.98.152.207)                                  │
│  ├─ Nginx (:80)                                                  │
│  │   ├─ /         → static/   (HTML+CSS+JS)                     │
│  │   ├─ /api/*    → proxy → Uvicorn :8000                       │
│  │   └─ /ws       → proxy (WebSocket upgrade)                   │
│  ├─ Uvicorn (FastAPI)  :8000                                     │
│  │   ├─ REST API (routers/)                                      │
│  │   ├─ WebSocket endpoint                                       │
│  │   └─ 3 background loops:                                     │
│  │       ├─ broadcast_loop   (10s — push data qua WS)           │
│  │       ├─ rule_engine_loop (60s — auto tạo case)              │
│  │       └─ ai_engine_loop   (60s — batch ML analysis)          │
│  ├─ OpenSearch / Wazuh Indexer (:9200)                           │
│  │   ├─ wazuh-alerts-4.x-*   (Wazuh + Suricata alerts)         │
│  │   └─ ai-anomaly-alerts    (AI detection results)             │
│  ├─ SQLite (backend/data/soc_cases.db)                           │
│  │   ├─ users, sessions                                          │
│  │   ├─ cases, triage_log                                        │
│  │   └─ processed_alerts                                         │
│  └─ iptables INPUT chain (local block)                           │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Cấu trúc thư mục

```
soc-platform/
├── nginx.conf                    # Cấu hình Nginx reverse proxy
├── README.md                     # README gốc
├── TECHNICAL_GUIDE.md            # ← File này
│
├── backend/                      # Python FastAPI backend
│   ├── main.py                   # Entry point — app, routers, lifespan
│   ├── config.py                 # Pydantic Settings (env vars)
│   ├── requirements.txt          # Python dependencies
│   ├── .env.example              # Template biến môi trường
│   │
│   ├── ai/                       # 🧠 AI Engine Module
│   │   ├── __init__.py           # Package docs
│   │   ├── extractor.py          # Feature extraction từ raw logs
│   │   ├── model.py              # 3 ML models (IF, EWMA, CUSUM)
│   │   ├── scoring.py            # Risk scoring (LOW/MEDIUM/HIGH)
│   │   ├── explain.py            # Giải thích AI bằng tiếng Việt
│   │   ├── engine.py             # Legacy detectors (class-based)
│   │   └── runner.py             # Background loop orchestrator
│   │
│   ├── routers/                  # 🔀 API Endpoints
│   │   ├── api.py                # Alerts, Stats, Response (block/unblock)
│   │   ├── auth.py               # Login, users, RBAC
│   │   ├── cases.py              # Case CRUD + triage
│   │   ├── ai.py                 # AI Engine endpoints
│   │   ├── ws.py                 # WebSocket broadcaster
│   │   ├── hunting.py            # Threat hunting search
│   │   ├── report.py             # Security report HTML
│   │   ├── rules.py              # Detection rules
│   │   └── threatintel.py        # IOC lookup, AbuseIPDB
│   │
│   ├── services/                 # ⚙ Business Logic
│   │   ├── __init__.py           # Mock/Real switch layer
│   │   ├── opensearch.py         # OpenSearch query client
│   │   ├── cases.py              # SQLite case management
│   │   ├── auth.py               # SQLite user/session management
│   │   ├── pipeline.py           # AI pipeline orchestration
│   │   ├── rule_engine.py        # Auto case creation rules
│   │   ├── html_generator.py     # Security report builder
│   │   └── mock_data.py          # Fake data cho development
│   │
│   ├── response/                 # 🛡 Auto-Response
│   │   └── firewall.py           # iptables block/unblock + SSH remote
│   │
│   └── data/                     # 💾 Runtime data
│       └── soc_cases.db          # SQLite database file
│
└── static/                       # Frontend SPA
    ├── index.html                # Single HTML file (~1400 dòng)
    ├── css/
    │   └── main.css              # Toàn bộ CSS (~1900 dòng)
    └── js/
        ├── app.js                # Main controller (~3000 dòng)
        ├── api.js                # REST API client
        ├── ws.js                 # WebSocket client
        ├── charts.js             # Chart.js wrapper (5 biểu đồ)
        ├── theme.js              # 8 theme + custom color picker
        ├── auth.js               # Login/logout, user management
        ├── triage.js             # Modal phân loại vụ việc
        ├── soar.js               # Playbook drag-drop canvas
        ├── ai-engine.js          # Trang AI detector
        ├── ai_labels.js          # Nhãn tiếng Việt cho AI models
        ├── threat-intel.js       # Threat intel: IOC, feeds, lookup
        ├── block_ip.js           # Modal chặn IP + audit log
        ├── toast.js              # Hệ thống thông báo toast
        ├── vn_format.js          # Format số/ngày tiếng Việt
        └── map.js                # Bản đồ tấn công (Leaflet.js)
```

---

## 4. Hạ tầng triển khai (VPS)

### VPS Dashboard — whmcs167530 (103.98.152.207)

| Thành phần | Chi tiết |
|------------|----------|
| OS | Ubuntu 24.x |
| Nginx | Port 80, reverse proxy |
| Uvicorn | Port 8000, systemd `soc-platform.service` |
| OpenSearch | Port 9200, HTTPS, self-signed cert |
| Wazuh Manager | Nhận logs từ agents |
| Python venv | `/var/www/soc/soc-platform/venv/` |
| Source code | `/var/www/soc/soc-platform/` |
| AI Service | systemd `soc-ai.service` (optional, chạy riêng) |

### VPS Suricata — whmcs167551 (103.98.152.197)

| Thành phần | Chi tiết |
|------------|----------|
| Suricata | IDS trên traffic thực |
| Wazuh Agent | Gửi log về VPS Dashboard |
| iptables | Chain `AI_BLOCK` cho auto-block |
| SSH | Nhận lệnh block từ VPS Dashboard |

### Systemd Services

```bash
# Quản lý services
sudo systemctl start/stop/restart soc-platform.service
sudo systemctl start/stop/restart soc-ai.service

# Xem logs
journalctl -u soc-platform -f
journalctl -u soc-ai -f
```

---

## 5. Backend — FastAPI

### 5.1 Cấu hình (`config.py`)

Dùng **Pydantic BaseSettings** — tự đọc biến từ `.env` file hoặc environment variables.

```python
class Settings(BaseSettings):
    # OpenSearch
    opensearch_url:  str = "https://localhost:9200"
    opensearch_user: str = "admin"
    opensearch_password: str = "CHANGE_ME"

    # AI Engine
    ai_risk_threshold: float = 0.70     # Ngưỡng risk để đánh dấu HIGH
    ai_block_auto:     bool  = False    # ⚠ Bật = AI tự block IP

    # Remote SSH (block trên VPS Suricata)
    suricata_vps_host: str = ""         # Để trống = chỉ block local
    suricata_vps_port: int = 22

    # External
    abuseipdb_api_key: str = ""         # 1000 req/ngày miễn phí

    # Development
    soc_mock_data:     bool = False     # True = dùng data giả
```

**Singleton pattern:** `get_settings()` có `@lru_cache`, gọi bao nhiêu lần cũng trả cùng 1 instance.

### 5.2 Entry point (`main.py`)

```python
# Startup flow
1. load_blocked_from_iptables()     # Đọc lại IP đã block từ iptables
2. asyncio.create_task(broadcast_loop())    # WS push mỗi 10s
3. asyncio.create_task(rule_engine_loop())  # Auto tạo case mỗi 60s
4. asyncio.create_task(ai_engine_loop())    # AI batch mỗi 60s
```

Mount static files: `app.mount("/", StaticFiles(directory="../static", html=True))`

**Lưu ý:** Nginx intercept `/` trước, nên static thực sự do Nginx serve, không phải FastAPI.

### 5.3 Routers (API Endpoints)

#### `routers/api.py` — Alerts, Stats, Response

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/api/alerts/wazuh` | GET | Cảnh báo Wazuh gần nhất |
| `/api/alerts/suricata` | GET | Cảnh báo Suricata gần nhất |
| `/api/alerts/ai` | GET | Kết quả AI detection |
| `/api/stats/kpis` | GET | KPI dashboard (total alerts, unique IPs...) |
| `/api/stats/top-ips` | GET | Top IP tấn công |
| `/api/stats/top-ips-geo` | GET | Top IP + tọa độ địa lý |
| `/api/stats/timeline` | GET | Alerts theo giờ |
| `/api/stats/mitre` | GET | MITRE ATT&CK stats |
| `/api/stats/severity` | GET | Phân bổ severity |
| `/api/stats/top-rules` | GET | Top rules triggered |
| `/api/stats/today` | GET | Thống kê hôm nay |
| `/api/response/block-ip` | POST | Chặn IP (iptables) |
| `/api/response/unblock-ip` | POST | Gỡ chặn IP |
| `/api/blocked-ips` | GET | Danh sách IP đang bị chặn |

#### `routers/auth.py` — Xác thực

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/api/auth/login` | POST | Đăng nhập → cookie HttpOnly |
| `/api/auth/logout` | POST | Xóa session |
| `/api/auth/me` | GET | Thông tin user hiện tại |
| `/api/auth/verify` | GET | Kiểm tra token còn hợp lệ |
| `/api/auth/users` | GET/POST/PATCH/DELETE | CRUD users (admin only) |
| `/api/auth/roles` | GET | Danh sách roles & quyền |

#### `routers/cases.py` — Case Management

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/api/cases/` | GET | Danh sách cases (filter: status, limit) |
| `/api/cases/` | POST | Tạo case mới |
| `/api/cases/{id}` | GET | Chi tiết 1 case |
| `/api/cases/{id}/status` | PATCH | Cập nhật trạng thái |
| `/api/cases/{id}/triage` | POST | Gửi phân loại (TP/FP/Benign) |
| `/api/cases/{id}/triage` | DELETE | Xóa triage log |
| `/api/cases/stats` | GET | Thống kê cases |
| `/api/cases/open` | GET | Cases đang mở (cho dashboard) |

#### `routers/ai.py` — AI Engine

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/api/ai/analyze` | POST | Phân tích 1 sự kiện (real-time) |
| `/api/ai/alerts` | GET | Lịch sử AI alerts |
| `/api/ai/anomalies` | GET | Top anomalies + context |
| `/api/ai/models/status` | GET | Trạng thái 4 models |
| `/api/ai/engine-stats` | GET | KPI: analyzed, anomalies, blocked |
| `/api/ai/block` | POST | Block IP từ AI page |
| `/api/ai/unblock` | POST | Unblock IP |
| `/api/ai/blocked` | GET | Danh sách AI blocked |
| `/api/ai/block-log` | GET | Lịch sử block/unblock |
| `/api/ai/test` | POST | Test pipeline với sample events |
| `/api/ai/lookup-ip` | POST | AbuseIPDB enrichment |

#### `routers/hunting.py` — Threat Hunting

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/api/hunting/search` | GET | Full-text + field search (IP, agent, rule, level) |
| `/api/hunting/stats` | GET | Aggregation stats cho query hiện tại |

#### `routers/threatintel.py` — Threat Intel

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/api/threatintel/lookup` | GET | AbuseIPDB + local Wazuh context |
| `/api/threatintel/iocs` | GET | Danh sách IOC (lấy từ Wazuh + AI) |
| `/api/threatintel/feeds` | GET | Trạng thái feeds |

#### `routers/report.py` — Báo cáo

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/api/report/security-intelligence` | GET | Generate HTML security report |

#### `routers/rules.py` — Detection Rules

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/api/rules/` | GET | List rules đang hoạt động |
| `/api/rules/run-now` | POST | Chạy rule engine ngay lập tức |
| `/api/rules/bulk-create-cases` | POST | Tạo case hàng loạt từ alerts |

#### `routers/ws.py` — WebSocket

| Endpoint | Protocol | Mô tả |
|----------|----------|-------|
| `/ws` | WebSocket | Real-time dashboard push |

### 5.4 Services (Business Logic)

#### `services/__init__.py` — Abstraction Layer

```python
# Switch giữa data thật (OpenSearch) và data giả (mock):
if get_settings().soc_mock_data:
    from .mock_data import *      # Development
else:
    from .opensearch import *     # Production
```

Các routers import từ `services` (không import trực tiếp `opensearch.py` hay `mock_data.py`).

#### `services/opensearch.py` — OpenSearch Client

Dùng `httpx` (async HTTP client) gọi OpenSearch REST API.

**Hàm quan trọng:**
- `_search(index, body, size)` — Wrapper cho ES Query DSL
- `_index_document(index, body)` — Ghi document vào index
- `get_recent_alerts()` — Query `wazuh-alerts-4.x-*`
- `get_suricata_alerts()` — Filter: `data.alert.signature` exists
- `index_ai_anomaly_alert()` — Ghi kết quả AI vào `ai-anomaly-alerts`

**Field mapping quan trọng:**

| Wazuh field | Ý nghĩa |
|-------------|---------|
| `rule.level` | Mức độ nghiêm trọng (1-15) |
| `rule.description` | Mô tả rule |
| `rule.mitre.id` | MITRE technique ID (T1110...) |
| `rule.mitre.tactic` | MITRE tactic |
| `data.src_ip` | IP nguồn tấn công |
| `data.dest_ip` | IP đích |
| `data.dest_port` | Port đích |
| `data.alert.signature` | Suricata signature |
| `data.alert.severity` | Suricata severity (1-4) |
| `GeoLocation.*` | Vị trí địa lý |

#### `services/cases.py` — Case Management (SQLite)

Quản lý vòng đời case:

```
New → In Progress → Escalated → Resolved → Closed
                  ↘ Resolved → Closed
```

**Triage workflow:**
1. Analyst mở case
2. Phân loại: True Positive / False Positive / Benign / Undetermined
3. Chọn lý do, MITRE technique, impact level
4. Viết analysis & recommendation
5. Nếu tick "escalate" → case tự chuyển sang Escalated

#### `services/pipeline.py` — AI Pipeline Core

Điều phối toàn bộ AI analysis:

```
extract_features → compute_anomaly_score → compute_risk_score → explain_risk → [auto_block]
```

**Auto-block logic:**
- Risk ≥ 0.70 → block ngay
- Risk ≥ 0.65 VÀ alerts/1h ≥ 1000 → block
- Chỉ hoạt động khi `ai_block_auto = True` trong config

**Ring buffer:** Lưu tối đa 500 kết quả gần nhất trong memory.

#### `services/rule_engine.py` — Auto Case Creation

6 rules mặc định:

| Rule | Điều kiện | Case severity |
|------|-----------|---------------|
| Critical Alerts | rule.level ≥ 12 | Critical |
| SSH Brute Force | rule.id = 5763 | High |
| File Integrity | rule.groups chứa "syscheck" | Medium |
| Privilege Escalation | rule.groups chứa "privilege_escalation" | High |
| Suricata Critical | alert.severity = 1 | High |
| SQL Injection | rule.description chứa "SQL" | Critical |

**Deduplication:** Bảng `processed_alerts` lưu alert ID đã xử lý, tránh tạo case trùng.

#### `services/html_generator.py` — Report Builder

Generate báo cáo HTML bao gồm:
- Executive Summary
- Findings table (ranked Critical → Low)
- CWE mapping (CWE-284, CWE-307, CWE-434...)
- CVSS score estimation
- Threat model (Actor / Vector / Asset / Mitigation)
- Remediation roadmap (P0-P3 priority)

### 5.5 AI Module — Machine Learning

#### `ai/extractor.py` — Feature Extraction

Chuyển raw log thành feature vector:

```python
{
    "src_ip":           "45.33.32.156",
    "connection_count": 47,           # Số kết nối trong window
    "alert_frequency":  12,           # Số cảnh báo có rule_level > 0
    "port_variance":    5,            # Số port đích unique
    "request_rate":     3.13,         # connections / phút
    "alert_severity":   3,            # Suricata severity cao nhất
    "rule_level":       12,           # Wazuh rule level cao nhất
    "mean_rule_level":  8.5,          # Trung bình rule level
}
```

**Batch mode:** Query OpenSearch 15 phút gần nhất → group by src_ip → aggregate features.

#### `ai/model.py` — 3 Mô hình ML

| Model | Thuật toán | Trọng số | Phát hiện |
|-------|-----------|----------|-----------|
| IsolationForest | sklearn IsolationForest | 50% | Hành vi bất thường đa chiều |
| EWMA | Exponential Moving Average | 30% | Đột biến lưu lượng (spikes) |
| CUSUM | Cumulative Sum | 20% | Thay đổi hành vi dần dần (drift) |

```python
anomaly_score = 0.5 * if_score + 0.3 * ewma_score + 0.2 * cusum_score
# Kết quả: 0.0 (bình thường) → 1.0 (rất bất thường)
```

**IsolationForest:** Cần tối thiểu 100 samples để `fit()`. Trước đó trả `anomaly_score = 0`.

#### `ai/scoring.py` — Risk Scoring

```python
risk_score = 0.4 × anomaly_score
           + 0.3 × (alert_severity / 4)         # normalize 0-1
           + 0.3 × min(alert_frequency / 50, 1)  # cap at 50

# Phân loại:
#   > 0.7 → HIGH   (đỏ)
#   0.3-0.7 → MEDIUM (vàng)
#   < 0.3 → LOW    (xanh, bỏ qua)
```

#### `ai/explain.py` — Explainable AI

Tạo giải thích bằng tiếng Việt cho SOC analyst:

```python
# Output:
{
    "summary": "IP 45.33.32.156 có rủi ro CAO (0.85)",
    "reasons": [
        "Phát hiện bất thường đa chiều (Isolation Forest: 0.92)",
        "Đột biến lưu lượng (EWMA trigger)",
        "47 kết nối trong 15 phút với 5 port khác nhau"
    ],
    "risk_level": "HIGH",
    "recommendation": "Khuyến nghị chặn IP ngay và điều tra"
}
```

### 5.6 Response Module (`response/firewall.py`)

**Block flow:**
1. Validate IP (`ipaddress.ip_address()`)
2. Check whitelist (private IPs + VPS IPs + admin IP)
3. Check cache (đã block trước đó?)
4. `iptables -I INPUT -s <ip> -j DROP` (local)
5. SSH → `iptables -I AI_BLOCK -s <ip> -j DROP` (remote Suricata VPS)
6. Ghi log file + cập nhật in-memory cache

**Whitelist cứng:**
```python
_WHITELIST = {
    "127.0.0.1", "0.0.0.0", "::1", "10.0.0.1",
    "103.98.152.207",   # VPS Dashboard
    "103.98.152.197",   # VPS Suricata
    "115.78.15.163",    # Admin IP
}
```

**⚠ Quan trọng:** Nếu ISP đổi IP admin, cập nhật lại whitelist trong `firewall.py`.

---

## 6. Frontend — SPA thuần JS

### 6.1 `index.html` — Layout & Pages

**Không dùng framework** (React, Vue, Angular) — hoàn toàn vanilla JS.

**SPA Navigation:**
```javascript
navigate('dashboard')  // Ẩn tất cả page, hiện page-dashboard
navigate('alerts')     // Hiện page-alerts
// ...
```

**Danh sách pages:**

| Page ID | Tab sidebar | Nội dung |
|---------|------------|----------|
| `page-dashboard` | 📊 Dashboard | KPI cards, map, charts, live alerts |
| `page-alerts` | 🔔 Alert Queue | Bảng Wazuh + Suricata, bulk actions |
| `page-cases` | 📁 Cases | 2 cột: danh sách + panel chi tiết |
| `page-mitre` | 🗺 MITRE ATT&CK | Heatmap + technique table |
| `page-threat-intel` | 🔍 Threat Intel | Tabs: Search, IOC, Feeds |
| `page-hunting` | 🎯 Threat Hunting | Search box + results table |
| `page-soar` | ⚡ SOAR | Canvas drag-drop playbook |
| `page-ai` | 🧠 AI Engine | Stepper, model cards, anomaly table |
| `page-settings` | ⚙ Settings | Theme picker, user management |

**Login page:** `id="login-page"` — hiện khi chưa authenticated.

**Modals:**
- `#modal-overlay` — Triage form (phân loại case)
- `#add-user-modal` — Thêm user mới
- `#soar-run-modal` — Confirm chạy playbook
- Block IP modal — injected bởi `block_ip.js`

### 6.2 CSS & Theme System

**8 theme mặc định:**

| ID | Tên | Accent | Background |
|----|-----|--------|------------|
| `green-dark` | Green Cyberpunk | #00ff41 | #010a03 |
| `blue-ocean` | Blue Ocean | #00aaff | #020a14 |
| `white-light` | White Light | #0066cc | #f5f5f5 |
| `purple-twi` | Purple Twilight | #cc44ff | #0a0514 |
| `red-fire` | Red Fire | #ff3333 | #140202 |
| `cyan-ice` | Cyan Ice | #00ffcc | #021410 |
| `amber` | Amber | #ff9900 | #140a02 |
| `gray-dark` | Gray Dark | #888888 | #0a0a0a |

**Theme switching flow:**
1. User chọn theme → `themeApp.apply('blue-ocean')`
2. `applyTheme(t)` set ~30 CSS custom properties trên `:root`
3. Gọi `socCharts.refreshChartColors()` để cập nhật màu Chart.js
4. Save vào `localStorage('soc-theme')`

**CSS variable chính:**

| Variable | Ý nghĩa | Default |
|----------|---------|---------|
| `--bg` | Background chính | #010a03 |
| `--bg1` | Card background | #020f04 |
| `--green` | Accent chính | #00ff41 |
| `--red` | Critical/Error | #ff3333 |
| `--amber` | High/Warning | #ff9900 |
| `--text` | Text chính | #b0ffb8 |
| `--muted` | Text phụ | #3a6b40 |
| `--border` | Border | rgba(0,255,65,0.2) |
| `--glow` | Box shadow glow | 0 0 8px rgba(0,255,65,0.3) |

### 6.3 Các module JS

#### `app.js` (~3000 dòng) — Main Controller

**Responsibilities:**
- SPA routing (`navigate()`)
- Dashboard rendering (KPIs, tables, top IPs)
- Alert Queue (filter, bulk action, pagination)
- Cases module (`window.casesApp`)
- Threat Hunting (`window.huntApp`)
- MITRE ATT&CK rendering
- WebSocket event listener (`soc:data`)

**Quan trọng:** Đây là file lớn nhất — nếu refactor, có thể tách ra thành modules riêng.

#### `api.js` — REST Client

```javascript
window.socApi = {
    kpis:           () => _get('/api/stats/kpis'),
    wazuhAlerts:    (n, lv) => _get(`/api/alerts/wazuh?limit=${n}&min_level=${lv}`),
    blockIP:        (ip) => _post(`/api/response/block-ip?ip=${ip}`),
    hunt:           (params) => _get('/api/hunting/search?' + new URLSearchParams(params)),
    // ... ~20 methods
};
```

#### `ws.js` — WebSocket

```javascript
// Connect → nhận data → dispatch event
ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    document.dispatchEvent(new CustomEvent('soc:data', { detail: data }));
};
// app.js lắng nghe:
document.addEventListener('soc:data', (e) => { renderKPIs(e.detail.kpis); ... });
```

Auto-reconnect với exponential backoff (tối đa 30 giây).

#### `charts.js` — Chart.js (5 biểu đồ)

| Chart | Loại | Vị trí |
|-------|------|--------|
| Timeline | Line | Dashboard |
| Severity Donut | Doughnut | Dashboard |
| Tactics Bar | Horizontal Bar | Dashboard |
| Rules Bar | Vertical Bar | Dashboard |
| Suricata Bar | Vertical Bar | Dashboard |

Màu đọc từ CSS vars qua `getComputedStyle()` → cập nhật khi đổi theme.

#### `auth.js` — Authentication

- Login form → POST `/api/auth/login` → cookie HttpOnly
- Mỗi page load → `checkSession()` → redirect login nếu hết hạn
- User menu: dropdown với logout, settings
- User management table (admin only)

#### `soar.js` (~1500 dòng) — Playbook Builder

**Canvas:** 2600×1800px, drag-drop nodes, Bezier arrows

**Node types:**
- `trigger` — Sự kiện kích hoạt
- `condition` — Điều kiện rẽ nhánh
- `action` — Hành động (firewall, EDR, threat_intel)
- `connector` — Kết nối giữa các nodes

**5 template sẵn:** SSH Brute Force, Malicious IP, Suricata Alert, Nmap Scan, AI Anomaly

**Execution:** Topological sort → sequential execution → visual feedback trên từng node.

#### `ai-engine.js` — AI Engine Page

**6-step stepper:**
1. 📥 Thu thập (Wazuh + Suricata)
2. ⚙ Trích xuất features
3. 🧠 Phân tích 4 lớp
4. 📊 Tính risk score
5. 💬 Giải thích
6. 🛡 Hành động

**Model cards:** IsolationForest, EWMA, CUSUM, Entropy — mỗi card hiện status + thống kê.

#### `threat-intel.js` — Threat Intelligence

**3 tabs:**
- **Search:** Nhập IP → AbuseIPDB lookup → risk gauge + geo + ISP
- **IOC:** Bảng IOC (IP/domain/hash) với filter, add, delete
- **Feeds:** 4 feed cards (AbuseIPDB, Emerging Threats, AlienVault, VirusTotal)

#### `block_ip.js` — Block IP Modal

Inject HTML modal khi click "Block":
- Hiện IP lớn, context (reason, agent, rule)
- Whitelist check (private IPs, VPS IPs)
- POST → `/api/response/block-ip`
- Audit log lưu `localStorage` (max 500 entries)

#### `toast.js` — Thông báo

5 loại toast:

| Type | Icon | Color | Duration |
|------|------|-------|----------|
| `nghiem_trong` | 🚨 | Đỏ | 10s + beep |
| `cao` | ⚠️ | Cam | 8s |
| `ai` | 🤖 | Tím | 10s |
| `thanh_cong` | ✅ | Xanh | 3s |
| `thong_tin` | ℹ️ | Cyan | 4s |

Max 5 toast đồng thời, hover = pause timer.

#### `vn_format.js` — Tiếng Việt

```javascript
formatSoLan(12345)    // → "12.345"
formatThoiGian(ts)    // → "10/04/2026 14:30:45"
formatTuongDoi(ts)    // → "5 phút trước"
```

#### `map.js` — Bản đồ tấn công

Dùng **Leaflet.js** CDN — hiện markers cho IP nguồn tấn công với tọa độ từ GeoLocation.

---

## 7. Luồng dữ liệu (Data Flow)

### 7.1 Real-time Dashboard

```
Wazuh Agent (Suricata VPS)
    ↓ (logs)
Wazuh Manager (Dashboard VPS)
    ↓ (index)
OpenSearch (wazuh-alerts-4.x-*)
    ↓ (query mỗi 10s)
broadcast_loop() → WebSocket → Browser
    ↓
ws.js → CustomEvent('soc:data') → app.js → DOM update
```

### 7.2 AI Detection Pipeline

```
ai_engine_loop() mỗi 60s
    ↓
extractor.py: Query OpenSearch 15 phút → group by IP → features
    ↓
model.py: IsolationForest(50%) + EWMA(30%) + CUSUM(20%) → anomaly_score
    ↓
scoring.py: anomaly_score + severity + frequency → risk_score + risk_level
    ↓
explain.py: Tạo giải thích tiếng Việt
    ↓
pipeline.py:
    ├─ risk < 0.3 → bỏ qua
    ├─ 0.3-0.7 → lưu vào lịch sử + index OpenSearch
    └─ ≥ 0.7 → nếu ai_block_auto=True → firewall.block_ip()
```

### 7.3 Auto Case Creation

```
rule_engine_loop() mỗi 60s
    ↓
Query OpenSearch: alerts 5 phút gần nhất, rule.level ≥ 7
    ↓
Match với 6 AUTO_RULES (critical, SSH brute force, syscheck...)
    ↓
Check deduplication (bảng processed_alerts)
    ↓
cases.create_case() → SQLite
```

### 7.4 User Action: Block IP

```
User click "Block" trên UI
    ↓
block_ip.js: Show modal → confirm
    ↓
POST /api/response/block-ip?ip=x.x.x.x
    ↓
routers/api.py → firewall.block_ip()
    ├─ 1. Validate IP
    ├─ 2. Check whitelist
    ├─ 3. iptables -I INPUT -s x.x.x.x -j DROP (local)
    ├─ 4. SSH → iptables trên VPS Suricata (remote)
    └─ 5. Log + cache + response
```

---

## 8. Cơ sở dữ liệu

### OpenSearch (runtime data)

| Index | Nội dung |
|-------|----------|
| `wazuh-alerts-4.x-*` | Tất cả alerts từ Wazuh agents (Suricata, Syscheck, Auth...) |
| `ai-anomaly-alerts` | Kết quả AI detection được index lại |

### SQLite (`backend/data/soc_cases.db`)

```sql
-- Users & Auth
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'viewer',     -- admin|soc2|soc1|viewer
    full_name TEXT,
    email TEXT,
    is_active BOOLEAN DEFAULT 1,
    created_at TEXT,
    last_login TEXT
);

CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    role TEXT,
    created_at TEXT,
    expires_at TEXT
);

-- Cases & Triage
CREATE TABLE cases (
    case_id TEXT PRIMARY KEY,       -- "CASE-001"
    title TEXT,
    status TEXT,                    -- New|In Progress|Escalated|Resolved|Closed
    severity TEXT,                  -- Critical|High|Medium|Low
    src_ip TEXT,
    agent TEXT,
    rule_id TEXT,
    rule_desc TEXT,
    mitre_ids TEXT,                 -- JSON array
    assignee TEXT,
    created_at TEXT,
    updated_at TEXT,
    closed_at TEXT
);

CREATE TABLE triage_log (
    id INTEGER PRIMARY KEY,
    case_id TEXT,
    classification TEXT,            -- TP|FP|Benign|Undetermined
    reasons TEXT,                   -- JSON array
    impact_level TEXT,
    analysis TEXT,
    recommendation TEXT,
    analyst TEXT,
    created_at TEXT
);

-- Rule Engine Dedup
CREATE TABLE processed_alerts (
    alert_id TEXT PRIMARY KEY,
    processed_at TEXT
);
```

### localStorage (browser)

| Key | Nội dung |
|-----|----------|
| `soc-theme` | Theme hiện tại (JSON) |
| `soc_block_ip_log` | Audit log block IP (max 500) |
| `soc_playbook` | Playbook canvas (nodes + connections) |
| `soc_playbook_history` | Lịch sử chạy playbook (max 50) |

---

## 9. Xác thực & phân quyền

### Roles

| Role | Level | Quyền |
|------|-------|-------|
| `admin` | 4 | Toàn quyền: user CRUD, config, block/unblock, triage |
| `soc2` | 3 | Triage, block, manage cases, view all |
| `soc1` | 2 | View alerts, create cases, submit triage |
| `viewer` | 1 | Chỉ xem dashboard, alerts, cases |

### Session flow

```
1. POST /api/auth/login { username, password }
2. Backend: bcrypt verify → tạo token UUID → lưu sessions table
3. Response: Set-Cookie: session=<token>; HttpOnly; Path=/
4. Mỗi request: Cookie gửi kèm → verify_token() → check expires
5. Logout: DELETE session từ DB + clear cookie
```

**Default admin:** `admin / admin123` — **đổi ngay sau khi deploy**.

---

## 10. AI Engine — Chi tiết kỹ thuật

### Pipeline hoàn chỉnh

```
                    ┌─────────────────────────────────────────┐
                    │         OpenSearch (15 min window)        │
                    └────────────────┬────────────────────────┘
                                     │
                    ┌────────────────▼────────────────────────┐
                    │   extractor.py: extract_features_batch   │
                    │   → Group by src_ip                      │
                    │   → connection_count, port_variance, etc  │
                    └────────────────┬────────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
    ┌─────────▼─────────┐  ┌────────▼────────┐  ┌─────────▼─────────┐
    │  IsolationForest   │  │     EWMA        │  │     CUSUM         │
    │  (50% weight)      │  │  (30% weight)   │  │  (20% weight)     │
    │  Multi-dimension   │  │  Traffic spike   │  │  Behavior drift   │
    └─────────┬─────────┘  └────────┬────────┘  └─────────┬─────────┘
              │                      │                      │
              └──────────────────────┼──────────────────────┘
                                     │
                    ┌────────────────▼────────────────────────┐
                    │   anomaly_score = weighted combination    │
                    │   0.5 × IF + 0.3 × EWMA + 0.2 × CUSUM  │
                    └────────────────┬────────────────────────┘
                                     │
                    ┌────────────────▼────────────────────────┐
                    │   scoring.py: compute_risk_score          │
                    │   0.4×anomaly + 0.3×severity + 0.3×freq  │
                    │                                          │
                    │   < 0.3 → LOW (skip)                     │
                    │   0.3-0.7 → MEDIUM (monitor)             │
                    │   > 0.7 → HIGH (alert / auto-block)      │
                    └────────────────┬────────────────────────┘
                                     │
                    ┌────────────────▼────────────────────────┐
                    │   explain.py: Human-readable Vietnamese   │
                    └────────────────┬────────────────────────┘
                                     │
                    ┌────────────────▼────────────────────────┐
                    │   Auto Response (if ai_block_auto=True)  │
                    │   risk ≥ 0.70 → block                    │
                    │   risk ≥ 0.65 & alerts/1h ≥ 1000 → block │
                    └──────────────────────────────────────────┘
```

### Thay đổi trọng số model

Sửa `ai/model.py`:
```python
def compute_anomaly_score(features: dict) -> dict:
    # Thay đổi trọng số ở đây:
    score = 0.5 * if_score + 0.3 * ewma_score + 0.2 * cusum_score
```

### Thêm model mới

1. Tạo class mới trong `ai/model.py` (implement `.score(features) → float`)
2. Thêm vào `compute_anomaly_score()` với trọng số
3. Cập nhật `ai_labels.js` cho nhãn tiếng Việt
4. Cập nhật `routers/ai.py` endpoint `/models/status`

---

## 11. WebSocket — Real-time

### Server (routers/ws.py)

```python
class ConnectionManager:
    active_connections: list[WebSocket]

    async def connect(ws):    # Accept + add to list
    def disconnect(ws):       # Remove from list
    async def broadcast(data): # Send JSON to all clients
```

**Broadcast payload** (mỗi 10 giây):
```json
{
    "kpis": { "total_alerts": 1234, "unique_ips": 56, ... },
    "wazuh_alerts": [ ... ],
    "suricata_alerts": [ ... ],
    "top_ips": [ ... ],
    "timeline": [ ... ],
    "mitre": [ ... ],
    "severity": { ... },
    "case_stats": { ... },
    "rule_stats": [ ... ]
}
```

### Client (ws.js)

```javascript
// Auto-detect protocol
const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(`${proto}//${host}/ws`);

// Dispatch event cho app.js xử lý
ws.onmessage = (e) => {
    document.dispatchEvent(new CustomEvent('soc:data', { detail: JSON.parse(e.data) }));
};
```

---

## 12. SOAR Playbook Engine

### Kiến trúc

```
soar.js
├── PlaybookCanvas class
│   ├── nodes: Map<id, NodeData>
│   ├── connections: Array<{from, to}>
│   ├── zoom/pan state
│   └── undo stack (max 20)
│
├── Node Types
│   ├── trigger:     Sự kiện kích hoạt (alert, schedule)
│   ├── condition:   Rẽ nhánh logic (if/else)
│   ├── action:      Hành động thực thi (block, scan, notify)
│   └── connector:   Kết nối module (firewall, EDR, TI)
│
├── Templates (5 sẵn)
│   ├── ssh_bruteforce
│   ├── malicious_ip
│   ├── suricata_alert
│   ├── nmap_scan
│   └── ai_anomaly
│
└── Execution Engine
    ├── Topological sort (DAG)
    ├── Sequential node execution
    ├── Visual feedback (green=success, red=error)
    └── Log output panel
```

### Canvas interactions
- **Drag-drop** từ sidebar component → canvas
- **Connect** kéo từ port (output → input)
- **Zoom** Ctrl+scroll (0.5x → 2x)
- **Pan** click+drag trên canvas
- **Undo** Ctrl+Z (max 20 steps)
- **Save** localStorage + export JSON file

---

## 13. Cách chạy local (Development)

### Yêu cầu

- Python 3.11+
- Node.js (không cần — frontend là vanilla JS)
- OpenSearch (hoặc dùng mock data)

### Setup

```bash
# 1. Clone
git clone https://github.com/doankhanh212/soc-platform.git
cd soc-platform

# 2. Backend
cd backend
python -m venv venv
source venv/bin/activate          # Linux/Mac
# venv\Scripts\activate           # Windows

pip install -r requirements.txt

# 3. Config
cp .env.example .env
# Sửa .env:
#   SOC_MOCK_DATA=true            # Dùng data giả nếu không có OpenSearch
#   OPENSEARCH_URL=https://localhost:9200
#   OPENSEARCH_PASSWORD=...

# 4. Chạy
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 5. Mở browser: http://localhost:8000
# Login: admin / admin123
```

### Mock Data mode

Set `SOC_MOCK_DATA=true` trong `.env` → backend trả data giả (10 IPs, 4 rules, random alerts).
Phù hợp khi phát triển frontend mà không cần OpenSearch.

---

## 14. Triển khai Production

### Deploy lên VPS

```bash
# Trên VPS
cd /var/www/soc/soc-platform
git pull

# Restart services
sudo systemctl restart soc-platform.service
sudo systemctl restart soc-ai.service     # Nếu dùng AI riêng

# Kiểm tra
systemctl status soc-platform.service
journalctl -u soc-platform -f
```

### Nginx config

```nginx
server {
    listen 80;
    server_name _;

    root /var/www/soc/soc-platform/static;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;    # SPA fallback
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
```

### Systemd service

```ini
# /etc/systemd/system/soc-platform.service
[Unit]
Description=HQG AI-SOC Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/soc/soc-platform/backend
ExecStart=/var/www/soc/soc-platform/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## 15. Hướng dẫn nâng cấp & mở rộng

### Thêm API endpoint mới

```python
# 1. Tạo router file: backend/routers/new_feature.py
from fastapi import APIRouter
router = APIRouter(prefix="/api/new-feature", tags=["NewFeature"])

@router.get("/")
async def get_data():
    return {"data": "hello"}

# 2. Đăng ký trong main.py:
from routers.new_feature import router as new_feature_router
app.include_router(new_feature_router)
```

### Thêm trang frontend mới

```html
<!-- 1. Trong index.html, thêm section: -->
<section id="page-new-feature" class="page" style="display:none">
    <h2 class="page-title">Tính năng mới</h2>
    <div id="new-feature-content"></div>
</section>

<!-- 2. Thêm nav item trong sidebar: -->
<div class="nav-item" onclick="navigate('new-feature')">
    <span class="nav-icon">🆕</span>
    <span class="nav-label">New Feature</span>
</div>
```

```javascript
// 3. Tạo js/new-feature.js và load trong index.html
// 4. Hook vào navigate() trong app.js nếu cần init khi mở page
```

### Thêm model AI mới

```python
# 1. Trong ai/model.py, thêm class:
class NewModel:
    def score(self, features: dict) -> float:
        # Implement logic
        return 0.0

# 2. Thêm vào compute_anomaly_score():
new_score = _new_model.score(features)
score = 0.4 * if_score + 0.25 * ewma_score + 0.15 * cusum_score + 0.2 * new_score

# 3. Cập nhật ai_labels.js:
NewModel: { nhan: "Tên tiếng Việt", mo_ta: "Mô tả", icon: "🔥", mau: ... }
```

### Thêm detection rule mới

```python
# Trong services/rule_engine.py, thêm vào AUTO_RULES:
{
    "name": "New Detection Rule",
    "condition": lambda alert: "keyword" in alert.get("rule", {}).get("description", ""),
    "severity": "High",
    "title_template": "Phát hiện: {rule_desc}",
}
```

### Tích hợp API bên ngoài mới

```python
# 1. Thêm API key vào config.py:
class Settings(BaseSettings):
    new_api_key: str = ""

# 2. Tạo service function trong services/ hoặc routers/:
async def _fetch_new_api(param: str):
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://api.example.com/{param}",
                                headers={"X-Key": get_settings().new_api_key})
        return resp.json()
```

### Conventions khi code

| Quy tắc | Chi tiết |
|----------|----------|
| **Backend naming** | snake_case cho functions, PascalCase cho classes |
| **Frontend naming** | camelCase cho functions, `window.moduleApp` cho module exports |
| **API format** | JSON, field names snake_case |
| **Error handling** | Backend trả `{"error": "message"}`, frontend `toast()` |
| **Colors** | LUÔN dùng CSS variables (`var(--green)`), KHÔNG hardcode hex |
| **Tiếng Việt** | UI hiển thị tiếng Việt, code comments tiếng Anh hoặc Việt |
| **State management** | Global variables trong closure/IIFE, không dùng framework |

---

## 16. Troubleshooting

### AI Engine không chạy

```bash
# Kiểm tra service
systemctl status soc-ai.service
journalctl -u soc-ai -n 50

# Lỗi phổ biến:
# ValueError: cannot convert float NaN to integer
#   → Fix: .fillna(0) trước khi int() (đã fix trong extractor.py)
#
# OpenSearch connection refused
#   → Kiểm tra: curl -k https://localhost:9200
```

### WebSocket không kết nối

```bash
# Kiểm tra nginx ws proxy
tail -f /var/log/nginx/error.log

# Phải có:
# proxy_http_version 1.1;
# proxy_set_header Upgrade $http_upgrade;
# proxy_set_header Connection "upgrade";
```

### UI không thay đổi sau khi push code

```
1. Hard refresh: Ctrl+Shift+R
2. Incognito mode (không cache)
3. DevTools → Network → Disable cache
4. Kiểm tra file trên VPS:
   head -5 /var/www/soc/soc-platform/static/css/main.css
```

### Bị lock out SSH (AI tự block admin IP)

```
1. Vào VPS qua hosting console (VNC/IPMI)
2. iptables -L INPUT -n | grep <your-ip>
3. iptables -D INPUT -s <your-ip> -j DROP
4. Thêm IP mới vào _WHITELIST trong firewall.py
```

### OpenSearch query chậm

```bash
# Kiểm tra index size
curl -k -u admin:pw https://localhost:9200/_cat/indices?v

# Nếu quá lớn, xóa index cũ:
curl -k -u admin:pw -X DELETE https://localhost:9200/wazuh-alerts-4.x-2026.01.*
```

---

## Sơ đồ tổng kết

```
┌─────────────────── FRONTEND (Vanilla JS SPA) ───────────────────┐
│                                                                   │
│  index.html ← main.css (CSS vars) ← theme.js (8 themes)        │
│       │                                                           │
│       ├── app.js      (dashboard, cases, alerts, hunting)        │
│       ├── api.js      (REST client → /api/*)                     │
│       ├── ws.js       (WebSocket → /ws)                          │
│       ├── charts.js   (Chart.js × 5)                             │
│       ├── auth.js     (login/logout, user management)            │
│       ├── triage.js   (classification modal)                     │
│       ├── soar.js     (playbook canvas builder)                  │
│       ├── ai-engine.js (AI detector page)                        │
│       ├── threat-intel.js (IOC, feeds, AbuseIPDB)               │
│       ├── block_ip.js (firewall modal + audit log)              │
│       ├── toast.js    (notification system)                      │
│       └── map.js      (Leaflet threat map)                       │
│                                                                   │
└───────────────────────────┬───────────────────────────────────────┘
                            │ HTTP + WebSocket
┌───────────────────────────▼───────────────────────────────────────┐
│                    Nginx (:80) reverse proxy                      │
└───────────────────────────┬───────────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────────┐
│                  FastAPI / Uvicorn (:8000)                        │
│                                                                   │
│  Routers: api, auth, cases, ai, ws, hunting, report, rules, ti  │
│       │                                                           │
│  Services: opensearch, cases, auth, pipeline, rule_engine        │
│       │                                                           │
│  AI: extractor → model(IF+EWMA+CUSUM) → scoring → explain       │
│       │                                                           │
│  Response: firewall.py (iptables local + SSH remote)             │
│                                                                   │
└──────────┬────────────────────────────┬───────────────────────────┘
           │                            │
┌──────────▼──────────┐    ┌────────────▼───────────────┐
│   OpenSearch :9200   │    │   SQLite (soc_cases.db)    │
│   wazuh-alerts-*     │    │   users, sessions          │
│   ai-anomaly-alerts  │    │   cases, triage_log        │
└──────────────────────┘    │   processed_alerts         │
                            └────────────────────────────┘
```

---

> **Ghi chú cuối:** File này mô tả trạng thái source code tại thời điểm 10/04/2026. Khi nâng cấp hệ thống, hãy cập nhật lại document này cho phù hợp.
