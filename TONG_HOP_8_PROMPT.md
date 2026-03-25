# TỔNG HỢP OUTPUT 8 PROMPT — HQG SOC DASHBOARD

> Tài liệu tổng hợp toàn bộ 14 file JS + 4 file hướng dẫn được tạo từ 8 prompt.  
> Trạng thái tích hợp, bug đã sửa, và phân loại module.

---

## MỤC LỤC

1. [Tổng quan kiến trúc hiện tại](#1-tổng-quan-kiến-trúc-hiện-tại)
2. [Danh sách file theo prompt](#2-danh-sách-file-theo-prompt)  
3. [Phân loại module](#3-phân-loại-module)
4. [Bug đã phát hiện & sửa](#4-bug-đã-phát-hiện--sửa)
5. [Trạng thái tích hợp](#5-trạng-thái-tích-hợp)
6. [Thứ tự load script trong index.html](#6-thứ-tự-load-script-trong-indexhtml)
7. [Chi tiết từng prompt](#7-chi-tiết-từng-prompt)

---

## 1. Tổng quan kiến trúc hiện tại

### Backend
- **FastAPI** (Python) — port 8000
- **OpenSearch/Wazuh** — nguồn alert
- **SQLite** — lưu vụ việc (cases)
- **AI Engine** — 5 model: IsolationForest, CUSUM, EWMA, Entropy, WazuhRule

### Frontend (Vanilla JS — KHÔNG dùng framework)
- `index.html` (~1400 dòng) — 8 trang: Dashboard, Alerts, Cases, MITRE, Threat Intel, Hunting, SOAR, AI, Settings
- Tất cả page nằm trong cùng 1 file HTML, navigation bằng show/hide `.page.active`
- Chart.js v4.4.4 cho biểu đồ
- WebSocket real-time qua `/ws`

### File JS gốc (đã hoạt động trước 8 prompt)
| File | Chức năng | Dòng |
|------|-----------|------|
| `auth.js` | Login/logout, RBAC, quản lý user | ~300 |
| `api.js` | Fetch wrapper cho tất cả API endpoint | ~50 |
| `ws.js` | WebSocket auto-reconnect, dispatch `soc:data` event | ~20 |
| `charts.js` | Chart.js wrappers (timeline, severity, tactics, rules) | ~180 |
| `triage.js` | Modal phân loại alert (True/False Positive) | ~220 |
| `app.js` | Main controller: toast, navigation, tables, cases, alerts, hunting | ~1700 |
| `soar.js` | SOAR playbook canvas: drag-drop, zoom, undo/redo | ~1200 |
| `theme.js` | 8 theme preset, custom colors, localStorage | ~320 |
| `map.js` | Canvas world map với attack lines | ~150 |

---

## 2. Danh sách file theo prompt

### Prompt 1 — Utility Modules (3 file)
| File | Kích thước | Mô tả |
|------|-----------|-------|
| `vn_format.js` | 7.6 KB | Hàm format tiếng Việt: `formatSoLan()`, `formatThoiGian()`, `formatMucDo()` |
| `ai_labels.js` | 5.9 KB | Map tên thuật toán AI → nhãn tiếng Việt + badge render |
| `toast.js` | 11.7 KB | Hệ thống thông báo nâng cao: 5 loại, stack, progress bar, audio |

### Prompt 2 — Chart Modules (3 file)
| File | Kích thước | Mô tả |
|------|-----------|-------|
| `mitre_heatmap.js` | 15.2 KB | Class MitreHeatmap: heatmap custom (không dùng Chart.js) |
| `timeline_24h.js` | 14.0 KB | Class Timeline24h: SVG timeline chart |
| `top_rules_24h.js` | 8.9 KB | Class TopRules24h: SVG bar chart top rules |

### Prompt 3 — Alert Queue (2 file)
| File | Kích thước | Mô tả |
|------|-----------|-------|
| `alerts_queue.js` | 24.4 KB | Class AlertsQueue: bảng alert với virtual scroll |
| `alert_detail_modal.js` | 22.7 KB | Class AlertDetailModal: modal 3 tab (overview, classification, history) |

### Prompt 4 — AI Engine Page (1 file)
| File | Kích thước | Mô tả |
|------|-----------|-------|
| `ai_engine_page.js` | 35.5 KB | Class AIEnginePage: toàn bộ trang AI (6 section, Explainable AI) |

### Prompt 5 — Threat Hunting Page (1 file)
| File | Kích thước | Mô tả |
|------|-----------|-------|
| `threat_hunt_page.js` | 30.4 KB | Class ThreatHuntPage: trang hunting (search, filter, results) |

### Prompt 6 — SOAR Playbook (1 file)
| File | Kích thước | Mô tả |
|------|-----------|-------|
| `soar_playbook.js` | 68.8 KB | Class SOARPlaybookBuilder: node editor (drag-drop, connections) |

### Prompt 7 — Infrastructure (3 file)
| File | Kích thước | Mô tả |
|------|-----------|-------|
| `soc_websocket.js` | 17.7 KB | Class SOCWebSocket: WebSocket manager nâng cao |
| `virtual_scroll.js` | 19.9 KB | Class VirtualScrollTable: virtual scroll cho bảng lớn |
| `block_ip.js` | 22.3 KB | `confirmBlockIP()`: modal xác nhận + whitelist + audit log |

### Prompt 8 — Integration Guides (4 file tài liệu)
| File | Kích thước | Mô tả |
|------|-----------|-------|
| `CHART_INTEGRATION_GUIDE.js` | 16.7 KB | Hướng dẫn tích hợp 3 chart module |
| `ALERTS_QUEUE_INTEGRATION.js` | 21.2 KB | Hướng dẫn tích hợp alerts queue |
| `AI_ENGINE_INTEGRATION.js` | 30.2 KB | Hướng dẫn tích hợp AI Engine page |
| `THREAT_HUNT_INTEGRATION.js` | 33.2 KB | Hướng dẫn tích hợp Threat Hunting page |

---

## 3. Phân loại module

### ✅ ĐÃ TÍCH HỢP (4 file)
Các module bổ sung tính năng mới, không conflict với code hiện tại:

| Module | Vai trò | Cách tích hợp |
|--------|---------|---------------|
| `toast.js` | Thay thế `window.toast()` đơn giản bằng hệ thống thông báo nâng cao (5 loại severity, progress bar, stack, audio alert) | Load trước `app.js`. Compatibility bridge map `window.toast(msg, 'ok'/'err'/'warn')` → `showToast()` |
| `ai_labels.js` | Hiển thị nhãn tiếng Việt cho AI model (thay vì tên thuật toán thô) | Load trước inline script AI. Dùng `renderModelBadges()` và `renderActionSuggestion()` |
| `block_ip.js` | Modal xác nhận chặn IP thay vì `confirm()` đơn giản. Có whitelist, audit log | Load sau `app.js`. Override `window.blockIP` để gọi `confirmBlockIP()` |
| `alert_detail_modal.js` | Modal chi tiết alert 3 tab (overview, classification, history) | Load sau `app.js`. Khởi tạo qua `window._alertModal = new AlertDetailModal()` |

### ⚠️ KHÔNG TÍCH HỢP — Trùng lặp code hiện tại (7 file)
Các module tạo DOM riêng, conflict với HTML đã có trong `index.html`:

| Module | Lý do không tích hợp |
|--------|---------------------|
| `soc_websocket.js` | `ws.js` (20 dòng) đã hoạt động tốt. Load cả hai → 2 WebSocket connection chồng chéo |
| `soar_playbook.js` | `soar.js` (1200 dòng) đã có full playbook canvas. Load cả hai → conflict DOM |
| `alerts_queue.js` | `app.js` đã có Alert Queue IIFE (~300 dòng) với filter, pagination, bulk actions |
| `threat_hunt_page.js` | `app.js` đã có Hunting IIFE (~300 dòng) với search, stats, expand rows |
| `ai_engine_page.js` | Inline script + HTML trong `index.html` đã render trang AI |
| `vn_format.js` | `app.js` đã có `fmtTime()`, `fmtDate()`, `sevBadge()` — duplicate |
| `virtual_scroll.js` | Standalone component, không có table nào đủ lớn cần virtual scroll hiện tại |

### 📋 CHỈ LÀ TÀI LIỆU (4 file)
| File | Nội dung |
|------|----------|
| `CHART_INTEGRATION_GUIDE.js` | Hướng dẫn thay Chart.js bằng 3 SVG chart |
| `ALERTS_QUEUE_INTEGRATION.js` | Hướng dẫn thay bảng alert bằng virtual scroll |
| `AI_ENGINE_INTEGRATION.js` | Hướng dẫn thay trang AI bằng class module |
| `THREAT_HUNT_INTEGRATION.js` | Hướng dẫn thay hunting bằng class module |

### 🗂 CÓ THỂ DÙNG SAU (3 file chart)
Chart SVG thay thế Chart.js — không tích hợp ngay vì Chart.js đang ổn:

| Module | Ghi chú |
|--------|---------|
| `mitre_heatmap.js` | Có thể thay `renderMitre()` trong `app.js` |
| `timeline_24h.js` | Có thể thay `initTimeline()` trong `charts.js` |
| `top_rules_24h.js` | Có thể thay `initRulesBar()` trong `charts.js` |

---

## 4. Bug đã phát hiện & sửa

### 🐛 Bug 1: `block_ip.js` — SAI API endpoint
- **Trước**: `POST /api/response` + JSON body → 404 Not Found
- **Sau**: `POST /api/response/block-ip?ip=...` → đúng endpoint backend
- **File**: `block_ip.js` dòng `_executeBlockIP()`

### 🐛 Bug 2: `toast.js` — Không tương thích `window.toast()`
- **Vấn đề**: `showToast(type, title, message)` có signature khác `window.toast(msg, type, ms)`
- **Sửa**: Thêm compatibility bridge map `'ok'→'thanh_cong'`, `'err'→'nghiem_trong'`, `'warn'→'cao'`
- **Kết quả**: 30+ lời gọi `window.toast()` trong app.js/soar.js tiếp tục hoạt động

### 🐛 Bug 3: `app.js` — `window.toast()` bị override
- **Vấn đề**: `app.js` define `window.toast()` đè lên toast.js vì load sau
- **Sửa**: Đổi thành fallback: `if (typeof window.toast !== 'function') { ... }`

### 🐛 Bug 4: Inline AI script — Hiển thị tên thuật toán thô
- **Trước**: `(a.triggered_models||[]).join(', ')` → "IsolationForest, CUSUM"
- **Sau**: `renderModelBadges(a.triggered_models)` → "🔍 Hành vi bất thường 📈 Tăng đột biến"

### 🐛 Bug 5: `window.blockIP()` — Chỉ dùng confirm() đơn giản
- **Trước**: `confirm('Chặn IP?')` → không có whitelist, audit log
- **Sau**: `confirmBlockIP(ip)` → modal đẹp, whitelist check, localStorage audit log

### ⚠️ Bug tiềm ẩn (KHÔNG SỬA — module không tích hợp)
| Module | Bug | Lý do không sửa |
|--------|-----|-----------------|
| `soc_websocket.js` | Tạo WS connection thứ 2 nếu load cùng `ws.js` | Không tích hợp |
| `soar_playbook.js` | `container.innerHTML = ''` xóa HTML SOAR page hiện tại | Không tích hợp |
| `threat_hunt_page.js` | Tạo DOM riêng, conflict với `#page-hunting` HTML | Không tích hợp |
| `ai_engine_page.js` | Tạo DOM riêng, conflict với `#page-ai` HTML | Không tích hợp |
| `alerts_queue.js` | Tạo bảng riêng, conflict với `window.alertQueue` | Không tích hợp |

---

## 5. Trạng thái tích hợp

```
index.html
├── toast.js          ✅ Loaded — enhanced notifications
├── ai_labels.js      ✅ Loaded — Vietnamese AI labels
├── auth.js           (gốc)
├── api.js            (gốc)
├── ws.js             (gốc)
├── charts.js         (gốc)
├── triage.js         (gốc)
├── app.js            ✅ Modified — fallback toast, enhanced blockIP
├── soar.js           (gốc)
├── block_ip.js       ✅ Loaded — confirmation modal, whitelist, audit
├── alert_detail_modal.js  ✅ Loaded — 3-tab detail modal
├── [inline AI script] ✅ Modified — uses renderModelBadges()
├── [integration bridge] ✅ Added — wires blockIP + alertModal
└── theme.js          (gốc)
```

---

## 6. Thứ tự load script trong index.html

```html
<!-- CDN -->
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>

<!-- NEW: Toast system (load đầu tiên để window.toast sẵn sàng) -->
<script src="js/toast.js"></script>

<!-- NEW: AI labels (load trước inline AI script) -->
<script src="js/ai_labels.js"></script>

<!-- Core modules -->
<script src="js/auth.js"></script>
<script src="js/api.js"></script>
<script src="js/ws.js"></script>
<script src="js/charts.js"></script>
<script src="js/triage.js"></script>
<script src="js/app.js"></script>
<script src="js/soar.js"></script>

<!-- NEW: Enhancement modules (load sau app.js) -->
<script src="js/block_ip.js"></script>
<script src="js/alert_detail_modal.js"></script>

<!-- Inline: AI page rendering (uses ai_labels.js) -->
<script>/* ... AI inline ... */</script>

<!-- Inline: Integration bridge (wires blockIP + alertModal) -->
<script>/* ... bridge ... */</script>

<!-- Theme (luôn load cuối) -->
<script src="js/theme.js"></script>
```

---

## 7. Chi tiết từng prompt

### PROMPT 1: Utility Modules
**Yêu cầu**: Tạo các hàm tiện ích cơ bản cho SOC dashboard  
**Output**: `vn_format.js`, `ai_labels.js`, `toast.js`  
**Kết quả**:
- `toast.js` → ✅ Tích hợp (thay thế toast đơn giản)
- `ai_labels.js` → ✅ Tích hợp (nhãn AI tiếng Việt)  
- `vn_format.js` → ⚠️ Không tích hợp (duplicate `fmtTime`/`fmtDate` trong app.js)

### PROMPT 2: Chart Modules
**Yêu cầu**: Tạo biểu đồ chuyên dụng cho dashboard  
**Output**: `mitre_heatmap.js`, `timeline_24h.js`, `top_rules_24h.js`  
**Kết quả**: ⚠️ Không tích hợp — Chart.js đang hoạt động tốt, SVG chart là alternative

### PROMPT 3: Alert Queue & Detail Modal
**Yêu cầu**: Bảng alert queue và modal chi tiết  
**Output**: `alerts_queue.js`, `alert_detail_modal.js`  
**Kết quả**:
- `alert_detail_modal.js` → ✅ Tích hợp (modal 3 tab mới)
- `alerts_queue.js` → ⚠️ Không tích hợp (app.js đã có alert queue đầy đủ)

### PROMPT 4: AI Engine Page
**Yêu cầu**: Trang AI Engine hoàn chỉnh  
**Output**: `ai_engine_page.js`  
**Kết quả**: ⚠️ Không tích hợp — trang AI đã có HTML + inline script. Module tạo DOM riêng (`container.innerHTML = ''`) sẽ xóa HTML hiện tại

### PROMPT 5: Threat Hunting Page
**Yêu cầu**: Trang Threat Hunting hoàn chỉnh  
**Output**: `threat_hunt_page.js`  
**Kết quả**: ⚠️ Không tích hợp — app.js đã có Hunting IIFE (~300 dòng) với search, stats, expandable rows

### PROMPT 6: SOAR Playbook Builder
**Yêu cầu**: SOAR playbook visual editor  
**Output**: `soar_playbook.js`  
**Kết quả**: ⚠️ Không tích hợp — `soar.js` (1200 dòng) đã có full canvas editor với drag-drop, zoom, undo/redo

### PROMPT 7: Infrastructure Modules
**Yêu cầu**: WebSocket, virtual scroll, block IP  
**Output**: `soc_websocket.js`, `virtual_scroll.js`, `block_ip.js`  
**Kết quả**:
- `block_ip.js` → ✅ Tích hợp (modal xác nhận + whitelist + audit log)
- `soc_websocket.js` → ⚠️ Không tích hợp (ws.js đã hoạt động, load cả hai → 2 WS connection)
- `virtual_scroll.js` → ⚠️ Không tích hợp (standalone, chưa cần)

### PROMPT 8: Integration Guides
**Yêu cầu**: Tài liệu hướng dẫn tích hợp  
**Output**: 4 file `*_INTEGRATION.js` + `CHART_INTEGRATION_GUIDE.js`  
**Kết quả**: 📋 Chỉ là tài liệu tham khảo, không phải code thực thi

---

## Tóm tắt

| Chỉ số | Giá trị |
|--------|---------|
| Tổng file JS mới | 14 |
| Tổng file tài liệu | 4 |
| Đã tích hợp | **4** (toast, ai_labels, block_ip, alert_detail_modal) |
| Không tích hợp (duplicate) | **7** |
| Chỉ tài liệu | **4** |
| Có thể dùng sau | **3** (SVG charts) |
| Bug đã sửa | **5** |

> **Lý do chính không tích hợp 10 module**: Sản phẩm (`index.html` + 8 file JS gốc) đã có đầy đủ chức năng cho tất cả 8 trang. Các module page-level (`ai_engine_page.js`, `threat_hunt_page.js`, `soar_playbook.js`, `alerts_queue.js`) tạo DOM riêng bằng `innerHTML = ''`, sẽ xóa HTML hiện có nếu load.

---

*Tạo bởi SOC Dashboard build process — $(date)*
