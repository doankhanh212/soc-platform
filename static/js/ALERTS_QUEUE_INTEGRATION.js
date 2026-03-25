/**
 * ALERTS_QUEUE_INTEGRATION.MD
 * 
 * === Level 1 SOC Alert Queue Integration Guide ===
 */

// ═══════════════════════════════════════════════════════════════════════════
// 1. HTML STRUCTURE
// ═══════════════════════════════════════════════════════════════════════════

/*
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Hàng đợi cảnh báo — HQG SOC</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      background: #0a0f0a;
      color: #ccc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      overflow: hidden;
    }

    #app {
      display: flex;
      flex-direction: column;
      height: 100vh;
      padding: 16px;
      gap: 16px;
    }

    .header {
      padding: 16px;
      border-bottom: 2px solid #00ff88;
      background: #111;
      border-radius: 6px;
    }

    .header h1 {
      font-size: 20px;
      color: #00ff88;
      margin: 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    #alerts-queue-container {
      flex: 1;
      overflow: hidden;
    }
  </style>
</head>
<body>
  <div id="app">
    <div class="header">
      <h1>🚨 Hàng đợi cảnh báo Level 1</h1>
    </div>
    <div id="alerts-queue-container"></div>
  </div>

  <!-- Utility modules (must load first) -->
  <script src="static/js/vn_format.js"></script>
  <script src="static/js/ai_labels.js"></script>
  <script src="static/js/toast.js"></script>

  <!-- Alert queue modules -->
  <script src="static/js/alerts_queue.js"></script>
  <script src="static/js/alert_detail_modal.js"></script>

  <!-- Application setup -->
  <script>
    // Initialize queue
    let queue = null;
    let detailModal = null;

    document.addEventListener('DOMContentLoaded', () => {
      // Create queue instance
      queue = new AlertsQueue('alerts-queue-container', (alert) => {
        // On row click: show detail modal
        if (!detailModal) {
          detailModal = new AlertDetailModal();
        }
        detailModal.show(alert);
      });

      console.log('✓ Alert Queue initialized');
    });
  </script>
</body>
</html>
*/

// ═══════════════════════════════════════════════════════════════════════════
// 2. QUICK START
// ═══════════════════════════════════════════════════════════════════════════

/*
MINIMAL INITIALIZATION:

// Create queue
const queue = new AlertsQueue('container-id', (alert) => {
  // Callback when user clicks a row
  console.log('Alert clicked:', alert);
  
  // Show detail modal
  const modal = new AlertDetailModal();
  modal.show(alert);
});

// That's it! Data will auto-fetch from GET /api/alerts
*/

// ═══════════════════════════════════════════════════════════════════════════
// 3. API ENDPOINTS REQUIRED
// ═══════════════════════════════════════════════════════════════════════════

/*
All endpoints must return the correct response format:

─────────────────────────────────────────────────────────────────────────────
GET /api/alerts?limit=500&hours=24
─────────────────────────────────────────────────────────────────────────────

Returns: Alert[]

Example Response:
[
  {
    alert_id: "ALT-20260324-0001",
    timestamp: "2026-03-24T15:14:28Z",
    rule_description: "SSH root login attempt",
    rule_level: 15,
    rule_id: 5503,
    loai: "IDS",
    may_chu: "web-server-01",
    ip_nguon: "37.111.53.110",
    ip_dich: "192.168.1.100",
    mitre_technique: "T1110.001",
    trang_thai: "OPEN",        // OPEN|RESOLVED|FALSE_POSITIVE
    phan_tich_vien: "Analyst1",
    updated_at: "2026-03-24T15:14:28Z"
  },
  ... (500 results)
]

─────────────────────────────────────────────────────────────────────────────
POST /api/alerts/:id/classify
─────────────────────────────────────────────────────────────────────────────

Body:
{
  classification: "true_positive" | "false_positive" | "needs_investigation" | "known_issue",
  analyst: "analyst_id",
  notes: "User notes"
}

Response:
{
  status: "success",
  alert_id: "ALT-20260324-0001"
}
*/

// ═══════════════════════════════════════════════════════════════════════════
// 4. FEATURES & INTERACTIONS
// ═══════════════════════════════════════════════════════════════════════════

/*
ALERTS QUEUE (Part A):
──────────────────────

Virtual Scrolling:
  ✓ Renders 20 visible rows + 5 buffer rows
  ✓ Handles 10,000+ rows smoothly
  ✓ Row height: 44px
  ✓ Sticky header (top 48px)

Columns (in order):
  ☑️  Checkbox (bulk select)
  ID  ALERT ID (monospace, green, clickable)
  📋 QUY TẮC (rule description)
  🎯 MỨC ĐỘ (colored badge: THẤP/TRUNG/CAO/NGHIÊM TRỌNG)
  🔷 LOẠI (IDS, log, etc.)
  🕐 THỜI GIAN (relative: "vừa xong", "5 phút trước", or full datetime on hover)
  🖥️  MÁY CHỦ (host name, monospace)
  📡 IP NGUỒN (yellow, monospace, click to copy)
  🎯 MITRE (technique ID, cyan)
  ✅ TRẠNG THÁI (badge: MỞ/GIẢI/NHẦM)
  👤 PHÂN TÍCH VIÊN (analyst name)
  ⚙️  HÀNH ĐỘNG (buttons below)

Actions (per row):
  🔍  View details (click anywhere on row, or this button)
  ＋   Create incident
  ✕   Mark as False Positive

Filters (sticky bar at top):
  Mức độ:     TẤT CẢ | NGHIÊM TRỌNG (15+) | CAO (12-14) | TRUNG BÌNH (7-11) | THẤP (1-6)
  Thời gian:  1 Giờ | 24 Giờ | 7 Ngày
  Trạng thái: TẤT CẢ | MỞ | ĐÃ GIẢI QUYẾT | CẢNH BÁO NHẦM
  Refresh:    🔄 button

Sorting:
  Click any column header to sort
  ASC ↔ DESC toggle on next click
  Supports: timestamp, rule_level, ip_nguon, etc.

Selection & Bulk Actions:
  ☑️  Select all (header checkbox)
  Multi-select (Ctrl+Click or use checkboxes)
  Bulk bar appears when >1 selected
  👤 Giao việc (assign multiple)
  ✕ Báo động nhầm (mark multiple as FP)

Real-Time Updates:
  Critical alerts (rule_level >= 15) flash red
  @keyframes alertFlash: red background pulsing

ALERT DETAIL MODAL (Part B):
───────────────────────────

Header:
  Left:  Alert ID (monospace)
  Right: 🛡 CHẶN IP [X.X.X.X] | 🔗 MITRE ATT&CK | ✕ Close

Tabs (3):
  📋 TỔNG QUAN
    Grid 2 columns:
      Left:  Raw JSON with syntax highlighting
             - Keys: #00ff88 (green)
             - Strings: #ffcc00 (yellow)
             - Numbers: #ff8800 (orange)
             - Booleans: #00ccff (cyan)
      Right: Metadata table
             - Trạng thái, Mức độ, IP nguồn, IP đích
             - Máy chủ, Rule ID, Mô tả, MITRE
             - Tạo lúc, Cập nhật, Phân tích viên

  🏷 PHÂN LOẠI
    Radio options (single select):
      ✅ True Positive
      ❌ False Positive
      ⚠️  Cần điều tra
      📋 Đã biết
    Analyst dropdown: assign to analyst
    Notes textarea: free-form comments
    💾 LƯU PHÂN LOẠI → POST /api/alerts/:id/classify

  📜 LỊCH SỬ
    Vertical timeline with events:
      ✨ Alert created
      👀 Viewed by Analyst1
      (etc., fetched from history)
    Dots and vertical line styling
    Timestamps + user attribution

Interactions:
  ✕ Close: Esc key or backdrop click
  Block IP: POST to /api/response (auto-toast notification)
  MITRE link: Opens new tab on attack.mitre.org
  Classification save: Validates form, sends POST, shows toast
*/

// ═══════════════════════════════════════════════════════════════════════════
// 5. EVENT HANDLING
// ═══════════════════════════════════════════════════════════════════════════

/*
// Row click handler
queue = new AlertsQueue('container-id', (alert) => {
  console.log('User clicked alert:', alert.alert_id);
  
  // Example: Do something with the alert
  if (alert.rule_level >= 15) {
    showToast('nghiem_torn', 'Cảnh báo NGHIÊM TRỌNG', alert.rule_description);
  }
  
  // Show detail modal
  const modal = new AlertDetailModal();
  modal.show(alert);
});

// Custom event: filter-by-rule (from charts)
window.addEventListener('filter-by-rule', (e) => {
  const { rule_id } = e.detail;
  // Could filter queue by this rule_id
});
*/

// ═══════════════════════════════════════════════════════════════════════════
// 6. CSS CUSTOMIZATION
// ═══════════════════════════════════════════════════════════════════════════

/*
All components use inline styles, but you can override via CSS:

.alert-row {
  // Virtual scroll row styling
}

.alert-row:hover {
  // Hover effect
}

.modal-tab-btn {
  // Tab buttons
}

.alert-flash {
  // Critical alert animation
  animation: alertFlash 2s ease-in-out infinite;
}

To customize:
  - Edit colors in alerts_queue.js and alert_detail_modal.js
  - Or override specific inline styles with CSS !important
  - Or modify the files directly before deployment
*/

// ═══════════════════════════════════════════════════════════════════════════
// 7. PERFORMANCE NOTES
// ═══════════════════════════════════════════════════════════════════════════

/*
✓ Virtual scrolling: Can handle 10,000+ rows
  - Only renders 20 visible + 10 buffer
  - Recalculates on scroll
  - Row height: 44px (fixed)

✓ Memory usage: Minimal
  - Stores full data in memory (can paginate if needed)
  - DOM nodes only for visible rows
  - Garbage collected on scroll

✓ Sorting: O(n log n)
  - All done in-memory
  - Instant feedback

✓ Filtering:
  - Applied in real-time
  - Multiple filters: severity + time + status
  - Re-render on filter change

OPTIMIZATION TIPS:
  - Paginate alerts (fetch 500 at a time max)
  - Batch API calls (GET /api/stats should also return top_rules)
  - Debounce scroll events (already done)
  - Lazy-load large JSON objects (current impl: full data in DOM)
*/

// ═══════════════════════════════════════════════════════════════════════════
// 8. WEBSOCKET REAL-TIME UPDATES (OPTIONAL)
// ═══════════════════════════════════════════════════════════════════════════

/*
// In app.js or main initialization:

function initWebSocket(queue) {
  const ws = new WebSocket('ws://localhost:8000/ws');
  
  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    
    if (message.type === 'new_alert') {
      // Add new alert to top of queue
      queue.allAlerts.unshift(message.data);
      queue.applyFilters();
      queue.renderTableBody();
      
      // Show toast for critical alerts
      if (message.data.rule_level >= 15) {
        showToast('nghiem_trong', '🚨 Cảnh báo NGHIÊM TRỌNG!', 
          `${message.data.rule_description} from ${message.data.ip_nguon}`);
      }
    }
  };
}

initWebSocket(queue);
*/

// ═══════════════════════════════════════════════════════════════════════════
// 9. INTEGRATION WITH OTHER MODULES
// ═══════════════════════════════════════════════════════════════════════════

/*
This queue integrates with:

vn_format.js:
  - formatThoiGian() → displays "24/03/2026 15:14:28"
  - formatTuongDoi() → displays "vừa xong", "5 phút trước"
  - formatMucDo() → returns {label, color, bg}
  - renderBadgeMucDo() → HTML badge

toast.js:
  - showToast() → notifications for actions
  - Types: 'nghiem_trong', 'cao', 'thanh_cong', 'thong_tin'

Charts (mitre_heatmap.js, timeline_24h.js, top_rules_24h.js):
  - Both fire custom events (filter-by-rule)
  - Queue can listen and apply filters

ai_labels.js:
  - Currently not used in queue
  - Could add AI anomaly indicators to future version
*/

// ═══════════════════════════════════════════════════════════════════════════
// 10. TROUBLESHOOTING
// ═══════════════════════════════════════════════════════════════════════════

/*
ALERTS NOT APPEARING:
  □ Check container ID matches ('alerts-queue-container')
  □ Verify GET /api/alerts returns data (check Network tab)
  □ Check browser console for errors
  □ Verify response format matches expected structure

NO SORTING/FILTERING:
  □ Click column header to sort
  □ Use filter dropdowns in filter bar
  □ Check console for errors

MODAL NOT OPENING:
  □ Verify AlertDetailModal is instantiated
  □ Check onRowClick callback is fired
  □ Verify modal shows in DOM and z-index is 10000

PERFORMANCE ISSUES:
  □ Check # of alerts (should be <1000 for good perf)
  □ Monitor scroll events (debounced but check logs)
  □ Check browser console for warnings
  □ Try refreshing data (🔄 button)

DATA NOT UPDATING:
  □ Click 🔄 refresh button
  □ Check WebSocket connection (optional feature)
  □ Verify API /api/alerts service is running
  □ Check browser cache (Ctrl+Shift+Delete)
*/

// ═══════════════════════════════════════════════════════════════════════════
// 11. COMPLETE EXAMPLE: INIT CODE
// ═══════════════════════════════════════════════════════════════════════════

/*
// app.js - Complete initialization

class SOCAlertPage {
  constructor() {
    this.queue = null;
    this.modal = null;
    this.ws = null;
  }

  async init() {
    // Create queue with detail modal callback
    this.queue = new AlertsQueue('alerts-queue-container', (alert) => {
      this.showAlertDetail(alert);
    });

    // Setup real-time updates
    this.initWebSocket();

    // Setup keyboard shortcuts
    this.setupKeyboardShortcuts();

    console.log('✓ Alert Queue Page initialized');
  }

  showAlertDetail(alert) {
    if (!this.modal) {
      this.modal = new AlertDetailModal();
    }
    this.modal.show(alert);
  }

  initWebSocket() {
    try {
      this.ws = new WebSocket('ws://localhost:8000/ws');
      
      this.ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        
        if (msg.type === 'new_alert') {
          this.queue.allAlerts.unshift(msg.data);
          this.queue.applyFilters();
          this.queue.renderTableBody();
          
          if (msg.data.rule_level >= 15) {
            showToast('nghiem_trong', '🚨 Cảnh báo NGHIÊM TRỌNG',
              `${msg.data.ip_nguon} — ${msg.data.rule_description}`);
          }
        }
      };

      this.ws.onerror = (error) => {
        console.warn('WebSocket error:', error);
      };
    } catch (error) {
      console.warn('WebSocket not available:', error);
    }
  }

  setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      if (e.key === 'f' && e.ctrlKey) {
        e.preventDefault();
        // Focus search/filter
      }
      if (e.key === 'r' && e.ctrlKey) {
        e.preventDefault();
        // Refresh queue
        this.queue.fetchAlerts();
      }
    });
  }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  const app = new SOCAlertPage();
  app.init();
});
*/

// ═══════════════════════════════════════════════════════════════════════════
// 12. STYLING REFERENCE (Colors & Theme)
// ═══════════════════════════════════════════════════════════════════════════

/*
Dark Theme Colors:
  Background depth:
    #0a0f0a  → Main background
    #050705  → Darker panels
    #1a1f1a  → Input backgrounds
    #111     → Header backgrounds

  Text colors:
    #00ff88  → Primary (HQG green)
    #00ccff  → Secondary (cyan)
    #ffcc00  → Warning (yellow)
    #ff8800  → Caution (orange)
    #ff4444  → Danger (red)
    #ccc     → Normal text
    #888     → Muted text

Severity Badges (from rule.level):
  1-6:    THẤP       → #00FF88 bg #001a00
  7-11:   TRUNG BÌNH → #FFCC00 bg #1a1a00
  12-14:  CAO        → #FF8800 bg #1a0800
  15+:    NGHIÊM TRỌ → #FF4444 bg #1a0000

Status Badges:
  OPEN           → #FF4444 (red)
  RESOLVED       → #00FF88 (green)
  FALSE_POSITIVE → #888888 (gray)

Borders:
  Primary   → #00ff8844 (green with opacity)
  Secondary → #00ff8822 (lighter green)
  Danger    → #ff444444 (red with opacity)
  Warning   → #ffcc0044 (yellow with opacity)
*/

// ═══════════════════════════════════════════════════════════════════════════
// END INTEGRATION GUIDE
// ═══════════════════════════════════════════════════════════════════════════
