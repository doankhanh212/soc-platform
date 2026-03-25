/**
 * ═══════════════════════════════════════════════════════════════════════════
 * AI_ENGINE_PAGE INTEGRATION GUIDE
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * This document explains how to integrate the AIEnginePage module into your
 * SOC dashboard. It includes HTML setup, API contracts, features, and complete
 * example initialization code.
 * 
 * CRITICAL PRINCIPLE:
 * ────────────────────
 * NEVER display algorithm names in HTML: IsolationForest, CUSUM, EWMA, Entropy
 * Only show behavioral descriptions and explanations to end users.
 * Algorithm names are used internally in JS only.
 */

// ═══════════════════════════════════════════════════════════════════════════
// 1. HTML STRUCTURE & CSS
// ═══════════════════════════════════════════════════════════════════════════

/*

  <!DOCTYPE html>
  <html lang="vi">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Động cơ AI — SOC Dashboard</title>
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      body {
        background: #0a0f0a;
        color: #ccc;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Courier New', monospace;
        overflow-x: hidden;
      }

      main {
        max-width: 1400px;
        margin: 0 auto;
        padding: 20px;
      }

      h1, h2, h3 {
        font-weight: 700;
        letter-spacing: 1px;
      }

      button {
        font-family: inherit;
        cursor: pointer;
      }

      select {
        font-family: inherit;
      }
    </style>
  </head>
  <body>
    <main id="ai-engine-container"></main>

    <!-- Dependencies -->
    <script src="vn_format.js"></script>
    <script src="ai_labels.js"></script>
    <script src="ai_engine_page.js"></script>

    <!-- Initialize -->
    <script>
      document.addEventListener('DOMContentLoaded', async () => {
        const page = new AIEnginePage();
        await page.init();
      });
    </script>
  </body>
  </html>

*/

// ═══════════════════════════════════════════════════════════════════════════
// 2. QUICK START (3 lines)
// ═══════════════════════════════════════════════════════════════════════════

/*

  const page = new AIEnginePage();
  await page.init();
  // Done! All sections rendered with live data from APIs

*/

// ═══════════════════════════════════════════════════════════════════════════
// 3. API ENDPOINTS REQUIRED
// ═══════════════════════════════════════════════════════════════════════════

/*

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ GET /api/ai/stats                                                       │
  ├─────────────────────────────────────────────────────────────────────────┤
  │ Response: {                                                             │
  │   "anomalies_24h": 3847,           // Total anomalies in 24h           │
  │   "high_severity": 184,             // Count of HIGH severity           │
  │   "avg_risk_score": 0.62,           // Average risk score (0.0-1.0)    │
  │   "auto_blocked_ips": 23,           // Auto-blocked IPs in 24h         │
  │   "monitored_ips": 1250             // Total IPs being monitored       │
  │ }                                                                       │
  │                                                                         │
  │ Used by: Section 2 (Metric Cards)                                      │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ GET /api/ai/anomalies?limit=50                                          │
  ├─────────────────────────────────────────────────────────────────────────┤
  │ Response: [{                                                            │
  │   "src_ip": "192.168.1.45",                                            │
  │   "country": "Vietnam",              // Optional                       │
  │   "timestamp": "2026-03-25T14:30:00Z",                                 │
  │   "risk_score": 0.87,                // 0.0-1.0, higher = more danger │
  │   "rule_level": 14,                  // Severity 1-15+                  │
  │   "models_triggered": [              // ONLY behavior names!!! NOT ...  │
  │     "Hành vi bất thường",            // (NOT IsolationForest)          │
  │     "Tăng đột biến"                  // (NOT EWMA)                     │
  │   ],                                                                   │
  │                                                                         │
  │   // For building explanations (NO algorithm names):                   │
  │   "unique_dest_ports": 47,           // Port scanning detection        │
  │   "cusum_s": 6.2,                    // Behavioral drift (INTERNAL)    │
  │   "if_score": 0.94,                  // Outlier score (INTERNAL)       │
  │   "if_percentile": 92,               // Outlier percentile (INTERNAL)   │
  │   "so_canh_bao_1h": 1847,            // Alerts in last hour            │
  │   "so_canh_bao": 23486               // Total alerts                    │
  │ }, ...]                                                                │
  │                                                                         │
  │ Used by: Section 5 (Dangerous IP Panel) + Section 6 (Table)            │
  └─────────────────────────────────────────────────────────────────────────┘

*/

// ═══════════════════════════════════════════════════════════════════════════
// 4. FEATURES & INTERACTIONS
// ═══════════════════════════════════════════════════════════════════════════

/*

  SECTION 1: Stepper (AI Workflow)
  ────────────────────────────────
  • 6 horizontal steps with animated load (staggered 100ms)
  • Hover → tooltip shows full Vietnamese description
  • Active state: border #00ff88, background #001a00
  • Visual flow: 📥 Thu thập → ⚙ Trích xuất → 🧠 4 Lớp AI → 📊 Tính điểm → 💬 Giải thích → 🛡 Hành động

  SECTION 2: Metric Cards
  ──────────────────────
  • 5 cards with real-time metrics (loaded from /api/ai/stats)
  • Grid layout: responsive (auto-fit minmax 180px)
  • Formatting:
    - anomalies_24h: thousands separator (vi-VN locale)
    - high_severity: plain number
    - avg_risk_score: fixed 2 decimals (0.00 - 1.00)
    - auto_blocked_ips: plain number
    - monitored_ips: plain number

  SECTION 3: Monitoring Cards (4 Behavior Types)
  ──────────────────────────────────────────────
  • 4 cards representing AI monitoring types (NO algorithm names)
    - 🔍 Hành vi bất thường (Behavior Anomaly) [= IsolationForest internally]
    - ⚡ Đột biến lưu lượng (Traffic Spike) [= EWMA internally]
    - 📈 Leo thang âm thầm (Behavioral Drift) [= CUSUM internally]
    - 🔐 Mã hóa & Dữ liệu ẩn (Encrypted Data) [= Entropy internally]
  • Status badge (top right): 🟢 ĐANG CHẠY | 🟡 CẢNH BÁO | ⚫ TẮT
  • Progress bar: 0-100% (mocked at 65% for all)
  • Count: "X.XXX bất thường hôm nay" (today's anomaly count, mocked)

  SECTION 4: Monitored Behaviors Widget
  ─────────────────────────────────────
  • 4 rows showing active behavior monitoring:
    - 🔑 Đăng nhập bất thường (99.718 sự kiện, ACTIVE=green pulse)
    - 🌐 Lưu lượng mạng (48.386 sự kiện, ACTIVE=green pulse)
    - 📁 Thay đổi file (0 sự kiện, IDLE=opacity 0.4)
    - ⚙ Hành vi tiến trình (5 sự kiện, IDLE=opacity 0.4)
  • Styling: ACTIVE rows bright, IDLE rows dim

  SECTION 5: Dangerous IP Panel
  ────────────────────────────
  • Header shows top IP (from anomalies[0]) with:
    - Large red IP address (monospace)
    - Location badge (📍 Country)
    - Risk score bar (gradient #ff8800→#ff4444)
    - Score in decimals (0.00-1.00)
    - Action suggestion (rendered via renderActionSuggestion)
  
  • Explainable Reasons (generated by buildExplainableReasons()):
    ✓ Checks unique_dest_ports (port scanning)
    ✓ Checks cusum_s (behavioral drift)
    ✓ Checks if_percentile (outlier detection)
    ✓ Checks so_canh_bao_1h (alert frequency)
    Each reason shows:
      - Main description in Vietnamese (RED text)
      - Evidence with numbers (monospace, GRAY)
  
  • 3 action buttons (all functional stubs):
    - 🔍 Threat Hunt (cyan)
    - 📋 Tạo vụ việc (yellow)
    - 🛡 Chặn thủ công (red)

  SECTION 6: Anomalies Table
  ──────────────────────────
  • 7 columns: Time | IP | Country | Risk Score | Severity | AI Findings | Action Suggestion
  • Scrollable container (max-height 600px)
  • Sticky header (position: sticky, top: 0)
  • Alternating row colors with hover highlight
  • Risk score: bar graph + decimal value
  • Severity: colored badge via renderBadgeMucDo()
  • AI Findings: checkboxes via renderModelBadges() (NO algorithm names!)
  • Action: suggestion via renderActionSuggestion()
  • Filter dropdown: Tất cả | NGHIÊM TRỌNG | CAO | TRUNG BÌNH | THẤP
  • Displays first 20 anomalies from API
  • Rows sortable/expandable (structure ready, expand logic stubbed)

*/

// ═══════════════════════════════════════════════════════════════════════════
// 5. DEPENDENCIES & IMPORTS
// ═══════════════════════════════════════════════════════════════════════════

/*

  REQUIRED MODULES (in load order):
  ─────────────────────────────────

  1. vn_format.js
     • formatTuongDoi(iso8601_string) → "vừa xong", "5 phút trước", etc.
     • formatBadgeMucDo(rule_level) → HTML <span> with color

  2. ai_labels.js
     • renderModelBadges(array_of_labels) → HTML checkboxes (✔ Label)
     • renderActionSuggestion(risk_score_0_1) → HTML suggestion text
     • AI_MODEL_LABELS constant (internal reference, NOT used)

  OPTIONAL:
  ─────────
  3. toast.js (if you want notifications for button clicks)
     • showToast(type, title, message)

*/

// ═══════════════════════════════════════════════════════════════════════════
// 6. EXPLAINABLE REASONING (Core AI Transparency Feature)
// ═══════════════════════════════════════════════════════════════════════════

/*

  The AIEnginePage.buildExplainableReasons(ip) method generates human-readable
  reasons for why an IP was flagged. It checks these indicators:

  ┌──────────────────────────────────────────────────────────────────────────┐
  │ REASON 1: Port Scanning Detection                                        │
  ├──────────────────────────────────────────────────────────────────────────┤
  │ Trigger: if (unique_dest_ports >= 10)                                    │
  │ Main:    "Kết nối đến NHIỀU cổng — dấu hiệu đang quét tìm lỗ hổng"     │
  │ Evidence: "Đã kết nối tới {n} cổng (bình thường < 5)"                   │
  │ Internal: IsolationForest flag (NOT shown to user)                       │
  └──────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────┐
  │ REASON 2: Behavioral Drift / Leo Thang                                  │
  ├──────────────────────────────────────────────────────────────────────────┤
  │ Trigger: if (cusum_s >= 5.0)                                             │
  │ Main:    "Hành vi leo thang liên tục trong 2 giờ qua"                   │
  │ Evidence: "Chỉ số tích lũy: {n} (ngưỡng ≥ 5.0)"                         │
  │ Internal: CUSUM algorithm (NOT shown to user)                            │
  └──────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────┐
  │ REASON 3: Outlier Detection                                             │
  ├──────────────────────────────────────────────────────────────────────────┤
  │ Trigger: if (if_percentile >= 90)                                        │
  │ Main:    "Top {100-pct}% IP có hành vi khác biệt nhất từng gặp"        │
  │ Evidence: "Điểm bất thường: {score} · percentile {pct}"                 │
  │ Internal: Isolation Forest (NOT shown to user)                           │
  └──────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────┐
  │ REASON 4: High Alert Frequency                                          │
  ├──────────────────────────────────────────────────────────────────────────┤
  │ Trigger: if (so_canh_bao_1h >= 1000)                                     │
  │ Main:    "Tấn công cường độ cao — {n} lần trong 1 giờ"                 │
  │ Evidence: "Tổng: {total} lần"                                           │
  │ Internal: EWMA (NOT shown to user)                                       │
  └──────────────────────────────────────────────────────────────────────────┘

  PRINCIPLE:
  ──────────
  Algorithm names (IsolationForest, CUSUM, EWMA, Entropy) are used INTERNALLY
  only to fetch the data fields. The HTML UI NEVER displays these names.
  Instead, users see human-friendly descriptions like:
    • "Hành vi bất thường"
    • "Tăng đột biến"
    • "Leo thang âm thầm"
    • "Mã hóa & Dữ liệu ẩn"

*/

// ═══════════════════════════════════════════════════════════════════════════
// 7. COMPLETE EXAMPLE: Initialize AI Engine Page
// ═══════════════════════════════════════════════════════════════════════════

/*

  class SOCDashboard {
    constructor() {
      this.aiEngine = null;
      this.alertsQueue = null;
    }

    async init() {
      // Initialize AI Engine Page
      this.aiEngine = new AIEnginePage();
      await this.aiEngine.init();

      // Optional: Listen to AI Engine events
      document.addEventListener('ai-engine:ip-selected', (e) => {
        console.log('User selected IP:', e.detail.ip);
        // Could load additional details, trigger threat hunt, etc.
      });

      // Optional: Initialize other components
      // this.alertsQueue = new AlertsQueue('alert-container', this.onAlertClick);
    }

    onAlertClick(alert) {
      console.log('Alert clicked:', alert);
    }
  }

  // Bootstrap on page load
  document.addEventListener('DOMContentLoaded', async () => {
    const dashboard = new SOCDashboard();
    await dashboard.init();
  });

*/

// ═══════════════════════════════════════════════════════════════════════════
// 8. CSS CUSTOMIZATION REFERENCE
// ═══════════════════════════════════════════════════════════════════════════

/*

  Color Palette (Consistent Dark Theme):
  ──────────────────────────────────────

  Background:
    • Page bg:        #0a0f0a
    • Section bg:     #050705
    • Card bg:        #1a1f1a, #1a1a1a
    • Input bg:       #1a1f1a

  Accents (4 color tiers):
    • Primary (AI):   #9333EA (purple)
    • Summary (UI):   #00ff88 (bright green)
    • Metrics (WARN): #ffcc00 (yellow)
    • Networks:       #00ccff (cyan)
    • Data:           #ff4444 (red)
    • Secondary:      #ff8800 (orange)

  Text:
    • Headings:       #00ff88, #ffcc00, #00ccff, #ff4444, #9333EA
    • Normal:         #ccc, #888, #666
    • Monospace IPs:  #ffcc00 (yellow) or #ff4444 (red)
    • Subtle:         #666, #555

  Borders:
    • Normal:         #1a3a1a, #00ff8833, #00ff8844, #00ccff33, #00ccff44
    • Highlight:      #9333EA, #ff4444, #00ff88
    • Shadow:         transparent, XXXXXXbb (88 opacity)

  How to override:
  ────────────────
  All inline styles in AIEnginePage can be overridden via CSS rules:

  Example override for section titles:
    h3 { color: #00ffff !important; }

  Example override for metric cards:
    [style*="Metric Cards"] { grid-template-columns: repeat(2, 1fr) !important; }

*/

// ═══════════════════════════════════════════════════════════════════════════
// 9. KEYBOARD SHORTCUTS & ACCESSIBILITY
// ═══════════════════════════════════════════════════════════════════════════

/*

  (Currently not implemented — structure ready for enhancement)

  Suggested shortcuts:
    • Esc: Clear filters
    • Ctrl+F: Focus filter dropdown
    • ↓/↑: Navigate table rows
    • Enter: Expand/collapse row details
    • R: Refresh data

*/

// ═══════════════════════════════════════════════════════════════════════════
// 10. TROUBLESHOOTING
// ═══════════════════════════════════════════════════════════════════════════

/*

  PROBLEM: Metric cards show "—" (no data)
  SOLUTION: Ensure /api/ai/stats endpoint exists and returns valid JSON
            Check browser console for fetch errors

  PROBLEM: Algorithm names appear in HTML (e.g., "IsolationForest")
  SOLUTION: This is a framework bug. Check renderModelBadges() in ai_labels.js
            Must pass array of LABELS (like ["Hành vi bất thường"]), NOT model names

  PROBLEM: Tooltip position is off
  SOLUTION: Tooltip calculation assumes stepper boxes are at least 100px from viewport edges
            Adjust showTooltip() method coordinates if needed

  PROBLEM: Table doesn't show 20 rows
  SOLUTION: Check /api/ai/anomalies returns at least 20 items
            Verify response schema matches expected fields

  PROBLEM: Filter dropdown doesn't filter
  SOLUTION: Filter logic is stubbed. Implement applyTableFilter() to listen to
            filterSelect.addEventListener('change', this.applyTableFilter)

  PROBLEM: Animations don't play
  SOLUTION: Verify animations CSS is injected (injectAIEngineAnimations called)
            Check browser DevTools > Elements > <style id="ai-engine-animations">
            Ensure CSS support for @keyframes (modern browser required)

  PROBLEM: "formatTuongDoi is not defined"
  SOLUTION: Ensure vn_format.js is loaded BEFORE ai_engine_page.js

  PROBLEM: "renderModelBadges is not defined"
  SOLUTION: Ensure ai_labels.js is loaded BEFORE ai_engine_page.js

*/

// ═══════════════════════════════════════════════════════════════════════════
// 11. PERFORMANCE NOTES
// ═══════════════════════════════════════════════════════════════════════════

/*

  Virtual Scrolling: NOT used in AI Engine page (all sections are viewport-height)
  Max Row Rendering: Table renders first 20 anomalies (not 10,000+)
  Fetch Strategy: Parallel loads → loadAIMetrics() + loadAnomalies() concurrent
  DOM Operations: Minimal reflows (single append per element)
  Animation Frame: CSS animations only (no JS animation loops)
  Memory: Section DOM persists (no cleanup on hide)

  Optimization Tips:
  ──────────────────
  1. If you have 1000+ anomalies, implement pagination or virtual scroll
  2. Cache API responses in sessionStorage with 5-min TTL
  3. Debounce filter dropdown changes (300ms)
  4. Use requestAnimationFrame for smooth scrolling
  5. Consider lazy-loading sections (Intersection Observer API)

*/

// ═══════════════════════════════════════════════════════════════════════════
// 12. EVENT HANDLING & CUSTOM EVENTS
// ═══════════════════════════════════════════════════════════════════════════

/*

  (Ready to add in future versions)

  Events that could be dispatched:
    • 'ai-engine:ip-selected' - User clicked an IP row
    • 'ai-engine:threat-hunt' - User clicked "Threat Hunt" button
    • 'ai-engine:create-incident' - User clicked "Create Incident"
    • 'ai-engine:block-ip' - User clicked "Block IP" button
    • 'ai-engine:metrics-updated' - Metrics refreshed from API

  Usage example:
    document.addEventListener('ai-engine:ip-selected', (e) => {
      const ip = e.detail.src_ip;
      // Load details, integrate with threat hunt tool, etc.
    });

*/

// ═══════════════════════════════════════════════════════════════════════════
// 13. INTEGRATION WITH OTHER MODULES
// ═══════════════════════════════════════════════════════════════════════════

/*

  AIEnginePage <→ AlertsQueue:
  ──────────────────────────
  When user clicks "🔍 Threat Hunt" in dangerous IP panel, could:
    1. Dispatch custom event with IP
    2. AlertsQueue filters table to show only alerts from that IP
    3. Example:
       button.addEventListener('click', () => {
         document.dispatchEvent(new CustomEvent('filter-by-ip', {
           detail: { src_ip: ip.src_ip }
         }));
       });

  AIEnginePage <→ AlertDetailModal:
  ───────────────────────────────
  Could open alert detail for dangerous IP:
    1. Find alerts matching IP
    2. Open AlertDetailModal for first alert
    3. Example:
       button.addEventListener('click', () => {
         const alertModal = new AlertDetailModal();
         const relatedAlert = this.anomalyIPs.find(...);
         alertModal.show(relatedAlert);
       });

  AIEnginePage <→ Toast Notifications:
  ─────────────────────────────────────
  Show toast when user takes action:
    1. Block IP → "🛡 IP blocked successfully"
    2. Create incident → "📋 Incident #12345 created"
    3. Threat hunt start → "🔍 Threat hunt started (may take 2-3 min)"

*/

// ═══════════════════════════════════════════════════════════════════════════
// END OF DOCUMENTATION
// ═══════════════════════════════════════════════════════════════════════════

export { AIEnginePage };
