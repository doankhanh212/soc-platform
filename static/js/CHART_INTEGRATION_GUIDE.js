/**
 * CHART_INTEGRATION_GUIDE.MD
 * 
 * === SOC Dashboard Chart Integration ===
 * 
 * HOW TO USE THE THREE ANALYSIS CHARTS
 */

// ═══════════════════════════════════════════════════════════════════════════
// 1. ADD TO index.html <head> (or before closing </body>)
// ═══════════════════════════════════════════════════════════════════════════

/*
<!-- Utility modules (must load first) -->
<script src="static/js/vn_format.js"></script>
<script src="static/js/ai_labels.js"></script>
<script src="static/js/toast.js"></script>

<!-- Chart modules -->
<script src="static/js/mitre_heatmap.js"></script>
<script src="static/js/timeline_24h.js"></script>
<script src="static/js/top_rules_24h.js"></script>

<!-- App initialization -->
<script src="static/js/app.js"></script>
*/

// ═══════════════════════════════════════════════════════════════════════════
// 2. ADD HTML CONTAINERS TO DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════

/*
<!-- Dashboard layout with three chart sections -->
<div class="dashboard-grid">
  <!-- Chart 1: MITRE ATT&CK Heatmap -->
  <section class="chart-section chart-wide">
    <div id="mitre-heatmap-container"></div>
  </section>

  <!-- Chart 2: Timeline 24h -->
  <section class="chart-section chart-half">
    <div id="timeline-24h-container"></div>
  </section>

  <!-- Chart 3: Top Rules 24h -->
  <section class="chart-section chart-half">
    <div id="top-rules-24h-container"></div>
  </section>
</div>

<style>
  .dashboard-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    padding: 20px;
  }

  .chart-section {
    background: #0a0f0a;
    border: 1px solid #00ff8833;
    border-radius: 8px;
    overflow: hidden;
  }

  .chart-wide {
    grid-column: 1 / -1;
  }

  .chart-half {
    grid-column: span 1;
  }

  @media (max-width: 1024px) {
    .dashboard-grid {
      grid-template-columns: 1fr;
    }
    .chart-wide,
    .chart-half {
      grid-column: 1;
    }
  }
</style>
*/

// ═══════════════════════════════════════════════════════════════════════════
// 3. INITIALIZE CHARTS IN app.js
// ═══════════════════════════════════════════════════════════════════════════

/*
document.addEventListener('DOMContentLoaded', () => {
  // Initialize MITRE ATT&CK Heatmap
  const mitreChart = new MitreHeatmap('mitre-heatmap-container');
  mitreChart.fetchData();

  // Initialize 24-hour Timeline
  const timelineChart = new Timeline24h('timeline-24h-container');
  timelineChart.fetchData();

  // Initialize Top Rules Chart
  const rulesChart = new TopRules24h('top-rules-24h-container');
  rulesChart.fetchData();

  // Optional: Refresh charts every 5 minutes
  setInterval(() => {
    mitreChart.fetchData();
    timelineChart.fetchData();
    rulesChart.fetchData();
  }, 5 * 60 * 1000);

  // Listen for rule filter events
  window.addEventListener('filter-by-rule', (e) => {
    const { rule_id, rule_name } = e.detail;
    // Filter alert table by rule_id
    filterAlertsByRule(rule_id, rule_name);
  });
});
*/

// ═══════════════════════════════════════════════════════════════════════════
// 4. API ENDPOINT REQUIREMENTS
// ═══════════════════════════════════════════════════════════════════════════

/*
All three charts expect these API endpoints to exist:

1. GET /api/mitre
   Returns: [
     {
       technique_id: "T1110.001",
       ten: "Brute Force - Password Guessing",
       chien_thuat: "Credential Access",
       so_lan: 99718,
       tan_suat_pct: 45.2
     },
     ...
   ]

2. GET /api/stats
   Returns: {
     hourly_alerts: [
       250, 280, 300, ...(24 elements)...
     ],
     top_rules: [
       {
         rule_id: 5503,
         mo_ta: "SSH root login attempt",
         nhom: "authentication",
         so_lan: 48400
       },
       ...
     ],
     ... other stats ...
   }

3. WebSocket support (optional, for real-time updates)
   ws://localhost:8000/ws → {type: "new_alert"|"ai_anomaly"|"stats_update", data: {...}}
*/

// ═══════════════════════════════════════════════════════════════════════════
// 5. FEATURES & INTERACTIONS
// ═══════════════════════════════════════════════════════════════════════════

/*
CHART A: MITRE ATT&CK HEATMAP
─────────────────────────────

Part 1 - Heatmap Grid:
  • Color intensity = hit count per technique
  • Hover → shows tooltip with technique name + count
  • Click → opens attack.mitre.org/techniques/[ID]
  • Color scale:
      0         → #111 (dark gray)
      1-100     → #1a3a1a (dark green)
      101-1000  → #2d5a2d (medium green)
      1001-10k  → #cc6600 (orange)
      10k+      → #ff2200 (red)

Part 2 - Detail Table:
  • Shows: Technique ID | Tactic (badge) | Hit count | Frequency bar
  • Sortable by clicking column headers (optional)
  • Tactic colors:
      Credential Access    → #9333EA (purple)
      Lateral Movement     → #FF8800 (orange)
      Impact               → #FF4444 (red)
      Defense Evasion      → #00CCFF (cyan)

Part 3 - Tactic Distribution:
  • Horizontal bar chart grouped by tactic
  • Bars animate on load (0 → 100%)
  • Shows total count per tactic

CHART B: TIMELINE 24h
─────────────────────

  • SVG area chart with gradient fill
  • Line color: #ff4444 (red)
  • Area gradient: #ff440033 → transparent
  • Features:
      - Current time indicator (white dashed line + "Bây giờ" label)
      - Average line (yellow dashed + "TB: X" label)
      - Hover any data point → tooltip with count
      - Grid lines every 4 hours
      - X-axis labels (00:00, 04:00, 08:00, ...)
  • Animation: Draws left→right on load (800ms)
  • Responsive: Re-renders on window resize (debounce 300ms)

CHART C: TOP RULES 24h
─────────────────────

  • Horizontal bar chart (10 rules max)
  • Bar animated on load, staggered (500ms total)
  • Colors by rule group:
      authentication → #FF8800 (orange)
      ids            → #FF4444 (red)
      system         → #FFCC00 (yellow)
      malware        → #FF00FF (magenta)
      audit          → #00FF88 (green)
      access_control → #00CCFF (cyan)
  • Hover → tooltip showing rule ID + hit count + group
  • Click → fires 'filter-by-rule' event to filter alert table
  • Shows rule group badge on hover
*/

// ═══════════════════════════════════════════════════════════════════════════
// 6. CUSTOM EVENTS & CALLBACKS
// ═══════════════════════════════════════════════════════════════════════════

/*
// Listen for rule filtering (triggered when user clicks a top rule)
window.addEventListener('filter-by-rule', (event) => {
  const { rule_id, rule_name } = event.detail;
  
  // Example: Filter alert table
  filterAlertTable({
    rule_id: rule_id,
    hours: 24
  });

  // Show toast notification
  showToast('thong_tin', '📋 Lọc cảnh báo', `Rule #${rule_id}`);
});

// Example filter function
async function filterAlertTable(options) {
  try {
    const response = await fetch(`/api/alerts?rule_id=${options.rule_id}&hours=${options.hours}`);
    const alerts = await response.json();
    // Update UI with filtered alerts
    updateAlertTable(alerts);
  } catch (error) {
    console.error('Error filtering alerts:', error);
    showToast('cao', '⚠️ Lỗi lọc', 'Không thể lọc cảnh báo');
  }
}
*/

// ═══════════════════════════════════════════════════════════════════════════
// 7. REAL-TIME UPDATES VIA WEBSOCKET (OPTIONAL)
// ═══════════════════════════════════════════════════════════════════════════

/*
// In app.js or dedicated ws.js module:

function initWebSocket(chartsArray) {
  const ws = new WebSocket('ws://localhost:8000/ws');
  
  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    
    if (message.type === 'stats_update') {
      // Update timeline chart with new hourly data
      chartsArray.timeline.data = message.data.hourly_alerts;
      chartsArray.timeline.render();
      
      // Update top rules chart
      chartsArray.rules.data = message.data.top_rules;
      chartsArray.rules.render();
    }
    
    if (message.type === 'ai_anomaly') {
      // Show AI alert toast
      showToast('ai', '🤖 AI phát hiện bất thường', 
        `${message.data.ip} — Risk: ${message.data.risk_score}`);
    }
  };
}
*/

// ═══════════════════════════════════════════════════════════════════════════
// 8. STYLING & DARK THEME
// ═══════════════════════════════════════════════════════════════════════════

/*
All charts use consistent dark theme:
  Background   → #0a0f0a (near black)
  Accent       → #00ff88 (HQG green)
  Danger       → #ff4444 (red)
  Warning      → #ffcc00 (yellow)
  Info         → #00ccff (cyan)
  Text         → #ccc (light gray)
  Grid         → #00ff8811 (green with transparency)

Each chart adds its own section with colored borders:
  MITRE  → #00ff8833 (green)
  Timeline → #ff444433 (red)
  Rules  → #ffcc0033 (yellow)
*/

// ═════════════════════════════════════════════════════════════════════════
// 9. PERFORMANCE NOTES
// ═════════════════════════════════════════════════════════════════════════

/*
✓ All charts use vanilla JS (no framework overhead)
✓ MITRE heatmap: ~100 cells max, light DOM overhead
✓ Timeline: SVG-based, scales to any container width
✓ Top rules: ~10 bars max, minimal reflow
✓ All animations use CSS transitions (GPU-accelerated)
✓ Responsive resize uses debounced render (300ms)
✓ API calls cached/debounced with 5-minute refresh

OPTIMIZATION TIPS:
  - Use Service Worker for API response caching
  - Load charts asynchronously after page render
  - Debounce window resize to 300ms+ 
  - Lazy-load chart data on tab/panel visibility
  - Batch API calls: fetch /api/stats (includes stats + rules)
*/

// ═════════════════════════════════════════════════════════════════════════
// 10. TROUBLESHOOTING
// ═════════════════════════════════════════════════════════════════════════

/*
CHART NOT APPEARING:
  □ Check container ID exists in HTML
  □ Verify chart JS file is loaded (check Network tab)
  □ Check browser console for errors
  □ Verify API endpoints return data (check Network tab)

DATA NOT LOADING:
  □ Verify /api/mitre, /api/stats endpoints exist
  □ Check CORS headers if API is on different domain
  □ Verify response format matches expected structure
  □ Check browser console for fetch errors

ANIMATION ISSUES:
  □ Check browser supports CSS animations (all modern browsers do)
  □ Verify CSS was injected (search for 'toast-animations', 'timeline-animations')
  □ Try force-refresh (Ctrl+F5) to clear cache

TOOLTIP NOT SHOWING:
  □ Check z-index: 10000 (should be above other elements)
  □ Verify MouseEnter listener attached (inspect element)
  □ Check mouse coordinates calculation on different screens
*/

// ═════════════════════════════════════════════════════════════════════════
// 11. EXAMPLE: COMPLETE DASHBOARD INITIALIZATION
// ═════════════════════════════════════════════════════════════════════════

/*
// In app.js - complete initialization example

class SOCDashboard {
  constructor() {
    this.charts = {};
    this.refreshInterval = 5 * 60 * 1000; // 5 minutes
  }

  async init() {
    // Initialize all three charts
    this.charts.mitre = new MitreHeatmap('mitre-heatmap-container');
    this.charts.timeline = new Timeline24h('timeline-24h-container');
    this.charts.rules = new TopRules24h('top-rules-24h-container');

    // Fetch initial data
    await this.charts.mitre.fetchData();
    await this.charts.timeline.fetchData();
    await this.charts.rules.fetchData();

    // Setup auto-refresh
    this.setupRefresh();

    // Setup event listeners
    this.setupEventListeners();

    // Setup real-time updates (optional)
    // this.setupWebSocket();

    console.log('✓ SOC Dashboard initialized');
  }

  setupRefresh() {
    setInterval(() => {
      this.charts.mitre.fetchData();
      this.charts.timeline.fetchData();
      this.charts.rules.fetchData();
    }, this.refreshInterval);
  }

  setupEventListeners() {
    window.addEventListener('filter-by-rule', (e) => {
      this.filterAlertsByRule(e.detail.rule_id);
    });
  }

  setupWebSocket() {
    const ws = new WebSocket('ws://localhost:8000/ws');
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'stats_update') {
        this.charts.timeline.data = message.data.hourly_alerts;
        this.charts.timeline.render();
        this.charts.rules.data = message.data.top_rules;
        this.charts.rules.render();
      }
    };
  }

  filterAlertsByRule(ruleId) {
    // Implementation to filter alert table
    console.log(`Filtering by rule: ${ruleId}`);
  }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  const dashboard = new SOCDashboard();
  dashboard.init();
});
*/
