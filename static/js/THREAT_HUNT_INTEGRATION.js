/**
 * ═══════════════════════════════════════════════════════════════════════════
 * THREAT_HUNT_INTEGRATION.JS — Threat Hunting Module Integration Guide
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Complete reference for integrating the ThreatHuntPage module into your
 * SOC dashboard, including API contracts, features, and example code.
 */

// ═══════════════════════════════════════════════════════════════════════════
// 1. HTML STRUCTURE & SETUP
// ═══════════════════════════════════════════════════════════════════════════

/*

  <!DOCTYPE html>
  <html lang="vi">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Threat Hunting — SOC Platform</title>
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

      button, select, input {
        font-family: inherit;
      }

      button {
        cursor: pointer;
      }

      select {
        cursor: pointer;
      }
    </style>
  </head>
  <body>
    <main id="threat-hunt-container"></main>

    <!-- Dependencies (load in order) -->
    <script src="vn_format.js"></script>
    <script src="ai_labels.js"></script>
    <script src="toast.js"></script>
    <script src="threat_hunt_page.js"></script>

    <!-- Initialize -->
    <script>
      document.addEventListener('DOMContentLoaded', async () => {
        const huntPage = new ThreatHuntPage();
        await huntPage.init();
      });
    </script>
  </body>
  </html>

*/

// ═══════════════════════════════════════════════════════════════════════════
// 2. QUICK START (2 LINES)
// ═══════════════════════════════════════════════════════════════════════════

/*

  const huntPage = new ThreatHuntPage();
  await huntPage.init();

*/

// ═══════════════════════════════════════════════════════════════════════════
// 3. API ENDPOINT SPECIFICATION
// ═══════════════════════════════════════════════════════════════════════════

/*

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ GET /api/hunt?q=ssh&hours=24&host=&ip_nguon=&rule_id=&level=&limit=100 │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │ QUERY PARAMETERS:                                                      │
  │ ─────────────────                                                      │
  │ q             (string) — Search keyword (required)                     │
  │               Examples: "ssh", "brute force", "T1110", "auth failed"   │
  │               Searches: rule description, data.srcip, data.protocol    │
  │                                                                         │
  │ hours         (number) — Time range in hours (optional, default 24)   │
  │               Values: 1, 24, 168 (7d), 720 (30d)                      │
  │                                                                         │
  │ host          (string) — Filter by hostname/agent (optional)          │
  │               Example: "HAV-Security", "server-01"                    │
  │                                                                         │
  │ ip_nguon      (string) — Filter by source IP (optional)               │
  │               Example: "192.168.1.45" or "192.168.1.*"                │
  │                                                                         │
  │ rule_id       (string) — Filter by rule ID (optional, comma-separated)│
  │               Example: "5503,5505,5518"                               │
  │                                                                         │
  │ level         (string) — Filter by severity (optional)                │
  │               Values: "1-6", "7-11", "12-14", "15+"                  │
  │                                                                         │
  │ limit         (number) — Max results to return (optional, default 100)│
  │               Values: 50, 100, 500, 1000                             │
  │                                                                         │
  │ ─────────────────────────────────────────────────────────────────────────│
  │                                                                         │
  │ RESPONSE FORMAT:                                                       │
  │ ────────────────                                                       │
  │ {                                                                      │
  │   "total": 3847,          // Total matching alerts                    │
  │   "results": [{           // Array of alerts matching query           │
  │     "timestamp": "2026-03-25T14:30:00Z",                              │
  │     "agent": "HAV-Security",                                          │
  │     "hostname": "server-web-01",                                      │
  │     "rule": {                                                         │
  │       "id": 5503,          // Wazuh rule ID                           │
  │       "description": "SSHD authentication failed",                    │
  │       "level": 5,          // Severity 1-15                           │
  │       "cis": ["4.1.1"],    // CIS controls                            │
  │       "mitre": {                                                      │
  │         "technique_id": "T1110",     // MITRE ATT&CK                  │
  │         "technique": "Brute Force"                                    │
  │       }                                                               │
  │     },                                                                │
  │     "data": {                                                         │
  │       "srcip": "37.111.53.110",      // Source IP                     │
  │       "dst_ip": "10.0.1.45",         // Destination IP               │
  │       "src_port": 45230,             // Source port                   │
  │       "dst_port": 22,                // Destination port (SSH)        │
  │       "protocol": "tcp"              // Network protocol              │
  │     },                                                                │
  │     "geoip": {                                                        │
  │       "country_name": "Russia",      // Country from GeoIP            │
  │       "country_code": "RU",                                           │
  │       "city": "Moscow",                                               │
  │       "latitude": 55.7558,                                            │
  │       "longitude": 37.6173                                            │
  │     }                                                                 │
  │   }, ...],                                                            │
  │                                                                         │
  │   "top_agents": [         // Top agents by alert count                │
  │     { "agent": "HAV-Security", "count": 17785 },                     │
  │     { "agent": "Suricata", "count": 17522 },                         │
  │     { "agent": "whmcs167530", "count": 15721 }                       │
  │   ],                                                                   │
  │                                                                         │
  │   "top_rules": [          // Top rules by alert count                 │
  │     { "id": 5503, "description": "sshd auth failed", "count": 48400 },│
  │     { "id": 80001, "description": "connection reset", "count": 2425 }, │
  │     { "id": 18100, "description": "brute force", "count": 190 }      │
  │   ],                                                                   │
  │                                                                         │
  │   "top_ips": [            // Top source IPs by alert count            │
  │     { "ip": "37.111.53.110", "count": 4916 },                        │
  │     { "ip": "4.236.164.162", "count": 1468 },                        │
  │     { "ip": "91.202.233.33", "count": 1222 }                         │
  │   ]                                                                    │
  │ }                                                                      │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  EXAMPLE REQUESTS:
  ────────────────

  1. Search for SSH attempts in last 24h:
     GET /api/hunt?q=ssh&hours=24&limit=100

  2. Search with IP filtering:
     GET /api/hunt?q=auth&hours=24&ip_nguon=192.168.1.45&limit=500

  3. Search by rule ID and severity:
     GET /api/hunt?q=privilege&hours=168&rule_id=5503,5505&level=12-14

  4. Search with agent filter:
     GET /api/hunt?q=sql%20injection&hours=24&host=web-server-01

*/

// ═══════════════════════════════════════════════════════════════════════════
// 4. FEATURES & INTERACTIONS
// ═══════════════════════════════════════════════════════════════════════════

/*

  SECTION 1: Search Bar
  ─────────────────────
  • Large search input (monospace font) with placeholder "Tìm kiếm: ssh, brute force, T1110..."
  • 🔍 icon on left
  • "Tìm kiếm" button aligned right
  • Focus state: border #00ffff88, box-shadow 0 0 12px #00ffff22
  • Enter key triggers search
  • Clears previous results before new search

  SECTION 2: Filters Bar
  ─────────────────────
  • 6 filter controls in responsive grid (auto-fit minmax 140px):
    1. Thời gian (Time Range): dropdown with 1h / 24h / 7d / 30d
    2. Máy chủ (Host): text input for hostname/agent name
    3. IP nguồn (Source IP): text input for IP address filtering
    4. Rule ID: text input for comma-separated rule IDs
    5. Mức độ (Severity): dropdown with Tất cả / NGHIÊM TRỌNG / CAO / TRUNG BÌNH / THẤP
    6. Kết quả (Limit): dropdown with 50 / 100 / 500 / 1000
  
  • All filters are optional and stackable
  • Filter state stored in this.filters object
  • Updates default values: timeRange=24, limit=100
  • Color: #00ff8833 border (green theme)

  SECTION 3: Quick Search Chips
  ──────────────────────────────
  • 5 pre-defined quick searches (click to populate search bar)
    1. SSH brute force → "ssh" + tip about automated scanners
    2. Authentication failed → "auth" + tip about coordinated attacks
    3. Privilege escalation → "privilege" + tip about lateral movement
    4. File integrity → "file integrity" + tip about file modifications
    5. SQL injection → "sql injection" + tip about web app attacks
  
  • Chip styling: #1a2a1a bg, #ffcc0044 border, hover → #2a4a2a
  • Click chip → fills search bar + shows context tip (4s auto-dismiss)
  • Tips appear bottom-right corner with animation: slideInUp (300ms) → slideOutDown (300ms)
  • Tip color: #ffcc00 (yellow), box-shadow: 0 4px 12px rgba(255,204,0,0.2)

  SECTION 4: Statistics Cards (Appears after search)
  ──────────────────────────────────────────────────
  • 3 cards rendered in responsive grid (auto-fit minmax 300px)
  
  Card 1: TOP AGENTS (🖥)
    • Shows top 5 agents by alert count
    • Horizontal bar chart with label + gradient bar + count
    • Animation: slideInLeft staggered by index (50ms each)
    • Colors: gradient #00ff88→#00ffff
    • Example: "HAV-Security 17.785 / Suricata 17.522 / whmcs167530 15.721"
  
  Card 2: TOP RULES (📋)
    • Shows top 5 rules by alert count
    • Same chart styling as agents
    • Displays rule description (truncated with ellipsis if > max-width)
    • Example: "sshd auth failed 48.400 / connection reset 2.425"
  
  Card 3: TOP IPS (🌐)
    • Shows top 5 source IPs by alert count
    • Monospace font for IPs
    • Example: "37.111.53.110 4.916 / 4.236.164.162 1.468"

  SECTION 5: Results Table
  ────────────────────────
  • Header row:
    - Stats: "X kết quả · Hiển thị Y · Zms" (X = total, Y = displayed, Z = execution time)
    - Export button: "📥 Export CSV" (triggers download with timestamp in filename)
  
  • 9 columns (sticky header):
    1. THỜI GIAN (Timestamp, relative via formatTuongDoi)
    2. AGENT (hostname/agent name, green text)
    3. QUY TẮC PHÁT HIỆN (Rule description, truncated with ellipsis)
    4. MỨC ĐỘ (Severity badge via renderBadgeMucDo)
    5. IP NGUỒN (Source IP, yellow, monospace, click to copy)
    6. IP ĐÍCH (Destination IP, orange, monospace)
    7. MITRE (Technique ID, cyan, click opens https://attack.mitre.org/techniques/[ID])
    8. QUỐC GIA (Country from GeoIP DB)
    9. HÀNH ĐỘNG (Button: "+ Vụ việc" yellow button per row)
  
  • Scrollable: max-height 800px, overflow-y auto
  • Row styling: alternating row colors (idx % 2: transparent / rgba(0,204,255,0.02))
  • Hover: row background → rgba(0,204,255,0.08)
  • Displays: first 100 results from API response
  • Click source IP → copies to clipboard + toast "✅ Sao chép"
  • Click destination IP (optional) → could show reverse DNS
  • Click MITRE → opens in new tab redirect to attack.mitre.org
  • "+ Vụ việc" button → stub (ready to integrate with incident creation)

  SECTION 6: Loading Indicator
  ─────────────────────────────
  • Shows "⏳ Đang tìm kiếm..." while API request pending
  • Removed after results loaded
  • Positioned after search section

  SECTION 7: Context Tips
  ──────────────────────
  • Shows when quick chip clicked (built into showSearchContext method)
  • Example: "💡 Often from automated scanners targeting port 22"
  • Auto-dismiss after 4 seconds
  • Position: fixed bottom-right, z-index 1000
  • Styling: #1a1a2e bg, #ffcc00 border 2px, yellow text

*/

// ═══════════════════════════════════════════════════════════════════════════
// 5. COMPLETE EXAMPLE: Initialize Threat Hunt Page
// ═══════════════════════════════════════════════════════════════════════════

/*

  class SOCDashboard {
    constructor() {
      this.threatHunt = null;
      this.aiEngine = null;
      this.alertsQueue = null;
    }

    async init() {
      // Initialize Threat Hunting Page
      this.threatHunt = new ThreatHuntPage();
      await this.threatHunt.init();

      // Listen for search events
      document.addEventListener('threat-hunt:search-complete', (e) => {
        console.log('Search completed:', e.detail.query, e.detail.resultCount);
      });

      // Optional: Initialize other components
      // this.aiEngine = new AIEnginePage();
      // await this.aiEngine.init();
    }

    onIncidentCreate(alert) {
      console.log('Create incident from alert:', alert);
      // Route to incident creation form with pre-filled data
    }
  }

  // Bootstrap
  document.addEventListener('DOMContentLoaded', async () => {
    const dashboard = new SOCDashboard();
    await dashboard.init();
  });

*/

// ═══════════════════════════════════════════════════════════════════════════
// 6. DEPENDENCIES & IMPORTS
// ═══════════════════════════════════════════════════════════════════════════

/*

  REQUIRED MODULES (in load order):
  ─────────────────────────────────

  1. vn_format.js
     • formatTuongDoi(iso8601_string) → "vừa xong", "5 phút trước", etc.
     • formatBadgeMucDo(rule_level) → HTML <span> with color badge

  2. ai_labels.js
     • renderBadgeMucDo(rule_level) → HTML severity badge
     • Not strictly required but recommended for consistency

  OPTIONAL:
  ─────────
  3. toast.js (for user feedback notifications)
     • showToast(type, title, message) — shows toast notifications
     • Used when: copying IP, exporting CSV, creating incident

*/

// ═══════════════════════════════════════════════════════════════════════════
// 7. SEARCH QUERY EXAMPLES & TIPS
// ═══════════════════════════════════════════════════════════════════════════

/*

  SEARCHING FOR COMMON THREATS:
  ────────────────────────────

  SSH Brute Force:
    Query: "ssh"
    Expected: 5503 (SSHD authentication failed), 5504 (SSHD invalid user)
    Top agents: HAV-Security, whmcs167530
    Quick filter: Hours=24, Level=7-11

  Authentication Attacks:
    Query: "auth"
    Expected: 5503 (Auth failed), 40111 (Multiple auth failures)
    Top IPs: Check against known scanners

  Privilege Escalation:
    Query: "privilege" OR "sudo" OR "sudoers"
    Expected: 5401 (Privilege escalation attempt)
    Priority: HIGH - indicates lateral movement attempts

  File Integrity Monitoring:
    Query: "file integrity" OR "fim"
    Expected: 550 (File added), 551 (File modified), 552 (File deleted)
    Context: Monitor critical files (/etc, /var, /opt)

  Web Application Attacks:
    Query: "sql injection" OR "xss" OR "csrf"
    Expected: 31405 (Web application attack), 31503 (HTTP method)
    Source: Check external IPs (reverse proxy/WAF logs)

  Network Scanning:
    Query: "network scan" OR "port scan" OR "syn"
    Expected: Port scanning alerts from IDS (Suricata)
    Pattern: Single IP → multiple destination ports/hosts

  Data Exfiltration:
    Query: "ftp" OR "sftp" OR "rsync" OR "scp"
    Expected: Multiple file transfers to external IPs
    Check: Destination IPs against whitelist

  Malware:
    Query: "malware" OR "trojan" OR "ransomware"
    Expected: File scanning alerts (YARA rules)
    Action: Quarantine affected files, check execution history

*/

// ═══════════════════════════════════════════════════════════════════════════
// 8. CSV EXPORT FORMAT
// ═══════════════════════════════════════════════════════════════════════════

/*

  FILE NAME FORMAT:
  ────────────────
  threat_hunt_YYYY-MM-DDTHH-MM-SS.csv
  Example: threat_hunt_2026-03-25T14-30-45.csv

  CSV COLUMNS (9 columns):
  ───────────────────────
  1. Thời gian (Timestamp) — ISO format
  2. Agent (Hostname of alert source)
  3. Quy tắc (Rule description)
  4. Mức độ (Severity level 1-15)
  5. IP nguồn (Source IP address)
  6. IP đích (Destination IP address)
  7. MITRE (MITRE ATT&CK technique ID)
  8. Quốc gia (Country name from GeoIP)
  9. Rule ID (Wazuh rule ID for reference)

  EXAMPLE CSV CONTENT:
  ────────────────────
  "Thời gian","Agent","Quy tắc","Mức độ","IP nguồn","IP đích","MITRE","Quốc gia","Rule ID"
  "2026-03-25T14:30:00Z","HAV-Security","SSHD authentication failed","5","37.111.53.110","10.0.1.45","T1110","Russia","5503"
  "2026-03-25T14:29:45Z","Suricata","HTTP GET request","3","4.236.164.162","10.0.1.50","T1566","Ukraine","80001"
  ...

  EXPORT TRIGGER:
  ───────────────
  Click "📥 Export CSV" button → downloads with timestamp
  Shows toast: "✅ Đã xuất · Đã tải: threat_hunt_YYYY-MM-DDTHH-MM-SS.csv"

*/

// ═══════════════════════════════════════════════════════════════════════════
// 9. COLOR THEME REFERENCE
// ═══════════════════════════════════════════════════════════════════════════

/*

  Primary Page Color: #00ccff (Cyan)
  Background: #0a0f0a (Dark)
  Secondary: #ffcc00 (Yellow) for chips & quick actions
  Success: #00ff88 (Green) for agents & filters
  Danger: #ff4444 (Red) for critical alerts
  Warning: #ff8800 (Orange) for moderate alerts

  Specific Uses:
  ──────────────
  Search bar border: #00ffff (cyan)
  Filter labels: #00ff88 (green)
  Quick chip bg: #1a2a1a, border #ffcc0044
  Stat card bars: linear-gradient(#00ff88, #00ffff)
  Agent text: #00ff88 (green)
  Source IP: #ffcc00 (yellow, monospace)
  Dest IP: #ff8800 (orange, monospace)
  MITRE link: #00ffff (cyan)
  Table total text: #00ccff (cyan, monospace)

*/

// ═══════════════════════════════════════════════════════════════════════════
// 10. TROUBLESHOOTING
// ═══════════════════════════════════════════════════════════════════════════

/*

  PROBLEM: Search button doesn't work
  SOLUTION: Check that /api/hunt endpoint exists and returns valid JSON
            Verify browser console for fetch errors
            Ensure query parameter is being sent correctly

  PROBLEM: Statistics cards don't show after search
  SOLUTION: Check that API response includes "top_agents", "top_rules", "top_ips"
            Verify data structure matches expected format
            Check browser DevTools Network tab for API response

  PROBLEM: CSV export shows wrong data
  SOLUTION: Ensure all alert fields exist (timestamp, rule.description, data.src_ip)
            Check for null/undefined values causing empty columns
            Verify CSV escaping for special characters (quotes, commas)

  PROBLEM: Filter changes don't affect search
  SOLUTION: Filters only apply when executeSearch() is called
            Make sure filter change listeners are properly attached
            Check this.filters object for correct key names matching API params

  PROBLEM: Quick chip tips don't appear
  SOLUTION: Check showSearchContext() method and DOM append logic
            Verify toast.js is loaded (or fallback to showSearchContext)
            Check z-index layering (should be 1000)

  PROBLEM: Source IP click to copy doesn't work
  SOLUTION: Ensure navigator.clipboard API is supported (modern browsers)
            Check that showToast() function exists (from toast.js)
            Verify click listener is properly attached to IP cell

  PROBLEM: MITRE link doesn't open
  SOLUTION: Ensure rule.mitre.technique_id exists in API response
            Check URL format: attack.mitre.org/techniques/[ID]
            Verify browser window.open() not blocked by popup blocker

  PROBLEM: Animations don't play
  SOLUTION: Check injectThreatHuntAnimations() called
            Verify CSS in <style id="threat-hunt-animations">
            Ensure modern browser with @keyframes support

  PROBLEM: Table doesn't scroll
  SOLUTION: Check max-height: 800px on table container
            Verify overflow-y: auto is applied
            Check if results are actually returned (empty table won't scroll)

*/

// ═══════════════════════════════════════════════════════════════════════════
// 11. PERFORMANCE & OPTIMIZATION
// ═══════════════════════════════════════════════════════════════════════════

/*

  Virtual Scrolling: NOT currently implemented (table renders first 100 rows)
  
  Optimization Tips:
  ──────────────────
  1. For 10,000+ results, implement virtual scroll in renderResultsTable()
  2. Debounce filter changes (300ms) before triggering new search
  3. Cache popular searches in sessionStorage (ttl: 5 min)
  4. Lazy-load GeoIP data (country_name) only when displayed
  5. Paginate results instead of rendering all (default: page 1 of N)
  6. Pre-compute top_agents/top_rules on backend (cache 1 min)

  API Caching Strategy:
  ──────────────────
  GET /api/hunt?q=ssh&hours=24...
  → Cache key: "hunt:ssh:24:*:*:*:100"
  → TTL: 2 minutes (threat intel changes frequently)
  → Invalidate on: new alert, manual refresh

  Network Impact:
  ───────────────
  • Typical response size: 200KB (100 alerts × 2KB each)
  • Top agents/rules/ips: +50KB per search
  • GeoIP enhancement: +5KB per IP lookup
  • Recommend: streaming response or pagination

*/

// ═══════════════════════════════════════════════════════════════════════════
// 12. INTEGRATION WITH OTHER MODULES
// ═══════════════════════════════════════════════════════════════════════════

/*

  ThreatHuntPage <→ AlertsQueue:
  ──────────────────────────────
  When user clicks "+ Vụ việc" in threat hunt results:
    1. Dispatch custom event with alert data
    2. AlertsQueue component captures event
    3. Opens incident creation form
    4. Example:
       incidentBtn.addEventListener('click', () => {
         document.dispatchEvent(new CustomEvent('create-incident', {
           detail: {
             alert_id: alert.id,
             src_ip: alert.data.src_ip,
             rule_id: alert.rule.id,
             rule_description: alert.rule.description
           }
         }));
       });

  ThreatHuntPage <→ AIEnginePage:
  ──────────────────────────────
  When searching for anomalies:
    1. Use search results to feed AI Engine recommendations
    2. Highlight IPs that match AI anomalies
    3. Show concordance: "This IP was flagged by AI as high-risk"
    4. Example: Filter threat hunt results by top_ips from AI Engine

  ThreatHuntPage <→ Custom Integrations:
  ────────────────────────────────────
  • Dispatch custom events for external handlers
    - 'threat-hunt:search-complete' {query, resultCount, executionTime}
    - 'threat-hunt:export-csv' {filename, count}
    - 'threat-hunt:create-incident' {alert}

*/

// ═══════════════════════════════════════════════════════════════════════════
// 13. KEYBOARD SHORTCUTS (READY TO IMPLEMENT)
// ═══════════════════════════════════════════════════════════════════════════

/*

  Suggested shortcuts (currently not implemented):
  ────────────────────────────────────────────────
  Cmd/Ctrl + K: Focus search input
  Cmd/Ctrl + E: Export CSV (when results visible)
  Esc: Clear search (back to initial state)
  /: Focus search input (Vi-style)
  Shift + ?: Show help/shortcuts modal

  Implementation template:
  ────────────────────
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'k') {
      e.preventDefault();
      document.getElementById('threat-hunt-search').focus();
    }
  });

*/

// ═══════════════════════════════════════════════════════════════════════════
// END OF DOCUMENTATION
// ═══════════════════════════════════════════════════════════════════════════

export { ThreatHuntPage };
