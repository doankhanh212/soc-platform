# HQG AI-SOC — Codex Prompts (VSCode)
> Dán thẳng vào Codex chat hoặc dùng inline comment `// @codex`
> Mỗi prompt = 1 task độc lập, ngắn gọn, có đủ context

---

## ══════════════════════════════════════
## PHẦN 1 — THREAT INTEL (xây từ đầu)
## ══════════════════════════════════════

### TASK 1.1 — Layout + Search IP

```
Create a Threat Intelligence page in threat-intel.html using vanilla HTML/CSS/JS.
Dark theme: bg #0a0f0a, accent #00ff88, font monospace for IPs.
All UI text in Vietnamese.

Layout:
- Header: "Threat Intelligence" title + subtitle "IOC Enrichment · Nguồn đe dọa bên ngoài"
- Search bar full width: placeholder "Nhập IP, domain, hash để tra cứu..."
  with button "🔍 Tra cứu" (green border) + keyboard shortcut Enter
- Below search: 3 tab buttons — "Tra cứu IP" | "Danh sách IOC" | "Feed nguồn"
  active tab: border-bottom 2px solid #00ff88, text white

On search submit call lookupIP(query) which does:
  GET /api/threatintel/lookup?q={query}
  Show loading spinner (CSS animation, no library) while fetching
  On success render result card (see TASK 1.2)
  On error show: "Không tìm thấy thông tin cho: {query}" in #888
```

---

### TASK 1.2 — IP Reputation Result Card

```
In threat-intel.js, create renderIPResult(data) function.
data shape from GET /api/threatintel/lookup?q=37.111.53.110 :
{
  ip: "37.111.53.110",
  abuse_score: 87,          // 0-100
  country: "Myanmar",
  country_code: "MM",
  isp: "AS131333",
  usage_type: "Data Center",
  is_tor: false,
  is_vpn: false,
  categories: ["SSH Brute Force", "Port Scan"],
  last_reported: "2026-03-24T09:10:00Z",
  total_reports: 4916,
  so_canh_bao_wazuh: 13765,
  mo_hinh_ai: ["Hành vi bất thường", "Tăng đột biến"]
}

Render a result card (dark bg #0d1a0d, border #1a3a1a, radius 8px) with:
- Left: large IP text (#00ffcc monospace 20px) + country flag emoji + ISP
- Center: abuse score gauge (SVG semicircle 0-100):
    0-30 = #00ff88 (An toàn)
    31-70 = #FFCC00 (Đáng ngờ)  
    71-100 = #FF4444 (Nguy hiểm)
  Score number 32px bold centered below gauge
- Right: metadata table — Quốc gia | ISP | Loại | Tor | VPN
- Bottom row: category badges (red bg #1a0000 border #ff4444)
  + "Wazuh ghi nhận: X lần" + "AI phát hiện: [badges]"
- Action buttons: "🛡 Chặn IP" | "📋 Tạo vụ việc" | "🔍 Threat Hunt"
  "🛡 Chặn IP" calls POST /api/response {action:"block_ip", ip:data.ip}
```

---

### TASK 1.3 — IOC List Table

```
In threat-intel.js, create renderIOCList() for tab "Danh sách IOC".
Fetch: GET /api/threatintel/iocs?limit=100
Response item:
{
  ioc_id: "IOC-001",
  loai: "ip",           // ip | domain | hash | url
  gia_tri: "37.111.53.110",
  muc_do: "cao",        // cao | trung_binh | thap
  mo_ta: "SSH brute force Myanmar",
  nguon: "AbuseIPDB",
  lan_cuoi: "2026-03-24T09:10:00Z",
  da_kich_hoat: true
}

Render table with columns:
LOẠI (badge: IP=blue, Domain=purple, Hash=amber, URL=gray)
| GIÁ TRỊ (monospace, click to copy)
| MỨC ĐỘ (badge colors: cao=#FF4444, trung_binh=#FFCC00, thap=#00FF88)
| MÔ TẢ | NGUỒN | LẦN CUỐI | TRẠNG THÁI (toggle on/off) | HÀNH ĐỘNG (X xóa)

Add filter row above table:
  dropdown Loại (Tất cả/IP/Domain/Hash/URL)
  dropdown Mức độ (Tất cả/Cao/Trung bình/Thấp)
  button "+ Thêm IOC" → inline form row appears at top of table

All labels Vietnamese. Row hover: bg #111a11.
```

---

### TASK 1.4 — Feed Nguồn (Sources)

```
In threat-intel.js, create renderFeedSources() for tab "Feed nguồn".
Fetch: GET /api/threatintel/feeds

Show 4 source cards in 2x2 grid (each 200px min):
[
  {ten:"AbuseIPDB",     icon:"🛡", mo_ta:"IP reputation database",      trang_thai:"ket_noi", ioc_count:1247, cap_nhat:"5 phút trước"},
  {ten:"Emerging Threats",icon:"⚡",mo_ta:"Suricata rule feed",          trang_thai:"ket_noi", ioc_count:892,  cap_nhat:"1 giờ trước"},
  {ten:"AlienVault OTX", icon:"👽",mo_ta:"Open threat exchange",         trang_thai:"ngat",    ioc_count:0,    cap_nhat:"Chưa kết nối"},
  {ten:"VirusTotal",     icon:"🔬",mo_ta:"File & URL scanner",           trang_thai:"ngat",    ioc_count:0,    cap_nhat:"Chưa kết nối"}
]

Each card: dark bg, border color:
  ket_noi → #00ff88 border + "● KẾT NỐI" green badge
  ngat    → #555 border + "● CHƯA KẾT NỐI" gray badge

Show: icon + name + mo_ta + ioc_count + cap_nhat
Button: "⚙ Cấu hình" (gray) for all cards
        "🔄 Đồng bộ ngay" (green) for connected only
```

---

## ══════════════════════════════════════
## PHẦN 2 — ĐỘNG CƠ AI (bổ sung 4 section)
## ══════════════════════════════════════

### TASK 2.1 — Stepper "AI hoạt động như thế nào"

```
Add a horizontal stepper at top of ai-engine.html (above metric cards).
Vanilla JS/CSS only. Vietnamese text.

6 steps, scrollable on mobile (overflow-x auto):
const steps = [
  {icon:"📥", ten:"Thu thập",       mo_ta:"Wazuh + Suricata",
   giai_thich:"Thu thập log từ toàn bộ máy chủ và thiết bị mạng theo thời gian thực"},
  {icon:"⚙", ten:"Trích xuất",     mo_ta:"IP, port, tần suất",
   giai_thich:"Tách thông tin quan trọng: IP tấn công, cổng, số lần thử, thời gian"},
  {icon:"🧠", ten:"4 Lớp phân tích",mo_ta:"Phát hiện bất thường",
   giai_thich:"4 phương pháp chạy song song: hành vi bất thường, đột biến, leo thang âm thầm, dữ liệu ẩn"},
  {icon:"📊", ten:"Tính điểm",      mo_ta:"Rủi ro 0.0 → 1.0",
   giai_thich:"Tổng hợp kết quả thành 1 điểm rủi ro từ 0 (an toàn) đến 1 (nguy hiểm)"},
  {icon:"💬", ten:"Giải thích",     mo_ta:"Lý do dễ hiểu",
   giai_thich:"Chuyển kết quả kỹ thuật thành ngôn ngữ tự nhiên cho analyst"},
  {icon:"🛡", ten:"Hành động",      mo_ta:"Chặn / Theo dõi",
   giai_thich:"Đề xuất hoặc tự động thực hiện: theo dõi, tạo vụ việc, hoặc chặn IP"}
]

Each step box: 110px wide, 90px tall, bg #0d1a0d, border #1a3a1a, radius 8px
  icon 20px + ten 13px bold white + mo_ta 11px #888
Step 3 is "active": border #00ff88, bg #001a00
Arrow between steps: → color #1a3a1a

On load: animate steps lighting up left→right (opacity 0→1, delay 200ms per step)
Hover: show tooltip below with giai_thich text, bg #0d1a0d border #00ff88

Below stepper: small gray text
"Phân tích hành vi · Cập nhật mới 60 giây · Chu kỳ gần nhất: {timestamp}"
```

---

### TASK 2.2 — 4 Card giám sát (không dùng tên thuật toán)

```
Add 4 monitor cards section in ai-engine.html after metric cards.
Section title: "4 LOẠI GIÁM SÁT ĐANG HOẠT ĐỘNG"
Fetch status from: GET /api/ai/models/status

IMPORTANT RULE: Never show algorithm names (IsolationForest/CUSUM/EWMA/Entropy) in HTML.
Only show behavior descriptions.

const cards = [
  {model:"IsolationForest", label:"Hành vi bất thường",  icon:"🔍",
   mo_ta:"Phát hiện IP hành xử khác biệt hoàn toàn. Như tìm người lạ trong đám đông."},
  {model:"EWMA",            label:"Đột biến lưu lượng",  icon:"⚡",
   mo_ta:"Phát hiện traffic tăng đột ngột. Như báo động khi lưu lượng tăng 500%."},
  {model:"CUSUM",           label:"Leo thang âm thầm",   icon:"📈",
   mo_ta:"Phát hiện tấn công tăng dần theo thời gian để né qua rule thông thường."},
  {model:"Entropy",         label:"Dữ liệu mã hóa / ẩn", icon:"🔐",
   mo_ta:"Phát hiện file bị mã hóa hàng loạt hoặc dữ liệu ẩn trong DNS tunneling."}
]

Each card (grid 4 cols): bg #0d1a0d, border #1a3a1a, radius 8px, padding 16px
  - icon 20px + label 14px bold #fff
  - status badge from API response:
      running + score < threshold → "ĐANG CHẠY" bg #001a00 color #00ff88
      running + score >= threshold → "CẢNH BÁO" bg #1a0a00 color #FFCC00 + pulse animation
      stopped → "TẮT" bg #1a1a1a color #555
  - score number (1 decimal) in large font, color by value:
      <0.3 → #00ff88 | 0.3-0.6 → #FFCC00 | >0.6 → #FF4444
  - mo_ta text 12px #888
  - bar: height 4px, bg #1a3a1a, fill color by score
  - "Phát hiện X bất thường hôm nay" 11px #666

CSS pulse animation for CẢNH BÁO badge:
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }
```

---

### TASK 2.3 — Panel "Tại sao AI đánh dấu IP này"

```
Add explainable AI panel in ai-engine.html — shows for the highest-risk IP.
Fetch: GET /api/ai/anomalies?limit=1&sort=risk_desc
Response: { ip, diem_rui_ro, quoc_gia, asn, mo_hinh_kich_hoat[], ly_do:{} }

Panel layout (2 columns, right side):
Left col — "TẠI SAO AI ĐÁNH DẤU IP NÀY?":
  IP address large (#00ffcc 20px monospace) + country + risk score badge
  Risk level bar: AN TOÀN → THEO DÕI → CHẶN NGAY (color fill by score)
  
  Reason list — call generateReasons(ly_do) to build items:
  Each reason = bullet ● + main text (natural language) + evidence (small gray monospace)

  generateReasons(ly_do) logic:
  if ly_do.unique_dest_ports >= 10:
    main: "Kết nối đến NHIỀU cổng khác nhau — dấu hiệu đang quét tìm lỗ hổng"
    evidence: `Đã kết nối tới ${n} cổng (bình thường < 5)`
  if ly_do.cusum_s >= 5:
    main: "Hành vi leo thang liên tục — tăng dần trong 2 giờ qua"
    evidence: `Chỉ số tích lũy: ${n.toFixed(1)} (ngưỡng ≥ 5.0)`
  if ly_do.if_percentile >= 90:
    main: `Nằm trong top ${100 - pct}% IP có hành vi khác biệt nhất`
    evidence: `Điểm bất thường: ${score} · percentile ${pct}`
  if ly_do.so_canh_bao_1h >= 1000:
    main: `Tấn công cường độ cao — ${n.toLocaleString('vi-VN')} lần trong 1 giờ`
    evidence: `Tổng: ${tong.toLocaleString('vi-VN')} lần`

Right col — "AI ĐANG THEO DÕI TỪ IP NÀY":
  4 mini stat boxes: Tổng cảnh báo | Cổng khác nhau | Leo thang quyền | File bị sửa
  values from ly_do object, bg #111a11, border #1a3a1a

Bottom — 3 action buttons:
  "🔍 Threat Hunt IP này" (green border)
  "📋 Tạo vụ việc" (amber border)  
  "🛡 Chặn thủ công" (red border) → confirmBlockIP(ip)
```

---

### TASK 2.4 — Widget "AI đang theo dõi gì"

```
Add small widget "AI ĐANG THEO DÕI" in ai-engine.html sidebar or below cards.
Static data (no fetch needed — always show these 4 categories):

const monitoring = [
  {icon:"🔑", label:"Đăng nhập bất thường", mo_ta:"SSH brute force, đăng nhập thất bại nhiều lần",
   active:true,  count:99718},
  {icon:"🌐", label:"Lưu lượng mạng",       mo_ta:"Port scan, kết nối đến nhiều cổng lạ",
   active:true,  count:48386},
  {icon:"📁", label:"Thay đổi file",         mo_ta:"File bị sửa, xóa hoặc mã hóa hàng loạt",
   active:false, count:0},
  {icon:"⚙",  label:"Hành vi tiến trình",   mo_ta:"Tiến trình lạ, leo thang đặc quyền",
   active:false, count:5}
]

Widget box: bg #0d1a0d, border #1a3a1a, radius 8px, padding 16px, width 280px

Header: green dot (pulse if any active) + "AI ĐANG THEO DÕI" 11px uppercase #00ff88

Each item row:
  icon 16px | label 13px | count formatted (vi-VN) + " sự kiện" 11px #666
  right side: "ĐANG THEO DÕI" 10px #00ff88 (if active) OR "Yên tĩnh" #555 (if not)
  inactive items: opacity 0.4
  hover: show tooltip with mo_ta text

Pulse animation for green header dot when active:
  @keyframes dot-pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.6;transform:scale(1.3)} }
```

---

## ══════════════════════════════════════
## PHẦN 3 — SOAR PLAYBOOK (bổ sung)
## ══════════════════════════════════════

### TASK 3.1 — Log panel khi chạy playbook

```
Add execution log panel to soar-playbook.html.
Panel slides up from bottom when playbook starts running.
Vanilla JS/CSS only. Vietnamese text.

HTML structure (add inside main layout):
<div id="run-log-panel" class="log-panel hidden">
  <div class="log-header">
    <span>📋 Nhật ký thực thi</span>
    <span id="log-status">Đang chạy...</span>
    <button onclick="downloadLog()">📥 Tải log</button>
    <button onclick="closeLogPanel()">✕</button>
  </div>
  <div id="log-body"></div>
  <div id="log-footer"></div>
</div>

CSS:
  .log-panel: position fixed, bottom 0, left 200px (sidebar width), right 0
    height 220px, bg #050f05, border-top 2px solid #00ff88
    transform translateY(100%) when hidden
    transition transform 0.3s ease
  .log-panel.visible: transform translateY(0)
  .log-header: display flex, align-items center, gap 12px, padding 8px 16px
    border-bottom 1px solid #1a3a1a, font-size 13px
  #log-body: flex 1, overflow-y auto, padding 8px 16px, font-family monospace, font-size 12px
  log line colors: ⏳=waiting #FFCC00 | ✅=success #00ff88 | ❌=error #FF4444 | ℹ️=info #888

JS functions:
openLogPanel(): remove 'hidden', add 'visible', clear #log-body
addLogLine(icon, nodeName, message):
  append line: "[HH:mm:ss] {icon} {nodeName}: {message}"
  auto-scroll to bottom
closeLogPanel(): add 'hidden', remove 'visible'
downloadLog(): create Blob from log text, trigger download as "playbook-log-{timestamp}.txt"
finishLog(success, total, elapsed):
  append separator line "═".repeat(50)
  append: "HOÀN THÀNH: {success}/{total} node thành công · Thời gian: {elapsed}s"
  update #log-status to "Hoàn thành ✓" (#00ff88) or "Có lỗi ✗" (#FF4444)

Integrate with existing runPlaybook() function:
  call openLogPanel() before loop
  call addLogLine() at each step (waiting→running→success/error)
  call finishLog() after loop ends
```

---

### TASK 3.2 — Playbook mẫu 2: Nmap Scan

```
Add template to PLAYBOOK_TEMPLATES array in soar-playbook.js.
This is template #2 — Nmap/port scan response.

{
  id: "nmap_scan",
  ten: "🔍 Phản ứng Quét Nmap Suricata",
  mo_ta: "Xử lý khi Suricata phát hiện Nmap SYN Scan (rule 86601)",
  nodes: [
    {
      id:"n1", type:"trigger",
      ten:"Phát hiện Nmap Scan",
      dau_vao:"Suricata alert — data.alert.signature_id = 1000001",
      hanh_dong:"Kích hoạt khi Suricata ghi nhận SOC LAB Nmap SYN Scan",
      dau_ra:"data.src_ip, data.dest_port, flow.pkts_toserver",
      vi_tri:{x:80, y:180}
    },
    {
      id:"n2", type:"action",
      ten:"Tương quan cảnh báo",
      dau_vao:"src_ip, khung thời gian ±30 phút",
      hanh_dong:"Query /api/hunt?q={src_ip}&hours=1 — đếm số port đã quét",
      dau_ra:"ports_scanned, so_canh_bao_lien_quan",
      vi_tri:{x:440, y:180}
    },
    {
      id:"n3", type:"action",
      ten:"Tạo vụ việc điều tra",
      dau_vao:"ports_scanned, so_canh_bao_lien_quan",
      hanh_dong:"POST /api/incidents {title:'Nmap Scan từ {src_ip}', severity:'medium'}",
      dau_ra:"incident_id, trang_thai",
      vi_tri:{x:800, y:180}
    }
  ],
  connections:[{from:"n1",to:"n2"},{from:"n2",to:"n3"}]
}
```

---

### TASK 3.3 — Playbook mẫu 3: AI Anomaly

```
Add template to PLAYBOOK_TEMPLATES array in soar-playbook.js.
This is template #3 — AI anomaly auto-response (branching logic).

{
  id: "ai_anomaly",
  ten: "🤖 Phản ứng AI Bất thường",
  mo_ta: "Tự động phản ứng khi AI Engine phát hiện điểm rủi ro >= 0.5",
  nodes: [
    {
      id:"n1", type:"trigger",
      ten:"AI: Bất thường phát hiện",
      dau_vao:"WebSocket event type=ai_anomaly",
      hanh_dong:"Kích hoạt khi diem_rui_ro >= 0.5 (Hành vi bất thường + Tăng đột biến)",
      dau_ra:"ip, diem_rui_ro, so_canh_bao_1h",
      vi_tri:{x:80, y:200}
    },
    {
      id:"n2", type:"condition",
      ten:"Đánh giá mức rủi ro",
      dau_vao:"diem_rui_ro, so_canh_bao_1h",
      hanh_dong:"IF diem_rui_ro > 0.7 THEN chặn ngay\nELSE tạo vụ việc",
      dau_ra:"quyet_dinh: chan_ngay | tao_vu_viec",
      vi_tri:{x:460, y:200}
    },
    {
      id:"n3", type:"action",
      ten:"Chặn IP tự động",
      dau_vao:"quyet_dinh = chan_ngay",
      hanh_dong:"POST /api/response {action:'block_ip', ip, reason:'AI score > 0.7'}",
      dau_ra:"block_status, iptables_rule_id",
      vi_tri:{x:840, y:100}
    },
    {
      id:"n4", type:"action",
      ten:"Tạo vụ việc điều tra",
      dau_vao:"quyet_dinh = tao_vu_viec",
      hanh_dong:"POST /api/incidents {title:'AI: Bất thường IP {ip}', severity:'high'}",
      dau_ra:"incident_id",
      vi_tri:{x:840, y:320}
    }
  ],
  connections:[
    {from:"n1",to:"n2"},
    {from:"n2",to:"n3"},
    {from:"n2",to:"n4"}
  ]
}

Note: node n2 connects to BOTH n3 and n4 (branching).
Make sure createConnection() handles one source → multiple targets.
```

---

## ══════ THỨ TỰ THỰC HIỆN ══════

```
Threat Intel:   1.1 → 1.2 → 1.3 → 1.4
Động cơ AI:     2.1 → 2.2 → 2.3 → 2.4
SOAR Playbook:  3.1 → 3.2 → 3.3
```

## ══════ FILE CẦN MỞ TRONG VSCODE ══════

```
Threat Intel    → threat-intel.html + threat-intel.js
Động cơ AI      → ai-engine.html + ai-engine.js
SOAR Playbook   → soar-playbook.html + soar-playbook.js

Dùng chung      → vn_format.js (formatSoLan, formatThoiGian)
                  ai_labels.js  (renderModelBadges, renderActionSuggestion)
                  toast.js      (showToast)
```
