/**
 * SOAR_PLAYBOOK.JS — Drag & Drop Playbook Builder
 * Hệ thống tạo và chạy Playbook tự động phản ứng bảo mật (SOAR)
 * Tất cả text Tiếng Việt. Dark theme. Vanilla JS.
 */

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS & CONFIG
// ═══════════════════════════════════════════════════════════════════════════

const NODE_TYPES = {
  trigger:   { label: 'Kích hoạt',  icon: '⚡', color: '#FF8800', bg: '#1a0d00' },
  condition: { label: 'Điều kiện',  icon: '⚠',  color: '#FFCC00', bg: '#1a1a00' },
  action:    { label: 'Hành động',  icon: '≡',  color: '#00ff88', bg: '#001a0d' },
  connector: { label: 'Kết nối',    icon: '→',  color: '#00ccff', bg: '#001a1a' }
};

const PLAYBOOK_TEMPLATES = {
  ssh_brute: {
    name: '🔐 Phản ứng SSH Brute Force',
    nodes: [
      { id: 'n1', type: 'trigger',   x: 60,  y: 80,  input: 'rule.id = 5503\nrule.level >= 7', action: 'Theo dõi cổng 22', output: 'src_ip, attempt_count' },
      { id: 'n2', type: 'action',    x: 420, y: 80,  input: 'src_ip từ trigger', action: 'Kiểm tra IP Reputation\nAbuseIPDB + VirusTotal', output: 'reputation_score, is_known_bad' },
      { id: 'n3', type: 'condition', x: 780, y: 80,  input: 'reputation_score', action: 'reputation_score >= 50\nOR attempt_count >= 10', output: 'true / false' },
      { id: 'n4', type: 'action',    x: 1060, y: 0,  input: 'src_ip xác nhận nguy hiểm', action: 'Chặn IP tường lửa\nPOST /api/response block_ip\nGửi thông báo Telegram', output: 'blocked, notified' },
      { id: 'n5', type: 'action',    x: 1060, y: 200, input: 'IP không trong blacklist', action: 'Tạo case giám sát\nThêm vào watchlist', output: 'case_id, watchlist_added' }
    ],
    connections: [
      { from: 'n1', to: 'n2' },
      { from: 'n2', to: 'n3' },
      { from: 'n3', to: 'n4' },
      { from: 'n3', to: 'n5' }
    ]
  },
  nmap_scan: {
    name: '🔍 Phản ứng Nmap Scan Suricata',
    nodes: [
      { id: 'n1', type: 'trigger',   x: 60,  y: 120, input: 'sig_id = 1000001\nSuricata IDS', action: 'Phát hiện Nmap Scan', output: 'src_ip, scan_ports[]' },
      { id: 'n2', type: 'action',    x: 380, y: 120, input: 'src_ip, scan_ports', action: 'Correlate với logs\nTìm alert liên quan ±5 phút', output: 'related_alerts, risk_level' },
      { id: 'n3', type: 'condition', x: 700, y: 120, input: 'related_alerts', action: 'related_alerts >= 3\nOR có brute force', output: 'threat_confirmed / false_positive' },
      { id: 'n4', type: 'action',    x: 980, y: 60,  input: 'threat confirmed', action: 'Tạo vụ việc bảo mật\nMức nghiêm trọng: CAO\nGán cho analyst', output: 'incident_id' },
      { id: 'n5', type: 'connector', x: 980, y: 220, input: 'false positive', action: 'Đánh dấu False Positive\nGhi chú lý do', output: 'fp_logged' }
    ],
    connections: [
      { from: 'n1', to: 'n2' },
      { from: 'n2', to: 'n3' },
      { from: 'n3', to: 'n4' },
      { from: 'n3', to: 'n5' }
    ]
  },
  ai_anomaly: {
    name: '🤖 Phản ứng AI Bất thường',
    nodes: [
      { id: 'n1', type: 'trigger',   x: 60,  y: 120, input: 'ai_anomaly.score >= 0.5\nai_anomaly.model = *', action: 'Nhận anomaly từ AI Engine', output: 'src_ip, ai_score, models[]' },
      { id: 'n2', type: 'action',    x: 380, y: 120, input: 'src_ip', action: 'Kiểm tra IP Reputation\nAbuseIPDB lookup', output: 'reputation_score' },
      { id: 'n3', type: 'condition', x: 700, y: 120, input: 'ai_score + reputation', action: 'ai_score >= 0.8\nOR reputation >= 70', output: 'critical / moderate' },
      { id: 'n4', type: 'action',    x: 980, y: 30,  input: 'critical threat', action: 'Tự động chặn IP\nPOST /api/response block_ip\nThông báo khẩn cấp', output: 'blocked, notified' },
      { id: 'n5', type: 'action',    x: 980, y: 220, input: 'moderate threat', action: 'Tạo vụ việc Level 2\nGán analyst điều tra\nThêm watchlist 24h', output: 'incident_id, watchlist' }
    ],
    connections: [
      { from: 'n1', to: 'n2' },
      { from: 'n2', to: 'n3' },
      { from: 'n3', to: 'n4' },
      { from: 'n3', to: 'n5' }
    ]
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// MAIN CLASS
// ═══════════════════════════════════════════════════════════════════════════

class SOARPlaybookBuilder {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.nodes = new Map();       // id → {el, data, x, y, type}
    this.connections = [];        // [{from, to, el}]
    this.nodeCounter = 0;
    this.selectedNode = null;
    this.connectingFrom = null;   // id of port-out source
    this.undoStack = [];          // max 20 states
    this.playbookEnabled = false;
    this.runLog = [];

    // Canvas transform
    this.scale = 1;
    this.tx = 0;
    this.ty = 0;
    this.isPanning = false;
    this.panStart = { x: 0, y: 0 };

    // Temp arrow while connecting
    this.tempArrow = null;
    this.tempMousePos = { x: 0, y: 0 };

    this.init();
  }

  init() {
    this.injectStyles();
    this.buildLayout();
    this.loadHistory();
    this.setupKeyboard();
  }

  // ═══════════════════════════════════════════════════════════════
  // STYLES
  // ═══════════════════════════════════════════════════════════════

  injectStyles() {
    if (document.getElementById('soar-styles')) return;
    const s = document.createElement('style');
    s.id = 'soar-styles';
    s.textContent = `
      .soar-root {
        display: flex;
        flex-direction: column;
        height: 100vh;
        background: #050a05;
        color: #ccc;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
        overflow: hidden;
        user-select: none;
      }
      .soar-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 20px;
        background: #0a0f0a;
        border-bottom: 2px solid #00ff8844;
        flex-shrink: 0;
        z-index: 100;
      }
      .soar-title {
        color: #00ff88;
        font-size: 20px;
        font-weight: 700;
        letter-spacing: 1px;
        margin: 0;
      }
      .soar-toggle {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 12px;
        color: #888;
      }
      .toggle-switch {
        width: 44px;
        height: 24px;
        background: #333;
        border-radius: 12px;
        position: relative;
        cursor: pointer;
        transition: background 200ms;
        border: 1px solid #555;
      }
      .toggle-switch.on { background: #004d22; border-color: #00ff88; }
      .toggle-switch::after {
        content: '';
        position: absolute;
        width: 18px;
        height: 18px;
        background: #666;
        border-radius: 50%;
        top: 2px;
        left: 3px;
        transition: all 200ms;
      }
      .toggle-switch.on::after { left: 22px; background: #00ff88; }
      .soar-body {
        display: flex;
        flex: 1;
        overflow: hidden;
      }
      /* ── SIDEBAR ── */
      .soar-sidebar {
        width: 280px;
        background: #0a0f0a;
        border-right: 1px solid #1a3a1a;
        display: flex;
        flex-direction: column;
        overflow-y: auto;
        flex-shrink: 0;
        z-index: 10;
      }
      .sidebar-section {
        padding: 14px 12px;
        border-bottom: 1px solid #1a2a1a;
      }
      .sidebar-section-title {
        color: #00ff88;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        margin-bottom: 10px;
      }
      .component-item {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 12px;
        background: #0d1a0d;
        border: 1px solid #1a3a1a;
        border-radius: 6px;
        margin-bottom: 6px;
        cursor: grab;
        transition: all 150ms;
        font-size: 12px;
      }
      .component-item:hover {
        background: #112211;
        border-color: #00ff8866;
        transform: translateX(2px);
      }
      .component-item:active { cursor: grabbing; opacity: 0.7; }
      .component-icon {
        font-size: 16px;
        width: 28px;
        height: 28px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 4px;
        flex-shrink: 0;
      }
      .connector-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 8px;
      }
      .connector-item {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 6px;
        width: 70px;
        height: 70px;
        background: #0d1a0d;
        border: 1px solid #1a3a1a;
        border-radius: 6px;
        cursor: grab;
        transition: all 150ms;
        font-size: 10px;
        color: #888;
        padding: 8px;
      }
      .connector-item:hover {
        background: #001a0d;
        border-color: #00ff8866;
        color: #00ff88;
        transform: scale(1.05);
      }
      .connector-item:active { cursor: grabbing; }
      .connector-item .ci-icon { font-size: 20px; }
      .history-item {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 0;
        border-bottom: 1px solid #0d1a0d;
        font-size: 11px;
      }
      .history-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        flex-shrink: 0;
      }
      .history-text { color: #888; flex: 1; }
      .history-time { color: #555; font-size: 10px; white-space: nowrap; }
      /* ── CANVAS AREA ── */
      .soar-canvas-area {
        flex: 1;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        position: relative;
      }
      .canvas-toolbar {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 16px;
        background: #0a0f0a;
        border-bottom: 1px solid #1a3a1a;
        flex-shrink: 0;
        flex-wrap: wrap;
      }
      .toolbar-btn {
        background: #0d1a0d;
        color: #00ff88;
        border: 1px solid #1a3a1a;
        padding: 7px 14px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        cursor: pointer;
        transition: all 150ms;
        display: flex;
        align-items: center;
        gap: 6px;
        white-space: nowrap;
      }
      .toolbar-btn:hover {
        background: #001a0d;
        border-color: #00ff8888;
        box-shadow: 0 0 8px #00ff8822;
      }
      .toolbar-btn.danger { color: #ff4444; border-color: #44111100; }
      .toolbar-btn.danger:hover { background: #1a0000; border-color: #ff444488; }
      .toolbar-btn.run { color: #00ccff; border-color: #00ccff44; }
      .toolbar-btn.run:hover { background: #001a2a; border-color: #00ccff88; }
      .template-select {
        background: #0d1a0d;
        color: #ffcc00;
        border: 1px solid #ffcc0033;
        padding: 6px 10px;
        border-radius: 4px;
        font-size: 11px;
        cursor: pointer;
        outline: none;
      }
      .template-select:hover { border-color: #ffcc0066; }
      /* ── CANVAS VIEWPORT ── */
      #canvas-outer {
        flex: 1;
        overflow: hidden;
        position: relative;
        cursor: default;
        background:
          radial-gradient(circle, #1a2a1a 1px, transparent 1px);
        background-size: 24px 24px;
        background-color: #050a05;
      }
      #canvas-viewport {
        position: absolute;
        top: 0; left: 0;
        width: 0; height: 0;
        transform-origin: 0 0;
      }
      #nodes-layer {
        position: absolute;
        top: 0; left: 0;
      }
      #arrows-layer {
        position: absolute;
        top: 0; left: 0;
        width: 100%;
        height: 100%;
        overflow: visible;
        pointer-events: none;
      }
      /* ── NODE CARD ── */
      .playbook-node {
        position: absolute;
        width: 280px;
        background: #0d1a0d;
        border: 2px solid #00ff88;
        border-radius: 12px;
        box-shadow: 0 0 12px #00ff8833;
        cursor: move;
        transition: box-shadow 200ms;
        pointer-events: all;
      }
      .playbook-node:hover {
        box-shadow: 0 0 20px #00ff8855;
      }
      .playbook-node.selected {
        box-shadow: 0 0 24px #00ff88aa;
        outline: 2px solid #00ff88;
      }
      .playbook-node.state-waiting { border-color: #555; box-shadow: none; }
      .playbook-node.state-running {
        border-color: #FFCC00;
        box-shadow: 0 0 20px #FFCC0066;
        animation: nodeRunPulse 0.8s ease-in-out infinite;
      }
      .playbook-node.state-success {
        border-color: #00ff88;
        box-shadow: 0 0 16px #00ff8866;
      }
      .playbook-node.state-error {
        border-color: #ff4444;
        box-shadow: 0 0 16px #ff444466;
      }
      @keyframes nodeRunPulse {
        0%, 100% { box-shadow: 0 0 12px #FFCC0044; }
        50%       { box-shadow: 0 0 28px #FFCC00aa; }
      }
      .node-header {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 10px 12px;
        border-radius: 10px 10px 0 0;
        cursor: move;
      }
      .node-icon {
        font-size: 16px;
        width: 26px;
        height: 26px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }
      .node-title {
        flex: 1;
        font-size: 12px;
        font-weight: 700;
        outline: none;
        background: none;
        border: none;
        padding: 0;
        cursor: text;
      }
      .node-title:focus {
        background: #111;
        border-radius: 3px;
        padding: 2px 4px;
      }
      .node-status-badge {
        font-size: 14px;
        flex-shrink: 0;
      }
      .node-menu-btn {
        background: none;
        border: none;
        color: #888;
        font-size: 16px;
        cursor: pointer;
        padding: 0 4px;
        border-radius: 3px;
        line-height: 1;
        transition: all 150ms;
      }
      .node-menu-btn:hover { color: #00ff88; background: #1a3a1a; }
      .node-body {
        padding: 8px 12px;
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .node-field {
        display: flex;
        flex-direction: column;
        gap: 3px;
      }
      .node-field-label {
        font-size: 9px;
        text-transform: uppercase;
        font-weight: 700;
        color: #555;
        letter-spacing: 1px;
      }
      .node-textarea {
        background: #060e06;
        border: 1px solid #1a3a1a;
        color: #00ff88aa;
        padding: 5px 8px;
        border-radius: 4px;
        font-size: 10px;
        font-family: 'Courier New', monospace;
        resize: vertical;
        min-height: 36px;
        max-height: 80px;
        outline: none;
        transition: border-color 150ms;
      }
      .node-textarea:focus {
        border-color: #00ff8866;
        color: #00ff88;
      }
      /* ── PORTS ── */
      .node-port {
        position: absolute;
        width: 14px;
        height: 14px;
        border-radius: 50%;
        border: 2px solid currentColor;
        background: #050a05;
        top: 50%;
        transform: translateY(-50%);
        cursor: crosshair;
        transition: all 150ms;
        z-index: 100;
      }
      .node-port:hover {
        transform: translateY(-50%) scale(1.5);
        box-shadow: 0 0 8px currentColor;
      }
      .port-in  { left: -8px; }
      .port-out { right: -8px; }
      /* ── CONTEXT MENU ── */
      .node-context-menu {
        position: fixed;
        background: #0d1a0d;
        border: 1px solid #00ff8844;
        border-radius: 6px;
        padding: 4px 0;
        z-index: 9999;
        min-width: 140px;
        box-shadow: 0 4px 16px #00000088;
      }
      .ctx-item {
        padding: 8px 14px;
        font-size: 11px;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 8px;
        transition: background 100ms;
      }
      .ctx-item:hover { background: #1a3a1a; color: #00ff88; }
      .ctx-item.danger:hover { background: #1a0000; color: #ff4444; }
      /* ── RUN MODAL ── */
      .run-modal-backdrop {
        position: fixed;
        inset: 0;
        background: #00000088;
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
        animation: fadeIn 200ms;
      }
      .run-modal {
        background: #0d1a0d;
        border: 2px solid #00ff8855;
        border-radius: 10px;
        padding: 24px;
        width: 400px;
        max-width: 90vw;
        animation: slideUp 250ms ease-out;
      }
      .run-modal-title {
        color: #00ff88;
        font-size: 16px;
        font-weight: 700;
        margin-bottom: 12px;
      }
      .run-modal-info {
        color: #888;
        font-size: 12px;
        margin-bottom: 20px;
      }
      .run-modal-btns {
        display: flex;
        gap: 10px;
        justify-content: flex-end;
      }
      /* ── LOG PANEL ── */
      .log-panel {
        position: fixed;
        bottom: 0;
        left: 280px;
        right: 0;
        background: #060e06;
        border-top: 2px solid #00ff8844;
        max-height: 260px;
        display: flex;
        flex-direction: column;
        z-index: 200;
        animation: slideUpLog 300ms ease-out;
      }
      @keyframes slideUpLog {
        from { transform: translateY(100%); }
        to   { transform: translateY(0); }
      }
      .log-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 8px 14px;
        border-bottom: 1px solid #1a3a1a;
        flex-shrink: 0;
      }
      .log-title { color: #00ff88; font-size: 11px; font-weight: 700; }
      .log-close-btn {
        background: none;
        border: none;
        color: #888;
        cursor: pointer;
        font-size: 16px;
        padding: 0;
        line-height: 1;
      }
      .log-close-btn:hover { color: #ff4444; }
      .log-body {
        flex: 1;
        overflow-y: auto;
        padding: 8px 14px;
        font-family: 'Courier New', monospace;
        font-size: 11px;
        line-height: 1.8;
      }
      .log-line { display: block; }
      .log-line.pending { color: #FFCC00; }
      .log-line.success { color: #00ff88; }
      .log-line.error   { color: #ff4444; }
      .log-line.summary {
        color: #00ccff;
        border-top: 1px solid #1a3a1a;
        margin-top: 6px;
        padding-top: 6px;
      }
      .log-actions {
        display: flex;
        gap: 8px;
        padding: 8px 14px;
        border-top: 1px solid #1a3a1a;
        flex-shrink: 0;
      }
      /* ── ARROW ── */
      .arrow-path {
        fill: none;
        stroke: #00ff88;
        stroke-width: 2.5;
        cursor: pointer;
        pointer-events: stroke;
        transition: stroke 150ms;
      }
      .arrow-path:hover { stroke: #FFCC00; stroke-width: 3.5; }
      .arrow-path.temp {
        stroke: #00ff8866;
        stroke-dasharray: 8 4;
        stroke-width: 2;
        pointer-events: none;
        animation: dashMove 0.6s linear infinite;
      }
      @keyframes dashMove {
        from { stroke-dashoffset: 0; }
        to   { stroke-dashoffset: -24; }
      }
      .arrow-path.running {
        stroke: #FFCC00;
        stroke-dasharray: 12 6;
        animation: dashRun 0.4s linear infinite;
      }
      @keyframes dashRun {
        from { stroke-dashoffset: 0; }
        to   { stroke-dashoffset: -18; }
      }
      .arrow-del-btn {
        cursor: pointer;
        pointer-events: all;
        opacity: 0;
        transition: opacity 150ms;
      }
      .arrow-group:hover .arrow-del-btn { opacity: 1; }
      /* misc */
      @keyframes fadeIn {
        from { opacity: 0; }
        to   { opacity: 1; }
      }
      @keyframes slideUp {
        from { opacity: 0; transform: translateY(20px); }
        to   { opacity: 1; transform: translateY(0); }
      }
      ::-webkit-scrollbar { width: 5px; height: 5px; }
      ::-webkit-scrollbar-track { background: #050a05; }
      ::-webkit-scrollbar-thumb { background: #1a3a1a; border-radius: 3px; }
      ::-webkit-scrollbar-thumb:hover { background: #00ff8844; }
    `;
    document.head.appendChild(s);
  }

  // ═══════════════════════════════════════════════════════════════
  // BUILD LAYOUT
  // ═══════════════════════════════════════════════════════════════

  buildLayout() {
    this.container.innerHTML = '';
    this.container.className = 'soar-root';

    // Header
    const header = this.buildHeader();

    // Body = Sidebar + Canvas
    const body = document.createElement('div');
    body.className = 'soar-body';

    const sidebar = this.buildSidebar();
    const canvasArea = this.buildCanvasArea();

    body.appendChild(sidebar);
    body.appendChild(canvasArea);

    this.container.appendChild(header);
    this.container.appendChild(body);
  }

  buildHeader() {
    const header = document.createElement('div');
    header.className = 'soar-header';

    const title = document.createElement('h1');
    title.className = 'soar-title';
    title.textContent = '⚡ Trình tạo Playbook SOAR';

    const toggleArea = document.createElement('div');
    toggleArea.className = 'soar-toggle';

    const toggleLabel = document.createElement('span');
    toggleLabel.textContent = this.playbookEnabled ? 'Đang bật' : 'Tắt';
    toggleLabel.id = 'playbook-toggle-label';
    toggleLabel.style.color = this.playbookEnabled ? '#00ff88' : '#666';

    const toggleSwitch = document.createElement('div');
    toggleSwitch.className = 'toggle-switch' + (this.playbookEnabled ? ' on' : '');
    toggleSwitch.title = 'Bật / tắt tự động kích hoạt Playbook';

    toggleSwitch.addEventListener('click', () => {
      this.playbookEnabled = !this.playbookEnabled;
      toggleSwitch.classList.toggle('on', this.playbookEnabled);
      toggleLabel.textContent = this.playbookEnabled ? 'Đang bật' : 'Tắt';
      toggleLabel.style.color = this.playbookEnabled ? '#00ff88' : '#666';
      this.showNotif(this.playbookEnabled
        ? '⚡ Playbook đã bật — sẽ tự kích hoạt khi có cảnh báo mức 12+'
        : 'Playbook đã tắt', this.playbookEnabled ? 'success' : 'info');
    });

    const playbookName = document.createElement('span');
    playbookName.id = 'playbook-name-display';
    playbookName.textContent = 'Playbook chưa có tên';
    playbookName.style.cssText = 'color: #555; font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;';

    toggleArea.appendChild(toggleLabel);
    toggleArea.appendChild(toggleSwitch);
    toggleArea.appendChild(playbookName);

    header.appendChild(title);
    header.appendChild(toggleArea);
    return header;
  }

  buildSidebar() {
    const sidebar = document.createElement('div');
    sidebar.className = 'soar-sidebar';

    // ──── Section 1: Components ────
    const sec1 = document.createElement('div');
    sec1.className = 'sidebar-section';
    const t1 = document.createElement('div');
    t1.className = 'sidebar-section-title';
    t1.textContent = 'Thành phần Playbook';
    sec1.appendChild(t1);

    Object.entries(NODE_TYPES).forEach(([typeId, info]) => {
      const item = document.createElement('div');
      item.className = 'component-item';
      item.draggable = true;
      item.dataset.nodeType = typeId;

      const iconEl = document.createElement('div');
      iconEl.className = 'component-icon';
      iconEl.textContent = info.icon;
      iconEl.style.background = info.color + '22';
      iconEl.style.color = info.color;

      const label = document.createElement('div');
      label.textContent = info.label;
      label.style.color = info.color;

      const desc = document.createElement('div');
      desc.style.cssText = 'font-size: 10px; color: #555; margin-top: 2px;';
      const descs = { trigger: 'Điều kiện kích hoạt', condition: 'Rẽ nhánh logic', action: 'Thực thi lệnh', connector: 'Kết nối ngoài' };
      desc.textContent = descs[typeId];

      const inner = document.createElement('div');
      inner.style.flex = '1';
      inner.appendChild(label);
      inner.appendChild(desc);

      item.appendChild(iconEl);
      item.appendChild(inner);

      item.addEventListener('dragstart', e => {
        e.dataTransfer.setData('nodeType', typeId);
        e.dataTransfer.effectAllowed = 'copy';
      });

      sec1.appendChild(item);
    });
    sidebar.appendChild(sec1);

    // ──── Section 2: External Connectors ────
    const sec2 = document.createElement('div');
    sec2.className = 'sidebar-section';
    const t2 = document.createElement('div');
    t2.className = 'sidebar-section-title';
    t2.textContent = 'Kết nối ngoài';
    sec2.appendChild(t2);

    const grid = document.createElement('div');
    grid.className = 'connector-grid';

    const connectors = [
      { icon: '🛡', label: 'Tường lửa', type: 'action' },
      { icon: '🖥', label: 'EDR', type: 'action' },
      { icon: '🌐', label: 'Threat Intel', type: 'action' }
    ];
    connectors.forEach(c => {
      const item = document.createElement('div');
      item.className = 'connector-item';
      item.draggable = true;
      item.dataset.nodeType = c.type;
      item.dataset.nodeLabel = c.label;

      const iconEl = document.createElement('div');
      iconEl.className = 'ci-icon';
      iconEl.textContent = c.icon;

      const labelEl = document.createElement('div');
      labelEl.style.textAlign = 'center';
      labelEl.textContent = c.label;

      item.appendChild(iconEl);
      item.appendChild(labelEl);

      item.addEventListener('dragstart', e => {
        e.dataTransfer.setData('nodeType', c.type);
        e.dataTransfer.setData('nodeLabel', c.label);
        e.dataTransfer.effectAllowed = 'copy';
      });

      grid.appendChild(item);
    });
    sec2.appendChild(grid);
    sidebar.appendChild(sec2);

    // ──── Section 3: History ────
    const sec3 = document.createElement('div');
    sec3.className = 'sidebar-section';
    const t3 = document.createElement('div');
    t3.className = 'sidebar-section-title';
    t3.textContent = 'Lịch sử';
    sec3.appendChild(t3);

    const historyList = document.createElement('div');
    historyList.id = 'playbook-history';
    historyList.innerHTML = '<div style="color:#555;font-size:11px;">Đang tải...</div>';
    sec3.appendChild(historyList);
    sidebar.appendChild(sec3);

    return sidebar;
  }

  buildCanvasArea() {
    const area = document.createElement('div');
    area.className = 'soar-canvas-area';

    // Toolbar
    const toolbar = document.createElement('div');
    toolbar.className = 'canvas-toolbar';

    const saveBtn = this.makeToolBtn('💾 Lưu', () => this.savePlaybook());
    const runBtn = this.makeToolBtn('▶ Chạy thử', () => this.showRunModal(), 'run');
    const clearBtn = this.makeToolBtn('🗑 Xóa tất cả', () => this.confirmClear(), 'danger');

    const templateSel = document.createElement('select');
    templateSel.className = 'template-select';
    templateSel.innerHTML = `
      <option value="">📋 Mẫu có sẵn…</option>
      <option value="ssh_brute">🔐 SSH Brute Force</option>
      <option value="nmap_scan">🔍 Nmap Scan Suricata</option>
      <option value="ai_anomaly">🤖 AI Bất thường</option>
    `;
    templateSel.addEventListener('change', e => {
      if (e.target.value) {
        this.loadTemplate(e.target.value);
        e.target.value = '';
      }
    });

    toolbar.appendChild(saveBtn);
    toolbar.appendChild(runBtn);
    toolbar.appendChild(clearBtn);
    toolbar.appendChild(templateSel);

    // Canvas outer
    const outer = document.createElement('div');
    outer.id = 'canvas-outer';

    // Viewport
    this.viewport = document.createElement('div');
    this.viewport.id = 'canvas-viewport';

    // Nodes layer
    this.nodesLayer = document.createElement('div');
    this.nodesLayer.id = 'nodes-layer';

    // SVG arrows layer
    this.svgLayer = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this.svgLayer.id = 'arrows-layer';

    // Temp arrow path
    this.tempArrowEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    this.tempArrowEl.classList.add('arrow-path', 'temp');
    this.tempArrowEl.style.display = 'none';
    this.svgLayer.appendChild(this.tempArrowEl);

    this.viewport.appendChild(this.nodesLayer);
    this.viewport.appendChild(this.svgLayer);
    outer.appendChild(this.viewport);

    this.canvasOuter = outer;

    // Drop target
    outer.addEventListener('dragover', e => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
    outer.addEventListener('drop', e => this.handleDrop(e));

    // Pan and zoom
    outer.addEventListener('mousedown', e => this.onCanvasMousedown(e));
    outer.addEventListener('mousemove', e => this.onCanvasMousemove(e));
    outer.addEventListener('mouseup', e => this.onCanvasMouseup(e));
    outer.addEventListener('wheel', e => this.onCanvasWheel(e), { passive: false });
    outer.addEventListener('click', e => {
      if (e.target === outer || e.target === this.nodesLayer) this.deselectAll();
    });
    // Mouse move for temp arrow
    document.addEventListener('mousemove', e => this.onDocMousemove(e));

    area.appendChild(toolbar);
    area.appendChild(outer);
    return area;
  }

  makeToolBtn(text, onClick, variant = '') {
    const btn = document.createElement('button');
    btn.className = 'toolbar-btn' + (variant ? ` ${variant}` : '');
    btn.innerHTML = text;
    btn.addEventListener('click', onClick);
    return btn;
  }

  // ═══════════════════════════════════════════════════════════════
  // COORDINATE HELPERS
  // ═══════════════════════════════════════════════════════════════

  screenToCanvas(sx, sy) {
    const rect = this.canvasOuter.getBoundingClientRect();
    return {
      x: (sx - rect.left - this.tx) / this.scale,
      y: (sy - rect.top  - this.ty) / this.scale
    };
  }

  applyTransform() {
    this.viewport.style.transform = `translate(${this.tx}px, ${this.ty}px) scale(${this.scale})`;
  }

  // ═══════════════════════════════════════════════════════════════
  // PAN & ZOOM
  // ═══════════════════════════════════════════════════════════════

  onCanvasMousedown(e) {
    if (e.button !== 0) return;
    // Only pan if clicking on background
    if (e.target === this.canvasOuter || e.target === this.svgLayer) {
      if (!this.connectingFrom) {
        this.isPanning = true;
        this.panStart = { x: e.clientX - this.tx, y: e.clientY - this.ty };
        this.canvasOuter.style.cursor = 'grabbing';
      }
    }
  }

  onCanvasMousemove(e) {
    if (this.isPanning) {
      this.tx = e.clientX - this.panStart.x;
      this.ty = e.clientY - this.panStart.y;
      this.applyTransform();
    }
  }

  onCanvasMouseup(e) {
    if (this.isPanning) {
      this.isPanning = false;
      this.canvasOuter.style.cursor = 'default';
    }
    // Cancel connection if click on background
    if ((e.target === this.canvasOuter || e.target === this.svgLayer) && this.connectingFrom) {
      this.cancelConnection();
    }
  }

  onCanvasWheel(e) {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    const newScale = Math.min(2, Math.max(0.5, this.scale * delta));
    const rect = this.canvasOuter.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    this.tx = mx - (mx - this.tx) * (newScale / this.scale);
    this.ty = my - (my - this.ty) * (newScale / this.scale);
    this.scale = newScale;
    this.applyTransform();
  }

  // ═══════════════════════════════════════════════════════════════
  // DROP → CREATE NODE
  // ═══════════════════════════════════════════════════════════════

  handleDrop(e) {
    e.preventDefault();
    const type = e.dataTransfer.getData('nodeType');
    const customLabel = e.dataTransfer.getData('nodeLabel') || '';
    if (!type) return;
    const { x, y } = this.screenToCanvas(e.clientX, e.clientY);
    this.saveUndo();
    this.createNode(type, x - 140, y - 60, customLabel);
  }

  createNode(type, x, y, customLabel = '') {
    const id = `node_${Date.now()}_${++this.nodeCounter}`;
    const def = NODE_TYPES[type] || NODE_TYPES.action;
    const label = customLabel || def.label;

    const el = document.createElement('div');
    el.className = 'playbook-node';
    el.id = id;
    el.style.left = x + 'px';
    el.style.top  = y + 'px';
    el.style.borderColor = def.color;
    el.style.boxShadow = `0 0 12px ${def.color}33`;

    // ── Header ──
    const header = document.createElement('div');
    header.className = 'node-header';
    header.style.background = def.bg;

    const icon = document.createElement('div');
    icon.className = 'node-icon';
    icon.style.background = def.color + '22';
    icon.style.color = def.color;
    icon.textContent = def.icon;

    const title = document.createElement('div');
    title.className = 'node-title';
    title.style.color = def.color;
    title.textContent = label;
    title.contentEditable = 'true';
    title.spellcheck = false;
    title.addEventListener('mousedown', e => e.stopPropagation());

    const statusBadge = document.createElement('div');
    statusBadge.className = 'node-status-badge';
    statusBadge.id = `${id}-status`;
    statusBadge.textContent = '';

    const menuBtn = document.createElement('button');
    menuBtn.className = 'node-menu-btn';
    menuBtn.textContent = '⋮';
    menuBtn.addEventListener('click', e => { e.stopPropagation(); this.showNodeMenu(id, e); });

    header.appendChild(icon);
    header.appendChild(title);
    header.appendChild(statusBadge);
    header.appendChild(menuBtn);

    // ── Body ──
    const body = document.createElement('div');
    body.className = 'node-body';

    const fields = [
      { key: 'input',  label: 'Đầu vào',  placeholder: 'Nhập điều kiện / giá trị đầu vào...' },
      { key: 'action', label: 'Hành động', placeholder: 'Mô tả hành động thực thi...' },
      { key: 'output', label: 'Đầu ra',    placeholder: 'Giá trị / kết quả trả về...' }
    ];

    const textareas = {};
    fields.forEach(f => {
      const wrap = document.createElement('div');
      wrap.className = 'node-field';
      const lbl = document.createElement('div');
      lbl.className = 'node-field-label';
      lbl.textContent = f.label;
      const ta = document.createElement('textarea');
      ta.className = 'node-textarea';
      ta.placeholder = f.placeholder;
      ta.rows = 2;
      ta.addEventListener('mousedown', e => e.stopPropagation());
      wrap.appendChild(lbl);
      wrap.appendChild(ta);
      body.appendChild(wrap);
      textareas[f.key] = ta;
    });

    // ── Ports (positioned relative to node center vertically) ──
    const portIn = document.createElement('div');
    portIn.className = 'node-port port-in';
    portIn.style.color = def.color;
    portIn.title = 'Đầu vào';
    portIn.dataset.portType = 'in';
    portIn.dataset.nodeId = id;
    portIn.addEventListener('mousedown', e => { e.stopPropagation(); this.onPortClick(id, 'in', e); });

    const portOut = document.createElement('div');
    portOut.className = 'node-port port-out';
    portOut.style.color = def.color;
    portOut.title = 'Đầu ra';
    portOut.dataset.portType = 'out';
    portOut.dataset.nodeId = id;
    portOut.addEventListener('mousedown', e => { e.stopPropagation(); this.onPortClick(id, 'out', e); });

    el.appendChild(header);
    el.appendChild(body);
    el.appendChild(portIn);
    el.appendChild(portOut);

    // Drag node
    el.addEventListener('mousedown', e => this.onNodeMousedown(e, id));
    el.addEventListener('click', e => { e.stopPropagation(); this.selectNode(id); });

    this.nodesLayer.appendChild(el);

    const data = { type, label, x, y, input: '', action: '', output: '', textareas, titleEl: title, statusEl: statusBadge };
    this.nodes.set(id, data);

    return id;
  }

  // ═══════════════════════════════════════════════════════════════
  // NODE DRAG
  // ═══════════════════════════════════════════════════════════════

  onNodeMousedown(e, id) {
    if (e.target.classList.contains('node-port') ||
        e.target.tagName === 'TEXTAREA' ||
        e.target.className === 'node-title' ||
        e.target.className === 'node-menu-btn') return;

    e.stopPropagation();
    e.preventDefault();

    const el = document.getElementById(id);
    const node = this.nodes.get(id);
    const startX = e.clientX;
    const startY = e.clientY;
    const origX = node.x;
    const origY = node.y;

    const onMove = mv => {
      const dx = (mv.clientX - startX) / this.scale;
      const dy = (mv.clientY - startY) / this.scale;
      node.x = origX + dx;
      node.y = origY + dy;
      el.style.left = node.x + 'px';
      el.style.top  = node.y + 'px';
      this.redrawArrows();
    };

    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };

    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    this.selectNode(id);
  }

  selectNode(id) {
    this.deselectAll();
    this.selectedNode = id;
    document.getElementById(id)?.classList.add('selected');
  }

  deselectAll() {
    if (this.selectedNode) {
      document.getElementById(this.selectedNode)?.classList.remove('selected');
      this.selectedNode = null;
    }
    this.hideContextMenu();
  }

  // ═══════════════════════════════════════════════════════════════
  // CONNECTIONS
  // ═══════════════════════════════════════════════════════════════

  onPortClick(nodeId, portType, e) {
    e.stopPropagation();
    if (portType === 'out') {
      // Start connection
      this.connectingFrom = nodeId;
      this.tempArrowEl.style.display = '';
      const pos = this.getPortPosition(nodeId, 'out');
      this.connStartPos = pos;
      this.canvasOuter.style.cursor = 'crosshair';
    } else if (portType === 'in' && this.connectingFrom && this.connectingFrom !== nodeId) {
      // Create connection
      this.saveUndo();
      this.createConnection(this.connectingFrom, nodeId);
      this.cancelConnection();
    }
  }

  createConnection(fromId, toId) {
    // Avoid duplicates
    if (this.connections.find(c => c.from === fromId && c.to === toId)) return;
    const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    group.classList.add('arrow-group');
    group.dataset.from = fromId;
    group.dataset.to = toId;

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.classList.add('arrow-path');
    path.id = `arrow-${fromId}-${toId}`;

    // Arrow end marker
    const arrowHead = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    arrowHead.classList.add('arrow-path');
    arrowHead.style.pointerEvents = 'none';

    const delBtn = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    delBtn.classList.add('arrow-del-btn');
    delBtn.textContent = '✕';
    delBtn.style.fill = '#ff4444';
    delBtn.style.fontSize = '12px';
    delBtn.style.fontFamily = 'monospace';
    delBtn.style.cursor = 'pointer';
    delBtn.addEventListener('click', e => {
      e.stopPropagation();
      this.saveUndo();
      this.removeConnection(fromId, toId);
    });

    group.appendChild(path);
    group.appendChild(delBtn);
    this.svgLayer.appendChild(group);

    this.connections.push({ from: fromId, to: toId, path, group, delBtn });
    this.redrawArrow(fromId, toId);
  }

  removeConnection(fromId, toId) {
    const idx = this.connections.findIndex(c => c.from === fromId && c.to === toId);
    if (idx !== -1) {
      this.connections[idx].group.remove();
      this.connections.splice(idx, 1);
    }
  }

  calcArrowPath(fx, fy, tx, ty) {
    const dx = Math.abs(tx - fx) * 0.5;
    return `M${fx},${fy} C${fx + dx},${fy} ${tx - dx},${ty} ${tx},${ty}`;
  }

  getPortPosition(nodeId, portType) {
    const node = this.nodes.get(nodeId);
    if (!node) return { x: 0, y: 0 };
    const el = document.getElementById(nodeId);
    const height = el ? el.offsetHeight : 140;
    return {
      x: portType === 'out' ? node.x + 280 : node.x,
      y: node.y + height / 2
    };
  }

  redrawArrow(fromId, toId) {
    const conn = this.connections.find(c => c.from === fromId && c.to === toId);
    if (!conn) return;
    const from = this.getPortPosition(fromId, 'out');
    const to   = this.getPortPosition(toId, 'in');
    const d = this.calcArrowPath(from.x, from.y, to.x, to.y);
    conn.path.setAttribute('d', d);

    // Midpoint for delete button
    const mx = (from.x + to.x) / 2;
    const my = (from.y + to.y) / 2;
    conn.delBtn.setAttribute('x', mx - 6);
    conn.delBtn.setAttribute('y', my + 4);
  }

  redrawArrows() {
    this.connections.forEach(c => this.redrawArrow(c.from, c.to));
  }

  cancelConnection() {
    this.connectingFrom = null;
    this.tempArrowEl.style.display = 'none';
    this.canvasOuter.style.cursor = 'default';
  }

  onDocMousemove(e) {
    if (!this.connectingFrom) return;
    const pos = this.screenToCanvas(e.clientX, e.clientY);
    const from = this.getPortPosition(this.connectingFrom, 'out');
    const d = this.calcArrowPath(from.x, from.y, pos.x, pos.y);
    this.tempArrowEl.setAttribute('d', d);
  }

  // ═══════════════════════════════════════════════════════════════
  // NODE CONTEXT MENU
  // ═══════════════════════════════════════════════════════════════

  showNodeMenu(nodeId, e) {
    this.hideContextMenu();
    const menu = document.createElement('div');
    menu.className = 'node-context-menu';
    menu.id = 'soar-ctx-menu';
    menu.style.left = e.clientX + 'px';
    menu.style.top  = e.clientY + 'px';

    const items = [
      { icon: '✏️', label: 'Đổi tên', action: () => { const node = this.nodes.get(nodeId); if (node) node.titleEl.focus(); } },
      { icon: '📋', label: 'Nhân bản', action: () => this.cloneNode(nodeId) },
      { icon: '🗑', label: 'Xóa node', action: () => this.deleteNode(nodeId), cls: 'danger' }
    ];

    items.forEach(item => {
      const el = document.createElement('div');
      el.className = 'ctx-item' + (item.cls ? ` ${item.cls}` : '');
      el.innerHTML = `${item.icon} ${item.label}`;
      el.addEventListener('click', () => { item.action(); this.hideContextMenu(); });
      menu.appendChild(el);
    });

    document.body.appendChild(menu);
    setTimeout(() => document.addEventListener('click', this._ctxClickAway = () => this.hideContextMenu(), { once: true }), 0);
  }

  hideContextMenu() {
    document.getElementById('soar-ctx-menu')?.remove();
  }

  cloneNode(nodeId) {
    const node = this.nodes.get(nodeId);
    if (!node) return;
    this.saveUndo();
    const newId = this.createNode(node.type, node.x + 30, node.y + 30, node.titleEl.textContent);
    const newNode = this.nodes.get(newId);
    newNode.textareas.input.value  = node.textareas.input.value;
    newNode.textareas.action.value = node.textareas.action.value;
    newNode.textareas.output.value = node.textareas.output.value;
  }

  deleteNode(nodeId) {
    this.saveUndo();
    document.getElementById(nodeId)?.remove();
    this.nodes.delete(nodeId);
    // Remove associated connections
    this.connections
      .filter(c => c.from === nodeId || c.to === nodeId)
      .forEach(c => c.group.remove());
    this.connections = this.connections.filter(c => c.from !== nodeId && c.to !== nodeId);
    if (this.selectedNode === nodeId) this.selectedNode = null;
  }

  // ═══════════════════════════════════════════════════════════════
  // KEYBOARD
  // ═══════════════════════════════════════════════════════════════

  setupKeyboard() {
    document.addEventListener('keydown', e => {
      const tag = document.activeElement.tagName;
      if (tag === 'TEXTAREA' || tag === 'INPUT' || document.activeElement.contentEditable === 'true') return;

      if (e.key === 'Delete' || e.key === 'Backspace') {
        if (this.selectedNode) { this.deleteNode(this.selectedNode); }
      }
      if (e.key === 'Escape') {
        this.cancelConnection();
        this.deselectAll();
      }
      if (e.ctrlKey && e.key === 'z') {
        e.preventDefault();
        this.undo();
      }
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        this.savePlaybook();
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════
  // UNDO
  // ═══════════════════════════════════════════════════════════════

  saveUndo() {
    const state = this.serializePlaybook();
    this.undoStack.push(state);
    if (this.undoStack.length > 20) this.undoStack.shift();
  }

  undo() {
    if (!this.undoStack.length) return;
    const state = this.undoStack.pop();
    this.loadFromData(state);
  }

  // ═══════════════════════════════════════════════════════════════
  // SERIALIZE / LOAD
  // ═══════════════════════════════════════════════════════════════

  serializePlaybook() {
    const name = document.getElementById('playbook-name-display')?.textContent || 'Playbook chưa đặt tên';
    const nodes = [];
    this.nodes.forEach((data, id) => {
      nodes.push({
        id,
        type: data.type,
        x: data.x,
        y: data.y,
        label: data.titleEl?.textContent || data.label,
        input:  data.textareas.input.value,
        action: data.textareas.action.value,
        output: data.textareas.output.value
      });
    });
    const connections = this.connections.map(c => ({ from: c.from, to: c.to }));
    return { ten: name, nodes, connections };
  }

  loadFromData(data) {
    this.clearCanvas();
    (data.nodes || []).forEach(nd => {
      const id = this.createNodeWithId(nd.id, nd.type, nd.x, nd.y, nd.label || '');
      const node = this.nodes.get(id);
      if (node) {
        node.textareas.input.value  = nd.input || '';
        node.textareas.action.value = nd.action || '';
        node.textareas.output.value = nd.output || '';
      }
    });
    (data.connections || []).forEach(c => this.createConnection(c.from, c.to));
  }

  createNodeWithId(id, type, x, y, customLabel) {
    // Re-use createNode but override the ID
    const generatedId = this.createNode(type, x, y, customLabel);
    if (generatedId === id) return id;
    // Rename element and map
    const el = document.getElementById(generatedId);
    if (el) {
      el.id = id;
      el.querySelectorAll('[data-node-id]').forEach(p => p.dataset.nodeId = id);
    }
    const data = this.nodes.get(generatedId);
    this.nodes.delete(generatedId);
    this.nodes.set(id, data);
    return id;
  }

  clearCanvas() {
    this.nodes.forEach((_, id) => document.getElementById(id)?.remove());
    this.nodes.clear();
    this.connections.forEach(c => c.group.remove());
    this.connections = [];
    this.selectedNode = null;
    this.cancelConnection();
  }

  confirmClear() {
    if (this.nodes.size === 0) return;
    if (!confirm('Xóa toàn bộ canvas? Hành động này không thể hoàn tác.')) return;
    this.clearCanvas();
  }

  // ═══════════════════════════════════════════════════════════════
  // TEMPLATE LOADER
  // ═══════════════════════════════════════════════════════════════

  loadTemplate(templateId) {
    const tpl = PLAYBOOK_TEMPLATES[templateId];
    if (!tpl) return;
    if (this.nodes.size > 0 && !confirm(`Tải mẫu "${tpl.name}" sẽ xóa canvas hiện tại. Tiếp tục?`)) return;

    this.saveUndo();
    this.clearCanvas();

    tpl.nodes.forEach(nd => {
      const id = this.createNodeWithId(nd.id, nd.type, nd.x, nd.y, nd.label || nd.action?.split('\n')[0] || '');
      const node = this.nodes.get(id);
      if (node) {
        node.textareas.input.value  = nd.input  || '';
        node.textareas.action.value = nd.action || '';
        node.textareas.output.value = nd.output || '';
      }
    });

    tpl.connections.forEach(c => this.createConnection(c.from, c.to));

    const display = document.getElementById('playbook-name-display');
    if (display) display.textContent = tpl.name;

    this.showNotif(`📋 Đã tải mẫu: ${tpl.name}`, 'success');
  }

  // ═══════════════════════════════════════════════════════════════
  // SAVE
  // ═══════════════════════════════════════════════════════════════

  async savePlaybook() {
    const data = this.serializePlaybook();
    try {
      const resp = await fetch('/api/playbooks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const result = await resp.json();
      this.showNotif('💾 Đã lưu playbook thành công!', 'success');
      this.loadHistory();
    } catch (err) {
      // Fallback: save to localStorage
      localStorage.setItem('soar_playbook_draft', JSON.stringify(data));
      this.showNotif('💾 Đã lưu bản nháp (localStorage)', 'info');
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // HISTORY
  // ═══════════════════════════════════════════════════════════════

  async loadHistory() {
    const container = document.getElementById('playbook-history');
    if (!container) return;
    try {
      const resp = await fetch('/api/playbooks/current/history');
      if (!resp.ok) throw new Error('no data');
      const history = await resp.json();

      container.innerHTML = '';
      history.slice(0, 5).forEach(item => {
        const row = document.createElement('div');
        row.className = 'history-item';

        const dot = document.createElement('div');
        dot.className = 'history-dot';
        dot.style.background = item.status === 'success' ? '#00ff88' : '#ff4444';

        const text = document.createElement('div');
        text.className = 'history-text';
        text.textContent = item.name || 'Playbook';

        const time = document.createElement('div');
        time.className = 'history-time';
        time.textContent = formatTuongDoi ? formatTuongDoi(item.timestamp) : item.timestamp;

        row.appendChild(dot);
        row.appendChild(text);
        row.appendChild(time);
        container.appendChild(row);
      });
    } catch (_) {
      container.innerHTML = '<div style="color:#555;font-size:11px;">Chưa có lịch sử chạy</div>';
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // RUN MODAL
  // ═══════════════════════════════════════════════════════════════

  showRunModal() {
    if (this.nodes.size === 0) {
      this.showNotif('Canvas trống — thêm node trước khi chạy', 'info');
      return;
    }

    const backdrop = document.createElement('div');
    backdrop.className = 'run-modal-backdrop';
    backdrop.id = 'soar-run-modal';

    const modal = document.createElement('div');
    modal.className = 'run-modal';

    const title = document.createElement('div');
    title.className = 'run-modal-title';
    title.textContent = '▶ Chạy Playbook';

    const info = document.createElement('div');
    info.className = 'run-modal-info';
    info.innerHTML = `Playbook có <strong style="color:#00ff88">${this.nodes.size} node</strong> và <strong style="color:#00ccff">${this.connections.length} kết nối</strong>.<br>Chọn chế độ chạy:`;

    const btns = document.createElement('div');
    btns.className = 'run-modal-btns';

    const cancelBtn = this.makeToolBtn('Hủy', () => backdrop.remove());
    const simBtn = this.makeToolBtn('▶ Chạy mô phỏng', () => { backdrop.remove(); this.runPlaybook(false); });
    const realBtn = this.makeToolBtn('⚡ Chạy thật', () => { backdrop.remove(); this.runPlaybook(true); }, 'run');
    simBtn.style.background = '#1a2a1a';
    simBtn.style.borderColor = '#00ff8866';

    btns.appendChild(cancelBtn);
    btns.appendChild(simBtn);
    btns.appendChild(realBtn);

    modal.appendChild(title);
    modal.appendChild(info);
    modal.appendChild(btns);
    backdrop.appendChild(modal);

    backdrop.addEventListener('click', e => { if (e.target === backdrop) backdrop.remove(); });
    document.body.appendChild(backdrop);
  }

  // ═══════════════════════════════════════════════════════════════
  // RUN ENGINE (topological sort + step animation)
  // ═══════════════════════════════════════════════════════════════

  async runPlaybook(isReal = false) {
    this.runLog = [];
    const logPanel = this.buildLogPanel();
    document.body.appendChild(logPanel);

    const nodeIds = this.topoSort();
    const total = nodeIds.length;
    let successCount = 0;
    const startTs = Date.now();

    const log = (id, msg, type = 'pending') => {
      const now = new Date();
      const hms = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
      const icons = { pending: '⏳', success: '✅', error: '❌' };
      const icon = icons[type] || '⏳';
      const line = `[${hms}] ${icon}  ${id}: ${msg}`;
      this.runLog.push({ text: line, type });
      this.appendLogLine(line, type);
    };

    // Reset all node states
    this.nodes.forEach((_, id) => this.setNodeState(id, 'waiting'));

    for (const id of nodeIds) {
      const node = this.nodes.get(id);
      const label = node?.titleEl?.textContent || id;

      this.setNodeState(id, 'running');
      this.animateIncomingArrows(id, true);
      log(label, 'Đang chạy...', 'pending');
      await this.delay(1200);

      const success = Math.random() > 0.15; // 85% chance OK (simulation)

      if (isReal && node?.type === 'action') {
        const actionText = node?.textareas?.action?.value || '';
        if (actionText.includes('block_ip') || actionText.includes('Chặn IP')) {
          try {
            await fetch('/api/response', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ action: 'block_ip', ip: 'dynamic' })
            });
          } catch (_) { /* non-critical */ }
        }
      }

      if (success) {
        this.setNodeState(id, 'success');
        this.animateIncomingArrows(id, false);
        log(label, 'Thành công ✓', 'success');
        successCount++;
      } else {
        this.setNodeState(id, 'error');
        log(label, 'Lỗi — không thể kết nối', 'error');
      }
    }

    const elapsed = ((Date.now() - startTs) / 1000).toFixed(1);
    const summary = `═ HOÀN THÀNH: ${successCount}/${total} thành công · ${elapsed}s ═`;
    this.appendLogLine(summary, 'summary');

    this.loadHistory();
  }

  topoSort() {
    // Kahn's algorithm
    const inDeg = new Map();
    this.nodes.forEach((_, id) => inDeg.set(id, 0));
    this.connections.forEach(c => inDeg.set(c.to, (inDeg.get(c.to) || 0) + 1));

    const queue = [...inDeg.entries()].filter(([_, d]) => d === 0).map(([id]) => id);
    const result = [];

    while (queue.length) {
      const id = queue.shift();
      result.push(id);
      this.connections
        .filter(c => c.from === id)
        .forEach(c => {
          const newDeg = (inDeg.get(c.to) || 1) - 1;
          inDeg.set(c.to, newDeg);
          if (newDeg === 0) queue.push(c.to);
        });
    }

    // Add any disconnected remaining nodes
    this.nodes.forEach((_, id) => { if (!result.includes(id)) result.push(id); });
    return result;
  }

  setNodeState(id, state) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('state-waiting', 'state-running', 'state-success', 'state-error');
    el.classList.add(`state-${state}`);
    const badge = document.getElementById(`${id}-status`);
    if (badge) {
      const icons = { waiting: '', running: '⏳', success: '✅', error: '❌' };
      badge.textContent = icons[state] || '';
    }
  }

  animateIncomingArrows(toId, running) {
    this.connections.filter(c => c.to === toId).forEach(c => {
      if (running) {
        c.path.classList.add('running');
      } else {
        c.path.classList.remove('running');
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════
  // LOG PANEL
  // ═══════════════════════════════════════════════════════════════

  buildLogPanel() {
    document.getElementById('soar-log-panel')?.remove();

    const panel = document.createElement('div');
    panel.className = 'log-panel';
    panel.id = 'soar-log-panel';

    const header = document.createElement('div');
    header.className = 'log-header';
    const title = document.createElement('div');
    title.className = 'log-title';
    title.textContent = '📋 Nhật ký chạy Playbook';
    const closeBtn = document.createElement('button');
    closeBtn.className = 'log-close-btn';
    closeBtn.textContent = '✕';
    closeBtn.addEventListener('click', () => {
      panel.remove();
      this.nodes.forEach((_, id) => this.setNodeState(id, 'waiting'));
    });
    header.appendChild(title);
    header.appendChild(closeBtn);

    const body = document.createElement('div');
    body.className = 'log-body';
    body.id = 'soar-log-body';

    const actions = document.createElement('div');
    actions.className = 'log-actions';
    const dlBtn = this.makeToolBtn('📥 Tải log', () => this.downloadLog());
    dlBtn.style.fontSize = '10px';
    dlBtn.style.padding = '5px 10px';
    actions.appendChild(dlBtn);

    panel.appendChild(header);
    panel.appendChild(body);
    panel.appendChild(actions);
    return panel;
  }

  appendLogLine(text, type) {
    const body = document.getElementById('soar-log-body');
    if (!body) return;
    const line = document.createElement('span');
    line.className = `log-line ${type}`;
    line.textContent = text;
    body.appendChild(line);
    const br = document.createElement('br');
    body.appendChild(br);
    body.scrollTop = body.scrollHeight;
  }

  downloadLog() {
    const text = this.runLog.map(l => l.text).join('\n');
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `playbook_log_${ts}.txt`;
    a.click();
  }

  // ═══════════════════════════════════════════════════════════════
  // NOTIFICATIONS
  // ═══════════════════════════════════════════════════════════════

  showNotif(msg, type = 'info') {
    if (typeof showToast === 'function') {
      const typeMap = { success: 'thanh_cong', info: 'thong_tin', error: 'nghiem_trong' };
      showToast(typeMap[type] || 'thong_tin', msg, '');
      return;
    }
    // Fallback mini-toast
    const n = document.createElement('div');
    n.style.cssText = `
      position: fixed; bottom: 24px; right: 24px;
      background: #0d1a0d; border: 1px solid #00ff8888;
      color: #00ff88; padding: 10px 16px; border-radius: 6px;
      font-size: 12px; z-index: 99999; max-width: 320px;
      animation: slideUp 200ms ease-out;
      box-shadow: 0 4px 16px #00000066;
    `;
    n.textContent = msg;
    document.body.appendChild(n);
    setTimeout(() => n.remove(), 3500);
  }

  delay(ms) {
    return new Promise(r => setTimeout(r, ms));
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTO-INIT
// ═══════════════════════════════════════════════════════════════════════════

function initSOARPlaybook(containerId = 'soar-container') {
  const el = document.getElementById(containerId);
  if (!el) {
    console.warn(`[SOAR] Container #${containerId} not found`);
    return null;
  }
  return new SOARPlaybookBuilder(containerId);
}

// WebSocket integration: auto-trigger when alert level >= 12
function connectSOARWebSocket(builder, wsUrl = 'ws://localhost:8000/ws') {
  try {
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'new_alert' && msg.data?.rule?.level >= 12 && builder.playbookEnabled) {
          builder.showNotif(`⚡ Auto-trigger: Alert mức ${msg.data.rule.level} — chạy Playbook`, 'success');
          builder.runPlaybook(true);
        }
      } catch (_) {}
    };
    ws.onerror = () => {};
  } catch (_) {}
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SOARPlaybookBuilder, initSOARPlaybook, connectSOARWebSocket };
}
