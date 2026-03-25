/**
 * SOC_WEBSOCKET.JS — Quản lý kết nối WebSocket thời gian thực
 * Hỗ trợ: auto-reconnect, offline queue, event system, indicator trạng thái
 * Tích hợp với toast.js, vn_format.js
 */

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

const WS_RECONNECT_DELAYS_SEC = [1, 2, 4, 8, 16, 30];
const WS_OFFLINE_QUEUE_MAX    = 100;
const WS_VISIBLE_ROWS         = 20;

// Phân loại rule.level → severity
function _classifyLevel(level) {
  if (level >= 15) return { key: 'nghiem_trong', label: 'NGHIÊM TRỌNG', color: '#ff2200' };
  if (level >= 12) return { key: 'cao',         label: 'CAO',          color: '#FF8800' };
  if (level >= 7)  return { key: 'trung_binh',  label: 'TRUNG BÌNH',   color: '#FFCC00' };
  if (level >= 4)  return { key: 'thap',        label: 'THẤP',         color: '#00ccff' };
  return             { key: 'thong_tin',   label: 'THÔNG TIN',   color: '#888888' };
}

// ═══════════════════════════════════════════════════════════════════════════
// STYLES
// ═══════════════════════════════════════════════════════════════════════════

function _injectWSStyles() {
  if (document.getElementById('soc-ws-styles')) return;
  const s = document.createElement('style');
  s.id = 'soc-ws-styles';
  s.textContent = `
    .soc-ws-indicator {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      padding: 4px 10px;
      border-radius: 12px;
      background: #0a0f0a;
      border: 1px solid transparent;
      white-space: nowrap;
      user-select: none;
    }
    .soc-ws-indicator.connected {
      color: #00ff88;
      border-color: #00ff8833;
    }
    .soc-ws-indicator.reconnecting {
      color: #FFCC00;
      border-color: #FFCC0033;
    }
    .soc-ws-indicator.disconnected {
      color: #ff4444;
      border-color: #ff444433;
    }
    .soc-ws-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    .connected   .soc-ws-dot { background: #00ff88; animation: wsDotPulse 1.8s ease-in-out infinite; }
    .reconnecting .soc-ws-dot { background: #FFCC00; animation: wsDotBlink 0.7s ease-in-out infinite; }
    .disconnected .soc-ws-dot { background: #ff4444; }
    @keyframes wsDotPulse {
      0%, 100% { box-shadow: 0 0 0 0 #00ff8877; }
      50%       { box-shadow: 0 0 0 5px #00ff8800; }
    }
    @keyframes wsDotBlink {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.3; }
    }
    .soc-ws-rate {
      color: #555;
      font-size: 10px;
      font-weight: 400;
      margin-left: 2px;
    }
    .soc-ws-statusbar {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      height: 24px;
      background: #060e06;
      border-top: 1px solid #1a2a1a;
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 0 14px;
      z-index: 9000;
      font-size: 10px;
      color: #444;
    }
    .ws-statusbar-item {
      display: flex;
      align-items: center;
      gap: 5px;
    }
  `;
  document.head.appendChild(s);
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN CLASS
// ═══════════════════════════════════════════════════════════════════════════

class SOCWebSocket {
  /**
   * @param {string} url — WebSocket URL
   */
  constructor(url = 'ws://localhost:8000/ws') {
    this.url = url;
    this.ws  = null;

    // Event listeners: { type → [cb, ...] }
    this._listeners = {};

    // Reconnect state
    this._reconnectAttempt = 0;
    this._reconnectTimer   = null;
    this._manualClose      = false;

    // Offline queue — stores incoming messages received before handlers are attached
    this._offlineQueue = [];

    // Stats
    this._msgThisSecond = 0;
    this._msgPerSecond  = 0;
    this._msgTotal      = 0;

    // Indicator elements (may be multiple mounts)
    this._indicators = [];

    // Status bar element
    this._statusBar = null;

    _injectWSStyles();
    this._startRateCounter();
    this._connect();
  }

  // ─────────────────────────────────────────────
  // EVENT SYSTEM
  // ─────────────────────────────────────────────

  /**
   * Đăng ký listener cho một loại message
   * @param {string} type - 'new_alert' | 'ai_anomaly' | 'ip_blocked' | 'stats_update' | '*'
   * @param {Function} cb
   */
  on(type, cb) {
    if (!this._listeners[type]) this._listeners[type] = [];
    this._listeners[type].push(cb);
    return this; // chainable
  }

  /**
   * Hủy đăng ký listener
   */
  off(type, cb) {
    if (!this._listeners[type]) return this;
    this._listeners[type] = this._listeners[type].filter(f => f !== cb);
    return this;
  }

  _emit(type, data) {
    (this._listeners[type] || []).forEach(cb => {
      try { cb(data); } catch (e) { console.error('[SOCWebSocket] Listener error:', e); }
    });
    // Wildcard listeners
    (this._listeners['*'] || []).forEach(cb => {
      try { cb(type, data); } catch (e) {}
    });
  }

  // ─────────────────────────────────────────────
  // CONNECTION
  // ─────────────────────────────────────────────

  _connect() {
    try {
      this.ws = new WebSocket(this.url);
    } catch (e) {
      this._scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this._reconnectAttempt = 0;
      this._manualClose = false;
      this._setStatus('connected');
      this._replayQueue();
      this._emit('connected', { url: this.url });
    };

    this.ws.onmessage = (e) => {
      this._msgThisSecond++;
      this._msgTotal++;

      let msg;
      try {
        msg = JSON.parse(e.data);
      } catch (_) {
        return;
      }

      // Buffer in offline queue (cap at max)
      if (this._offlineQueue.length < WS_OFFLINE_QUEUE_MAX) {
        this._offlineQueue.push(msg);
      }

      this._handleMessage(msg);
    };

    this.ws.onclose = (ev) => {
      if (!this._manualClose) {
        this._setStatus('reconnecting');
        this._scheduleReconnect();
      } else {
        this._setStatus('disconnected');
      }
      this._emit('disconnected', { code: ev.code, reason: ev.reason });
    };

    this.ws.onerror = () => {
      // onclose will fire after onerror — no extra action needed
    };
  }

  _scheduleReconnect() {
    clearTimeout(this._reconnectTimer);
    const delaySec = WS_RECONNECT_DELAYS_SEC[
      Math.min(this._reconnectAttempt, WS_RECONNECT_DELAYS_SEC.length - 1)
    ];
    this._reconnectAttempt++;
    this._updateIndicatorText(`KẾT NỐI LẠI... (${delaySec}s)`);
    this._reconnectTimer = setTimeout(() => this._connect(), delaySec * 1000);
  }

  /** Phát lại tất cả message trong offline queue cho listeners */
  _replayQueue() {
    const queue = this._offlineQueue.splice(0);
    queue.forEach(msg => this._handleMessage(msg));
  }

  /** Đóng kết nối thủ công */
  close() {
    this._manualClose = true;
    clearTimeout(this._reconnectTimer);
    if (this.ws) this.ws.close();
    this._setStatus('disconnected');
  }

  /** Gửi message lên server */
  send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(typeof data === 'string' ? data : JSON.stringify(data));
    }
  }

  // ─────────────────────────────────────────────
  // MESSAGE HANDLER
  // ─────────────────────────────────────────────

  _handleMessage(msg) {
    const type = msg.type;
    const data = msg.data || msg;

    switch (type) {
      case 'new_alert':
        this._handleNewAlert(data);
        break;
      case 'ai_anomaly':
        this._handleAIAnomaly(data);
        break;
      case 'ip_blocked':
        this._handleIPBlocked(data);
        break;
      case 'stats_update':
        this._handleStatsUpdate(data);
        break;
    }

    this._emit(type, data);
  }

  _handleNewAlert(data) {
    const level = data?.rule?.level ?? 0;
    const sev = _classifyLevel(level);
    const ruleName = data?.rule?.description || data?.rule?.id || 'Cảnh báo bảo mật';
    const agent    = data?.agent?.name || data?.agent_name || 'unknown';

    const toastTypes = {
      nghiem_trong: 'nghiem_trong',
      cao:          'cao',
      trung_binh:   'cao',
      thap:         'thong_tin',
      thong_tin:    'thong_tin'
    };
    const toastType = toastTypes[sev.key] || 'thong_tin';

    if (typeof showToast === 'function') {
      showToast(toastType, `${sev.label}: ${ruleName}`, `Agent: ${agent} · Mức ${level}`);
    }
  }

  _handleAIAnomaly(data) {
    const score = data?.score ?? data?.ai_score ?? 0;
    const ip    = data?.src_ip || data?.ip || '';
    const pct   = Math.round(score * 100);
    if (typeof showToast === 'function') {
      showToast('ai', '🤖 AI phát hiện bất thường', `IP: ${ip} · Điểm nguy cơ ${pct}%`);
    }
  }

  _handleIPBlocked(data) {
    const ip = data?.ip || data?.src_ip || '';
    if (typeof showToast === 'function') {
      showToast('thanh_cong', 'IP đã bị chặn tự động', ip);
    }
    // Mark any visible IP elements as blocked
    if (typeof markIPAsBlocked === 'function') markIPAsBlocked(ip);
  }

  _handleStatsUpdate(data) {
    // Cập nhật metric cards không cần fetch lại
    // Dispatch custom event cho các components lắng nghe
    window.dispatchEvent(new CustomEvent('soc:stats_update', { detail: data }));

    // Direct DOM update — tìm metric cards theo data-metric attribute
    if (data.anomalies_24h !== undefined) _updateMetricCard('anomalies_24h', data.anomalies_24h);
    if (data.high_severity  !== undefined) _updateMetricCard('high_severity',  data.high_severity);
    if (data.avg_risk_score !== undefined) _updateMetricCard('avg_risk_score', data.avg_risk_score);
    if (data.auto_blocked   !== undefined) _updateMetricCard('auto_blocked',   data.auto_blocked);
    if (data.monitored      !== undefined) _updateMetricCard('monitored',       data.monitored);
    if (data.total_alerts   !== undefined) _updateMetricCard('total_alerts',    data.total_alerts);
  }

  // ─────────────────────────────────────────────
  // INDICATOR
  // ─────────────────────────────────────────────

  /**
   * Gắn indicator vào container
   * @param {string} containerId
   * @returns {HTMLElement} phần tử indicator
   */
  mountIndicator(containerId) {
    const parent = document.getElementById(containerId);
    if (!parent) return null;

    const el = document.createElement('div');
    el.className = 'soc-ws-indicator disconnected';

    const dot = document.createElement('div');
    dot.className = 'soc-ws-dot';

    const text = document.createElement('span');
    text.className = 'soc-ws-text';
    text.textContent = 'MẤT KẾT NỐI';

    const rate = document.createElement('span');
    rate.className = 'soc-ws-rate';

    el.appendChild(dot);
    el.appendChild(text);
    el.appendChild(rate);
    parent.appendChild(el);

    this._indicators.push({ el, text, rate });

    // Set current state
    this._applyStatusToEl(el, text, this._currentStatus || 'disconnected');
    return el;
  }

  /**
   * Tạo status bar dưới cùng màn hình
   */
  mountStatusBar() {
    if (this._statusBar) return this._statusBar;

    const bar = document.createElement('div');
    bar.className = 'soc-ws-statusbar';
    bar.id = 'soc-ws-statusbar';

    const indWrap = document.createElement('div');
    indWrap.className = 'ws-statusbar-item';
    indWrap.id = 'soc-ws-statusbar-ind';

    const sep = document.createElement('div');
    sep.style.cssText = 'width: 1px; height: 14px; background: #1a2a1a;';

    const rateWrap = document.createElement('div');
    rateWrap.className = 'ws-statusbar-item';
    rateWrap.id = 'soc-ws-rate-display';
    rateWrap.style.color = '#555';

    bar.appendChild(indWrap);
    bar.appendChild(sep);
    bar.appendChild(rateWrap);
    document.body.appendChild(bar);

    this._statusBar = bar;
    this.mountIndicator('soc-ws-statusbar-ind');
    this._updateRateDisplay();
    return bar;
  }

  _setStatus(status) {
    this._currentStatus = status;
    const labels = {
      connected:    '● TRỰC TIẾP',
      reconnecting: '● KẾT NỐI LẠI...',
      disconnected: '● MẤT KẾT NỐI'
    };
    const label = labels[status] || '● MẤT KẾT NỐI';
    this._indicators.forEach(({ el, text }) => {
      el.className = `soc-ws-indicator ${status}`;
      text.textContent = label.replace('● ', '');
    });
  }

  _updateIndicatorText(msg) {
    this._indicators.forEach(({ text }) => { text.textContent = msg; });
  }

  _applyStatusToEl(el, text, status) {
    const labels = { connected: 'TRỰC TIẾP', reconnecting: 'KẾT NỐI LẠI...', disconnected: 'MẤT KẾT NỐI' };
    el.className = `soc-ws-indicator ${status}`;
    text.textContent = labels[status] || 'MẤT KẾT NỐI';
  }

  // ─────────────────────────────────────────────
  // STATS
  // ─────────────────────────────────────────────

  _startRateCounter() {
    setInterval(() => {
      this._msgPerSecond  = this._msgThisSecond;
      this._msgThisSecond = 0;
      this._updateRateDisplay();
    }, 1000);
  }

  _updateRateDisplay() {
    const el = document.getElementById('soc-ws-rate-display');
    if (!el) return;
    el.textContent = `${this._msgPerSecond} msg/s · Tổng: ${this._msgTotal.toLocaleString('vi-VN')}`;

    this._indicators.forEach(({ rate }) => {
      if (rate) rate.textContent = ` ${this._msgPerSecond} msg/s`;
    });
  }

  /** Số message/giây hiện tại */
  get messagesPerSecond() { return this._msgPerSecond; }

  /** Tổng số message đã nhận */
  get totalMessages() { return this._msgTotal; }

  /** Trạng thái kết nối */
  get isConnected() {
    return this.ws && this.ws.readyState === WebSocket.OPEN;
  }
}

// ─────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────

function _updateMetricCard(key, value) {
  const el = document.querySelector(`[data-metric="${key}"] .metric-value`);
  if (el) {
    el.textContent = typeof value === 'number'
      ? value.toLocaleString('vi-VN')
      : value;
    // Flash animation
    el.style.transition = 'color 200ms';
    el.style.color = '#00ff88';
    setTimeout(() => { el.style.color = ''; }, 800);
  }
}

// ─────────────────────────────────────────────────────
// EXPORT / SINGLETON
// ─────────────────────────────────────────────────────

let _socWSInstance = null;

/**
 * Lấy singleton SOCWebSocket (khởi tạo nếu chưa có)
 * @param {string} [url]
 * @returns {SOCWebSocket}
 */
function getSOCWebSocket(url = 'ws://localhost:8000/ws') {
  if (!_socWSInstance) _socWSInstance = new SOCWebSocket(url);
  return _socWSInstance;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SOCWebSocket, getSOCWebSocket };
}
