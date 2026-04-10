/**
 * BLOCK_IP.JS — Chức năng chặn IP tường lửa
 * confirmBlockIP(ip, context): modal xác nhận → POST /api/response → badge + log
 * createBlockIPButton(ip, context): tạo nút "🛡 CHẶN IP"
 * Tích hợp: showToast (toast.js), whitelist, localStorage audit log
 */

// ═══════════════════════════════════════════════════════════════════════════
// WHITELIST — KHÔNG cho phép chặn các IP này
// ═══════════════════════════════════════════════════════════════════════════

const IP_WHITELIST = [
  '127.0.0.1',
  '::1',
  '0.0.0.0',
  '192.168.1.1',
  '192.168.0.1',
  '10.0.0.1',
  '10.0.0.2',
  '172.16.0.1',
  // Thêm IP nội bộ quan trọng ở đây
];

const BLOCK_LOG_KEY    = 'soc_block_ip_log';
const BLOCK_LOG_MAX    = 500;
const BLOCKED_IPS_KEY  = 'soc_blocked_ips';

// ═══════════════════════════════════════════════════════════════════════════
// STYLES
// ═══════════════════════════════════════════════════════════════════════════

function _injectBlockIPStyles() {
  if (document.getElementById('block-ip-styles')) return;
  const s = document.createElement('style');
  s.id = 'block-ip-styles';
  s.textContent = `
    /* ── Confirmation Modal ── */
    .bip-backdrop {
      position: fixed;
      inset: 0;
      background:rgba(0,0,0,.7);
      backdrop-filter: blur(3px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 99990;
      animation: bipFadeIn 150ms ease-out;
    }
    @keyframes bipFadeIn {
      from { opacity: 0; }
      to   { opacity: 1; }
    }
    .bip-modal {
      background:var(--bg1);
      border:2px solid var(--red);
      border-radius: 10px;
      padding: 28px 32px;
      width: 420px;
      max-width: 90vw;
      animation: bipSlideUp 200ms ease-out;
      box-shadow:0 8px 32px rgba(0,0,0,.5),0 0 0 1px var(--red);
    }
    @keyframes bipSlideUp {
      from { opacity: 0; transform: translateY(16px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    .bip-hdr {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 18px;
    }
    .bip-hdr-icon {
      font-size: 22px;
    }
    .bip-hdr-title {
      color:var(--red);
      font-size: 16px;
      font-weight: 700;
    }
    .bip-ip-display {
      display: flex;
      align-items: center;
      justify-content: center;
      background:var(--red2);
      border:1px solid var(--red);
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 18px;
      font-size: 20px;
      font-weight: 700;
      color:var(--red);
      font-family: 'Courier New', monospace;
      letter-spacing: 2px;
    }
    .bip-details {
      display: flex;
      flex-direction: column;
      gap: 8px;
      margin-bottom: 22px;
    }
    .bip-detail-row {
      display: flex;
      gap: 10px;
      font-size: 12px;
      padding: 6px 10px;
      background:var(--bg);
      border-radius: 4px;
    }
    .bip-detail-label {
      color:var(--muted);
      width: 90px;
      flex-shrink: 0;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      padding-top: 1px;
    }
    .bip-detail-value {
      color:var(--muted);
      flex: 1;
      word-break: break-all;
    }
    .bip-reason-input {
      background:var(--bg);
      border:1px solid var(--border);
      border-radius: 4px;
      color:var(--green);
      padding: 6px 10px;
      font-size: 12px;
      width: 100%;
      box-sizing: border-box;
      outline: none;
      transition: border-color 150ms;
      font-family: inherit;
    }
    .bip-reason-input:focus {
      border-color:var(--green)66;
    }
    .bip-warning {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      background:var(--amber2);
      border:1px solid var(--amber);
      border-radius: 4px;
      padding: 10px 12px;
      margin-bottom: 18px;
      font-size: 11px;
      color:var(--amber);
      line-height: 1.5;
    }
    .bip-btns {
      display: flex;
      gap: 10px;
      justify-content: flex-end;
    }
    .bip-btn {
      padding: 9px 18px;
      border-radius: 5px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 150ms;
      letter-spacing: 0.3px;
    }
    .bip-btn-cancel {
      background:var(--bg);
      color:var(--muted);
      border-color:var(--border);
    }
    .bip-btn-cancel:hover {
      background:var(--bg1);
      color:var(--muted);
    }
    .bip-btn-confirm {
      background:var(--red2);
      color:var(--red);
      border-color:var(--red)66;
    }
    .bip-btn-confirm:hover {
      background:var(--red2);
      border-color:var(--red)aa;
      box-shadow:0 0 12px var(--red);
    }
    .bip-btn-confirm:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .bip-btn-confirm .btn-spinner {
      display: inline-block;
      width: 12px;
      height: 12px;
      border:2px solid var(--red);
      border-top-color:var(--red);
      border-radius: 50%;
      animation: bipSpin 0.6s linear infinite;
      vertical-align: middle;
      margin-right: 6px;
    }
    @keyframes bipSpin { to { transform: rotate(360deg); } }

    /* ── Block IP Button ── */
    .btn-block-ip {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      background:var(--red2);
      color:var(--red);
      border:1px solid var(--red);
      border-radius: 4px;
      padding: 4px 9px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
      transition: all 150ms;
    }
    .btn-block-ip:hover {
      background:var(--red2);
      border-color:var(--red)aa;
      box-shadow:0 0 8px var(--red);
    }
    .btn-block-ip:active { transform: scale(0.96); }

    /* ── IP Blocked State ── */
    .ip-blocked-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      background:var(--bg1);
      color:var(--muted);
      border:1px solid var(--border);
      border-radius: 4px;
      padding: 2px 7px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-decoration: line-through;
      text-decoration-color:var(--muted);
    }
    .ip-text.is-blocked {
      color:var(--muted) !important;
      text-decoration: line-through;
      text-decoration-color:var(--muted);
    }

    /* Whitelist warning on hover */
    .ip-whitelisted {
      cursor: help;
      border-bottom:1px dashed var(--muted);
    }
  `;
  document.head.appendChild(s);
}

// ═══════════════════════════════════════════════════════════════════════════
// IN-MEMORY BLOCKED IP SET (synced with localStorage)
// ═══════════════════════════════════════════════════════════════════════════

let _blockedIPSet = new Set(
  (() => { try { return JSON.parse(localStorage.getItem(BLOCKED_IPS_KEY)) || []; } catch { return []; } })()
);

function _persistBlockedSet() {
  try { localStorage.setItem(BLOCKED_IPS_KEY, JSON.stringify([..._blockedIPSet])); } catch (_) {}
}

/** Kiểm tra IP có đang bị chặn không */
function isIPBlocked(ip) {
  return _blockedIPSet.has(ip);
}

/** Kiểm tra IP có trong whitelist không */
function isIPWhitelisted(ip) {
  return IP_WHITELIST.includes(ip);
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN: confirmBlockIP
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Hiển thị modal xác nhận chặn IP, sau đó thực thi nếu người dùng đồng ý.
 *
 * @param {string} ip        — IP cần chặn
 * @param {Object} [context] — {ly_do, agent, rule_id, alert_id, analyst}
 */
function confirmBlockIP(ip, context = {}) {
  if (!ip) return;

  _injectBlockIPStyles();

  // Kiểm tra whitelist trước
  if (isIPWhitelisted(ip)) {
    _notify('cao', `Không thể chặn IP ${ip}`, 'IP nằm trong danh sách trắng hệ thống');
    return;
  }

  // Kiểm tra đã bị chặn chưa
  if (isIPBlocked(ip)) {
    _notify('thong_tin', `IP ${ip} đã bị chặn`, 'Không cần chặn lại');
    return;
  }

  // Xây modal
  const backdrop = document.createElement('div');
  backdrop.className = 'bip-backdrop';

  const modal = document.createElement('div');
  modal.className = 'bip-modal';

  // Header
  const hdr = document.createElement('div');
  hdr.className = 'bip-hdr';
  hdr.innerHTML = `
    <span class="bip-hdr-icon">🛡</span>
    <span class="bip-hdr-title">Xác nhận chặn IP</span>
  `;

  // IP display
  const ipDisp = document.createElement('div');
  ipDisp.className = 'bip-ip-display';
  ipDisp.textContent = ip;

  // Detail rows
  const details = document.createElement('div');
  details.className = 'bip-details';

  const detailRows = [
    { label: 'Lý do',     value: context.ly_do    || 'Thủ công (analyst)' },
    { label: 'Hành động', value: `iptables DROP trên ${context.agent || 'tất cả agents'}` },
    { label: 'Quy tắc',   value: context.rule_id  || '—' },
    { label: 'Analyst',   value: context.analyst   || 'admin' }
  ];

  detailRows.forEach(d => {
    const row = document.createElement('div');
    row.className = 'bip-detail-row';
    row.innerHTML = `
      <span class="bip-detail-label">${d.label}</span>
      <span class="bip-detail-value">${_escapeHtml(String(d.value))}</span>
    `;
    details.appendChild(row);
  });

  // Reason input
  const reasonWrap = document.createElement('div');
  reasonWrap.className = 'bip-detail-row';
  reasonWrap.style.flexDirection = 'column';
  reasonWrap.style.gap = '6px';
  reasonWrap.innerHTML = '<span class="bip-detail-label">Ghi chú thêm</span>';
  const reasonInput = document.createElement('input');
  reasonInput.className = 'bip-reason-input';
  reasonInput.placeholder = 'Lý do bổ sung (không bắt buộc)...';
  reasonInput.value = context.ly_do || '';
  reasonWrap.appendChild(reasonInput);
  details.appendChild(reasonWrap);

  // Warning
  const warning = document.createElement('div');
  warning.className = 'bip-warning';
  warning.innerHTML = `
    <span>⚠️</span>
    <span>Hành động <strong>CHẶN IP</strong> sẽ được ghi nhận và gửi đến tường lửa ngay lập tức. Đảm bảo IP không phải là thiết bị nội bộ hợp lệ trước khi xác nhận.</span>
  `;

  // Buttons
  const btns = document.createElement('div');
  btns.className = 'bip-btns';

  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'bip-btn bip-btn-cancel';
  cancelBtn.textContent = 'HỦY';
  cancelBtn.addEventListener('click', () => backdrop.remove());

  const confirmBtn = document.createElement('button');
  confirmBtn.className = 'bip-btn bip-btn-confirm';
  confirmBtn.innerHTML = '🛡 XÁC NHẬN CHẶN';

  confirmBtn.addEventListener('click', async () => {
    const extraReason = reasonInput.value.trim();
    const finalReason = extraReason || context.ly_do || 'Chặn thủ công';

    // Disable during request
    confirmBtn.disabled = true;
    confirmBtn.innerHTML = '<span class="btn-spinner"></span>Đang xử lý...';
    cancelBtn.disabled = true;

    const success = await _executeBlockIP(ip, {
      ...context,
      ly_do: finalReason
    });

    backdrop.remove();

    if (success) {
      markIPAsBlocked(ip);
      _saveBlockLog(ip, { ...context, ly_do: finalReason });
    }
  });

  btns.appendChild(cancelBtn);
  btns.appendChild(confirmBtn);

  modal.appendChild(hdr);
  modal.appendChild(ipDisp);
  modal.appendChild(details);
  modal.appendChild(warning);
  modal.appendChild(btns);
  backdrop.appendChild(modal);

  // Close on backdrop click
  backdrop.addEventListener('click', e => { if (e.target === backdrop) backdrop.remove(); });

  // Close on Escape
  const onEsc = e => { if (e.key === 'Escape') { backdrop.remove(); document.removeEventListener('keydown', onEsc); } };
  document.addEventListener('keydown', onEsc);

  document.body.appendChild(backdrop);
  setTimeout(() => reasonInput.focus(), 100);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXECUTE BLOCK
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Gọi API chặn IP
 * @returns {Promise<boolean>} true nếu thành công
 */
async function _executeBlockIP(ip, context = {}) {
  try {
    const resp = await fetch(`/api/response/block-ip?ip=${encodeURIComponent(ip)}`, {
      method: 'POST'
    });

    if (!resp.ok) {
      const errText = await resp.text().catch(() => `HTTP ${resp.status}`);
      throw new Error(errText || `HTTP ${resp.status}`);
    }

    _notify('thanh_cong', `🛡 IP ${ip} đã bị chặn thành công`, `Analyst: ${context.analyst || 'admin'}`);
    return true;

  } catch (err) {
    const msg = err.message || 'Lỗi không xác định';
    _notify('cao', `Không thể chặn IP: ${msg}`, ip);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK IP AS BLOCKED IN DOM
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Sau khi chặn thành công, tìm tất cả phần tử hiển thị IP đó trong DOM
 * và áp dụng style "đã chặn" + badge.
 *
 * Cách dùng: thêm attribute `data-ip="1.2.3.4"` hoặc class `ip-text` vào phần tử hiển thị IP.
 *
 * @param {string} ip
 */
function markIPAsBlocked(ip) {
  _blockedIPSet.add(ip);
  _persistBlockedSet();

  // Đánh dấu tất cả phần tử [data-ip]
  document.querySelectorAll(`[data-ip="${ip}"]`).forEach(el => {
    el.classList.add('is-blocked');
    // Thêm badge nếu chưa có
    if (!el.querySelector('.ip-blocked-badge')) {
      const badge = document.createElement('span');
      badge.className = 'ip-blocked-badge';
      badge.innerHTML = '🔒 ĐÃ CHẶN';
      el.style.display = 'inline-flex';
      el.style.alignItems = 'center';
      el.style.gap = '6px';
      el.appendChild(badge);
    }
    // Vô hiệu nút CHẶN IP liên quan
    el.querySelectorAll('.btn-block-ip').forEach(btn => {
      btn.disabled = true;
      btn.style.opacity = '0.4';
      btn.title = 'IP này đã bị chặn';
    });
  });

  // Tìm nút block IP theo data-block-ip
  document.querySelectorAll(`[data-block-ip="${ip}"]`).forEach(btn => {
    btn.disabled = true;
    btn.style.opacity = '0.4';
    btn.innerHTML = '🔒 ĐÃ CHẶN';
    btn.title = 'IP này đã bị chặn';
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT LOG
// ═══════════════════════════════════════════════════════════════════════════

function _saveBlockLog(ip, context = {}) {
  let log = [];
  try { log = JSON.parse(localStorage.getItem(BLOCK_LOG_KEY)) || []; } catch (_) {}

  log.unshift({
    ip,
    thoi_gian: new Date().toISOString(),
    analyst:   context.analyst || 'admin',
    ly_do:     context.ly_do   || 'Không ghi chú',
    agent:     context.agent   || '',
    rule_id:   context.rule_id || ''
  });

  // Giữ tối đa BLOCK_LOG_MAX entries
  if (log.length > BLOCK_LOG_MAX) log = log.slice(0, BLOCK_LOG_MAX);

  try { localStorage.setItem(BLOCK_LOG_KEY, JSON.stringify(log)); } catch (_) {}
}

/**
 * Lấy danh sách log chặn IP từ localStorage
 * @param {number} [limit=50]
 * @returns {Array<{ip, thoi_gian, analyst, ly_do, agent, rule_id}>}
 */
function getBlockLog(limit = 50) {
  try {
    const log = JSON.parse(localStorage.getItem(BLOCK_LOG_KEY)) || [];
    return log.slice(0, limit);
  } catch (_) {
    return [];
  }
}

/**
 * Xóa toàn bộ log chặn IP
 */
function clearBlockLog() {
  localStorage.removeItem(BLOCK_LOG_KEY);
}

// ═══════════════════════════════════════════════════════════════════════════
// BUTTON FACTORY
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Tạo nút "🛡 CHẶN IP" có thể chèn vào bất kỳ đâu.
 * Dùng ở: country table hover, modal alert, bảng AI, Threat Hunting.
 *
 * @param {string}   ip
 * @param {Object}   [context] — {ly_do, agent, rule_id, alert_id, analyst}
 * @param {Object}   [opts]    — {compact: boolean, label: string}
 * @returns {HTMLButtonElement}
 */
function createBlockIPButton(ip, context = {}, opts = {}) {
  _injectBlockIPStyles();

  const btn = document.createElement('button');
  btn.className = 'btn-block-ip';
  btn.dataset.blockIp = ip;
  btn.title = `Chặn IP ${ip}`;

  const label = opts.label || (opts.compact ? '🛡' : '🛡 CHẶN IP');

  // Trạng thái ban đầu
  if (isIPWhitelisted(ip)) {
    btn.disabled = true;
    btn.innerHTML = '🛡 Danh sách trắng';
    btn.style.opacity = '0.4';
    btn.title = 'IP nằm trong danh sách trắng';
  } else if (isIPBlocked(ip)) {
    btn.disabled = true;
    btn.innerHTML = '🔒 ĐÃ CHẶN';
    btn.style.opacity = '0.4';
    btn.title = 'IP này đã bị chặn';
  } else {
    btn.innerHTML = label;
    btn.addEventListener('click', e => {
      e.stopPropagation();
      confirmBlockIP(ip, context);
    });
  }

  return btn;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function _escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function _notify(type, title, subtitle = '') {
  if (typeof showToast === 'function') {
    showToast(type, title, subtitle);
    return;
  }
  // Fallback minimal notification
  const n = document.createElement('div');
  n.style.cssText = `
    position:fixed; bottom:24px; right:24px; z-index:999999;
    background:var(--bg1); border:1px solid var(--border); color:var(--green);
    padding:10px 16px; border-radius:6px; font-size:12px;
    box-shadow:0 4px 16px rgba(0,0,0,.4); max-width:320px;
  `;
  n.textContent = `${title}${subtitle ? ' — ' + subtitle : ''}`;
  document.body.appendChild(n);
  setTimeout(() => n.remove(), 4000);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    confirmBlockIP,
    createBlockIPButton,
    markIPAsBlocked,
    isIPBlocked,
    isIPWhitelisted,
    getBlockLog,
    clearBlockLog,
    IP_WHITELIST
  };
}
