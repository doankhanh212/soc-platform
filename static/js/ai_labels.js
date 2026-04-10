/**
 * AI_LABELS.JS — AI Model Display Labels & Rendering
 * 
 * Maps internal algorithm names to user-facing Vietnamese labels.
 * CRITICAL: Display behavioral descriptions, NOT algorithm names.
 * 
 * Algorithm ↔ User Label Mapping:
 *   IsolationForest → "Hành vi bất thường"
 *   CUSUM          → "Tăng đột biến"
 *   EWMA           → "Đột biến lưu lượng"
 *   Entropy        → "Dữ liệu mã hóa/ẩn"
 *   WazuhRule      → "Quy tắc bảo mật"
 */

function _lbCss(v){ return getComputedStyle(document.documentElement).getPropertyValue(v).trim(); }

const AI_MODEL_LABELS = {
  IsolationForest: {
    nhan: 'Hành vi bất thường',
    icon: '🔍',
    get mau(){ return _lbCss('--green') || '#00ff88'; },
    mo_ta: 'IP này hành xử khác hoàn toàn so với các IP bình thường'
  },
  CUSUM: {
    nhan: 'Tăng đột biến',
    icon: '📈',
    get mau(){ return _lbCss('--medium') || '#FFCC00'; },
    mo_ta: 'Lưu lượng tăng liên tục — xu hướng leo thang âm thầm'
  },
  EWMA: {
    nhan: 'Đột biến lưu lượng',
    icon: '⚡',
    get mau(){ return _lbCss('--amber') || '#FF8800'; },
    mo_ta: 'Traffic tăng đột ngột vượt ngưỡng thống kê'
  },
  Entropy: {
    nhan: 'Dữ liệu mã hóa/ẩn',
    icon: '🔐',
    get mau(){ return _lbCss('--red') || '#FF4444'; },
    mo_ta: 'File mã hóa hàng loạt hoặc DNS tunneling'
  },
  WazuhRule: {
    nhan: 'Quy tắc bảo mật',
    icon: '🛡️',
    get mau(){ return _lbCss('--cyan') || '#00ccff'; },
    mo_ta: 'Quy tắc Wazuh kích hoạt từ log SSH/PAM/Syslog'
  }
};

// ═══════════════════════════════════════════════════════════════
// RENDER FUNCTIONS
// ═══════════════════════════════════════════════════════════════

/**
 * Render array of AI model names as styled badges
 * NEVER displays algorithm names — only behavioral labels
 * 
 * @param {string[]} modelArray - ["IsolationForest", "CUSUM", ...]
 * @returns {string} HTML with badges: "<span class='ai-badge'>🔍 Hành vi bất thường</span>..."
 */
function renderModelBadges(modelArray) {
  if (!Array.isArray(modelArray) || modelArray.length === 0) {
    return '';
  }

  return modelArray
    .map(model => {
      const label = AI_MODEL_LABELS[model];
      if (!label) return '';

      return `<span 
        class="ai-badge" 
        style="
          display: inline-block;
          background-color: rgba(${hexToRgb(label.mau).join(', ')}, 0.15);
          color: ${label.mau};
          padding: 6px 10px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 600;
          margin-right: 6px;
          margin-bottom: 4px;
          border-left: 3px solid ${label.mau};
          font-family: 'Courier New', monospace;
        "
        title="${label.mo_ta}"
      >
        ${label.icon} ${label.nhan}
      </span>`;
    })
    .join('');
}

/**
 * Render action suggestion badge based on risk score
 * 
 * @param {number} score - Risk score (0.0 - 1.0)
 * @returns {string} HTML badge with action recommendation
 *   <0.3  → "👁 Theo dõi"    #00FF88
 *   0.3-0.7→ "⚠️ Kiểm tra"   #FFCC00
 *   0.7+  → "🛡 Chặn IP"     #FF4444
 */
function renderActionSuggestion(score) {
  const _g = _lbCss('--green') || '#00FF88';
  const _m = _lbCss('--medium') || '#FFCC00';
  const _r = _lbCss('--red') || '#FF4444';
  const _bg = _lbCss('--bg1') || '#001a00';

  let action = { icon: '👁️', text: 'Theo dõi', color: _g, bg: _bg };

  if (score >= 0.7) {
    action = { icon: '🛡️', text: 'Chặn IP', color: _r, bg: _bg };
  } else if (score >= 0.3) {
    action = { icon: '⚠️', text: 'Kiểm tra', color: _m, bg: _bg };
  }

  return `<span 
    class="action-suggestion" 
    style="
      display: inline-block;
      background-color: ${action.bg};
      color: ${action.color};
      padding: 6px 12px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: bold;
      border: 1px solid ${action.color};
      cursor: default;
    "
  >
    ${action.icon} ${action.text}
  </span>`;
}

/**
 * Get explanation text for a triggered model
 * @param {string} model - Model name (IsolationForest, CUSUM, etc.)
 * @returns {object} {nhan, mo_ta, icon} or null if not found
 */
function getModelExplanation(model) {
  return AI_MODEL_LABELS[model] || null;
}

/**
 * Convert hex color to RGB array for rgba styling
 * @private
 */
function hexToRgb(hex) {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result ? [
    parseInt(result[1], 16),
    parseInt(result[2], 16),
    parseInt(result[3], 16)
  ] : [0, 255, 136];
}

/**
 * Render inline explanation with model details
 * @param {string} model - Model name
 * @returns {string} HTML with explanation
 */
function renderModelExplanation(model) {
  const label = AI_MODEL_LABELS[model];
  if (!label) return '';

  return `<div style="
    background-color: rgba(${hexToRgb(label.mau).join(', ')}, 0.1);
    border-left: 3px solid ${label.mau};
    padding: 8px 12px;
    border-radius: 4px;
    margin: 8px 0;
    font-size: 13px;
    line-height: 1.5;
  ">
    <strong>${label.icon} ${label.nhan}</strong><br/>
    <span style="color: var(--muted);">${label.mo_ta}</span>
  </div>`;
}

// ═══════════════════════════════════════════════════════════════
// EXPORT (UMD Pattern)
// ═══════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    AI_MODEL_LABELS,
    renderModelBadges,
    renderActionSuggestion,
    getModelExplanation,
    renderModelExplanation
  };
}
