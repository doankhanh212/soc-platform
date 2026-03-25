/**
 * VN_FORMAT.JS — Vietnamese Formatting Utilities for HQG SOC Dashboard
 * 
 * Provides consistent Vietnamese locale formatting for:
 * - Numbers (Vietnamese dot separator)
 * - Timestamps (GMT+7, smart relative display)
 * - Severity levels (color-coded badges)
 * - Time ranges
 */

// ═══════════════════════════════════════════════════════════════
// NUMBER FORMATTING
// ═══════════════════════════════════════════════════════════════

/**
 * Format number with Vietnamese thousands separator (dấu chấm)
 * @param {number} n - Number to format
 * @returns {string} "348.166" instead of "348166"
 */
function formatSoLan(n) {
  if (typeof n !== 'number' || isNaN(n)) return '0';
  return Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, '.');
}

// ═══════════════════════════════════════════════════════════════
// TIMESTAMP FORMATTING (GMT+7)
// ═══════════════════════════════════════════════════════════════

/**
 * Convert ISO 8601 timestamp to formatted Vietnamese datetime
 * Smart display: today shows HH:MM:SS, yesterday shows "Hôm qua HH:MM", older shows full date
 * 
 * @param {string|Date} isoString - ISO 8601 string or Date object
 * @returns {string} "24/03/2026 15:14:28" or "Hôm qua 15:14" or "15:14:28"
 */
function formatThoiGian(isoString) {
  let date = isoString instanceof Date ? isoString : new Date(isoString);
  if (isNaN(date.getTime())) return 'N/A';

  // Convert to GMT+7 (Vietnam timezone)
  const vietDate = new Date(date.getTime() + 7 * 60 * 60 * 1000);
  const now = new Date(new Date().getTime() + 7 * 60 * 60 * 1000);

  // Extract components
  const day = String(vietDate.getUTCDate()).padStart(2, '0');
  const month = String(vietDate.getUTCMonth() + 1).padStart(2, '0');
  const year = vietDate.getUTCFullYear();
  const hours = String(vietDate.getUTCHours()).padStart(2, '0');
  const minutes = String(vietDate.getUTCMinutes()).padStart(2, '0');
  const seconds = String(vietDate.getUTCSeconds()).padStart(2, '0');

  // Check if today or yesterday
  const isToday = 
    vietDate.getUTCDate() === now.getUTCDate() &&
    vietDate.getUTCMonth() === now.getUTCMonth() &&
    vietDate.getUTCFullYear() === now.getUTCFullYear();

  const isYesterday = (() => {
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    return vietDate.getUTCDate() === yesterday.getUTCDate() &&
           vietDate.getUTCMonth() === yesterday.getUTCMonth() &&
           vietDate.getUTCFullYear() === yesterday.getUTCFullYear();
  })();

  if (isToday) {
    return `${hours}:${minutes}:${seconds}`;
  } else if (isYesterday) {
    return `Hôm qua ${hours}:${minutes}`;
  } else {
    return `${day}/${month}/${year} ${hours}:${minutes}:${seconds}`;
  }
}

/**
 * Format relative time difference from now
 * @param {string|Date} isoString - ISO timestamp
 * @returns {string} "vừa xong" | "5 phút trước" | "2 giờ trước" | "3 ngày trước"
 */
function formatTuongDoi(isoString) {
  let date = isoString instanceof Date ? isoString : new Date(isoString);
  if (isNaN(date.getTime())) return 'N/A';

  const now = new Date();
  const diffSeconds = Math.floor((now - date) / 1000);

  if (diffSeconds < 0) return 'trong tương lai';
  if (diffSeconds < 60) return 'vừa xong';
  if (diffSeconds < 3600) {
    const minutes = Math.floor(diffSeconds / 60);
    return `${minutes} phút trước`;
  }
  if (diffSeconds < 86400) {
    const hours = Math.floor(diffSeconds / 3600);
    return `${hours} giờ trước`;
  }
  const days = Math.floor(diffSeconds / 86400);
  return `${days} ngày trước`;
}

// ═══════════════════════════════════════════════════════════════
// SEVERITY LEVEL FORMATTING
// ═══════════════════════════════════════════════════════════════

/**
 * Get severity label, color, and background based on rule.level
 * 
 * @param {number} level - Wazuh rule level (1-15+)
 * @returns {object} {label, color, bg, textColor}
 *   1-6:   THẤP        #00FF88  #001a00
 *   7-11:  TRUNG BÌNH  #FFCC00  #1a1a00
 *   12-14: CAO         #FF8800  #1a0800
 *   15+:   NGHIÊM TRỌNG #FF4444  #1a0000
 */
function formatMucDo(level) {
  const l = parseInt(level);
  
  if (l <= 6) {
    return {
      label: 'THẤP',
      color: '#00FF88',
      bg: '#001a00',
      textColor: '#fff'
    };
  } else if (l <= 11) {
    return {
      label: 'TRUNG BÌNH',
      color: '#FFCC00',
      bg: '#1a1a00',
      textColor: '#000'
    };
  } else if (l <= 14) {
    return {
      label: 'CAO',
      color: '#FF8800',
      bg: '#1a0800',
      textColor: '#fff'
    };
  } else {
    return {
      label: 'NGHIÊM TRỌNG',
      color: '#FF4444',
      bg: '#1a0000',
      textColor: '#fff'
    };
  }
}

/**
 * Render severity badge as HTML span element
 * @param {number} level - Wazuh rule level
 * @returns {string} HTML string
 */
function renderBadgeMucDo(level) {
  const sev = formatMucDo(level);
  return `<span class="badge-muc-do" style="
    background-color: ${sev.bg};
    color: ${sev.color};
    padding: 4px 8px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: bold;
    border: 1px solid ${sev.color};
    display: inline-block;
  ">${sev.label}</span>`;
}

// ═══════════════════════════════════════════════════════════════
// TIME RANGE FORMATTING
// ═══════════════════════════════════════════════════════════════

/**
 * Format seconds into human-readable time range
 * @param {number} giay - Seconds
 * @returns {string} "4m 30s" or "1g 0m"
 */
function formatPhanLoai(giay) {
  const s = Math.floor(giay);
  
  if (s < 60) {
    return `${s}s`;
  } else if (s < 3600) {
    const minutes = Math.floor(s / 60);
    const seconds = s % 60;
    return `${minutes}m ${seconds}s`;
  } else {
    const hours = Math.floor(s / 3600);
    const minutes = Math.floor((s % 3600) / 60);
    return `${hours}g ${minutes}m`;
  }
}

// ═══════════════════════════════════════════════════════════════
// EXPORT (UMD Pattern)
// ═══════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    formatSoLan,
    formatThoiGian,
    formatTuongDoi,
    formatMucDo,
    renderBadgeMucDo,
    formatPhanLoai
  };
}
