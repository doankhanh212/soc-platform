/**
 * TOAST.JS — Toast Notification System for AI-SOC Dashboard
 * 
 * Features:
 * - 5 severity types with distinct styling
 * - Stack management (max 5 notifications)
 * - Auto-dismiss with progress bar
 * - Hover to pause auto-dismiss
 * - Audio alert for 'nghiem_trong'
 * - Slide-in animation from right (300ms)
 * - Smooth slide-out on dismiss
 */

class ToastManager {
  constructor() {
    this.toasts = [];
    this.audioContext = null;
    this.container = null;
    this.initContainer();
  }

  /**
   * Initialize toast container in DOM
   * @private
   */
  initContainer() {
    if (document.getElementById('toast-container')) {
      this.container = document.getElementById('toast-container');
      return;
    }

    this.container = document.createElement('div');
    this.container.id = 'toast-container';
    this.container.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 10000;
      pointer-events: none;
      max-width: 400px;
    `;
    document.body.appendChild(this.container);
  }

  /**
   * Get toast configuration by type
   * @private
   */
  getConfig(type) {
    const _css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
    const bg = _css('--bg1') || '#001a00';
    const configs = {
      nghiem_trong: {
        label: 'Nghiêm Trọng',
        bgColor: bg,
        borderColor: _css('--red') || '#FF4444',
        textColor: _css('--red') || '#FF4444',
        icon: '🚨',
        duration: 10000,
        hasAudio: true,
        hasFlash: true
      },
      cao: {
        label: 'Cao',
        bgColor: bg,
        borderColor: _css('--amber') || '#FF8800',
        textColor: _css('--amber') || '#FF8800',
        icon: '⚠️',
        duration: 8000,
        hasAudio: false,
        hasFlash: false
      },
      ai: {
        label: 'AI Alert',
        bgColor: bg,
        borderColor: _css('--purple') || '#9333EA',
        textColor: _css('--purple') || '#9333EA',
        icon: '🤖',
        duration: 10000,
        hasAudio: false,
        hasFlash: false
      },
      thanh_cong: {
        label: 'Thành Công',
        bgColor: bg,
        borderColor: _css('--green') || '#00FF88',
        textColor: _css('--green') || '#00FF88',
        icon: '✅',
        duration: 3000,
        hasAudio: false,
        hasFlash: false
      },
      thong_tin: {
        label: 'Thông Tin',
        bgColor: bg,
        borderColor: _css('--cyan') || '#00ccff',
        textColor: _css('--cyan') || '#00ccff',
        icon: 'ℹ️',
        duration: 4000,
        hasAudio: false,
        hasFlash: false
      }
    };

    return configs[type] || configs.thong_tin;
  }

  /**
   * Show toast notification
   * @param {string} type - 'nghiem_trong'|'cao'|'ai'|'thanh_cong'|'thong_tin'
   * @param {string} title - Toast title
   * @param {string} message - Toast message (default: '')
   */
  show(type, title, message = '') {
    // Enforce max 5 toasts
    if (this.toasts.length >= 5) {
      const oldest = this.toasts.shift();
      if (oldest.element && oldest.element.parentNode) {
        oldest.element.remove();
      }
    }

    const config = this.getConfig(type);
    const toast = {
      id: Date.now(),
      type,
      config,
      element: null,
      timeout: null,
      isPaused: false
    };

    // Create DOM element
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.style.cssText = `
      position: relative;
      background-color: ${config.bgColor};
      border: 1px solid ${config.borderColor};
      border-left: 4px solid ${config.borderColor};
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 12px;
      color: ${config.textColor};
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      pointer-events: auto;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      animation: slideInRight 300ms ease-out;
      overflow: hidden;
    `;

    // Title
    const titleEl = document.createElement('div');
    titleEl.style.cssText = `
      font-size: 14px;
      font-weight: 700;
      margin-bottom: ${message ? '8px' : '0'};
      display: flex;
      align-items: center;
      gap: 8px;
    `;
    titleEl.innerHTML = `<span>${config.icon}</span><span>${this.escapeHtml(title)}</span>`;

    // Message
    const messageEl = document.createElement('div');
    messageEl.style.cssText = `
      font-size: 13px;
      line-height: 1.4;
      opacity: 0.9;
      font-family: 'Courier New', monospace;
    `;
    messageEl.textContent = message;

    // Progress bar
    const progressBar = document.createElement('div');
    progressBar.style.cssText = `
      position: absolute;
      bottom: 0;
      left: 0;
      height: 3px;
      background: linear-gradient(to right, ${config.borderColor}, transparent);
      width: 100%;
      animation: progressReverse ${config.duration}ms linear;
    `;

    // Close button
    const closeBtn = document.createElement('button');
    closeBtn.innerHTML = '✕';
    closeBtn.style.cssText = `
      position: absolute;
      top: 8px;
      right: 8px;
      background: none;
      border: none;
      color: ${config.textColor};
      font-size: 18px;
      cursor: pointer;
      opacity: 0.6;
      transition: opacity 200ms;
      padding: 0;
      width: 24px;
      height: 24px;
      display: flex;
      align-items: center;
      justify-content: center;
    `;
    closeBtn.onmouseover = () => closeBtn.style.opacity = '1';
    closeBtn.onmouseout = () => closeBtn.style.opacity = '0.6';
    closeBtn.onclick = () => this.dismiss(toast.id);

    // Assemble toast
    el.appendChild(titleEl);
    if (message) el.appendChild(messageEl);
    el.appendChild(progressBar);
    el.appendChild(closeBtn);

    // Add hover listeners
    el.addEventListener('mouseenter', () => {
      toast.isPaused = true;
      progressBar.style.animationPlayState = 'paused';
    });
    el.addEventListener('mouseleave', () => {
      toast.isPaused = false;
      progressBar.style.animationPlayState = 'running';
    });

    toast.element = el;
    this.toasts.push(toast);
    this.container.appendChild(el);

    // Audio alert for 'nghiem_trong'
    if (config.hasAudio) {
      this.playBeep();
      this.flashBorder(el);
    }

    // Auto-dismiss
    toast.timeout = setTimeout(() => {
      this.dismiss(toast.id);
    }, config.duration);

    return toast.id;
  }

  /**
   * Dismiss toast by ID
   * @param {number} id - Toast ID
   */
  dismiss(id) {
    const index = this.toasts.findIndex(t => t.id === id);
    if (index === -1) return;

    const toast = this.toasts[index];
    clearTimeout(toast.timeout);

    // Slide out animation
    if (toast.element) {
      toast.element.style.animation = 'slideOutRight 300ms ease-in';
      setTimeout(() => {
        if (toast.element && toast.element.parentNode) {
          toast.element.remove();
        }
      }, 300);
    }

    this.toasts.splice(index, 1);
  }

  /**
   * Play beep sound via Web Audio API
   * @private
   */
  playBeep() {
    try {
      const audioCtx = this.audioContext || (this.audioContext = new (window.AudioContext || window.webkitAudioContext)());
      const oscillator = audioCtx.createOscillator();
      const gainNode = audioCtx.createGain();

      oscillator.connect(gainNode);
      gainNode.connect(audioCtx.destination);

      oscillator.frequency.value = 800; // Hz
      oscillator.type = 'sine';

      gainNode.gain.setValueAtTime(0.3, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.1);

      oscillator.start(audioCtx.currentTime);
      oscillator.stop(audioCtx.currentTime + 0.1);
    } catch (e) {
      // Gracefully handle if Web Audio API not supported
      console.warn('Web Audio API not available:', e);
    }
  }

  /**
   * Flash border for critical alerts
   * @private
   */
  flashBorder(el) {
    let flashes = 0;
    const originalBorder = el.style.border;
    const flashInterval = setInterval(() => {
      if (flashes >= 4) {
        clearInterval(flashInterval);
        el.style.border = originalBorder;
        return;
      }
      el.style.borderColor = flashes % 2 === 0 ? (_css('--red')||'#FF4444') : (_css('--red')||'#aa0000');
      flashes++;
    }, 200);
  }

  /**
   * Escape HTML special characters
   * @private
   */
  escapeHtml(text) {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
  }

  /**
   * Clear all toasts
   */
  clearAll() {
    this.toasts.forEach(toast => {
      clearTimeout(toast.timeout);
      if (toast.element && toast.element.parentNode) {
        toast.element.remove();
      }
    });
    this.toasts = [];
  }
}

// ═══════════════════════════════════════════════════════════════
// GLOBAL INSTANCE & PUBLIC API
// ═══════════════════════════════════════════════════════════════

const toastManager = new ToastManager();

/**
 * Global function to show toast
 * Usage: showToast('nghiem_trong', 'Phát hiện tấn công!', 'IP: 37.111.53.110 — 4916 lần/giờ')
 */
function showToast(type, title, message = '') {
  return toastManager.show(type, title, message);
}

// ═══════════════════════════════════════════════════════════════
// CSS ANIMATIONS (inject into document head)
// ═══════════════════════════════════════════════════════════════

function injectAnimations() {
  if (document.getElementById('toast-animations')) return;

  const style = document.createElement('style');
  style.id = 'toast-animations';
  style.textContent = `
    @keyframes slideInRight {
      from {
        transform: translateX(420px);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }

    @keyframes slideOutRight {
      from {
        transform: translateX(0);
        opacity: 1;
      }
      to {
        transform: translateX(420px);
        opacity: 0;
      }
    }

    @keyframes progressReverse {
      from {
        width: 100%;
      }
      to {
        width: 0%;
      }
    }

    .toast {
      will-change: transform, opacity;
    }
  `;
  document.head.appendChild(style);
}

// Auto-inject animations when module loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectAnimations);
} else {
  injectAnimations();
}

// ═══════════════════════════════════════════════════════════════
// EXPORT (UMD Pattern)
// ═══════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    showToast,
    toastManager,
    ToastManager
  };
}

// ═══════════════════════════════════════════════════════════════
// COMPATIBILITY BRIDGE — window.toast(msg, type, ms)
// Maps existing app.js/soar.js calls to the new toast system
// ═══════════════════════════════════════════════════════════════

(function () {
  const TYPE_MAP = {
    'ok':   'thanh_cong',
    'err':  'nghiem_trong',
    'warn': 'cao',
    'info': 'thong_tin',
    'ai':   'ai',
  };

  /**
   * Drop-in replacement for the old window.toast(msg, type, ms).
   * Also supports the new showToast(type, title, message) signature
   * by detecting if the first argument looks like a known type key.
   */
  window.toast = function (msg, type, ms) {
    const mappedType = TYPE_MAP[type] || 'thong_tin';
    const id = showToast(mappedType, String(msg));
    // Honor custom duration if provided
    if (ms && typeof ms === 'number') {
      const toast = toastManager.toasts.find(t => t.id === id);
      if (toast) {
        clearTimeout(toast.timeout);
        toast.timeout = setTimeout(() => toastManager.dismiss(id), ms);
      }
    }
    return id;
  };
})();
