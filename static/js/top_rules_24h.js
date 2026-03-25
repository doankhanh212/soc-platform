/**
 * TOP_RULES_24H.JS — Top Rules 24-Hour Chart
 * 
 * Horizontal bar chart with:
 * - Rule name (280px)
 * - Animated expanding bars (500ms)
 * - Color-coded by rule group
 * - Hover tooltips with rule count
 * - Click to filter alerts by rule_id
 * - Responsive layout
 */

class TopRules24h {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      console.error(`Container with id '${containerId}' not found`);
      return;
    }
    this.data = [];
    this.groupColors = {
      'authentication': '#FF8800',
      'ids': '#FF4444',
      'system': '#FFCC00',
      'malware': '#FF00FF',
      'audit': '#00FF88',
      'access_control': '#00CCFF',
      'default': '#666'
    };
  }

  /**
   * Fetch top rules from API
   */
  async fetchData() {
    try {
      const response = await fetch('/api/stats');
      if (!response.ok) throw new Error(`API error: ${response.status}`);
      const stats = await response.json();
      
      this.data = stats.top_rules || [];
      if (this.data.length > 10) this.data = this.data.slice(0, 10);

      this.render();
    } catch (error) {
      console.error('Error fetching top rules data:', error);
      this.showError('Không thể tải dữ liệu quy tắc');
    }
  }

  /**
   * Main render method
   */
  render() {
    this.container.innerHTML = '';
    
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 16px;
      background: #0a0f0a;
      border: 1px solid #ffcc0033;
      border-radius: 6px;
    `;

    const title = document.createElement('h3');
    title.textContent = '🎯 TOP QUY TẮC 24 GIỜ';
    title.style.cssText = `
      color: #ffcc00;
      font-size: 14px;
      font-weight: 700;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    const chartContainer = document.createElement('div');
    chartContainer.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 12px;
      padding: 12px;
      background: #050705;
      border-radius: 4px;
    `;

    if (this.data.length === 0) {
      const emptyMsg = document.createElement('div');
      emptyMsg.textContent = 'Không có dữ liệu quy tắc';
      emptyMsg.style.cssText = `
        text-align: center;
        color: #666;
        padding: 32px 16px;
      `;
      chartContainer.appendChild(emptyMsg);
    } else {
      const maxCount = Math.max(...this.data.map(d => d.so_lan));

      this.data.forEach((item, index) => {
        const barItem = this.createBarItem(item, maxCount, index);
        chartContainer.appendChild(barItem);
      });
    }

    section.appendChild(chartContainer);
    this.container.appendChild(section);
  }

  /**
   * Create individual bar item
   * @private
   */
  createBarItem(item, maxCount, index) {
    const container = document.createElement('div');
    container.style.cssText = `
      display: grid;
      grid-template-columns: 280px 1fr 80px;
      gap: 12px;
      align-items: center;
      padding: 12px;
      background: rgba(0, 0, 0, 0.3);
      border-radius: 4px;
      transition: all 200ms;
      cursor: pointer;
    `;

    container.addEventListener('mouseenter', () => {
      container.style.background = 'rgba(255, 204, 0, 0.08)';
      container.style.transform = 'translateX(4px)';
    });

    container.addEventListener('mouseleave', () => {
      container.style.background = 'rgba(0, 0, 0, 0.3)';
      container.style.transform = 'translateX(0)';
    });

    // Rule name + ID
    const ruleName = document.createElement('div');
    ruleName.style.cssText = `
      font-size: 12px;
      color: #ccc;
      font-weight: 600;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    `;
    ruleName.textContent = `Rule #${item.rule_id} — ${item.mo_ta}`;
    ruleName.title = item.mo_ta;
    container.appendChild(ruleName);

    // Bar
    const barWrapper = document.createElement('div');
    barWrapper.style.cssText = `
      position: relative;
      height: 24px;
      background: rgba(255, 153, 0, 0.1);
      border-radius: 3px;
      overflow: hidden;
      border: 1px solid rgba(255, 153, 0, 0.3);
    `;

    const bar = document.createElement('div');
    const groupColor = this.groupColors[item.nhom] || this.groupColors.default;
    bar.style.cssText = `
      height: 100%;
      background: linear-gradient(90deg, ${groupColor}dd, ${groupColor}88);
      width: 0%;
      border-radius: 2px;
      position: relative;
      transition: width 500ms cubic-bezier(0.25, 0.46, 0.45, 0.94);
      border-right: 2px solid ${groupColor};
    `;

    // Badge for rule group
    const badge = document.createElement('div');
    badge.style.cssText = `
      position: absolute;
      top: 50%;
      left: 4px;
      transform: translateY(-50%);
      font-size: 9px;
      font-weight: 700;
      color: ${groupColor};
      text-transform: uppercase;
      letter-spacing: 0.5px;
      opacity: 0;
      transition: opacity 300ms;
    `;
    badge.textContent = item.nhom || 'UNKNOWN';
    bar.appendChild(badge);

    barWrapper.appendChild(bar);
    container.appendChild(barWrapper);

    // Count
    const countText = document.createElement('div');
    countText.style.cssText = `
      font-size: 12px;
      color: #ffcc00;
      font-weight: 700;
      font-family: 'Courier New', monospace;
      text-align: right;
    `;
    countText.textContent = item.so_lan.toLocaleString('vi-VN');
    container.appendChild(countText);

    // Hover tooltip
    container.addEventListener('mouseenter', (e) => {
      this.showTooltip(item, e);
      badge.style.opacity = '1';
    });

    container.addEventListener('mouseleave', () => {
      this.hideTooltip();
      badge.style.opacity = '0';
    });

    container.addEventListener('mousemove', (e) => {
      this.showTooltip(item, e);
    });

    // Click to filter (dispatch custom event)
    container.addEventListener('click', () => {
      window.dispatchEvent(new CustomEvent('filter-by-rule', {
        detail: { rule_id: item.rule_id, rule_name: item.mo_ta }
      }));
      showToast('thong_tin', '📋 Lọc cảnh báo', `Rule #${item.rule_id} — ${item.mo_ta}`);
    });

    // Trigger animation after small delay
    setTimeout(() => {
      bar.style.width = (item.so_lan / maxCount) * 100 + '%';
    }, 50 + index * 80);

    return container;
  }

  /**
   * Show tooltip on hover
   * @private
   */
  showTooltip(item, event) {
    this.hideTooltip();
    const tooltip = document.createElement('div');
    tooltip.id = 'toprules-tooltip';
    tooltip.style.cssText = `
      position: fixed;
      background: #1a1f1a;
      border: 1px solid #ffcc00;
      border-radius: 4px;
      padding: 8px 12px;
      font-size: 12px;
      color: #ffcc00;
      font-family: 'Courier New', monospace;
      pointer-events: none;
      z-index: 10000;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
      white-space: nowrap;
    `;
    tooltip.innerHTML = `
      <strong>Rule #${item.rule_id}</strong>
      <br/>
      <span style="color: #aaa;">${item.so_lan.toLocaleString('vi-VN')} lần trong 24h</span>
      <br/>
      <span style="color: #888; font-size: 10px;">Nhóm: ${item.nhom || 'Unknown'}</span>
    `;
    document.body.appendChild(tooltip);

    if (event) {
      tooltip.style.left = (event.clientX + 10) + 'px';
      tooltip.style.top = (event.clientY + 10) + 'px';
    }
  }

  /**
   * Hide tooltip
   * @private
   */
  hideTooltip() {
    const existing = document.getElementById('toprules-tooltip');
    if (existing) existing.remove();
  }

  /**
   * Show error message
   * @private
   */
  showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = `
      padding: 16px;
      background: #1a0000;
      color: #ff4444;
      border: 1px solid #ff4444;
      border-radius: 4px;
      text-align: center;
    `;
    errorDiv.textContent = message;
    this.container.appendChild(errorDiv);
  }
}

// ═══════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { TopRules24h };
}
