/**
 * MITRE_HEATMAP.JS — MITRE ATT&CK Heatmap Visualization
 * 
 * Three-part layout:
 * 1. Heatmap grid (100x60px cells with color intensity based on hit count)
 * 2. Detail table (technique | tactic | count | frequency bar)
 * 3. Tactic distribution bar chart
 */

class MitreHeatmap {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      console.error(`Container with id '${containerId}' not found`);
      return;
    }
    this.data = [];
    this.tacticColors = {
      'Credential Access': '#9333EA',
      'Lateral Movement': '#FF8800',
      'Impact': '#FF4444',
      'Defense Evasion': '#00CCFF',
      'Exfiltration': '#FF6B9D',
      'Persistence': '#FFA500',
      'Privilege Escalation': '#FFD700',
      'Initial Access': '#FF0000',
      'Execution': '#00FF88',
      'Reconnaissance': '#00CCFF'
    };
  }

  /**
   * Determine color intensity based on hit count
   * @private
   */
  getHeatmapColor(count) {
    if (count === 0) return '#111111';
    if (count <= 100) return '#1a3a1a';
    if (count <= 1000) return '#2d5a2d';
    if (count <= 10000) return '#cc6600';
    return '#ff2200';
  }

  /**
   * Fetch MITRE data from API
   */
  async fetchData() {
    try {
      const response = await fetch('/api/mitre');
      if (!response.ok) throw new Error(`API error: ${response.status}`);
      this.data = await response.json();
      this.render();
    } catch (error) {
      console.error('Error fetching MITRE data:', error);
      this.showError('Không thể tải dữ liệu MITRE ATT&CK');
    }
  }

  /**
   * Render all three components
   */
  render() {
    this.container.innerHTML = '';
    this.renderHeatmap();
    this.renderDetailTable();
    this.renderTacticDistribution();
  }

  /**
   * Render Part 1: Heatmap Grid
   * @private
   */
  renderHeatmap() {
    const section = document.createElement('div');
    section.style.cssText = `
      margin-bottom: 32px;
      padding: 16px;
      background: #0a0f0a;
      border: 1px solid #00ff8833;
      border-radius: 6px;
    `;

    const title = document.createElement('h3');
    title.textContent = '📊 BẢN ĐỒ NHIỆT KỸ THUẬT';
    title.style.cssText = `
      color: #00ff88;
      font-size: 14px;
      font-weight: 700;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    const grid = document.createElement('div');
    grid.style.cssText = `
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
      gap: 8px;
      padding: 12px;
      background: #050705;
      border-radius: 4px;
      overflow-x: auto;
      min-height: 200px;
    `;

    this.data.forEach(item => {
      const cell = document.createElement('div');
      const bgColor = this.getHeatmapColor(item.so_lan);
      const intensity = Math.min(item.so_lan / 10000, 1);
      
      cell.style.cssText = `
        background-color: ${bgColor};
        border: 1px solid rgba(0, 255, 136, ${0.2 + intensity * 0.5});
        border-radius: 3px;
        padding: 8px;
        text-align: center;
        cursor: pointer;
        transition: all 200ms;
        min-height: 60px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
      `;

      const techniqueId = document.createElement('div');
      techniqueId.textContent = item.technique_id;
      techniqueId.style.cssText = `
        font-weight: 700;
        font-size: 12px;
        color: #00ff88;
        font-family: 'Courier New', monospace;
      `;

      const count = document.createElement('div');
      count.textContent = `${item.so_lan.toLocaleString('vi-VN')}`;
      count.style.cssText = `
        font-size: 10px;
        color: #aaa;
        margin-top: 4px;
        font-family: 'Courier New', monospace;
      `;

      cell.appendChild(techniqueId);
      cell.appendChild(count);

      cell.addEventListener('mouseenter', () => {
        cell.style.transform = 'scale(1.05)';
        cell.style.boxShadow = `0 0 12px ${this.getHeatmapColor(item.so_lan)}99`;
        this.showTooltip(item);
      });

      cell.addEventListener('mouseleave', () => {
        cell.style.transform = 'scale(1)';
        cell.style.boxShadow = 'none';
        this.hideTooltip();
      });

      cell.addEventListener('click', () => {
        window.open(`https://attack.mitre.org/techniques/${item.technique_id.replace('.', '/')}`, '_blank');
      });

      grid.appendChild(cell);
    });

    section.appendChild(grid);
    this.container.appendChild(section);
  }

  /**
   * Render Part 2: Detail Table
   * @private
   */
  renderDetailTable() {
    const section = document.createElement('div');
    section.style.cssText = `
      margin-bottom: 32px;
      padding: 16px;
      background: #0a0f0a;
      border: 1px solid #00ccff33;
      border-radius: 6px;
      overflow-x: auto;
    `;

    const title = document.createElement('h3');
    title.textContent = '📋 CHI TIẾT KỸ THUẬT';
    title.style.cssText = `
      color: #00ccff;
      font-size: 14px;
      font-weight: 700;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    const table = document.createElement('table');
    table.style.cssText = `
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    `;

    // Header
    const headerRow = document.createElement('tr');
    headerRow.style.cssText = `
      border-bottom: 2px solid #00ccff;
      background: rgba(0, 204, 255, 0.05);
    `;
    const headers = ['KỸ THUẬT', 'CHIẾN THUẬT', 'SỐ LẦN', 'TẦN SUẤT (%)'];
    headers.forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      th.style.cssText = `
        text-align: left;
        padding: 12px;
        color: #00ccff;
        font-weight: 700;
        font-family: 'Courier New', monospace;
      `;
      headerRow.appendChild(th);
    });
    table.appendChild(headerRow);

    // Rows
    this.data.forEach((item, idx) => {
      const row = document.createElement('tr');
      row.style.cssText = `
        border-bottom: 1px solid #00ccff22;
        transition: background 200ms;
        cursor: pointer;
      `;
      row.addEventListener('mouseenter', () => {
        row.style.background = 'rgba(0, 204, 255, 0.08)';
      });
      row.addEventListener('mouseleave', () => {
        row.style.background = 'transparent';
      });

      // Technique ID & Name
      const tdTechnique = document.createElement('td');
      tdTechnique.style.cssText = `padding: 12px; color: #00ff88; font-weight: 600; font-family: 'Courier New', monospace;`;
      tdTechnique.textContent = `${item.technique_id} — ${item.ten}`;
      row.appendChild(tdTechnique);

      // Tactic Badge
      const tdTactic = document.createElement('td');
      tdTactic.style.cssText = `padding: 12px;`;
      const badge = document.createElement('span');
      const tacticColor = this.tacticColors[item.chien_thuat] || '#666';
      badge.textContent = item.chien_thuat;
      badge.style.cssText = `
        background-color: rgba(${this.hexToRgb(tacticColor).join(', ')}, 0.2);
        color: ${tacticColor};
        padding: 4px 8px;
        border-radius: 3px;
        border-left: 2px solid ${tacticColor};
        font-size: 11px;
        font-weight: 600;
        display: inline-block;
      `;
      tdTactic.appendChild(badge);
      row.appendChild(tdTactic);

      // Count
      const tdCount = document.createElement('td');
      tdCount.style.cssText = `
        padding: 12px;
        color: #ffcc00;
        font-family: 'Courier New', monospace;
        font-weight: 600;
      `;
      tdCount.textContent = item.so_lan.toLocaleString('vi-VN');
      row.appendChild(tdCount);

      // Frequency bar
      const tdFreq = document.createElement('td');
      tdFreq.style.cssText = `padding: 12px;`;
      const freqBar = document.createElement('div');
      freqBar.style.cssText = `
        background: linear-gradient(90deg, #00ff8833, transparent);
        height: 20px;
        border-radius: 2px;
        position: relative;
        overflow: hidden;
      `;
      const freqFill = document.createElement('div');
      freqFill.style.cssText = `
        background: #00ff88;
        height: 100%;
        width: ${item.tan_suat_pct}%;
        transition: width 300ms ease;
      `;
      freqBar.appendChild(freqFill);
      const freqText = document.createElement('div');
      freqText.textContent = `${item.tan_suat_pct.toFixed(1)}%`;
      freqText.style.cssText = `
        position: absolute;
        top: 50%;
        left: 4px;
        transform: translateY(-50%);
        color: #fff;
        font-size: 10px;
        font-weight: 600;
      `;
      freqBar.appendChild(freqText);
      tdFreq.appendChild(freqBar);
      row.appendChild(tdFreq);

      row.addEventListener('click', () => {
        window.open(`https://attack.mitre.org/techniques/${item.technique_id.replace('.', '/')}`, '_blank');
      });

      table.appendChild(row);
    });

    section.appendChild(table);
    this.container.appendChild(section);
  }

  /**
   * Render Part 3: Tactic Distribution Bar Chart
   * @private
   */
  renderTacticDistribution() {
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 16px;
      background: #0a0f0a;
      border: 1px solid #ffcc0033;
      border-radius: 6px;
    `;

    const title = document.createElement('h3');
    title.textContent = '📈 PHÂN BỐ CHIẾN THUẬT';
    title.style.cssText = `
      color: #ffcc00;
      font-size: 14px;
      font-weight: 700;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    // Group by tactic
    const tacticMap = {};
    this.data.forEach(item => {
      if (!tacticMap[item.chien_thuat]) {
        tacticMap[item.chien_thuat] = 0;
      }
      tacticMap[item.chien_thuat] += item.so_lan;
    });

    const maxCount = Math.max(...Object.values(tacticMap));

    Object.entries(tacticMap)
      .sort((a, b) => b[1] - a[1])
      .forEach(([tactic, count]) => {
        const row = document.createElement('div');
        row.style.cssText = `
          display: grid;
          grid-template-columns: 200px 1fr 80px;
          gap: 12px;
          margin-bottom: 12px;
          align-items: center;
        `;

        const label = document.createElement('div');
        label.textContent = tactic;
        label.style.cssText = `
          font-size: 12px;
          color: #ccc;
          font-weight: 600;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        `;
        row.appendChild(label);

        const bar = document.createElement('div');
        const color = this.tacticColors[tactic] || '#666';
        bar.style.cssText = `
          background: linear-gradient(90deg, ${color}88, ${color}33);
          height: 24px;
          border-radius: 3px;
          position: relative;
          overflow: hidden;
          border: 1px solid ${color}66;
        `;
        const fill = document.createElement('div');
        fill.style.cssText = `
          background: ${color};
          height: 100%;
          width: 0%;
          transition: width 600ms ease;
        `;
        bar.appendChild(fill);

        // Trigger animation
        setTimeout(() => {
          fill.style.width = (count / maxCount) * 100 + '%';
        }, 50);

        row.appendChild(bar);

        const countText = document.createElement('div');
        countText.textContent = count.toLocaleString('vi-VN');
        countText.style.cssText = `
          font-size: 12px;
          color: ${color};
          font-weight: 700;
          font-family: 'Courier New', monospace;
          text-align: right;
        `;
        row.appendChild(countText);

        section.appendChild(row);
      });

    this.container.appendChild(section);
  }

  /**
   * Show tooltip on hover
   * @private
   */
  showTooltip(item) {
    this.hideTooltip();
    const tooltip = document.createElement('div');
    tooltip.id = 'mitre-tooltip';
    tooltip.style.cssText = `
      position: fixed;
      background: #1a1f1a;
      border: 1px solid #00ff88;
      border-radius: 4px;
      padding: 8px 12px;
      font-size: 12px;
      color: #00ff88;
      font-family: 'Courier New', monospace;
      pointer-events: none;
      z-index: 10000;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
      white-space: nowrap;
    `;
    tooltip.innerHTML = `
      <strong>${item.technique_id}</strong>
      <br/>
      <span style="color: #aaa;">${item.ten}</span>
      <br/>
      <span style="color: #ffcc00;">${item.so_lan.toLocaleString('vi-VN')} lần</span>
    `;
    document.body.appendChild(tooltip);

    const event = window.event;
    if (event && event.clientX && event.clientY) {
      tooltip.style.left = (event.clientX + 10) + 'px';
      tooltip.style.top = (event.clientY + 10) + 'px';
    }

    document.addEventListener('mousemove', (e) => {
      tooltip.style.left = (e.clientX + 10) + 'px';
      tooltip.style.top = (e.clientY + 10) + 'px';
    });
  }

  /**
   * Hide tooltip
   * @private
   */
  hideTooltip() {
    const existing = document.getElementById('mitre-tooltip');
    if (existing) existing.remove();
  }

  /**
   * Convert hex to RGB
   * @private
   */
  hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? [
      parseInt(result[1], 16),
      parseInt(result[2], 16),
      parseInt(result[3], 16)
    ] : [0, 0, 0];
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
  module.exports = { MitreHeatmap };
}
