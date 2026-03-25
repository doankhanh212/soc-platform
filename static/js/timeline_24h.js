/**
 * TIMELINE_24H.JS — 24-Hour Alert Timeline Chart
 * 
 * SVG area chart with:
 * - Gradient fill
 * - Current time indicator (dashed white line)
 * - Average line (dashed yellow)
 * - Hover tooltips
 * - Animated draw on load
 * - Responsive (debounced resize)
 */

class Timeline24h {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      console.error(`Container with id '${containerId}' not found`);
      return;
    }
    this.data = [];
    this.svg = null;
    this.resizeTimeout = null;
  }

  /**
   * Fetch 24-hour timeline data
   */
  async fetchData() {
    try {
      const response = await fetch('/api/stats');
      if (!response.ok) throw new Error(`API error: ${response.status}`);
      const stats = await response.json();
      
      // Ensure 24 data points
      this.data = stats.hourly_alerts || [];
      if (this.data.length > 24) this.data = this.data.slice(-24);
      while (this.data.length < 24) this.data.push(0);

      this.render();
    } catch (error) {
      console.error('Error fetching timeline data:', error);
      this.showError('Không thể tải dữ liệu timeline');
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
      border: 1px solid #ff444433;
      border-radius: 6px;
    `;

    const title = document.createElement('h3');
    title.textContent = '📅 TIMELINE CẢNH BÁO 24 GIỜ';
    title.style.cssText = `
      color: #ff4444;
      font-size: 14px;
      font-weight: 700;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    const chartContainer = document.createElement('div');
    chartContainer.style.cssText = `
      position: relative;
      width: 100%;
      height: 240px;
      background: #050705;
      border-radius: 4px;
      overflow: hidden;
    `;

    this.svg = this.createSVG(chartContainer);
    this.drawChart();

    section.appendChild(chartContainer);
    this.container.appendChild(section);

    // Responsive resize
    window.addEventListener('resize', () => {
      clearTimeout(this.resizeTimeout);
      this.resizeTimeout = setTimeout(() => {
        this.render();
      }, 300);
    });
  }

  /**
   * Create SVG element
   * @private
   */
  createSVG(container) {
    const rect = container.getBoundingClientRect();
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', rect.width || 800);
    svg.setAttribute('height', 240);
    svg.setAttribute('viewBox', `0 0 ${rect.width || 800} 240`);
    svg.style.cssText = `
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
    `;
    container.appendChild(svg);
    return svg;
  }

  /**
   * Draw the area chart
   * @private
   */
  drawChart() {
    if (!this.svg) return;

    const padding = { top: 20, right: 20, bottom: 40, left: 50 };
    const width = this.svg.getAttribute('width');
    const height = this.svg.getAttribute('height');
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    // Calculate scale
    const maxValue = Math.max(...this.data, 1);
    const minValue = 0;
    const range = maxValue - minValue || 1;
    const average = this.data.reduce((a, b) => a + b, 0) / this.data.length;

    // Create gradient
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    const gradient = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
    gradient.setAttribute('id', 'areaGradient');
    gradient.setAttribute('x1', '0%');
    gradient.setAttribute('y1', '0%');
    gradient.setAttribute('x2', '0%');
    gradient.setAttribute('y2', '100%');

    const stop1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
    stop1.setAttribute('offset', '0%');
    stop1.setAttribute('stop-color', '#ff4444');
    stop1.setAttribute('stop-opacity', '0.2');

    const stop2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
    stop2.setAttribute('offset', '100%');
    stop2.setAttribute('stop-color', '#ff4444');
    stop2.setAttribute('stop-opacity', '0');

    gradient.appendChild(stop1);
    gradient.appendChild(stop2);
    defs.appendChild(gradient);
    this.svg.appendChild(defs);

    // Y-axis scale (0 to max)
    const yScale = chartHeight / range;

    // Calculate points
    const points = this.data.map((value, i) => {
      const x = padding.left + (i / (this.data.length - 1)) * chartWidth;
      const y = padding.top + chartHeight - ((value - minValue) / range) * chartHeight;
      return { x, y, value, i };
    });

    // Draw grid lines (every 4 hours)
    for (let i = 0; i < 24; i += 4) {
      const x = points[i].x;
      const gridLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      gridLine.setAttribute('x1', x);
      gridLine.setAttribute('y1', padding.top);
      gridLine.setAttribute('x2', x);
      gridLine.setAttribute('y2', height - padding.bottom);
      gridLine.setAttribute('stroke', '#00ff8811');
      gridLine.setAttribute('stroke-width', '1');
      this.svg.appendChild(gridLine);
    }

    // Draw area
    const pathData = [
      `M${points[0].x},${points[0].y}`,
      ...points.map((p, i) => `L${p.x},${p.y}`),
      `L${points[points.length - 1].x},${height - padding.bottom}`,
      `L${points[0].x},${height - padding.bottom}`,
      'Z'
    ].join(' ');

    const area = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    area.setAttribute('d', pathData);
    area.setAttribute('fill', 'url(#areaGradient)');
    area.setAttribute('stroke', 'none');
    area.style.animation = 'drawArea 800ms ease-out forwards';
    this.svg.appendChild(area);

    // Draw line
    const lineData = ['M' + points.map(p => `${p.x},${p.y}`).join(' L ')].join(' ');
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    line.setAttribute('d', lineData);
    line.setAttribute('fill', 'none');
    line.setAttribute('stroke', '#ff4444');
    line.setAttribute('stroke-width', '2');
    line.setAttribute('stroke-linecap', 'round');
    line.setAttribute('stroke-linejoin', 'round');
    line.style.animation = 'drawLine 800ms ease-out forwards';
    this.svg.appendChild(line);

    // Current time indicator
    const now = new Date();
    const currentHour = now.getHours();
    const currentPoint = points[currentHour];
    if (currentPoint) {
      const currentLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      currentLine.setAttribute('x1', currentPoint.x);
      currentLine.setAttribute('y1', padding.top);
      currentLine.setAttribute('x2', currentPoint.x);
      currentLine.setAttribute('y2', height - padding.bottom);
      currentLine.setAttribute('stroke', '#ffffff');
      currentLine.setAttribute('stroke-width', '1.5');
      currentLine.setAttribute('stroke-dasharray', '4,4');
      this.svg.appendChild(currentLine);

      // "Now" label
      const nowLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      nowLabel.setAttribute('x', currentPoint.x);
      nowLabel.setAttribute('y', height - padding.bottom + 20);
      nowLabel.setAttribute('text-anchor', 'middle');
      nowLabel.setAttribute('font-size', '11px');
      nowLabel.setAttribute('fill', '#ffffff');
      nowLabel.setAttribute('font-weight', '600');
      nowLabel.textContent = 'Bây giờ';
      this.svg.appendChild(nowLabel);
    }

    // Average line
    const avgY = padding.top + chartHeight - ((average - minValue) / range) * chartHeight;
    const avgLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    avgLine.setAttribute('x1', padding.left);
    avgLine.setAttribute('y1', avgY);
    avgLine.setAttribute('x2', width - padding.right);
    avgLine.setAttribute('y2', avgY);
    avgLine.setAttribute('stroke', '#ffcc00');
    avgLine.setAttribute('stroke-width', '1');
    avgLine.setAttribute('stroke-dasharray', '4,4');
    this.svg.appendChild(avgLine);

    // "Avg" label
    const avgLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    avgLabel.setAttribute('x', padding.left - 5);
    avgLabel.setAttribute('y', avgY - 5);
    avgLabel.setAttribute('text-anchor', 'end');
    avgLabel.setAttribute('font-size', '10px');
    avgLabel.setAttribute('fill', '#ffcc00');
    avgLabel.setAttribute('font-weight', '600');
    avgLabel.textContent = `TB: ${Math.round(average).toLocaleString('vi-VN')}`;
    this.svg.appendChild(avgLabel);

    // Data points (interactive)
    points.forEach((point, i) => {
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', point.x);
      circle.setAttribute('cy', point.y);
      circle.setAttribute('r', '4');
      circle.setAttribute('fill', '#ff4444');
      circle.setAttribute('opacity', '0');
      circle.style.cursor = 'pointer';
      circle.style.transition = 'all 200ms';

      circle.addEventListener('mouseenter', (e) => {
        circle.setAttribute('r', '6');
        circle.setAttribute('opacity', '1');
        this.showTooltip(point, e);
      });

      circle.addEventListener('mouseleave', () => {
        circle.setAttribute('r', '4');
        circle.setAttribute('opacity', '0');
        this.hideTooltip();
      });

      circle.addEventListener('mousemove', (e) => {
        this.showTooltip(point, e);
      });

      this.svg.appendChild(circle);
    });

    // X-axis labels (every 4 hours)
    for (let i = 0; i < 24; i += 4) {
      const point = points[i];
      const hour = String(i).padStart(2, '0');
      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('x', point.x);
      label.setAttribute('y', height - padding.bottom + 20);
      label.setAttribute('text-anchor', 'middle');
      label.setAttribute('font-size', '11px');
      label.setAttribute('fill', '#666');
      label.setAttribute('font-family', 'Courier New, monospace');
      label.textContent = `${hour}:00`;
      this.svg.appendChild(label);
    }
  }

  /**
   * Show tooltip on hover
   * @private
   */
  showTooltip(point, event) {
    this.hideTooltip();
    const tooltip = document.createElement('div');
    tooltip.id = 'timeline-tooltip';
    tooltip.style.cssText = `
      position: fixed;
      background: #1a1f1a;
      border: 1px solid #ff4444;
      border-radius: 4px;
      padding: 8px 12px;
      font-size: 12px;
      color: #ff4444;
      font-family: 'Courier New', monospace;
      pointer-events: none;
      z-index: 10000;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
      white-space: nowrap;
    `;
    const hour = String(point.i).padStart(2, '0');
    tooltip.innerHTML = `
      <strong>${hour}:00 — ${point.value.toLocaleString('vi-VN')} cảnh báo</strong>
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
    const existing = document.getElementById('timeline-tooltip');
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
// CSS ANIMATIONS
// ═══════════════════════════════════════════════════════════════

function injectTimelineAnimations() {
  if (document.getElementById('timeline-animations')) return;

  const style = document.createElement('style');
  style.id = 'timeline-animations';
  style.textContent = `
    @keyframes drawArea {
      from {
        clip-path: inset(0 100% 0 0);
      }
      to {
        clip-path: inset(0 0 0 0);
      }
    }

    @keyframes drawLine {
      from {
        stroke-dasharray: 1000;
        stroke-dashoffset: 1000;
      }
      to {
        stroke-dasharray: 1000;
        stroke-dashoffset: 0;
      }
    }
  `;
  document.head.appendChild(style);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectTimelineAnimations);
} else {
  injectTimelineAnimations();
}

// ═══════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { Timeline24h };
}
