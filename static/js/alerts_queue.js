/**
 * ALERTS_QUEUE.JS — Virtual Scroll Alert Queue Table
 * 
 * Features:
 * - Virtual scrolling (10,000+ rows, render 20 + 5 buffer)
 * - Sticky header with sortable columns
 * - Dynamic filtering (severity, time range, status)
 * - Multi-select bulk actions
 * - Real-time WebSocket updates with red flash animation
 * - Customizable row height (44px)
 * - Click row to open detail modal
 */

class AlertsQueue {
  constructor(containerId, onRowClick = null) {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      console.error(`Container with id '${containerId}' not found`);
      return;
    }

    this.allAlerts = [];
    this.filteredAlerts = [];
    this.selectedAlerts = new Set();
    this.sortColumn = 'timestamp';
    this.sortDirection = 'desc';
    this.onRowClick = onRowClick;

    // Virtual scroll settings
    this.rowHeight = 44;
    this.visibleRows = 20;
    this.bufferRows = 5;
    this.scrollTop = 0;

    // Filter states
    this.filters = {
      severity: 'ALL',     // ALL|15+|12-14|7-11|1-6
      timeRange: '24h',    // 1h|24h|7d
      status: 'ALL'        // ALL|OPEN|RESOLVED|FALSE_POSITIVE
    };

    this.init();
  }

  /**
   * Initialize the queue component
   */
  init() {
    this.container.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      background: #0a0f0a;
      border: 1px solid #00ff8833;
      border-radius: 6px;
      overflow: hidden;
    `;

    this.renderFilterBar();
    this.renderTableHeader();
    this.renderVirtualScroll();
    this.renderBulkActions();

    // Fetch initial data
    this.fetchAlerts();
  }

  /**
   * Fetch alerts from API
   */
  async fetchAlerts() {
    try {
      const timeHours = this.filters.timeRange === '1h' ? 1 : 
                        this.filters.timeRange === '7d' ? 168 : 24;
      const response = await fetch(`/api/alerts?limit=500&hours=${timeHours}`);
      if (!response.ok) throw new Error(`API error: ${response.status}`);
      
      this.allAlerts = await response.json();
      this.applyFilters();
      this.renderTableBody();
    } catch (error) {
      console.error('Error fetching alerts:', error);
      showToast('cao', '⚠️ Lỗi tải cảnh báo', error.message);
    }
  }

  /**
   * Render filter bar
   * @private
   */
  renderFilterBar() {
    const filterBar = document.createElement('div');
    filterBar.style.cssText = `
      display: grid;
      grid-template-columns: auto auto auto 1fr auto;
      gap: 12px;
      padding: 12px 16px;
      background: #050705;
      border-bottom: 1px solid #00ff8822;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    `;

    // Severity filter
    const sevLabel = document.createElement('label');
    sevLabel.textContent = 'Mức độ:';
    sevLabel.style.cssText = `color: #888; font-size: 12px; font-weight: 600;`;
    filterBar.appendChild(sevLabel);

    const sevSelect = document.createElement('select');
    sevSelect.style.cssText = `
      background: #1a1f1a;
      color: #00ff88;
      border: 1px solid #00ff8844;
      padding: 6px 8px;
      border-radius: 3px;
      font-size: 11px;
      font-family: 'Courier New', monospace;
      cursor: pointer;
    `;
    sevSelect.innerHTML = `
      <option value="ALL">TẤT CẢ</option>
      <option value="15+">NGHIÊM TRỌNG (15+)</option>
      <option value="12-14">CAO (12-14)</option>
      <option value="7-11">TRUNG BÌNH (7-11)</option>
      <option value="1-6">THẤP (1-6)</option>
    `;
    sevSelect.addEventListener('change', (e) => {
      this.filters.severity = e.target.value;
      this.applyFilters();
      this.renderTableBody();
    });
    filterBar.appendChild(sevSelect);

    // Time range filter
    const timeLabel = document.createElement('label');
    timeLabel.textContent = 'Thời gian:';
    timeLabel.style.cssText = `color: #888; font-size: 12px; font-weight: 600;`;
    filterBar.appendChild(timeLabel);

    const timeSelect = document.createElement('select');
    timeSelect.style.cssText = `
      background: #1a1f1a;
      color: #00ff88;
      border: 1px solid #00ff8844;
      padding: 6px 8px;
      border-radius: 3px;
      font-size: 11px;
      font-family: 'Courier New', monospace;
      cursor: pointer;
    `;
    timeSelect.innerHTML = `
      <option value="1h">1 Giờ</option>
      <option value="24h" selected>24 Giờ</option>
      <option value="7d">7 Ngày</option>
    `;
    timeSelect.addEventListener('change', (e) => {
      this.filters.timeRange = e.target.value;
      this.fetchAlerts();
    });
    filterBar.appendChild(timeSelect);

    // Status filter
    const statusLabel = document.createElement('label');
    statusLabel.textContent = 'Trạng thái:';
    statusLabel.style.cssText = `color: #888; font-size: 12px; font-weight: 600;`;
    filterBar.appendChild(statusLabel);

    const statusSelect = document.createElement('select');
    statusSelect.style.cssText = `
      background: #1a1f1a;
      color: #00ff88;
      border: 1px solid #00ff8844;
      padding: 6px 8px;
      border-radius: 3px;
      font-size: 11px;
      font-family: 'Courier New', monospace;
      cursor: pointer;
    `;
    statusSelect.innerHTML = `
      <option value="ALL">TẤT CẢ</option>
      <option value="OPEN">MỞ</option>
      <option value="RESOLVED">ĐÃ GIẢI QUYẾT</option>
      <option value="FALSE_POSITIVE">CẢNH BÁO NHẦM</option>
    `;
    statusSelect.addEventListener('change', (e) => {
      this.filters.status = e.target.value;
      this.applyFilters();
      this.renderTableBody();
    });
    filterBar.appendChild(statusSelect);

    // Spacer
    const spacer = document.createElement('div');
    filterBar.appendChild(spacer);

    // Refresh button
    const refreshBtn = document.createElement('button');
    refreshBtn.innerHTML = '🔄';
    refreshBtn.title = 'Làm mới';
    refreshBtn.style.cssText = `
      background: none;
      border: none;
      color: #00ff88;
      font-size: 16px;
      cursor: pointer;
      padding: 6px;
      transition: transform 200ms;
    `;
    refreshBtn.addEventListener('click', () => {
      refreshBtn.style.transform = 'rotate(360deg)';
      this.fetchAlerts();
      setTimeout(() => {
        refreshBtn.style.transform = 'rotate(0)';
      }, 600);
    });
    filterBar.appendChild(refreshBtn);

    this.container.appendChild(filterBar);
    this.filterBar = filterBar;
  }

  /**
   * Render table header
   * @private
   */
  renderTableHeader() {
    const headerContainer = document.createElement('div');
    headerContainer.style.cssText = `
      display: grid;
      grid-template-columns: 40px 120px 180px 60px 60px 100px 120px 80px 60px 100px 120px;
      gap: 8px;
      padding: 12px 16px;
      background: #111;
      border-bottom: 2px solid #00ff88;
      position: sticky;
      top: 48px;
      z-index: 99;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    `;

    const columns = [
      { key: 'select', label: '☑' },
      { key: 'alert_id', label: 'ALERT ID' },
      { key: 'rule_description', label: 'QUY TẮC' },
      { key: 'rule_level', label: 'MỨC ĐỘ' },
      { key: 'loai', label: 'LOẠI' },
      { key: 'timestamp', label: 'THỜI GIAN' },
      { key: 'may_chu', label: 'MÁY CHỦ' },
      { key: 'ip_nguon', label: 'IP NGUỒN' },
      { key: 'mitre_technique', label: 'MITRE' },
      { key: 'trang_thai', label: 'TRẠNG THÁI' },
      { key: 'phan_tich_vien', label: 'PHÂN TÍCH VIÊN' },
      { key: 'actions', label: 'HÀNH ĐỘNG' }
    ];

    columns.forEach(col => {
      const header = document.createElement('div');
      header.style.cssText = `
        color: #00ff88;
        cursor: ${col.key !== 'select' && col.key !== 'actions' ? 'pointer' : 'default'};
        display: flex;
        align-items: center;
        gap: 4px;
        padding: 4px;
        transition: background 200ms;
      `;
      header.textContent = col.label;

      if (col.key !== 'select' && col.key !== 'actions') {
        header.addEventListener('mouseenter', () => {
          header.style.background = 'rgba(0, 255, 136, 0.1)';
        });
        header.addEventListener('mouseleave', () => {
          header.style.background = 'transparent';
        });
        header.addEventListener('click', () => {
          this.sortColumn = col.key;
          this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
          this.applyFilters();
          this.renderTableBody();
        });
      }

      if (col.key === 'select') {
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.style.cssText = `cursor: pointer;`;
        checkbox.addEventListener('change', (e) => {
          if (e.target.checked) {
            this.filteredAlerts.forEach(alert => this.selectedAlerts.add(alert.alert_id));
          } else {
            this.selectedAlerts.clear();
          }
          this.renderTableBody();
          this.updateBulkActionsVisibility();
        });
        header.innerHTML = '';
        header.appendChild(checkbox);
      }

      headerContainer.appendChild(header);
    });

    this.container.appendChild(headerContainer);
  }

  /**
   * Render virtual scroll container
   * @private
   */
  renderVirtualScroll() {
    const scrollContainer = document.createElement('div');
    scrollContainer.id = 'alerts-scroll-container';
    scrollContainer.style.cssText = `
      flex: 1;
      overflow-y: auto;
      overflow-x: hidden;
      background: #0a0f0a;
      position: relative;
    `;

    scrollContainer.addEventListener('scroll', () => {
      this.scrollTop = scrollContainer.scrollTop;
      this.renderTableBody();
    });

    const tableBody = document.createElement('div');
    tableBody.id = 'table-body';
    tableBody.style.cssText = `
      position: relative;
    `;

    scrollContainer.appendChild(tableBody);
    this.container.appendChild(scrollContainer);
    this.scrollContainer = scrollContainer;
  }

  /**
   * Render table body with virtual scroll
   * @private
   */
  renderTableBody() {
    const tableBody = document.getElementById('table-body');
    if (!tableBody) return;

    const startRow = Math.max(0, Math.floor(this.scrollTop / this.rowHeight) - this.bufferRows);
    const endRow = startRow + this.visibleRows + this.bufferRows * 2;

    // Set container height for scroll bar
    tableBody.style.height = this.filteredAlerts.length * this.rowHeight + 'px';

    // Clear existing rows
    const existingRows = tableBody.querySelectorAll('.alert-row');
    existingRows.forEach(row => row.remove());

    // Render visible rows
    for (let i = startRow; i < Math.min(endRow, this.filteredAlerts.length); i++) {
      const alert = this.filteredAlerts[i];
      const row = this.createAlertRow(alert, i);
      tableBody.appendChild(row);
    }
  }

  /**
   * Create individual alert row
   * @private
   */
  createAlertRow(alert, index) {
    const row = document.createElement('div');
    row.className = 'alert-row';
    row.dataset.alertId = alert.alert_id;
    row.style.cssText = `
      display: grid;
      grid-template-columns: 40px 120px 180px 60px 60px 100px 120px 80px 60px 100px 120px;
      gap: 8px;
      padding: 8px 16px;
      height: ${this.rowHeight}px;
      align-items: center;
      border-bottom: 1px solid #00ff8822;
      background: #0a0f0a;
      position: absolute;
      top: ${index * this.rowHeight}px;
      left: 0;
      right: 0;
      transition: background 200ms;
      cursor: pointer;
      font-size: 11px;
      overflow: hidden;
    `;

    // CRITICAL alerts: add red flash animation
    if (alert.rule_level >= 15) {
      row.style.animation = 'alertFlash 2s ease-in-out infinite';
    }

    row.addEventListener('mouseenter', () => {
      row.style.background = 'rgba(0, 255, 136, 0.05)';
    });

    row.addEventListener('mouseleave', () => {
      row.style.background = '#0a0f0a';
    });

    row.addEventListener('click', (e) => {
      if (!e.target.closest('input, button')) {
        this.onRowClick && this.onRowClick(alert);
      }
    });

    // Checkbox
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = this.selectedAlerts.has(alert.alert_id);
    checkbox.style.cssText = `cursor: pointer;`;
    checkbox.addEventListener('click', (e) => {
      e.stopPropagation();
    });
    checkbox.addEventListener('change', (e) => {
      if (e.target.checked) {
        this.selectedAlerts.add(alert.alert_id);
      } else {
        this.selectedAlerts.delete(alert.alert_id);
      }
      this.updateBulkActionsVisibility();
    });
    row.appendChild(checkbox);

    // Alert ID
    const id = document.createElement('div');
    id.textContent = alert.alert_id;
    id.style.cssText = `color: #00ff88; font-weight: 600; font-family: 'Courier New', monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;`;
    row.appendChild(id);

    // Rule Description
    const rule = document.createElement('div');
    rule.textContent = alert.rule_description;
    rule.style.cssText = `color: #ccc; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;`;
    rule.title = alert.rule_description;
    row.appendChild(rule);

    // Severity badge
    const severity = document.createElement('div');
    severity.innerHTML = renderBadgeMucDo(alert.rule_level);
    row.appendChild(severity);

    // Type
    const type = document.createElement('div');
    type.textContent = alert.loai || '—';
    type.style.cssText = `color: #aaa; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;`;
    row.appendChild(type);

    // Timestamp
    const time = document.createElement('div');
    time.textContent = formatTuongDoi(alert.timestamp);
    time.title = formatThoiGian(alert.timestamp);
    time.style.cssText = `color: #888; font-family: 'Courier New', monospace;`;
    row.appendChild(time);

    // Host
    const host = document.createElement('div');
    host.textContent = alert.may_chu || '—';
    host.style.cssText = `color: #aaa; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: 'Courier New', monospace;`;
    host.title = alert.may_chu;
    row.appendChild(host);

    // Source IP
    const sourceIp = document.createElement('div');
    sourceIp.textContent = alert.ip_nguon || '—';
    sourceIp.style.cssText = `
      color: #ffcc00;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-family: 'Courier New', monospace;
      cursor: pointer;
      text-decoration: underline;
    `;
    sourceIp.title = alert.ip_nguon;
    sourceIp.addEventListener('click', (e) => {
      e.stopPropagation();
      this.copyToClipboard(alert.ip_nguon);
    });
    row.appendChild(sourceIp);

    // MITRE Technique
    const mitre = document.createElement('div');
    mitre.textContent = alert.mitre_technique || '—';
    mitre.style.cssText = `
      color: #00ccff;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-family: 'Courier New', monospace;
    `;
    mitre.title = alert.mitre_technique;
    row.appendChild(mitre);

    // Status badge
    const status = document.createElement('div');
    const statusColors = {
      'OPEN': '#FF4444',
      'RESOLVED': '#00FF88',
      'FALSE_POSITIVE': '#888888'
    };
    const statusColor = statusColors[alert.trang_thai] || '#666';
    status.style.cssText = `
      background: rgba(${this.hexToRgb(statusColor).join(', ')}, 0.15);
      color: ${statusColor};
      padding: 3px 6px;
      border-radius: 2px;
      font-size: 10px;
      font-weight: 600;
      text-align: center;
      border-left: 2px solid ${statusColor};
    `;
    status.textContent = this.translateStatus(alert.trang_thai);
    row.appendChild(status);

    // Analyst
    const analyst = document.createElement('div');
    analyst.textContent = alert.phan_tich_vien || '—';
    analyst.style.cssText = `color: #aaa; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;`;
    analyst.title = alert.phan_tich_vien;
    row.appendChild(analyst);

    // Actions
    const actions = document.createElement('div');
    actions.style.cssText = `
      display: flex;
      gap: 6px;
      padding: 4px;
    `;

    const viewBtn = document.createElement('button');
    viewBtn.innerHTML = '🔍';
    viewBtn.title = 'Xem chi tiết';
    viewBtn.style.cssText = `
      background: none;
      border: none;
      color: #00ff88;
      font-size: 14px;
      cursor: pointer;
      padding: 2px 4px;
      transition: transform 200ms;
    `;
    viewBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this.onRowClick && this.onRowClick(alert);
    });
    viewBtn.addEventListener('mouseenter', () => viewBtn.style.transform = 'scale(1.15)');
    viewBtn.addEventListener('mouseleave', () => viewBtn.style.transform = 'scale(1)');
    actions.appendChild(viewBtn);

    const incidentBtn = document.createElement('button');
    incidentBtn.innerHTML = '＋';
    incidentBtn.title = 'Tạo vụ việc';
    incidentBtn.style.cssText = `
      background: none;
      border: none;
      color: #ffcc00;
      font-size: 16px;
      cursor: pointer;
      padding: 0 2px;
      transition: transform 200ms;
    `;
    incidentBtn.addEventListener('mouseenter', () => incidentBtn.style.transform = 'scale(1.2)');
    incidentBtn.addEventListener('mouseleave', () => incidentBtn.style.transform = 'scale(1)');
    actions.appendChild(incidentBtn);

    const fpBtn = document.createElement('button');
    fpBtn.innerHTML = '✕';
    fpBtn.title = 'Báo động nhầm';
    fpBtn.style.cssText = `
      background: none;
      border: none;
      color: #ff8800;
      font-size: 14px;
      cursor: pointer;
      padding: 2px 4px;
      transition: transform 200ms;
    `;
    fpBtn.addEventListener('mouseenter', () => fpBtn.style.transform = 'scale(1.15)');
    fpBtn.addEventListener('mouseleave', () => fpBtn.style.transform = 'scale(1)');
    actions.appendChild(fpBtn);

    row.appendChild(actions);

    return row;
  }

  /**
   * Apply filters and sorting
   * @private
   */
  applyFilters() {
    let filtered = [...this.allAlerts];

    // Severity filter
    if (this.filters.severity !== 'ALL') {
      const [min, max] = this.filters.severity.includes('+')
        ? [parseInt(this.filters.severity), 999]
        : this.filters.severity.split('-').map(Number);
      filtered = filtered.filter(a => a.rule_level >= min && a.rule_level <= max);
    }

    // Status filter
    if (this.filters.status !== 'ALL') {
      filtered = filtered.filter(a => a.trang_thai === this.filters.status);
    }

    // Sort
    filtered.sort((a, b) => {
      let aVal = a[this.sortColumn];
      let bVal = b[this.sortColumn];

      // Handle timestamp sorting
      if (this.sortColumn === 'timestamp') {
        aVal = new Date(aVal).getTime();
        bVal = new Date(bVal).getTime();
      }

      if (aVal < bVal) return this.sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return this.sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    this.filteredAlerts = filtered;
    this.scrollContainer.scrollTop = 0;
    this.scrollTop = 0;
  }

  /**
   * Bulk actions bar
   * @private
   */
  renderBulkActions() {
    const bulkBar = document.createElement('div');
    bulkBar.id = 'bulk-actions-bar';
    bulkBar.style.cssText = `
      display: none;
      padding: 12px 16px;
      background: #1a1a00;
      border-top: 1px solid #ffcc0044;
      gap: 12px;
      align-items: center;
      font-size: 12px;
    `;

    const count = document.createElement('span');
    count.style.cssText = `color: #ffcc00; font-weight: 600; flex: 1;`;

    const assignBtn = document.createElement('button');
    assignBtn.textContent = '👤 Giao việc';
    assignBtn.style.cssText = `
      background: #664400;
      color: #ffcc00;
      border: 1px solid #ffcc00;
      padding: 6px 12px;
      border-radius: 3px;
      cursor: pointer;
      font-size: 11px;
      font-weight: 600;
    `;

    const fpBtn = document.createElement('button');
    fpBtn.textContent = '✕ Báo động nhầm';
    fpBtn.style.cssText = `
      background: #440000;
      color: #ff8800;
      border: 1px solid #ff8800;
      padding: 6px 12px;
      border-radius: 3px;
      cursor: pointer;
      font-size: 11px;
      font-weight: 600;
    `;

    bulkBar.appendChild(count);
    bulkBar.appendChild(assignBtn);
    bulkBar.appendChild(fpBtn);

    this.container.appendChild(bulkBar);
    this.bulkBar = bulkBar;
  }

  /**
   * Update bulk actions visibility
   * @private
   */
  updateBulkActionsVisibility() {
    const bulkBar = document.getElementById('bulk-actions-bar');
    if (!bulkBar) return;

    const count = bulkBar.querySelector('span');
    count.textContent = `✓ Đã chọn ${this.selectedAlerts.size}`;

    bulkBar.style.display = this.selectedAlerts.size > 0 ? 'flex' : 'none';
  }

  /**
   * Copy to clipboard
   * @private
   */
  copyToClipboard(text) {
    navigator.clipboard.writeText(text);
    showToast('thong_tin', '📋 Đã sao chép', text);
  }

  /**
   * Translate status
   * @private
   */
  translateStatus(status) {
    const map = {
      'OPEN': 'MỞ',
      'RESOLVED': 'ĐÃ GIẢI',
      'FALSE_POSITIVE': 'NHẦM'
    };
    return map[status] || status;
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
}

// ═══════════════════════════════════════════════════════════════════════════
// CSS ANIMATIONS
// ═══════════════════════════════════════════════════════════════════════════

function injectAlertsQueueAnimations() {
  if (document.getElementById('alerts-queue-animations')) return;

  const style = document.createElement('style');
  style.id = 'alerts-queue-animations';
  style.textContent = `
    @keyframes alertFlash {
      0%, 100% {
        background: #0a0f0a;
      }
      50% {
        background: rgba(255, 68, 68, 0.1);
        box-shadow: inset 0 0 8px rgba(255, 68, 68, 0.15);
      }
    }
  `;
  document.head.appendChild(style);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectAlertsQueueAnimations);
} else {
  injectAlertsQueueAnimations();
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { AlertsQueue };
}
