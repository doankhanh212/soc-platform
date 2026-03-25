/**
 * ALERT_DETAIL_MODAL.JS — Alert Detail Modal with Tabs
 * 
 * Features:
 * - 3 tabs: OVERVIEW | CLASSIFICATION | HISTORY
 * - Tab 1: Raw JSON + metadata table
 * - Tab 2: Classification (True/False Positive, etc.) + notes
 * - Tab 3: Action timeline
 * - Block IP button in header
 * - MITRE link button
 * - Close on Esc or backdrop click
 */

class AlertDetailModal {
  constructor() {
    this.modal = null;
    this.currentAlert = null;
    this.currentTab = 'overview';
  }

  /**
   * Show modal with alert data
   */
  show(alert) {
    this.currentAlert = alert;
    this.currentTab = 'overview';
    
    // Remove existing modal
    if (this.modal && this.modal.parentNode) {
      this.modal.remove();
    }

    this.render();
  }

  /**
   * Main render method
   */
  render() {
    // Backdrop
    const backdrop = document.createElement('div');
    backdrop.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      z-index: 9999;
      animation: fadeIn 200ms ease-out;
    `;
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) this.close();
    });
    document.body.appendChild(backdrop);

    // Modal
    this.modal = document.createElement('div');
    this.modal.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: #0a0f0a;
      border: 2px solid #00ff88;
      border-radius: 8px;
      width: 90%;
      max-width: 1200px;
      max-height: 80vh;
      z-index: 10000;
      display: flex;
      flex-direction: column;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.8);
      animation: slideUp 300ms ease-out;
    `;

    // Header
    this.renderHeader(backdrop);

    // Tab selector
    this.renderTabs();

    // Tab content
    const contentContainer = document.createElement('div');
    contentContainer.id = 'modal-content';
    contentContainer.style.cssText = `
      flex: 1;
      overflow-y: auto;
      padding: 20px;
      background: #050705;
    `;
    this.modal.appendChild(contentContainer);

    // Render initial tab
    this.renderTabContent();

    // Close on Esc
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        this.close();
        document.removeEventListener('keydown', handleKeyDown);
      }
    };
    document.addEventListener('keydown', handleKeyDown);

    // Store backdrop reference for close
    this.backdrop = backdrop;
    backdrop.appendChild(this.modal);
  }

  /**
   * Render modal header
   * @private
   */
  renderHeader(backdrop) {
    const header = document.createElement('div');
    header.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 20px;
      border-bottom: 1px solid #00ff8844;
      background: #111;
    `;

    // Title
    const title = document.createElement('div');
    title.style.cssText = `
      font-size: 16px;
      font-weight: 700;
      color: #00ff88;
      font-family: 'Courier New', monospace;
    `;
    title.textContent = `Alert: ${this.currentAlert.alert_id}`;
    header.appendChild(title);

    // Right buttons
    const rightSection = document.createElement('div');
    rightSection.style.cssText = `
      display: flex;
      gap: 12px;
      align-items: center;
    `;

    // Block IP button
    if (this.currentAlert.ip_nguon) {
      const blockBtn = document.createElement('button');
      blockBtn.innerHTML = `🛡 CHẶN IP ${this.currentAlert.ip_nguon}`;
      blockBtn.style.cssText = `
        background: #440000;
        color: #ff4444;
        border: 1px solid #ff4444;
        padding: 6px 12px;
        border-radius: 3px;
        cursor: pointer;
        font-size: 11px;
        font-weight: 600;
        transition: all 200ms;
      `;
      blockBtn.addEventListener('mouseenter', () => {
        blockBtn.style.background = '#660000';
      });
      blockBtn.addEventListener('mouseleave', () => {
        blockBtn.style.background = '#440000';
      });
      blockBtn.addEventListener('click', () => {
        this.blockIP(this.currentAlert.ip_nguon);
      });
      rightSection.appendChild(blockBtn);
    }

    // MITRE Link
    if (this.currentAlert.mitre_technique) {
      const mitreBtn = document.createElement('button');
      mitreBtn.innerHTML = '🔗 MITRE ATT&CK';
      mitreBtn.style.cssText = `
        background: #003366;
        color: #00ccff;
        border: 1px solid #00ccff;
        padding: 6px 12px;
        border-radius: 3px;
        cursor: pointer;
        font-size: 11px;
        font-weight: 600;
        transition: all 200ms;
      `;
      mitreBtn.addEventListener('mouseenter', () => {
        mitreBtn.style.background = '#004488';
      });
      mitreBtn.addEventListener('mouseleave', () => {
        mitreBtn.style.background = '#003366';
      });
      mitreBtn.addEventListener('click', () => {
        const url = `https://attack.mitre.org/techniques/${this.currentAlert.mitre_technique.replace('.', '/')}`;
        window.open(url, '_blank');
      });
      rightSection.appendChild(mitreBtn);
    }

    // Close button
    const closeBtn = document.createElement('button');
    closeBtn.innerHTML = '✕';
    closeBtn.style.cssText = `
      background: none;
      border: none;
      color: #ff4444;
      font-size: 20px;
      cursor: pointer;
      padding: 4px 8px;
      transition: transform 200ms;
    `;
    closeBtn.addEventListener('click', () => this.close());
    rightSection.appendChild(closeBtn);

    header.appendChild(rightSection);
    this.modal.appendChild(header);
  }

  /**
   * Render tab selector
   * @private
   */
  renderTabs() {
    const tabBar = document.createElement('div');
    tabBar.style.cssText = `
      display: flex;
      gap: 0;
      padding: 0 20px;
      background: #111;
      border-bottom: 1px solid #00ff8844;
    `;

    const tabs = ['overview', 'classification', 'history'];
    const labels = ['📋 TỔNG QUAN', '🏷 PHÂN LOẠI', '📜 LỊCH SỬ'];

    tabs.forEach((tab, i) => {
      const tabBtn = document.createElement('button');
      tabBtn.style.cssText = `
        background: none;
        border: none;
        color: ${this.currentTab === tab ? '#00ff88' : '#666'};
        padding: 12px 16px;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        cursor: pointer;
        border-bottom: ${this.currentTab === tab ? '2px solid #00ff88' : '2px solid transparent'};
        transition: all 200ms;
      `;
      tabBtn.textContent = labels[i];
      tabBtn.addEventListener('click', () => {
        this.currentTab = tab;
        document.querySelectorAll('.modal-tab-btn').forEach(btn => {
          btn.style.color = '#666';
          btn.style.borderBottom = '2px solid transparent';
        });
        tabBtn.style.color = '#00ff88';
        tabBtn.style.borderBottom = '2px solid #00ff88';
        this.renderTabContent();
      });
      tabBtn.className = 'modal-tab-btn';
      tabBar.appendChild(tabBtn);
    });

    this.modal.appendChild(tabBar);
  }

  /**
   * Render tab content
   * @private
   */
  renderTabContent() {
    const content = document.getElementById('modal-content');
    content.innerHTML = '';

    switch (this.currentTab) {
      case 'overview':
        this.renderOverviewTab(content);
        break;
      case 'classification':
        this.renderClassificationTab(content);
        break;
      case 'history':
        this.renderHistoryTab(content);
        break;
    }
  }

  /**
   * Render OVERVIEW tab (Raw JSON + Metadata)
   * @private
   */
  renderOverviewTab(container) {
    const grid = document.createElement('div');
    grid.style.cssText = `
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    `;

    // Left: Raw JSON
    const jsonContainer = document.createElement('div');
    jsonContainer.style.cssText = `
      flex: 1;
    `;

    const jsonTitle = document.createElement('h4');
    jsonTitle.textContent = '📄 Raw JSON';
    jsonTitle.style.cssText = `
      color: #00ff88;
      font-size: 12px;
      margin: 0 0 12px 0;
      text-transform: uppercase;
    `;
    jsonContainer.appendChild(jsonTitle);

    const jsonPre = document.createElement('pre');
    jsonPre.style.cssText = `
      background: #1a1f1a;
      border: 1px solid #00ff8844;
      border-radius: 4px;
      padding: 12px;
      color: #aaa;
      font-size: 11px;
      font-family: 'Courier New', monospace;
      overflow-x: auto;
      max-height: 400px;
      line-height: 1.4;
    `;

    // Pretty-print JSON with syntax highlighting
    const jsonStr = JSON.stringify(this.currentAlert, null, 2);
    jsonPre.innerHTML = this.syntaxHighlightJSON(jsonStr);
    jsonContainer.appendChild(jsonPre);

    // Right: Metadata table
    const metaContainer = document.createElement('div');
    metaContainer.style.cssText = `
      flex: 1;
    `;

    const metaTitle = document.createElement('h4');
    metaTitle.textContent = '📊 Metadata';
    metaTitle.style.cssText = `
      color: #00ff88;
      font-size: 12px;
      margin: 0 0 12px 0;
      text-transform: uppercase;
    `;
    metaContainer.appendChild(metaTitle);

    const metaTable = document.createElement('table');
    metaTable.style.cssText = `
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
    `;

    const metadata = [
      { label: 'Trạng thái', value: this.currentAlert.trang_thai },
      { label: 'Mức độ', value: this.currentAlert.rule_level },
      { label: 'IP nguồn', value: this.currentAlert.ip_nguon },
      { label: 'IP đích', value: this.currentAlert.ip_dich },
      { label: 'Máy chủ', value: this.currentAlert.may_chu },
      { label: 'Rule ID', value: this.currentAlert.rule_id },
      { label: 'Mô tả', value: this.currentAlert.rule_description },
      { label: 'MITRE', value: this.currentAlert.mitre_technique },
      { label: 'Tạo lúc', value: formatThoiGian(this.currentAlert.timestamp) },
      { label: 'Cập nhật', value: formatThoiGian(this.currentAlert.updated_at) },
      { label: 'Phân tích viên', value: this.currentAlert.phan_tich_vien }
    ];

    metadata.forEach((item, idx) => {
      const row = document.createElement('tr');
      row.style.cssText = `
        border-bottom: 1px solid #00ff8822;
        background: ${idx % 2 === 0 ? 'rgba(0, 255, 136, 0.02)' : 'transparent'};
      `;

      const labelCell = document.createElement('td');
      labelCell.style.cssText = `
        padding: 8px;
        color: #00ff88;
        font-weight: 600;
        white-space: nowrap;
        width: 120px;
      `;
      labelCell.textContent = item.label;
      row.appendChild(labelCell);

      const valueCell = document.createElement('td');
      valueCell.style.cssText = `
        padding: 8px;
        color: #ccc;
        word-break: break-word;
        font-family: 'Courier New', monospace;
      `;
      valueCell.textContent = item.value || '—';
      row.appendChild(valueCell);

      metaTable.appendChild(row);
    });

    metaContainer.appendChild(metaTable);

    grid.appendChild(jsonContainer);
    grid.appendChild(metaContainer);
    container.appendChild(grid);
  }

  /**
   * Render CLASSIFICATION tab
   * @private
   */
  renderClassificationTab(container) {
    const form = document.createElement('div');
    form.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 16px;
      max-width: 600px;
    `;

    // Classification options
    const classTitle = document.createElement('h4');
    classTitle.textContent = '🏷 Phân loại cảnh báo';
    classTitle.style.cssText = `
      color: #00ff88;
      font-size: 12px;
      margin: 0;
      text-transform: uppercase;
    `;
    form.appendChild(classTitle);

    const options = [
      { value: 'true_positive', label: '✅ True Positive', color: '#00ff88' },
      { value: 'false_positive', label: '❌ False Positive', color: '#ff8800' },
      { value: 'needs_investigation', label: '⚠️ Cần điều tra', color: '#ffcc00' },
      { value: 'known_issue', label: '📋 Đã biết', color: '#00ccff' }
    ];

    const radioGroup = document.createElement('div');
    radioGroup.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 8px;
      padding: 12px;
      background: #1a1f1a;
      border-radius: 4px;
      border: 1px solid #00ff8844;
    `;

    options.forEach(opt => {
      const label = document.createElement('label');
      label.style.cssText = `
        display: flex;
        align-items: center;
        gap: 8px;
        cursor: pointer;
        color: #ccc;
        font-size: 12px;
      `;

      const radio = document.createElement('input');
      radio.type = 'radio';
      radio.name = 'classification';
      radio.value = opt.value;
      radio.style.cssText = `cursor: pointer;`;

      label.appendChild(radio);
      label.appendChild(document.createTextNode(opt.label));
      radioGroup.appendChild(label);
    });

    form.appendChild(radioGroup);

    // Analyst assignment
    const analystLabel = document.createElement('label');
    analystLabel.textContent = '👤 Giao cho phân tích viên:';
    analystLabel.style.cssText = `
      color: #00ff88;
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 600;
    `;
    form.appendChild(analystLabel);

    const analystSelect = document.createElement('select');
    analystSelect.style.cssText = `
      background: #1a1f1a;
      color: #ccc;
      border: 1px solid #00ff8844;
      padding: 8px;
      border-radius: 3px;
      font-size: 11px;
      font-family: 'Courier New', monospace;
    `;
    analystSelect.innerHTML = `
      <option value="">— Chưa giao —</option>
      <option value="analyst1">Analyst 1</option>
      <option value="analyst2">Analyst 2</option>
      <option value="analyst3">Analyst 3</option>
    `;
    analystSelect.value = this.currentAlert.phan_tich_vien || '';
    form.appendChild(analystSelect);

    // Notes
    const notesLabel = document.createElement('label');
    notesLabel.textContent = '📝 Ghi chú:';
    notesLabel.style.cssText = `
      color: #00ff88;
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 600;
    `;
    form.appendChild(notesLabel);

    const notesTextarea = document.createElement('textarea');
    notesTextarea.placeholder = 'Nhập ghi chú về cảnh báo...';
    notesTextarea.style.cssText = `
      background: #1a1f1a;
      color: #ccc;
      border: 1px solid #00ff8844;
      padding: 8px;
      border-radius: 3px;
      font-size: 11px;
      font-family: 'Courier New', monospace;
      resize: vertical;
      min-height: 100px;
    `;
    form.appendChild(notesTextarea);

    // Save button
    const saveBtn = document.createElement('button');
    saveBtn.innerHTML = '💾 LƯU PHÂN LOẠI';
    saveBtn.style.cssText = `
      background: #003300;
      color: #00ff88;
      border: 1px solid #00ff88;
      padding: 10px 16px;
      border-radius: 3px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 700;
      transition: all 200ms;
    `;
    saveBtn.addEventListener('mouseenter', () => {
      saveBtn.style.background = '#005500';
    });
    saveBtn.addEventListener('mouseleave', () => {
      saveBtn.style.background = '#003300';
    });
    saveBtn.addEventListener('click', () => {
      this.saveClassification(
        radioGroup.querySelector('input[name="classification"]:checked')?.value,
        analystSelect.value,
        notesTextarea.value
      );
    });
    form.appendChild(saveBtn);

    container.appendChild(form);
  }

  /**
   * Render HISTORY tab
   * @private
   */
  renderHistoryTab(container) {
    const timeline = document.createElement('div');
    timeline.style.cssText = `
      position: relative;
      padding: 20px 0 20px 40px;
    `;

    // Vertical line
    const line = document.createElement('div');
    line.style.cssText = `
      position: absolute;
      left: 10px;
      top: 0;
      bottom: 0;
      width: 2px;
      background: linear-gradient(180deg, #00ff88, transparent);
    `;
    timeline.appendChild(line);

    // Sample history events (in real implementation, fetch from API)
    const events = [
      { timestamp: this.currentAlert.timestamp, action: '✨ Cảnh báo được tạo', user: 'System' },
      { timestamp: new Date(new Date(this.currentAlert.timestamp).getTime() + 5 * 60000), action: '👀 Được xem', user: 'Analyst1' }
    ];

    events.forEach((event, idx) => {
      const item = document.createElement('div');
      item.style.cssText = `
        display: flex;
        gap: 16px;
        margin-bottom: 20px;
        position: relative;
      `;

      // Dot
      const dot = document.createElement('div');
      dot.style.cssText = `
        position: absolute;
        left: -35px;
        top: 4px;
        width: 8px;
        height: 8px;
        background: #00ff88;
        border-radius: 50%;
        border: 2px solid #0a0f0a;
        z-index: 1;
      `;
      item.appendChild(dot);

      // Content
      const content = document.createElement('div');
      content.style.cssText = `
        flex: 1;
        padding: 12px;
        background: #1a1f1a;
        border-radius: 4px;
        border-left: 2px solid #00ff88;
      `;

      const action = document.createElement('div');
      action.textContent = event.action;
      action.style.cssText = `
        color: #00ff88;
        font-weight: 600;
        font-size: 12px;
        margin-bottom: 4px;
      `;
      content.appendChild(action);

      const meta = document.createElement('div');
      meta.textContent = `${formatThoiGian(event.timestamp)} by ${event.user}`;
      meta.style.cssText = `
        color: #666;
        font-size: 10px;
        font-family: 'Courier New', monospace;
      `;
      content.appendChild(meta);

      item.appendChild(content);
      timeline.appendChild(item);
    });

    container.appendChild(timeline);
  }

  /**
   * Syntax highlight JSON
   * @private
   */
  syntaxHighlightJSON(json) {
    return json
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
        if (/^"/.test(match)) {
          if (/:$/.test(match)) {
            return `<span style="color:#00ff88">${match}</span>`;
          }
          return `<span style="color:#ffcc00">${match}</span>`;
        }
        if (/true|false/.test(match)) {
          return `<span style="color:#00ccff">${match}</span>`;
        }
        if (/null/.test(match)) {
          return `<span style="color:#888">${match}</span>`;
        }
        return `<span style="color:#ff8800">${match}</span>`;
      });
  }

  /**
   * Block IP
   * @private
   */
  blockIP(ip) {
    showToast('nghiem_trong', '🛡 Đang chặn IP', ip);
    // In real implementation, call API endpoint
    // POST /api/response {action: "block_ip", ip: ip}
  }

  /**
   * Save classification
   * @private
   */
  async saveClassification(classification, analyst, notes) {
    try {
      const response = await fetch(`/api/alerts/${this.currentAlert.alert_id}/classify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          classification,
          analyst,
          notes
        })
      });

      if (!response.ok) throw new Error(`API error: ${response.status}`);
      
      showToast('thanh_cong', '💾 Đã lưu phân loại', this.currentAlert.alert_id);
      this.close();
    } catch (error) {
      console.error('Error saving classification:', error);
      showToast('cao', '⚠️ Lỗi lưu', error.message);
    }
  }

  /**
   * Close modal
   */
  close() {
    if (this.backdrop && this.backdrop.parentNode) {
      this.backdrop.remove();
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CSS ANIMATIONS
// ═══════════════════════════════════════════════════════════════════════════

function injectAlertDetailAnimations() {
  if (document.getElementById('alert-detail-animations')) return;

  const style = document.createElement('style');
  style.id = 'alert-detail-animations';
  style.textContent = `
    @keyframes fadeIn {
      from {
        opacity: 0;
      }
      to {
        opacity: 1;
      }
    }

    @keyframes slideUp {
      from {
        transform: translate(-50%, 60%);
        opacity: 0;
      }
      to {
        transform: translate(-50%, -50%);
        opacity: 1;
      }
    }
  `;
  document.head.appendChild(style);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectAlertDetailAnimations);
} else {
  injectAlertDetailAnimations();
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { AlertDetailModal };
}
