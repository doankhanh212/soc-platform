/**
 * AI_ENGINE_PAGE.JS — Explainable AI Dashboard
 * 
 * PRINCIPLE: NEVER display algorithm names (IsolationForest, CUSUM, EWMA, Entropy)
 * Only show behavioral descriptions and reasoning in the UI.
 * Algorithm names used internally in JS only.
 */

class AIEnginePage {
  constructor() {
    this.aiMetrics = {
      anomalies_24h: 0,
      high_severity: 0,
      avg_risk_score: 0,
      auto_blocked_ips: 0,
      monitored_ips: 0
    };
    this.topDangerousIP = null;
    this.anomalyIPs = [];
  }

  /**
   * Initialize page and render all sections
   */
  async init() {
    this.renderPageHeader();
    this.renderStepper();
    this.renderMetricCards();
    this.renderMonitoringCards();
    this.renderMonitoredBehaviors();
    await this.loadAIMetrics();
    await this.loadAnomalies();
    this.renderDangerousIPPanel();
    this.renderAnomaliesTable();
  }

  /**
   * SECTION 0: Page Header
   * @private
   */
  renderPageHeader() {
    const header = document.createElement('div');
    header.style.cssText = `
      padding: 20px;
      background: #111;
      border-bottom: 2px solid #9333EA;
      margin-bottom: 20px;
      border-radius: 6px;
    `;

    const title = document.createElement('h1');
    title.innerHTML = '🤖 Động cơ AI — Explainable Anomaly Detection';
    title.style.cssText = `
      color: #9333EA;
      font-size: 24px;
      margin: 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;

    const subtitle = document.createElement('p');
    subtitle.textContent = 'Hiểu rõ cách AI phát hiện và phân loại mối đe dọa bảo mật';
    subtitle.style.cssText = `
      color: #888;
      font-size: 13px;
      margin: 8px 0 0 0;
      font-style: italic;
    `;

    header.appendChild(title);
    header.appendChild(subtitle);
    document.body.insertBefore(header, document.body.firstChild);
  }

  /**
   * SECTION 1: Stepper - AI Workflow Steps
   * @private
   */
  renderStepper() {
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 20px;
      background: #0a0f0a;
      border: 1px solid #9333ea33;
      border-radius: 6px;
      margin-bottom: 20px;
    `;

    const title = document.createElement('h3');
    title.textContent = '📋 AI Hoạt động như thế nào';
    title.style.cssText = `
      color: #9333ea;
      font-size: 14px;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    const stepperContainer = document.createElement('div');
    stepperContainer.style.cssText = `
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
      gap: 12px;
      padding: 12px;
      background: #050705;
      border-radius: 4px;
      overflow-x: auto;
    `;

    const steps = [
      { icon: '📥', label: 'Thu thập', desc: 'Lấy dữ liệu từ Wazuh, Suricata và syslog' },
      { icon: '⚙', label: 'Trích xuất', desc: 'Tính toán 4 đặc trưng: tần suất, độ đa dạng cổng, tốc độ kết nối, mức độ cảnh báo' },
      { icon: '🧠', label: '4 Lớp AI', desc: '4 phương pháp độc lập phân tích hành vi: bất thường, tăng đột biến, leo thang, mã hóa' },
      { icon: '📊', label: 'Tính điểm', desc: 'Kết hợp 4 điểm thành 1 điểm rủi ro tổng: 0.0 (an toàn) → 1.0 (nguy hiểm)' },
      { icon: '💬', label: 'Giải thích', desc: 'Tạo lý do bằng ngôn ngữ tự nhiên cho mỗi cảnh báo' },
      { icon: '🛡', label: 'Hành động', desc: 'Gợi ý hoặc tự động chặn IP theo mức độ rủi ro' }
    ];

    steps.forEach((step, idx) => {
      const box = document.createElement('div');
      box.style.cssText = `
        background: #0d1a0d;
        border: 2px solid #1a3a1a;
        border-radius: 6px;
        padding: 12px;
        text-align: center;
        min-height: 100px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        gap: 8px;
        cursor: pointer;
        transition: all 300ms;
        animation: stepperGlow 600ms ease-out ${idx * 100}ms forwards;
      `;

      const icon = document.createElement('div');
      icon.textContent = step.icon;
      icon.style.cssText = `font-size: 20px;`;

      const label = document.createElement('div');
      label.textContent = step.label;
      label.style.cssText = `
        color: #00ff88;
        font-size: 11px;
        font-weight: 700;
        white-space: nowrap;
      `;

      box.appendChild(icon);
      box.appendChild(label);

      box.addEventListener('mouseenter', () => {
        box.style.background = '#001a00';
        box.style.borderColor = '#00ff88';
        this.showTooltip(step.desc, box);
      });

      box.addEventListener('mouseleave', () => {
        box.style.background = '#0d1a0d';
        box.style.borderColor = '#1a3a1a';
        this.hideTooltip();
      });

      stepperContainer.appendChild(box);
    });

    section.appendChild(stepperContainer);
    document.body.appendChild(section);
  }

  /**
   * SECTION 2: 5 Metric Cards
   * @private
   */
  renderMetricCards() {
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 20px;
      background: #0a0f0a;
      border: 1px solid #00ff8833;
      border-radius: 6px;
      margin-bottom: 20px;
    `;

    const title = document.createElement('h3');
    title.textContent = '📊 Tóm tắt 24 giờ';
    title.style.cssText = `
      color: #00ff88;
      font-size: 14px;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    const metricsContainer = document.createElement('div');
    metricsContainer.style.cssText = `
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      padding: 12px;
      background: #050705;
      border-radius: 4px;
    `;

    const metrics = [
      { icon: '🤖', label: 'Bất thường AI', key: 'anomalies_24h', unit: 'sự kiện' },
      { icon: '🔴', label: 'Mức cao (HIGH)', key: 'high_severity', unit: 'cảnh báo' },
      { icon: '📈', label: 'Điểm RỦI RO TB', key: 'avg_risk_score', unit: '', format: (v) => v.toFixed(2) },
      { icon: '🛡', label: 'IP tự động chặn', key: 'auto_blocked_ips', unit: 'IP' },
      { icon: '👁', label: 'IP theo dõi', key: 'monitored_ips', unit: 'IP' }
    ];

    metrics.forEach(metric => {
      const card = document.createElement('div');
      card.style.cssText = `
        background: #1a1f1a;
        border: 1px solid #00ff8844;
        border-radius: 4px;
        padding: 16px;
        text-align: center;
      `;

      const icon = document.createElement('div');
      icon.textContent = metric.icon;
      icon.style.cssText = `font-size: 24px; margin-bottom: 8px;`;

      const label = document.createElement('div');
      label.textContent = metric.label;
      label.style.cssText = `
        color: #888;
        font-size: 11px;
        text-transform: uppercase;
        margin-bottom: 8px;
      `;

      const value = document.createElement('div');
      value.id = `metric-${metric.key}`;
      value.textContent = '—';
      value.style.cssText = `
        color: #00ff88;
        font-size: 24px;
        font-weight: 700;
        font-family: 'Courier New', monospace;
        margin-bottom: 4px;
      `;

      const unit = document.createElement('div');
      unit.textContent = metric.unit;
      unit.style.cssText = `
        color: #666;
        font-size: 10px;
      `;

      card.appendChild(icon);
      card.appendChild(label);
      card.appendChild(value);
      card.appendChild(unit);

      metricsContainer.appendChild(card);
      metric.valueElement = value;
    });

    section.appendChild(metricsContainer);
    document.body.appendChild(section);
    this.metricElements = metrics;
  }

  /**
   * SECTION 3: 4 Monitoring Cards (No Algorithm Names!)
   * @private
   */
  renderMonitoringCards() {
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 20px;
      background: #0a0f0a;
      border: 1px solid #ffcc0033;
      border-radius: 6px;
      margin-bottom: 20px;
    `;

    const title = document.createElement('h3');
    title.textContent = '🎯 Bộ phân tích hoạt động';
    title.style.cssText = `
      color: #ffcc00;
      font-size: 14px;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    const cardsContainer = document.createElement('div');
    cardsContainer.style.cssText = `
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      padding: 12px;
      background: #050705;
      border-radius: 4px;
    `;

    const monitors = [
      {
        icon: '🔍',
        title: 'Hành vi bất thường',
        desc: 'Phát hiện IP có hành vi khác biệt so với mẫu bình thường',
        statusAttr: 'behavior_anomaly'
      },
      {
        icon: '⚡',
        title: 'Đột biến lưu lượng',
        desc: 'Cảnh báo khi lưu lượng tăng đột ngột vượt ngưỡng',
        statusAttr: 'traffic_spike'
      },
      {
        icon: '📈',
        title: 'Leo thang âm thầm',
        desc: 'Theo dõi sự tăng dần liên tục chỉ trạng thái tấn công',
        statusAttr: 'behavioral_drift'
      },
      {
        icon: '🔐',
        title: 'Mã hóa & Dữ liệu ẩn',
        desc: 'Phát hiện file mã hóa hàng loạt hoặc DNS tunneling',
        statusAttr: 'encrypted_data'
      }
    ];

    monitors.forEach(monitor => {
      const card = document.createElement('div');
      card.style.cssText = `
        background: #1a1a1a;
        border: 1px solid #ffcc0044;
        border-radius: 4px;
        padding: 16px;
        position: relative;
      `;

      // Status badge
      const statusBadge = document.createElement('div');
      statusBadge.className = 'monitor-status';
      statusBadge.style.cssText = `
        position: absolute;
        top: 12px;
        right: 12px;
        background: #003300;
        color: #00ff88;
        padding: 4px 8px;
        border-radius: 3px;
        font-size: 9px;
        font-weight: 700;
        text-transform: uppercase;
      `;
      statusBadge.textContent = '🟢 ĐANG CHẠY';
      statusBadge.dataset.status = 'running';
      card.appendChild(statusBadge);

      const icon = document.createElement('div');
      icon.textContent = monitor.icon;
      icon.style.cssText = `font-size: 20px; margin-bottom: 8px;`;

      const title = document.createElement('div');
      title.textContent = monitor.title;
      title.style.cssText = `
        color: #ffcc00;
        font-size: 12px;
        font-weight: 700;
        margin-bottom: 8px;
      `;

      const desc = document.createElement('div');
      desc.textContent = monitor.desc;
      desc.style.cssText = `
        color: #888;
        font-size: 11px;
        line-height: 1.4;
        margin-bottom: 12px;
      `;

      const barContainer = document.createElement('div');
      barContainer.style.cssText = `
        margin-bottom: 8px;
      `;

      const barLabel = document.createElement('div');
      barLabel.textContent = 'Điểm TB';
      barLabel.style.cssText = `
        color: #666;
        font-size: 10px;
        margin-bottom: 4px;
      `;

      const bar = document.createElement('div');
      bar.style.cssText = `
        background: #333;
        height: 6px;
        border-radius: 3px;
        overflow: hidden;
      `;

      const fill = document.createElement('div');
      fill.style.cssText = `
        background: #ffcc00;
        height: 100%;
        width: 65%;
        transition: width 300ms;
      `;
      bar.appendChild(fill);

      barContainer.appendChild(barLabel);
      barContainer.appendChild(bar);

      const count = document.createElement('div');
      count.textContent = '2.847 bất thường hôm nay';
      count.style.cssText = `
        color: #ffcc00;
        font-size: 11px;
        font-weight: 600;
        font-family: 'Courier New', monospace;
      `;

      card.appendChild(icon);
      card.appendChild(title);
      card.appendChild(desc);
      card.appendChild(barContainer);
      card.appendChild(count);

      cardsContainer.appendChild(card);
    });

    section.appendChild(cardsContainer);
    document.body.appendChild(section);
  }

  /**
   * SECTION 4: Monitored Behaviors Widget
   * @private
   */
  renderMonitoredBehaviors() {
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 20px;
      background: #0a0f0a;
      border: 1px solid #00ccff33;
      border-radius: 6px;
      margin-bottom: 20px;
    `;

    const title = document.createElement('h3');
    title.textContent = '📡 AI đang theo dõi';
    title.style.cssText = `
      color: #00ccff;
      font-size: 14px;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    const behaviorsList = document.createElement('div');
    behaviorsList.style.cssText = `
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 12px;
      padding: 12px;
      background: #050705;
      border-radius: 4px;
    `;

    const behaviors = [
      { icon: '🔑', label: 'Đăng nhập bất thường', events: 99718, active: true },
      { icon: '🌐', label: 'Lưu lượng mạng', events: 48386, active: true },
      { icon: '📁', label: 'Thay đổi file', events: 0, active: false },
      { icon: '⚙', label: 'Hành vi tiến trình', events: 5, active: false }
    ];

    behaviors.forEach(behavior => {
      const item = document.createElement('div');
      item.style.cssText = `
        background: #1a1f1a;
        border: 1px solid #00ccff44;
        border-radius: 4px;
        padding: 12px;
        display: flex;
        gap: 12px;
        align-items: center;
        opacity: ${behavior.active ? '1' : '0.4'};
        transition: all 200ms;
      `;

      const leftSection = document.createElement('div');
      leftSection.style.cssText = `
        display: flex;
        gap: 8px;
        align-items: center;
        flex: 1;
      `;

      const status = document.createElement('div');
      status.style.cssText = `
        width: 8px;
        height: 8px;
        background: ${behavior.active ? '#00ff88' : '#666'};
        border-radius: 50%;
        ${behavior.active ? 'animation: pulse 2s ease-in-out infinite;' : ''}
      `;

      const icon = document.createElement('div');
      icon.textContent = behavior.icon;
      icon.style.cssText = `font-size: 16px;`;

      const content = document.createElement('div');
      content.style.cssText = `
        flex: 1;
      `;

      const label = document.createElement('div');
      label.textContent = behavior.label;
      label.style.cssText = `
        color: #00ccff;
        font-size: 11px;
        font-weight: 600;
      `;

      const eventCount = document.createElement('div');
      eventCount.textContent = `${behavior.events.toLocaleString('vi-VN')} sự kiện`;
      eventCount.style.cssText = `
        color: #666;
        font-size: 9px;
        font-family: 'Courier New', monospace;
      `;

      content.appendChild(label);
      content.appendChild(eventCount);

      leftSection.appendChild(status);
      leftSection.appendChild(icon);
      leftSection.appendChild(content);

      const status_text = document.createElement('div');
      status_text.textContent = behavior.active ? 'ACTIVE' : 'IDLE';
      status_text.style.cssText = `
        color: ${behavior.active ? '#00ff88' : '#666'};
        font-size: 9px;
        font-weight: 700;
        text-transform: uppercase;
        white-space: nowrap;
      `;

      item.appendChild(leftSection);
      item.appendChild(status_text);

      behaviorsList.appendChild(item);
    });

    section.appendChild(behaviorsList);
    document.body.appendChild(section);
  }

  /**
   * Load AI metrics from API
   * @private
   */
  async loadAIMetrics() {
    try {
      const response = await fetch('/api/ai/stats');
      if (!response.ok) throw new Error(`API error: ${response.status}`);
      const data = await response.json();

      this.aiMetrics = {
        anomalies_24h: data.anomalies_24h || 0,
        high_severity: data.high_severity || 0,
        avg_risk_score: data.avg_risk_score || 0,
        auto_blocked_ips: data.auto_blocked_ips || 0,
        monitored_ips: data.monitored_ips || 0
      };

      // Update metric cards
      this.metricElements?.forEach(metric => {
        const value = this.aiMetrics[metric.key];
        const formatted = metric.format ? metric.format(value) : value.toLocaleString('vi-VN');
        metric.valueElement.textContent = formatted;
      });
    } catch (error) {
      console.error('Error loading AI metrics:', error);
    }
  }

  /**
   * Load anomalies from API
   * @private
   */
  async loadAnomalies() {
    try {
      const response = await fetch('/api/ai/anomalies?limit=50');
      if (!response.ok) throw new Error(`API error: ${response.status}`);
      this.anomalyIPs = await response.json();

      if (this.anomalyIPs.length > 0) {
        this.topDangerousIP = this.anomalyIPs[0];
      }
    } catch (error) {
      console.error('Error loading anomalies:', error);
    }
  }

  /**
   * SECTION 5: Dangerous IP Panel with Explainable Reasons
   * @private
   */
  renderDangerousIPPanel() {
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 20px;
      background: #0a0f0a;
      border: 2px solid #ff4444;
      border-radius: 6px;
      margin-bottom: 20px;
    `;

    const title = document.createElement('h3');
    title.textContent = '🚨 TẠI SAO AI ĐÁNH DẤU IP NÀY?';
    title.style.cssText = `
      color: #ff4444;
      font-size: 14px;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    if (!this.topDangerousIP) {
      const placeholder = document.createElement('div');
      placeholder.textContent = '(Không có dữ liệu IP nguy hiểm)';
      placeholder.style.cssText = `color: #666; text-align: center; padding: 20px;`;
      section.appendChild(placeholder);
      document.body.appendChild(section);
      return;
    }

    const ip = this.topDangerousIP;

    // IP header with risk score
    const header = document.createElement('div');
    header.style.cssText = `
      background: #1a0000;
      border: 1px solid #ff444444;
      border-radius: 4px;
      padding: 16px;
      margin-bottom: 16px;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 20px;
      align-items: center;
    `;

    const ipInfo = document.createElement('div');
    const ipLabel = document.createElement('div');
    ipLabel.textContent = 'IP TẤN CÔNG:';
    ipLabel.style.cssText = `
      color: #666;
      font-size: 10px;
      text-transform: uppercase;
      margin-bottom: 4px;
    `;

    const ipValue = document.createElement('div');
    ipValue.textContent = ip.src_ip;
    ipValue.style.cssText = `
      color: #ff4444;
      font-size: 16px;
      font-weight: 700;
      font-family: 'Courier New', monospace;
      margin-bottom: 8px;
    `;

    const locationLabel = document.createElement('div');
    locationLabel.textContent = `📍 ${ip.country || 'Unknown'}`;
    locationLabel.style.cssText = `
      color: #888;
      font-size: 11px;
    `;

    ipInfo.appendChild(ipLabel);
    ipInfo.appendChild(ipValue);
    ipInfo.appendChild(locationLabel);

    const scoreSection = document.createElement('div');
    scoreSection.style.cssText = `
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 8px;
    `;

    const scoreBar = document.createElement('div');
    scoreBar.style.cssText = `
      width: 200px;
      height: 30px;
      background: #333;
      border-radius: 4px;
      overflow: hidden;
      border: 1px solid #ff444444;
    `;

    const scoreFill = document.createElement('div');
    scoreFill.style.cssText = `
      height: 100%;
      background: linear-gradient(90deg, #ff8800, #ff4444);
      width: ${(ip.risk_score || 0) * 100}%;
      transition: width 500ms;
    `;
    scoreBar.appendChild(scoreFill);

    const scoreLabel = document.createElement('div');
    scoreLabel.style.cssText = `
      text-align: center;
      color: #ff4444;
      font-size: 12px;
      font-weight: 700;
      font-family: 'Courier New', monospace;
    `;
    scoreLabel.textContent = `Điểm rủi ro: ${(ip.risk_score || 0).toFixed(2)}`;

    const actionLabel = document.createElement('div');
    actionLabel.innerHTML = renderActionSuggestion(ip.risk_score || 0);
    actionLabel.style.cssText = `text-align: right; margin-top: 4px;`;

    scoreSection.appendChild(scoreBar);
    scoreSection.appendChild(scoreLabel);
    scoreSection.appendChild(actionLabel);

    header.appendChild(ipInfo);
    header.appendChild(scoreSection);
    section.appendChild(header);

    // Explainable reasons
    const reasons = this.buildExplainableReasons(ip);
    const reasonsContainer = document.createElement('div');
    reasonsContainer.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-bottom: 16px;
    `;

    reasons.forEach((reason, idx) => {
      const reasonBox = document.createElement('div');
      reasonBox.style.cssText = `
        background: #1a1a1a;
        border-left: 4px solid #ff4444;
        padding: 12px;
        border-radius: 3px;
      `;

      const main = document.createElement('div');
      main.textContent = reason.main;
      main.style.cssText = `
        color: #ff4444;
        font-size: 12px;
        font-weight: 600;
        margin-bottom: 6px;
      `;

      const evidence = document.createElement('div');
      evidence.textContent = reason.evidence;
      evidence.style.cssText = `
        color: #888;
        font-size: 11px;
        font-family: 'Courier New', monospace;
      `;

      reasonBox.appendChild(main);
      reasonBox.appendChild(evidence);
      reasonsContainer.appendChild(reasonBox);
    });

    section.appendChild(reasonsContainer);

    // Action buttons
    const buttonBar = document.createElement('div');
    buttonBar.style.cssText = `
      display: flex;
      gap: 12px;
    `;

    const buttons = [
      { text: '🔍 Threat Hunt', color: '#00ccff', bg: '#003366' },
      { text: '📋 Tạo vụ việc', color: '#ffcc00', bg: '#333300' },
      { text: '🛡 Chặn thủ công', color: '#ff4444', bg: '#660000' }
    ];

    buttons.forEach(btn => {
      const button = document.createElement('button');
      button.textContent = btn.text;
      button.style.cssText = `
        background: ${btn.bg};
        color: ${btn.color};
        border: 1px solid ${btn.color};
        padding: 8px 12px;
        border-radius: 3px;
        cursor: pointer;
        font-size: 11px;
        font-weight: 600;
        transition: all 200ms;
      `;
      button.addEventListener('mouseenter', () => {
        button.style.boxShadow = `0 0 12px ${btn.color}44`;
      });
      button.addEventListener('mouseleave', () => {
        button.style.boxShadow = 'none';
      });
      buttonBar.appendChild(button);
    });

    section.appendChild(buttonBar);
    document.body.appendChild(section);
  }

  /**
   * Build explainable reasons for IP (NO algorithm names!)
   * @private
   */
  buildExplainableReasons(ip) {
    const reasons = [];

    // Port scanning detection
    if (ip.unique_dest_ports >= 10) {
      reasons.push({
        main: `Kết nối đến NHIỀU cổng — dấu hiệu đang quét tìm lỗ hổng`,
        evidence: `Đã kết nối tới ${ip.unique_dest_ports} cổng (bình thường < 5)`
      });
    }

    // Behavioral drift (CUSUM internally)
    if (ip.cusum_s >= 5.0) {
      reasons.push({
        main: `Hành vi leo thang liên tục trong 2 giờ qua`,
        evidence: `Chỉ số tích lũy: ${(ip.cusum_s || 0).toFixed(2)} (ngưỡng ≥ 5.0)`
      });
    }

    // Outlier detection (IsolationForest internally)
    if (ip.if_percentile >= 90) {
      const pct = 100 - ip.if_percentile;
      reasons.push({
        main: `Top ${pct}% IP có hành vi khác biệt nhất từng gặp`,
        evidence: `Điểm bất thường: ${(ip.if_score || 0).toFixed(4)} · percentile ${ip.if_percentile}`
      });
    }

    // High alert frequency (EWMA internally)
    if (ip.so_canh_bao_1h >= 1000) {
      reasons.push({
        main: `Tấn công cường độ cao — ${ip.so_canh_bao_1h.toLocaleString('vi-VN')} lần trong 1 giờ`,
        evidence: `Tổng: ${ip.so_canh_bao.toLocaleString('vi-VN')} lần`
      });
    }

    // Default if no specific reason
    if (reasons.length === 0) {
      reasons.push({
        main: `Kết hợp nhiều yếu tố tạo nên điểm rủi ro cao`,
        evidence: `Điểm: ${(ip.risk_score || 0).toFixed(2)}`
      });
    }

    return reasons;
  }

  /**
   * SECTION 6: Anomalies Table
   * @private
   */
  renderAnomaliesTable() {
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 20px;
      background: #0a0f0a;
      border: 1px solid #00ccff33;
      border-radius: 6px;
      margin-bottom: 20px;
    `;

    const title = document.createElement('h3');
    title.textContent = '🌐 Bảng IP bất thường (Explainable)';
    title.style.cssText = `
      color: #00ccff;
      font-size: 14px;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    // Filter dropdown
    const filterBar = document.createElement('div');
    filterBar.style.cssText = `
      margin-bottom: 12px;
      display: flex;
      gap: 12px;
      align-items: center;
    `;

    const filterLabel = document.createElement('label');
    filterLabel.textContent = 'Mức độ:';
    filterLabel.style.cssText = `color: #888; font-size: 11px; font-weight: 600;`;

    const filterSelect = document.createElement('select');
    filterSelect.style.cssText = `
      background: #1a1f1a;
      color: #00ccff;
      border: 1px solid #00ccff44;
      padding: 6px 8px;
      border-radius: 3px;
      font-size: 11px;
      cursor: pointer;
    `;
    filterSelect.innerHTML = `
      <option value="">Tất cả</option>
      <option value="15+">NGHIÊM TRỌNG (15+)</option>
      <option value="12-14">CAO (12-14)</option>
      <option value="7-11">TRUNG BÌNH (7-11)</option>
      <option value="1-6">THẤP (1-6)</option>
    `;

    filterBar.appendChild(filterLabel);
    filterBar.appendChild(filterSelect);
    section.appendChild(filterBar);

    // Table container
    const tableContainer = document.createElement('div');
    tableContainer.style.cssText = `
      background: #050705;
      border-radius: 4px;
      overflow-x: auto;
      max-height: 600px;
      overflow-y: auto;
    `;

    const table = document.createElement('table');
    table.style.cssText = `
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
    `;

    // Header
    const headerRow = document.createElement('tr');
    headerRow.style.cssText = `
      background: #111;
      border-bottom: 2px solid #00ccff;
      position: sticky;
      top: 0;
      z-index: 10;
    `;

    const headers = ['THỜI GIAN', 'IP TẤN CÔNG', 'QUỐC GIA', 'ĐIỂM RỦI RO', 'MỨC ĐỘ', 'AI PHÁT HIỆN GÌ', 'HÀNH ĐỘNG GỢI Ý'];
    headers.forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      th.style.cssText = `
        text-align: left;
        padding: 12px;
        color: #00ccff;
        font-weight: 700;
        border-right: 1px solid #00ccff22;
      `;
      headerRow.appendChild(th);
    });
    table.appendChild(headerRow);

    // Rows
    this.anomalyIPs.slice(0, 20).forEach((ip, idx) => {
      const row = document.createElement('tr');
      row.style.cssText = `
        border-bottom: 1px solid #00ccff11;
        background: ${idx % 2 === 0 ? 'transparent' : 'rgba(0, 204, 255, 0.02)'};
        cursor: pointer;
        transition: background 200ms;
      `;

      row.addEventListener('mouseenter', () => {
        row.style.background = 'rgba(0, 204, 255, 0.08)';
      });
      row.addEventListener('mouseleave', () => {
        row.style.background = idx % 2 === 0 ? 'transparent' : 'rgba(0, 204, 255, 0.02)';
      });

      // Timestamp
      const tdTime = document.createElement('td');
      tdTime.textContent = formatTuongDoi(ip.timestamp);
      tdTime.style.cssText = `padding: 8px 12px; color: #888; white-space: nowrap;`;
      row.appendChild(tdTime);

      // IP
      const tdIP = document.createElement('td');
      tdIP.textContent = ip.src_ip;
      tdIP.style.cssText = `
        padding: 8px 12px;
        color: #ffcc00;
        font-weight: 600;
        font-family: 'Courier New', monospace;
      `;
      row.appendChild(tdIP);

      // Country
      const tdCountry = document.createElement('td');
      tdCountry.textContent = ip.country || '—';
      tdCountry.style.cssText = `padding: 8px 12px; color: #888;`;
      row.appendChild(tdCountry);

      // Risk score with bar
      const tdRisk = document.createElement('td');
      tdRisk.style.cssText = `padding: 8px 12px;`;
      const riskBar = document.createElement('div');
      riskBar.style.cssText = `
        background: #222;
        height: 16px;
        border-radius: 2px;
        overflow: hidden;
        width: 80px;
        position: relative;
      `;
      const riskFill = document.createElement('div');
      riskFill.style.cssText = `
        background: linear-gradient(90deg, #ffcc00, #ff4444);
        height: 100%;
        width: ${(ip.risk_score || 0) * 100}%;
      `;
      riskBar.appendChild(riskFill);
      const riskText = document.createElement('div');
      riskText.textContent = (ip.risk_score || 0).toFixed(2);
      riskText.style.cssText = `
        color: #00ccff;
        font-size: 9px;
        font-weight: 600;
        font-family: 'Courier New', monospace;
        margin-top: 2px;
      `;
      tdRisk.appendChild(riskBar);
      tdRisk.appendChild(riskText);
      row.appendChild(tdRisk);

      // Severity
      const tdSeverity = document.createElement('td');
      tdSeverity.innerHTML = renderBadgeMucDo(ip.rule_level);
      tdSeverity.style.cssText = `padding: 8px 12px;`;
      row.appendChild(tdSeverity);

      // AI findings
      const tdAI = document.createElement('td');
      tdAI.style.cssText = `padding: 8px 12px; min-width: 200px;`;
      const badgesHtml = renderModelBadges(ip.models_triggered || []);
      tdAI.innerHTML = badgesHtml;
      row.appendChild(tdAI);

      // Action suggestion
      const tdAction = document.createElement('td');
      tdAction.style.cssText = `padding: 8px 12px;`;
      tdAction.innerHTML = renderActionSuggestion(ip.risk_score || 0);
      row.appendChild(tdAction);

      table.appendChild(row);
    });

    tableContainer.appendChild(table);
    section.appendChild(tableContainer);
    document.body.appendChild(section);
  }

  /**
   * Show tooltip
   * @private
   */
  showTooltip(text, element) {
    const tooltip = document.createElement('div');
    tooltip.style.cssText = `
      position: fixed;
      background: #1a1f1a;
      border: 1px solid #9333ea;
      border-radius: 4px;
      padding: 8px 12px;
      font-size: 11px;
      color: #ccc;
      pointer-events: none;
      z-index: 10000;
      max-width: 200px;
      white-space: normal;
    `;
    tooltip.textContent = text;
    document.body.appendChild(tooltip);

    const rect = element.getBoundingClientRect();
    tooltip.style.top = (rect.top - 50) + 'px';
    tooltip.style.left = (rect.left + rect.width / 2 - 100) + 'px';

    this.currentTooltip = tooltip;
  }

  /**
   * Hide tooltip
   * @private
   */
  hideTooltip() {
    if (this.currentTooltip) {
      this.currentTooltip.remove();
      this.currentTooltip = null;
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CSS ANIMATIONS
// ═══════════════════════════════════════════════════════════════════════════

function injectAIEngineAnimations() {
  if (document.getElementById('ai-engine-animations')) return;

  const style = document.createElement('style');
  style.id = 'ai-engine-animations';
  style.textContent = `
    @keyframes stepperGlow {
      from {
        opacity: 0;
        transform: translateY(20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes pulse {
      0%, 100% {
        opacity: 1;
      }
      50% {
        opacity: 0.5;
      }
    }
  `;
  document.head.appendChild(style);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectAIEngineAnimations);
} else {
  injectAIEngineAnimations();
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { AIEnginePage };
}
