/**
 * THREAT_HUNT_PAGE.JS — Advanced Threat Hunting Query Builder
 * 
 * Provides interactive threat hunting interface with real-time search,
 * filters, statistics, and results table with CSV export.
 * 
 * API: GET /api/hunt?q=query&hours=24&host=&ip_nguon=&rule_id=&level=&limit=100
 */

class ThreatHuntPage {
  constructor() {
    this.currentQuery = '';
    this.queryStats = {
      totalResults: 0,
      displayedResults: 0,
      executionTime: 0
    };
    this.searchResults = [];
    this.topAgents = [];
    this.topRules = [];
    this.topIPs = [];

    // Filter state
    this.filters = {
      timeRange: 24,        // hours
      host: '',
      src_ip: '',
      rule_id: '',
      level: '',            // severity filter
      limit: 100
    };

    // Quick search suggestions with context
    this.quickSearches = [
      { label: 'SSH brute force', query: 'ssh', tips: 'Often from automated scanners targeting port 22' },
      { label: 'Authentication failed', query: 'auth', tips: 'Check for coordinated attacks from multiple IPs' },
      { label: 'Privilege escalation', query: 'privilege', tips: 'High priority - may indicate lateral movement' },
      { label: 'File integrity', query: 'file integrity', tips: 'Check which files were modified and by whom' },
      { label: 'SQL injection', query: 'sql injection', tips: 'Likely web application attack - isolate affected servers' }
    ];
  }

  /**
   * Initialize page and render all sections
   */
  async init() {
    this.renderPageHeader();
    this.renderSearchSection();
    this.renderFiltersBar();
    this.renderQuickChips();
  }

  /**
   * Page header
   * @private
   */
  renderPageHeader() {
    const header = document.createElement('div');
    header.style.cssText = `
      padding: 20px;
      background: #111;
      border-bottom: 2px solid #00ffff;
      margin-bottom: 20px;
      border-radius: 6px;
    `;

    const title = document.createElement('h1');
    title.innerHTML = '🔍 Threat Hunting — Advanced Query Builder';
    title.style.cssText = `
      color: #00ffff;
      font-size: 24px;
      margin: 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;

    const subtitle = document.createElement('p');
    subtitle.textContent = 'Tìm kiếm, lọc và phân tích các cảnh báo bảo mật với query builder mạnh mẽ';
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
   * SECTION 1: Large Search Bar
   * @private
   */
  renderSearchSection() {
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 20px;
      background: #0a0f0a;
      border: 1px solid #00ffff33;
      border-radius: 6px;
      margin-bottom: 20px;
    `;

    const searchContainer = document.createElement('div');
    searchContainer.style.cssText = `
      position: relative;
      display: flex;
      gap: 12px;
      align-items: center;
    `;

    const icon = document.createElement('div');
    icon.textContent = '🔍';
    icon.style.cssText = `font-size: 24px; padding: 0 8px;`;

    const searchBox = document.createElement('input');
    searchBox.id = 'threat-hunt-search';
    searchBox.type = 'text';
    searchBox.placeholder = 'Tìm kiếm: ssh, brute force, T1110...';
    searchBox.style.cssText = `
      flex: 1;
      background: #1a1f1a;
      color: #00ffff;
      border: 2px solid #00ffff44;
      padding: 14px 16px;
      border-radius: 4px;
      font-size: 14px;
      font-family: 'Courier New', monospace;
      transition: all 200ms;
    `;

    searchBox.addEventListener('focus', () => {
      searchBox.style.borderColor = '#00ffff88';
      searchBox.style.boxShadow = '0 0 12px #00ffff22';
    });

    searchBox.addEventListener('blur', () => {
      searchBox.style.borderColor = '#00ffff44';
      searchBox.style.boxShadow = 'none';
    });

    const searchButton = document.createElement('button');
    searchButton.textContent = 'Tìm kiếm';
    searchButton.style.cssText = `
      background: #003366;
      color: #00ffff;
      border: 2px solid #00ffff;
      padding: 12px 24px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      cursor: pointer;
      transition: all 200ms;
      white-space: nowrap;
    `;

    searchButton.addEventListener('mouseenter', () => {
      searchButton.style.background = '#005588';
      searchButton.style.boxShadow = '0 0 12px #00ffff44';
    });

    searchButton.addEventListener('mouseleave', () => {
      searchButton.style.background = '#003366';
      searchButton.style.boxShadow = 'none';
    });

    searchButton.addEventListener('click', () => this.executeSearch());

    // Enter key to search
    searchBox.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        this.executeSearch();
      }
    });

    searchContainer.appendChild(icon);
    searchContainer.appendChild(searchBox);
    searchContainer.appendChild(searchButton);

    section.appendChild(searchContainer);
    document.body.appendChild(section);

    this.searchInput = searchBox;
  }

  /**
   * SECTION 2: Filters Bar
   * @private
   */
  renderFiltersBar() {
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 16px;
      background: #0a0f0a;
      border: 1px solid #00ff8833;
      border-radius: 6px;
      margin-bottom: 20px;
      overflow-x: auto;
    `;

    const title = document.createElement('div');
    title.textContent = '⚙ Bộ lọc';
    title.style.cssText = `
      color: #00ff88;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      margin-bottom: 12px;
    `;
    section.appendChild(title);

    const filtersContainer = document.createElement('div');
    filtersContainer.style.cssText = `
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
    `;

    const filterDefs = [
      { key: 'timeRange', label: 'Thời gian', options: [
        { label: '1 giờ', value: 1 },
        { label: '24 giờ', value: 24 },
        { label: '7 ngày', value: 168 },
        { label: '30 ngày', value: 720 }
      ]},
      { key: 'host', label: 'Máy chủ', type: 'text', placeholder: 'Hostname' },
      { key: 'src_ip', label: 'IP nguồn', type: 'text', placeholder: '192.168.x.x' },
      { key: 'rule_id', label: 'Rule ID', type: 'text', placeholder: '5503, 86...' },
      { key: 'level', label: 'Mức độ', options: [
        { label: 'Tất cả', value: '' },
        { label: 'Nghiêm trọng', value: '15+' },
        { label: 'Cao', value: '12-14' },
        { label: 'Trung bình', value: '7-11' },
        { label: 'Thấp', value: '1-6' }
      ]},
      { key: 'limit', label: 'Kết quả', options: [
        { label: '50', value: 50 },
        { label: '100', value: 100 },
        { label: '500', value: 500 },
        { label: '1000', value: 1000 }
      ]}
    ];

    filterDefs.forEach(filter => {
      const filterBox = document.createElement('div');
      filterBox.style.cssText = `
        display: flex;
        flex-direction: column;
        gap: 6px;
      `;

      const label = document.createElement('label');
      label.textContent = filter.label;
      label.style.cssText = `
        color: #888;
        font-size: 10px;
        text-transform: uppercase;
        font-weight: 600;
      `;

      if (filter.options) {
        const select = document.createElement('select');
        select.style.cssText = `
          background: #1a1f1a;
          color: #00ff88;
          border: 1px solid #00ff8844;
          padding: 6px 8px;
          border-radius: 3px;
          font-size: 11px;
          cursor: pointer;
        `;

        filter.options.forEach(opt => {
          const option = document.createElement('option');
          option.value = opt.value;
          option.textContent = opt.label;
          select.appendChild(option);
        });

        select.addEventListener('change', (e) => {
          this.filters[filter.key] = filter.key === 'limit' ? parseInt(e.target.value) : e.target.value;
        });

        filterBox.appendChild(label);
        filterBox.appendChild(select);
      } else {
        const input = document.createElement('input');
        input.type = filter.type || 'text';
        input.placeholder = filter.placeholder || '';
        input.style.cssText = `
          background: #1a1f1a;
          color: #00ff88;
          border: 1px solid #00ff8844;
          padding: 6px 8px;
          border-radius: 3px;
          font-size: 11px;
        `;

        input.addEventListener('change', (e) => {
          this.filters[filter.key] = e.target.value;
        });

        filterBox.appendChild(label);
        filterBox.appendChild(input);
      }

      filtersContainer.appendChild(filterBox);
    });

    section.appendChild(filtersContainer);
    document.body.appendChild(section);
  }

  /**
   * SECTION 3: Quick Search Chips
   * @private
   */
  renderQuickChips() {
    const section = document.createElement('div');
    section.style.cssText = `
      padding: 16px;
      background: #0a0f0a;
      border: 1px solid #ffcc0033;
      border-radius: 6px;
      margin-bottom: 20px;
    `;

    const title = document.createElement('div');
    title.textContent = '⭐ Tìm kiếm nhanh';
    title.style.cssText = `
      color: #ffcc00;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      margin-bottom: 12px;
    `;
    section.appendChild(title);

    const chipsContainer = document.createElement('div');
    chipsContainer.style.cssText = `
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    `;

    this.quickSearches.forEach((search, idx) => {
      const chip = document.createElement('button');
      chip.innerHTML = `<span style="display: block; white-space: nowrap;">${search.label}</span>`;
      chip.style.cssText = `
        background: #1a2a1a;
        color: #ffcc00;
        border: 1px solid #ffcc0044;
        padding: 8px 12px;
        border-radius: 20px;
        font-size: 11px;
        cursor: pointer;
        transition: all 200ms;
        white-space: nowrap;
      `;

      chip.addEventListener('mouseenter', () => {
        chip.style.background = '#2a4a2a';
        chip.style.borderColor = '#ffcc0088';
      });

      chip.addEventListener('mouseleave', () => {
        chip.style.background = '#1a2a1a';
        chip.style.borderColor = '#ffcc0044';
      });

      chip.addEventListener('click', () => {
        this.searchInput.value = search.query;
        this.showSearchContext(search);
        this.executeSearch();
      });

      chipsContainer.appendChild(chip);
    });

    section.appendChild(chipsContainer);
    document.body.appendChild(section);
  }

  /**
   * Show contextual tips for specific searches
   * @private
   */
  showSearchContext(search) {
    const existingTip = document.getElementById('search-context-tip');
    if (existingTip) existingTip.remove();

    const tip = document.createElement('div');
    tip.id = 'search-context-tip';
    tip.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: #1a1a2e;
      border: 2px solid #ffcc00;
      border-radius: 4px;
      padding: 12px 16px;
      color: #ffcc00;
      font-size: 11px;
      max-width: 250px;
      z-index: 1000;
      animation: slideInUp 300ms ease-out;
      box-shadow: 0 4px 12px rgba(255, 204, 0, 0.2);
    `;

    tip.textContent = `💡 ${search.tips}`;

    document.body.appendChild(tip);

    setTimeout(() => {
      tip.style.animation = 'slideOutDown 300ms ease-in forwards';
      setTimeout(() => tip.remove(), 300);
    }, 4000);
  }

  /**
   * Execute search query
   * @private
   */
  async executeSearch() {
    this.currentQuery = this.searchInput.value.trim();

    if (!this.currentQuery) {
      showToast('thong_tin', 'ℹ Yêu cầu', 'Vui lòng nhập từ khóa tìm kiếm');
      return;
    }

    // Show loading indicator
    const loadingDiv = document.getElementById('hunt-loading');
    if (!loadingDiv) {
      const loader = document.createElement('div');
      loader.id = 'hunt-loading';
      loader.style.cssText = `
        padding: 20px;
        text-align: center;
        color: #00ffff;
        font-size: 12px;
      `;
      loader.textContent = '⏳ Đang tìm kiếm...';
      document.body.appendChild(loader);
    }

    const startTime = Date.now();

    try {
      const params = new URLSearchParams({
        q: this.currentQuery,
        hours: this.filters.timeRange,
        host: this.filters.host,
        ip_nguon: this.filters.src_ip,
        rule_id: this.filters.rule_id,
        level: this.filters.level,
        limit: this.filters.limit
      });

      const response = await fetch(`/api/hunt?${params.toString()}`);
      if (!response.ok) throw new Error(`API error: ${response.status}`);

      const data = await response.json();

      // Update stats
      this.queryStats = {
        totalResults: data.total || 0,
        displayedResults: data.results.length || 0,
        executionTime: Date.now() - startTime
      };

      this.searchResults = data.results || [];
      this.topAgents = data.top_agents || [];
      this.topRules = data.top_rules || [];
      this.topIPs = data.top_ips || [];

      // Remove loading and render results
      document.getElementById('hunt-loading')?.remove();

      // Clear previous results sections
      document.getElementById('hunt-stats-cards')?.remove();
      document.getElementById('hunt-results-section')?.remove();

      this.renderStatCards();
      this.renderResultsTable();
    } catch (error) {
      console.error('Search error:', error);
      showToast('nghiem_trong', '🚨 Lỗi', 'Không thể tìm kiếm: ' + error.message);
      document.getElementById('hunt-loading')?.remove();
    }
  }

  /**
   * SECTION 4: Statistics Cards (Top Agents, Rules, IPs)
   * @private
   */
  renderStatCards() {
    const section = document.createElement('div');
    section.id = 'hunt-stats-cards';
    section.style.cssText = `
      padding: 20px;
      background: #0a0f0a;
      border: 1px solid #00ff8833;
      border-radius: 6px;
      margin-bottom: 20px;
    `;

    const title = document.createElement('h3');
    title.textContent = '📊 Thống kê tìm kiếm';
    title.style.cssText = `
      color: #00ff88;
      font-size: 14px;
      margin: 0 0 16px 0;
      text-transform: uppercase;
      letter-spacing: 1px;
    `;
    section.appendChild(title);

    const cardsContainer = document.createElement('div');
    cardsContainer.style.cssText = `
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 16px;
    `;

    // Top Agents Card
    if (this.topAgents.length > 0) {
      const agentCard = this.createBarChartCard('🖥 Agent hàng đầu', this.topAgents.slice(0, 5));
      cardsContainer.appendChild(agentCard);
    }

    // Top Rules Card
    if (this.topRules.length > 0) {
      const rulesCard = this.createBarChartCard('📋 Quy tắc hàng đầu', this.topRules.slice(0, 5));
      cardsContainer.appendChild(rulesCard);
    }

    // Top IPs Card
    if (this.topIPs.length > 0) {
      const ipsCard = this.createBarChartCard('🌐 IP tấn công hàng đầu', this.topIPs.slice(0, 5));
      cardsContainer.appendChild(ipsCard);
    }

    section.appendChild(cardsContainer);
    document.body.appendChild(section);
  }

  /**
   * Create bar chart card helper
   * @private
   */
  createBarChartCard(title, data) {
    const card = document.createElement('div');
    card.style.cssText = `
      background: #1a1f1a;
      border: 1px solid #00ff8844;
      border-radius: 4px;
      padding: 16px;
    `;

    const cardTitle = document.createElement('div');
    cardTitle.textContent = title;
    cardTitle.style.cssText = `
      color: #00ff88;
      font-size: 12px;
      font-weight: 700;
      margin-bottom: 12px;
    `;
    card.appendChild(cardTitle);

    const maxValue = Math.max(...data.map(d => d.count || d.value || 0));

    data.forEach((item, idx) => {
      const barContainer = document.createElement('div');
      barContainer.style.cssText = `
        margin-bottom: 10px;
        animation: slideInLeft 300ms ease-out ${idx * 50}ms both;
      `;

      const label = document.createElement('div');
      label.textContent = item.name || item.label || item.agent || item.rule || item.ip;
      label.style.cssText = `
        color: #888;
        font-size: 10px;
        margin-bottom: 4px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      `;

      const bar = document.createElement('div');
      bar.style.cssText = `
        background: #333;
        height: 20px;
        border-radius: 3px;
        overflow: hidden;
        position: relative;
      `;

      const fill = document.createElement('div');
      const percentage = (item.count || item.value || 0) / maxValue * 100;
      fill.style.cssText = `
        background: linear-gradient(90deg, #00ff88, #00ffff);
        height: 100%;
        width: ${percentage}%;
        transition: width 500ms ease-out;
        animation: grow 500ms ease-out ${idx * 50}ms both;
      `;

      const value = document.createElement('div');
      value.textContent = (item.count || item.value || 0).toLocaleString('vi-VN');
      value.style.cssText = `
        position: absolute;
        right: 8px;
        top: 50%;
        transform: translateY(-50%);
        color: #000;
        font-size: 9px;
        font-weight: 700;
        white-space: nowrap;
      `;

      bar.appendChild(fill);
      bar.appendChild(value);

      barContainer.appendChild(label);
      barContainer.appendChild(bar);
      card.appendChild(barContainer);
    });

    return card;
  }

  /**
   * SECTION 5: Results Table with CSV Export
   * @private
   */
  renderResultsTable() {
    const section = document.createElement('div');
    section.id = 'hunt-results-section';
    section.style.cssText = `
      padding: 20px;
      background: #0a0f0a;
      border: 1px solid #00ccff33;
      border-radius: 6px;
      margin-bottom: 20px;
    `;

    // Header with stats and export
    const header = document.createElement('div');
    header.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      flex-wrap: wrap;
      gap: 12px;
    `;

    const stats = document.createElement('div');
    stats.style.cssText = `
      color: #00ccff;
      font-size: 12px;
      font-family: 'Courier New', monospace;
    `;
    stats.innerHTML = `
      <strong>${this.queryStats.totalResults.toLocaleString('vi-VN')}</strong> kết quả · 
      Hiển thị <strong>${this.queryStats.displayedResults.toLocaleString('vi-VN')}</strong> · 
      <strong>${this.queryStats.executionTime}ms</strong>
    `;

    const exportBtn = document.createElement('button');
    exportBtn.textContent = '📥 Export CSV';
    exportBtn.style.cssText = `
      background: #003366;
      color: #00ccff;
      border: 1px solid #00ccff;
      padding: 8px 12px;
      border-radius: 3px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      transition: all 200ms;
    `;

    exportBtn.addEventListener('click', () => this.exportToCSV());
    exportBtn.addEventListener('mouseenter', () => {
      exportBtn.style.background = '#005588';
      exportBtn.style.boxShadow = '0 0 8px #00ccff44';
    });
    exportBtn.addEventListener('mouseleave', () => {
      exportBtn.style.background = '#003366';
      exportBtn.style.boxShadow = 'none';
    });

    header.appendChild(stats);
    header.appendChild(exportBtn);
    section.appendChild(header);

    // Table
    const tableContainer = document.createElement('div');
    tableContainer.style.cssText = `
      background: #050705;
      border-radius: 4px;
      overflow-x: auto;
      max-height: 800px;
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

    const headers = ['THỜI GIAN', 'AGENT', 'QUY TẮC PHÁT HIỆN', 'MỨC ĐỘ', 'IP NGUỒN', 'IP ĐÍCH', 'MITRE', 'QUỐC GIA', 'HÀNH ĐỘNG'];
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
    this.searchResults.slice(0, 100).forEach((alert, idx) => {
      const row = document.createElement('tr');
      row.style.cssText = `
        border-bottom: 1px solid #00ccff11;
        background: ${idx % 2 === 0 ? 'transparent' : 'rgba(0, 204, 255, 0.02)'};
        transition: background 200ms;
      `;

      row.addEventListener('mouseenter', () => {
        row.style.background = 'rgba(0, 204, 255, 0.08)';
      });
      row.addEventListener('mouseleave', () => {
        row.style.background = idx % 2 === 0 ? 'transparent' : 'rgba(0, 204, 255, 0.02)';
      });

      // Time
      const tdTime = document.createElement('td');
      tdTime.textContent = formatTuongDoi(alert.timestamp || new Date().toISOString());
      tdTime.style.cssText = `padding: 8px 12px; color: #888; white-space: nowrap;`;
      row.appendChild(tdTime);

      // Agent
      const tdAgent = document.createElement('td');
      tdAgent.textContent = alert.agent || alert.hostname || '—';
      tdAgent.style.cssText = `padding: 8px 12px; color: #00ff88; font-weight: 600;`;
      row.appendChild(tdAgent);

      // Rule
      const tdRule = document.createElement('td');
      tdRule.textContent = alert.rule?.description || alert.rule || '—';
      tdRule.style.cssText = `
        padding: 8px 12px;
        color: #ccc;
        max-width: 200px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      `;
      row.appendChild(tdRule);

      // Severity
      const tdSeverity = document.createElement('td');
      tdSeverity.innerHTML = renderBadgeMucDo(alert.rule?.level || 5);
      tdSeverity.style.cssText = `padding: 8px 12px;`;
      row.appendChild(tdSeverity);

      // Source IP
      const tdSrcIP = document.createElement('td');
      tdSrcIP.textContent = alert.data?.src_ip || '—';
      tdSrcIP.style.cssText = `
        padding: 8px 12px;
        color: #ffcc00;
        font-weight: 600;
        font-family: 'Courier New', monospace;
        cursor: pointer;
      `;
      tdSrcIP.addEventListener('click', () => {
        navigator.clipboard.writeText(tdSrcIP.textContent);
        showToast('thanh_cong', '✅ Sao chép', 'Đã sao chép IP');
      });
      row.appendChild(tdSrcIP);

      // Dest IP
      const tdDstIP = document.createElement('td');
      tdDstIP.textContent = alert.data?.dst_ip || '—';
      tdDstIP.style.cssText = `
        padding: 8px 12px;
        color: #ff8800;
        font-weight: 600;
        font-family: 'Courier New', monospace;
      `;
      row.appendChild(tdDstIP);

      // MITRE
      const tdMitre = document.createElement('td');
      tdMitre.textContent = alert.rule?.mitre?.technique_id || '—';
      tdMitre.style.cssText = `
        padding: 8px 12px;
        color: #00ffff;
        font-weight: 600;
        cursor: pointer;
      `;
      if (alert.rule?.mitre?.technique_id) {
        tdMitre.addEventListener('click', () => {
          window.open(`https://attack.mitre.org/techniques/${alert.rule.mitre.technique_id}`, '_blank');
        });
      }
      row.appendChild(tdMitre);

      // Country
      const tdCountry = document.createElement('td');
      tdCountry.textContent = alert.geoip?.country_name || '—';
      tdCountry.style.cssText = `padding: 8px 12px; color: #888;`;
      row.appendChild(tdCountry);

      // Actions
      const tdActions = document.createElement('td');
      tdActions.style.cssText = `padding: 8px 12px;`;

      const incidentBtn = document.createElement('button');
      incidentBtn.textContent = '+ Vụ việc';
      incidentBtn.style.cssText = `
        background: #333300;
        color: #ffcc00;
        border: 1px solid #ffcc00;
        padding: 4px 8px;
        border-radius: 2px;
        font-size: 9px;
        cursor: pointer;
        transition: all 150ms;
      `;

      incidentBtn.addEventListener('click', () => {
        showToast('thong_tin', '📋', 'Tạo vụ việc từ cảnh báo này');
        // TODO: Integrate with incident creation flow
      });

      incidentBtn.addEventListener('mouseenter', () => {
        incidentBtn.style.background = '#664400';
      });
      incidentBtn.addEventListener('mouseleave', () => {
        incidentBtn.style.background = '#333300';
      });

      tdActions.appendChild(incidentBtn);
      row.appendChild(tdActions);

      table.appendChild(row);
    });

    tableContainer.appendChild(table);
    section.appendChild(tableContainer);
    document.body.appendChild(section);
  }

  /**
   * Export results to CSV
   * @private
   */
  exportToCSV() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    const filename = `threat_hunt_${timestamp}.csv`;

    // Prepare CSV headers
    const headers = ['Thời gian', 'Agent', 'Quy tắc', 'Mức độ', 'IP nguồn', 'IP đích', 'MITRE', 'Quốc gia', 'Rule ID'];

    // Prepare CSV rows
    const rows = this.searchResults.map(alert => [
      alert.timestamp || '',
      alert.agent || alert.hostname || '',
      alert.rule?.description || alert.rule || '',
      alert.rule?.level || '',
      alert.data?.src_ip || '',
      alert.data?.dst_ip || '',
      alert.rule?.mitre?.technique_id || '',
      alert.geoip?.country_name || '',
      alert.rule?.id || ''
    ]);

    // Create CSV content
    let csv = headers.map(h => `"${h}"`).join(',') + '\n';
    csv += rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');

    // Trigger download
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);

    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    showToast('thanh_cong', '✅ Đã xuất', `Đã tải: ${filename}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CSS ANIMATIONS
// ═══════════════════════════════════════════════════════════════════════════

function injectThreatHuntAnimations() {
  if (document.getElementById('threat-hunt-animations')) return;

  const style = document.createElement('style');
  style.id = 'threat-hunt-animations';
  style.textContent = `
    @keyframes slideInLeft {
      from {
        opacity: 0;
        transform: translateX(-20px);
      }
      to {
        opacity: 1;
        transform: translateX(0);
      }
    }

    @keyframes grow {
      from {
        width: 0;
      }
      to {
        width: var(--width-target);
      }
    }

    @keyframes slideInUp {
      from {
        opacity: 0;
        transform: translateY(20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes slideOutDown {
      from {
        opacity: 1;
        transform: translateY(0);
      }
      to {
        opacity: 0;
        transform: translateY(20px);
      }
    }
  `;
  document.head.appendChild(style);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectThreatHuntAnimations);
} else {
  injectThreatHuntAnimations();
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ThreatHuntPage };
}
