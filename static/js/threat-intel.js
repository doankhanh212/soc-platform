/**
 * Threat Intel Page Controller
 * Task 1.1 -> 1.4
 */
(function () {
  'use strict';

  const state = {
    activeTab: 'lookup',
    iocs: [],
    iocFilters: { loai: 'tat_ca', muc_do: 'tat_ca' },
    showInlineAdd: false,
    feeds: [],
  };

  const IOC_TYPE_META = {
    ip: { label: 'IP', color: '#00aaff' },
    domain: { label: 'Domain', color: '#9333ea' },
    hash: { label: 'Hash', color: '#FFCC00' },
    url: { label: 'URL', color: '#888888' },
  };

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function notify(message, level = 'ok') {
    if (typeof window.toast === 'function') {
      window.toast(message, level);
      return;
    }
    console.log(message);
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function setupEvents() {
    const input = byId('ti-search-input');
    const btn = byId('ti-search-btn');
    if (btn) {
      btn.addEventListener('click', () => lookupFromInput());
    }
    if (input) {
      input.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          lookupFromInput();
        }
      });
    }

    const tabs = document.querySelectorAll('.ti-tab-btn');
    const panels = document.querySelectorAll('.ti-tab-panel');
    tabs.forEach((btnTab, i) => {
      btnTab.addEventListener('click', () => {
        tabs.forEach((t) => t.classList.remove('active'));
        panels.forEach((p) => { p.style.display = 'none'; });
        btnTab.classList.add('active');
        if (panels[i]) {
          panels[i].style.display = 'block';
        }
        if (i === 0) renderSearchPanel();
        if (i === 1) loadIOCList();
        if (i === 2) loadFeedSources();
      });
    });

    if (tabs[0]) {
      tabs[0].click();
    }
  }

  function renderSearchPanel() {
    const panel = byId('ti-search-panel');
    if (!panel) return;
    const resultArea = byId('ti-result-area');
    if (!resultArea || !String(resultArea.innerHTML || '').trim()) {
      panel.innerHTML = `
        <div id="ti-loading" class="ti-loading" style="display:none">
          <span class="ti-spinner"></span>
          <span>Đang truy vấn threat intelligence...</span>
        </div>
        <div id="ti-error" class="ti-error" style="display:none"></div>
        <div id="ti-result-area">
          <p style="color:#666;font-size:13px">Nhập IP, domain hoặc hash để tra cứu danh tiếng...</p>
        </div>
      `;
    }
  }

  function showLookupLoading(isLoading) {
    const loadingEl = byId('ti-loading');
    if (loadingEl) {
      loadingEl.style.display = isLoading ? 'flex' : 'none';
    }
  }

  function showLookupError(msg) {
    const errorEl = byId('ti-error');
    if (!errorEl) return;
    errorEl.style.display = msg ? 'block' : 'none';
    errorEl.textContent = msg || '';
  }

  function lookupFromInput() {
    const input = byId('ti-search-input');
    const query = String(input?.value || '').trim();
    if (!query) {
      showLookupError('Vui lòng nhập IP, domain hoặc hash để tra cứu.');
      return;
    }
    lookupIP(query);
  }

  async function lookupIP(query) {
    renderSearchPanel();
    const wrap = byId('ti-result-area');
    showLookupError('');
    showLookupLoading(true);
    if (wrap) wrap.innerHTML = '';

    try {
      const resp = await fetch(`/api/threatintel/lookup?q=${encodeURIComponent(query)}`);
      if (!resp.ok) {
        throw new Error('not_found');
      }
      const data = await resp.json();
      if (wrap) {
        wrap.innerHTML = renderIPResult(data);
      }
      bindResultActions(data);
    } catch (_error) {
      const mockData = {
        ip: query,
        abuse_score: 75,
        country: 'Unknown',
        country_code: 'XX',
        isp: 'Unknown ISP',
        usage_type: 'Unknown',
        is_tor: false,
        is_vpn: false,
        categories: ['SSH Brute Force'],
        total_reports: 100,
        so_canh_bao_wazuh: 0,
        mo_hinh_ai: [],
      };
      if (wrap) {
        wrap.innerHTML = renderIPResult(mockData);
      }
      showLookupError(`Không lấy được dữ liệu thật, đang hiển thị dữ liệu mô phỏng cho: ${query}`);
      bindResultActions(mockData);
    } finally {
      showLookupLoading(false);
    }
  }

  function riskColor(score) {
    const n = Number(score) || 0;
    if (n <= 30) return '#00ff88';
    if (n <= 70) return '#FFCC00';
    return '#FF4444';
  }

  function riskLabel(score) {
    const n = Number(score) || 0;
    if (n <= 30) return 'An toàn';
    if (n <= 70) return 'Đáng ngờ';
    return 'Nguy hiểm';
  }

  function scoreGauge(score) {
    const n = Math.max(0, Math.min(100, Number(score) || 0));
    const color = riskColor(n);
    const pct = n;
    return `
      <svg viewBox="0 0 220 130" class="ti-gauge" aria-label="Abuse score">
        <path d="M20 110 A90 90 0 0 1 200 110" class="ti-gauge-track"></path>
        <path d="M20 110 A90 90 0 0 1 200 110" class="ti-gauge-fill"
          style="stroke:${color};stroke-dasharray:${pct} 100"></path>
        <text x="110" y="92" text-anchor="middle" style="font-size:12px;fill:#8aa78a;">${escapeHtml(riskLabel(n))}</text>
        <text x="110" y="120" text-anchor="middle" style="font-size:32px;font-weight:700;fill:${color};">${n}</text>
      </svg>
    `;
  }

  function countryFlag(code) {
    if (!code || code.length < 2) return '🌐';
    const chars = String(code).slice(0, 2).toUpperCase().split('');
    return String.fromCodePoint(...chars.map((c) => 127397 + c.charCodeAt(0)));
  }

  function renderIPResult(data) {
    const categories = Array.isArray(data.categories) ? data.categories : [];
    const models = Array.isArray(data.mo_hinh_ai) ? data.mo_hinh_ai : [];

    return `
      <div class="ti-result-card">
        <div class="ti-result-top">
          <div class="ti-result-left">
            <div class="ti-result-ip">${escapeHtml(data.ip)}</div>
            <div class="ti-result-country">${countryFlag(data.country_code)} ${escapeHtml(data.country || 'Unknown')}</div>
            <div class="ti-result-isp">${escapeHtml(data.isp || 'AS-Unknown')}</div>
          </div>
          <div class="ti-result-center">
            ${scoreGauge(data.abuse_score)}
          </div>
          <div class="ti-result-right">
            <table class="ti-meta-table">
              <tr><td>Quốc gia</td><td>${escapeHtml(data.country || 'Unknown')}</td></tr>
              <tr><td>ISP</td><td>${escapeHtml(data.isp || 'AS-Unknown')}</td></tr>
              <tr><td>Loại</td><td>${escapeHtml(data.usage_type || 'Unknown')}</td></tr>
              <tr><td>Tor</td><td>${data.is_tor ? 'Có' : 'Không'}</td></tr>
              <tr><td>VPN</td><td>${data.is_vpn ? 'Có' : 'Không'}</td></tr>
            </table>
          </div>
        </div>
        <div class="ti-result-bottom">
          <div class="ti-cat-wrap">
            ${categories.map((c) => `<span class="ti-cat-badge">${escapeHtml(c)}</span>`).join('')}
          </div>
          <div class="ti-extra-metrics">
            <span>Wazuh ghi nhận: <strong>${window.formatSoLan ? formatSoLan(data.so_canh_bao_wazuh) : (Number(data.so_canh_bao_wazuh || 0)).toLocaleString('vi-VN')}</strong> lần</span>
            <span>AI phát hiện:
              ${models.length
                ? models.map((m) => `<span class="ti-ai-badge">${escapeHtml(m)}</span>`).join('')
                : '<span class="ti-muted">Chưa có</span>'
              }
            </span>
          </div>
        </div>
        <div class="ti-action-row">
          <button type="button" class="ti-btn ti-btn-block" id="ti-block-btn">🛡 Chặn IP</button>
          <button type="button" class="ti-btn ti-btn-case" id="ti-case-btn">📋 Tạo vụ việc</button>
          <button type="button" class="ti-btn ti-btn-hunt" id="ti-hunt-btn">🔍 Threat Hunt</button>
        </div>
      </div>
    `;
  }

  function bindResultActions(data) {
    const blockBtn = byId('ti-block-btn');
    const caseBtn = byId('ti-case-btn');
    const huntBtn = byId('ti-hunt-btn');

    if (blockBtn) {
      blockBtn.addEventListener('click', async () => {
        try {
          const payload = { action: 'block_ip', ip: data.ip };
          const res = await fetch('/api/response', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          if (!res.ok) throw new Error('block_failed');
          notify(`Đã gửi chặn IP ${data.ip}`, 'ok');
        } catch (_error) {
          notify(`Không thể chặn IP ${data.ip}`, 'err');
        }
      });
    }

    if (caseBtn) {
      caseBtn.addEventListener('click', async () => {
        try {
          if (!window.socApi || typeof window.socApi.createCase !== 'function') {
            throw new Error('api_missing');
          }
          await window.socApi.createCase({
            title: `Threat Intel: ${data.ip}`,
            severity: Number(data.abuse_score || 0) > 70 ? 'High' : 'Medium',
            src_ip: data.ip,
            agent: 'Threat Intel',
            rule_id: 'THREAT-INTEL',
            rule_desc: `IOC enrichment cho ${data.ip}`,
            mitre_ids: [],
          });
          notify(`Đã tạo vụ việc cho ${data.ip}`, 'ok');
        } catch (_error) {
          notify('Tạo vụ việc thất bại', 'err');
        }
      });
    }

    if (huntBtn) {
      huntBtn.addEventListener('click', () => {
        if (typeof window.navigate === 'function') {
          window.navigate('hunting');
          setTimeout(() => {
            const input = byId('hunt-ip');
            if (input) input.value = data.ip;
            if (window.huntApp && typeof window.huntApp.search === 'function') {
              window.huntApp.search();
            }
          }, 120);
        }
      });
    }
  }

  async function loadIOCList() {
    const panel = byId('ti-ioc-panel');
    if (!panel) return;
    if (!byId('ti-ioc-view')) {
      panel.innerHTML = '<div id="ti-ioc-view"></div>';
    }
    const wrap = byId('ti-ioc-view');
    if (!wrap) return;

    if (!state.iocs.length) {
      wrap.innerHTML = `<div class="ti-empty">Đang tải danh sách IOC...</div>`;
      try {
        const resp = await fetch('/api/threatintel/iocs?limit=100');
        if (!resp.ok) throw new Error('fetch_failed');
        state.iocs = await resp.json();
      } catch (_error) {
        wrap.innerHTML = `<div class="ti-empty">Không thể tải IOC từ hệ thống.</div>`;
        return;
      }
    }

    wrap.innerHTML = renderIOCTable();
    bindIOCControls();
    applyIOCFilters();
  }

  function renderIOCTable() {
    return `
      <div class="ti-ioc-wrap">
        <div class="ti-ioc-filters">
          <select id="ti-filter-loai" class="ti-select">
            <option value="tat_ca">Loại: Tất cả</option>
            <option value="ip">IP</option>
            <option value="domain">Domain</option>
            <option value="hash">Hash</option>
            <option value="url">URL</option>
          </select>
          <select id="ti-filter-mucdo" class="ti-select">
            <option value="tat_ca">Mức độ: Tất cả</option>
            <option value="cao">Cao</option>
            <option value="trung_binh">Trung bình</option>
            <option value="thap">Thấp</option>
          </select>
          <button type="button" id="ti-add-ioc-btn" class="ti-btn ti-btn-add">+ Thêm IOC</button>
        </div>
        <div class="ti-ioc-table-wrap">
          <table class="ti-ioc-table">
            <thead>
              <tr>
                <th>LOẠI</th>
                <th>GIÁ TRỊ</th>
                <th>MỨC ĐỘ</th>
                <th>MÔ TẢ</th>
                <th>NGUỒN</th>
                <th>LẦN CUỐI</th>
                <th>TRẠNG THÁI</th>
                <th>HÀNH ĐỘNG</th>
              </tr>
            </thead>
            <tbody id="ti-ioc-tbody"></tbody>
          </table>
        </div>
      </div>
    `;
  }

  function bindIOCControls() {
    const loai = byId('ti-filter-loai');
    const mucdo = byId('ti-filter-mucdo');
    const addBtn = byId('ti-add-ioc-btn');

    if (loai) {
      loai.value = state.iocFilters.loai;
      loai.addEventListener('change', () => {
        state.iocFilters.loai = loai.value;
        applyIOCFilters();
      });
    }
    if (mucdo) {
      mucdo.value = state.iocFilters.muc_do;
      mucdo.addEventListener('change', () => {
        state.iocFilters.muc_do = mucdo.value;
        applyIOCFilters();
      });
    }
    if (addBtn) {
      addBtn.addEventListener('click', () => {
        state.showInlineAdd = !state.showInlineAdd;
        applyIOCFilters();
      });
    }
  }

  function filteredIOCs() {
    return state.iocs.filter((row) => {
      const matchLoai = state.iocFilters.loai === 'tat_ca' || row.loai === state.iocFilters.loai;
      const matchMuc = state.iocFilters.muc_do === 'tat_ca' || row.muc_do === state.iocFilters.muc_do;
      return matchLoai && matchMuc;
    });
  }

  function severityBadge(mucDo) {
    const map = {
      cao: '#FF4444',
      trung_binh: '#FFCC00',
      thap: '#00FF88',
    };
    const color = map[mucDo] || '#888';
    return `<span class="ti-sev-badge" style="border-color:${color};color:${color};">${escapeHtml(mucDo.replace('_', ' '))}</span>`;
  }

  function typeBadge(loai) {
    const meta = IOC_TYPE_META[loai] || { label: loai, color: '#888' };
    return `<span class="ti-type-badge" style="border-color:${meta.color};color:${meta.color};">${escapeHtml(meta.label)}</span>`;
  }

  function applyIOCFilters() {
    const tbody = byId('ti-ioc-tbody');
    if (!tbody) return;

    const rows = filteredIOCs();
    const parts = [];

    if (state.showInlineAdd) {
      parts.push(`
        <tr class="ti-inline-add-row">
          <td>
            <select id="ti-new-loai" class="ti-select ti-select-sm">
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="hash">Hash</option>
              <option value="url">URL</option>
            </select>
          </td>
          <td><input id="ti-new-giatri" class="ti-input-sm" placeholder="Giá trị IOC"></td>
          <td>
            <select id="ti-new-mucdo" class="ti-select ti-select-sm">
              <option value="cao">Cao</option>
              <option value="trung_binh">Trung bình</option>
              <option value="thap">Thấp</option>
            </select>
          </td>
          <td><input id="ti-new-mota" class="ti-input-sm" placeholder="Mô tả"></td>
          <td><input id="ti-new-nguon" class="ti-input-sm" placeholder="Nguồn"></td>
          <td>${new Date().toLocaleString('vi-VN')}</td>
          <td>—</td>
          <td>
            <button type="button" class="ti-mini-btn" id="ti-save-new">Lưu</button>
          </td>
        </tr>
      `);
    }

    if (!rows.length) {
      parts.push(`<tr><td colspan="8" class="ti-empty-row">Không có IOC phù hợp bộ lọc.</td></tr>`);
      tbody.innerHTML = parts.join('');
      bindInlineSave();
      return;
    }

    rows.forEach((row) => {
      const typeMeta = IOC_TYPE_META[row.loai] || IOC_TYPE_META.url;
      parts.push(`
        <tr class="ti-ioc-row" data-ioc-id="${escapeHtml(row.ioc_id)}">
          <td>${typeBadge(row.loai)}</td>
          <td>
            <button type="button" class="ti-copy-link"
              data-copy="${escapeHtml(row.gia_tri)}"
              title="Click để copy">${escapeHtml(row.gia_tri)}</button>
          </td>
          <td>${severityBadge(row.muc_do)}</td>
          <td title="${escapeHtml(row.mo_ta)}">${escapeHtml(row.mo_ta)}</td>
          <td>${escapeHtml(row.nguon)}</td>
          <td>${window.formatThoiGian ? formatThoiGian(row.lan_cuoi) : escapeHtml(row.lan_cuoi)}</td>
          <td>
            <button type="button" class="ti-toggle-btn ${row.da_kich_hoat ? 'on' : ''}" data-toggle="${escapeHtml(row.ioc_id)}">
              ${row.da_kich_hoat ? 'ON' : 'OFF'}
            </button>
          </td>
          <td>
            <button type="button" class="ti-delete-btn" data-delete="${escapeHtml(row.ioc_id)}">X</button>
          </td>
        </tr>
      `);
    });

    tbody.innerHTML = parts.join('');

    tbody.querySelectorAll('[data-copy]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const value = btn.getAttribute('data-copy') || '';
        try {
          await navigator.clipboard.writeText(value);
          notify(`Đã copy: ${value}`, 'ok');
        } catch (_error) {
          notify('Không thể copy IOC', 'warn');
        }
      });
    });

    tbody.querySelectorAll('[data-toggle]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-toggle');
        const found = state.iocs.find((x) => x.ioc_id === id);
        if (!found) return;
        found.da_kich_hoat = !found.da_kich_hoat;
        applyIOCFilters();
      });
    });

    tbody.querySelectorAll('[data-delete]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-delete');
        state.iocs = state.iocs.filter((x) => x.ioc_id !== id);
        applyIOCFilters();
      });
    });

    bindInlineSave();
  }

  function bindInlineSave() {
    const saveBtn = byId('ti-save-new');
    if (!saveBtn) return;
    saveBtn.addEventListener('click', () => {
      const loai = String(byId('ti-new-loai')?.value || 'ip');
      const giaTri = String(byId('ti-new-giatri')?.value || '').trim();
      const mucDo = String(byId('ti-new-mucdo')?.value || 'trung_binh');
      const moTa = String(byId('ti-new-mota')?.value || '').trim();
      const nguon = String(byId('ti-new-nguon')?.value || 'Analyst').trim();
      if (!giaTri) {
        notify('Giá trị IOC không được để trống', 'warn');
        return;
      }
      state.iocs.unshift({
        ioc_id: `IOC-${Date.now()}`,
        loai,
        gia_tri: giaTri,
        muc_do: mucDo,
        mo_ta: moTa || 'IOC thêm thủ công',
        nguon: nguon || 'Analyst',
        lan_cuoi: new Date().toISOString(),
        da_kich_hoat: true,
      });
      state.showInlineAdd = false;
      applyIOCFilters();
      notify('Đã thêm IOC mới', 'ok');
    });
  }

  async function loadFeedSources() {
    const panel = byId('ti-feed-panel');
    if (!panel) return;
    if (!byId('ti-feed-view')) {
      panel.innerHTML = '<div id="ti-feed-view"></div>';
    }
    const wrap = byId('ti-feed-view');
    if (!wrap) return;

    if (!state.feeds.length) {
      wrap.innerHTML = `<div class="ti-empty">Đang tải feed nguồn...</div>`;
      try {
        const resp = await fetch('/api/threatintel/feeds');
        if (!resp.ok) throw new Error('feed_fail');
        state.feeds = await resp.json();
      } catch (_error) {
        wrap.innerHTML = `<div class="ti-empty">Không thể tải trạng thái feed.</div>`;
        return;
      }
    }

    wrap.innerHTML = `
      <div class="ti-feed-grid">
        ${state.feeds.map((feed) => {
          const connected = feed.trang_thai === 'ket_noi';
          return `
            <div class="ti-feed-card ${connected ? 'connected' : 'offline'}">
              <div class="ti-feed-head">
                <div class="ti-feed-icon">${escapeHtml(feed.icon || '🌐')}</div>
                <div>
                  <div class="ti-feed-name">${escapeHtml(feed.ten)}</div>
                  <div class="ti-feed-desc">${escapeHtml(feed.mo_ta)}</div>
                </div>
                <span class="ti-feed-status ${connected ? 'connected' : 'offline'}">
                  ${connected ? '● KẾT NỐI' : '● CHƯA KẾT NỐI'}
                </span>
              </div>
              <div class="ti-feed-meta">
                <div>IOC: <strong>${window.formatSoLan ? formatSoLan(feed.ioc_count) : Number(feed.ioc_count || 0).toLocaleString('vi-VN')}</strong></div>
                <div>Cập nhật: ${escapeHtml(feed.cap_nhat)}</div>
              </div>
              <div class="ti-feed-actions">
                <button type="button" class="ti-btn ti-btn-feed-cfg">⚙ Cấu hình</button>
                ${connected ? '<button type="button" class="ti-btn ti-btn-feed-sync">🔄 Đồng bộ ngay</button>' : ''}
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }

  function initThreatIntelPage() {
    if (!byId('page-threat-intel')) return;
    renderSearchPanel();
    setupEvents();
  }

  document.addEventListener('DOMContentLoaded', initThreatIntelPage);

  window.lookupIP = lookupIP;
  window.renderIPResult = renderIPResult;
  window.renderSearchPanel = renderSearchPanel;
  window.loadIOCList = loadIOCList;
  window.loadFeedSources = loadFeedSources;
  window.renderIOCList = loadIOCList;
  window.renderFeedSources = loadFeedSources;
})();
