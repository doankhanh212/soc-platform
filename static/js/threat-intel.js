/*
 * Threat Intel UI (rewrite)
 * Dark theme #0a0f0a, accent #00ff88
 * Vanilla JS, full Vietnamese content
 */

function _css(v){ return getComputedStyle(document.documentElement).getPropertyValue(v).trim(); }

const TI_THEME = {
  get bg()     { return _css('--bg') || '#0a0f0a'; },
  get accent() { return _css('--green') || '#00ff88'; },
};

const TI_STATE = {
  iocItems: [],
};

function tiEsc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function tiNotify(message, level = 'ok') {
  if (typeof window.toast === 'function') {
    window.toast(message, level);
    return;
  }
  console.log(message);
}

function ensureThreatIntelContainer() {
  let container = document.getElementById('threat-intel-content');
  if (container) return container;

  const page = document.getElementById('page-threat-intel');
  if (!page) return null;

  container = document.createElement('div');
  container.id = 'threat-intel-content';
  page.appendChild(container);
  return container;
}

function initThreatIntel() {
  const container = ensureThreatIntelContainer();
  if (!container) return;
  renderThreatIntelLayout();
  switchTab('search');
}

function renderThreatIntelLayout() {
  const container = ensureThreatIntelContainer();
  if (!container) return;

  container.innerHTML = `
    <div style="padding:20px 24px;background:${TI_THEME.bg};min-height:100%">
      <h2 style="color:${TI_THEME.accent};font-size:20px;font-weight:600;margin-bottom:4px">
        Threat Intelligence
      </h2>
      <p style="color:var(--muted);font-size:13px;margin-bottom:20px">
        IOC Enrichment · Nguồn đe dọa bên ngoài
      </p>

      <div style="display:flex;gap:8px;margin-bottom:16px">
        <input id="ti-search-input" type="text"
          placeholder="Nhập IP, domain, hash để tra cứu..."
          style="flex:1;padding:10px 14px;background:var(--bg1);border:1px solid var(--border-subtle);
                 border-radius:6px;color:var(--text);font-size:14px;outline:none"
          onkeydown="if(event.key==='Enter') doLookup()"
        />
        <button onclick="doLookup()"
          style="padding:10px 20px;background:var(--bg1);border:1px solid ${TI_THEME.accent};
                 color:${TI_THEME.accent};border-radius:6px;font-size:13px;cursor:pointer;
                 font-weight:500;white-space:nowrap">
          🔍 Tra cứu
        </button>
      </div>

      <div style="display:flex;gap:8px;margin-bottom:20px;border-bottom:1px solid var(--border-subtle);padding-bottom:0">
        <button class="ti-tab active" onclick="switchTab('search')" id="tab-search">Tra cứu IP</button>
        <button class="ti-tab" onclick="switchTab('ioc')" id="tab-ioc">Danh sách IOC</button>
        <button class="ti-tab" onclick="switchTab('feeds')" id="tab-feeds">Feed nguồn</button>
      </div>

      <div id="panel-search">
        <div id="ti-result-area">
          <div style="text-align:center;padding:40px 0;color:var(--muted);font-size:13px">
            🔍 Nhập IP, domain hoặc hash để tra cứu danh tiếng và thông tin mối đe dọa
          </div>
        </div>
      </div>
      <div id="panel-ioc" style="display:none"></div>
      <div id="panel-feeds" style="display:none"></div>
    </div>
  `;

  if (!document.getElementById('ti-style')) {
    const style = document.createElement('style');
    style.id = 'ti-style';
    style.textContent = `
      .ti-tab {
        padding: 8px 18px;
        background: transparent;
        border: none;
        border-bottom: 2px solid transparent;
        color: var(--muted);
        font-size: 13px;
        cursor: pointer;
        margin-bottom: -1px;
      }
      .ti-tab:hover { color: var(--text); }
      .ti-tab.active { color: var(--green); border-bottom-color: var(--green); }
      .ti-card {
        background:var(--bg1);
        border:1px solid var(--border);
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
      }
      .ti-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
      }
      @media (max-width: 1024px) {
        #panel-feeds > div {
          grid-template-columns: 1fr !important;
        }
      }
      @media (max-width: 900px) {
        #ti-result-area .ti-meta-grid {
          grid-template-columns: 1fr !important;
        }
      }
    `;
    document.head.appendChild(style);
  }
}

function switchTab(tab) {
  ['search', 'ioc', 'feeds'].forEach((name) => {
    const panel = document.getElementById(`panel-${name}`);
    const button = document.getElementById(`tab-${name}`);
    if (panel) panel.style.display = 'none';
    if (button) button.classList.remove('active');
  });

  const targetPanel = document.getElementById(`panel-${tab}`);
  const targetBtn = document.getElementById(`tab-${tab}`);
  if (targetPanel) targetPanel.style.display = 'block';
  if (targetBtn) targetBtn.classList.add('active');

  if (tab === 'ioc') loadIOCList();
  if (tab === 'feeds') loadFeedSources();
}

async function doLookup() {
  const input = document.getElementById('ti-search-input');
  const query = String(input?.value || '').trim();
  if (!query) return;

  const area = document.getElementById('ti-result-area');
  if (!area) return;
  area.innerHTML = `<div style="color:var(--medium);font-size:13px;padding:20px 0">⏳ Đang tra cứu ${tiEsc(query)}...</div>`;

  try {
    // Try existing threatintel endpoint first, fallback to AI lookup-ip
    let data = null;
    try {
      const res = await fetch(`/api/threatintel/lookup?q=${encodeURIComponent(query)}`);
      data = await res.json();
      if (data && data.error) data = null;
    } catch (_) {}

    if (!data) {
      const res2 = await fetch(`/api/ai/lookup-ip?ip=${encodeURIComponent(query)}`, { method: 'POST' });
      const d2 = await res2.json();
      if (d2 && !d2.error) {
        data = {
          ip: d2.ip,
          abuse_score: d2.abuse_score || 0,
          country: d2.country || 'Unknown',
          country_code: d2.country || 'XX',
          isp: d2.isp || 'Unknown',
          usage_type: d2.usage_type || 'Unknown',
          is_tor: d2.is_tor || false,
          is_vpn: false,
          total_reports: d2.total_reports || 0,
          last_reported: d2.last_reported || null,
          categories: [],
          mo_hinh_ai: [],
        };
      }
    }
    area.innerHTML = renderIPResultCard(data || buildMockResult(query));
  } catch (_error) {
    area.innerHTML = renderIPResultCard(buildMockResult(query));
  }
}

function buildMockResult(ip) {
  return {
    ip,
    abuse_score: 0,
    country: 'Unknown',
    country_code: 'XX',
    isp: 'Chưa có dữ liệu',
    usage_type: 'Unknown',
    is_tor: false,
    is_vpn: false,
    categories: [],
    total_reports: 0,
    last_reported: null,
    so_canh_bao_wazuh: 0,
    mo_hinh_ai: [],
    note: 'Chưa có dữ liệu từ feed. Kết nối AbuseIPDB để tra cứu thật.',
  };
}

function renderIPResultCard(data) {
  const d = data || {};
  const score = Math.max(0, Math.min(100, Number(d.abuse_score || 0)));
  const scoreColor = score >= 70 ? (_css('--red') || '#FF4444') : score >= 30 ? (_css('--medium') || '#FFCC00') : (_css('--green') || '#00ff88');
  const scoreLabel = score >= 70 ? 'NGUY HIỂM' : score >= 30 ? 'ĐÁNG NGỜ' : 'AN TOÀN';

  const flags = {
    VN: '🇻🇳', US: '🇺🇸', CN: '🇨🇳', RU: '🇷🇺', MM: '🇲🇲',
    DE: '🇩🇪', FR: '🇫🇷', GB: '🇬🇧', KR: '🇰🇷', JP: '🇯🇵',
  };
  const flag = flags[String(d.country_code || '').toUpperCase()] || '🌐';

  const categories = Array.isArray(d.categories) ? d.categories : [];
  const models = Array.isArray(d.mo_hinh_ai) ? d.mo_hinh_ai : [];
  const safeIp = String(d.ip || '');

  const categoryHtml = categories.length
    ? categories.map((item) => `
      <span class="ti-badge" style="background:var(--bg);border:1px solid var(--red);color:var(--red);margin:2px">
        ${tiEsc(item)}
      </span>
    `).join('')
    : '<span style="color:var(--muted);font-size:12px">Chưa có phân loại</span>';

  const aiHtml = models.length
    ? models.map((item) => `
      <span class="ti-badge" style="background:var(--bg);border:1px solid var(--purple);color:var(--purple);margin:2px">
        ${tiEsc(item)}
      </span>
    `).join('')
    : '';

  const noteHtml = d.note
    ? `<div style="margin-top:12px;padding:10px;background:var(--bg1);border:1px solid var(--border-subtle);border-radius:6px;color:var(--muted);font-size:12px">ℹ️ ${tiEsc(d.note)}</div>`
    : '';

  return `
    <div class="ti-card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;gap:16px;flex-wrap:wrap">
        <div>
          <div style="font-size:22px;font-weight:700;color:var(--cyan);font-family:monospace">${tiEsc(safeIp)}</div>
          <div style="color:var(--muted);font-size:13px;margin-top:4px">${flag} ${tiEsc(d.country || 'Unknown')} · ${tiEsc(d.isp || 'Unknown ISP')}</div>
        </div>
        <div style="text-align:center;padding:12px 20px;background:var(--bg);border-radius:8px;border:2px solid ${scoreColor}">
          <div style="font-size:32px;font-weight:700;color:${scoreColor}">${score}</div>
          <div style="font-size:10px;color:${scoreColor};font-weight:600;letter-spacing:1px">${scoreLabel}</div>
          <div style="font-size:10px;color:var(--muted);margin-top:2px">/ 100</div>
        </div>
      </div>

      <div style="margin-bottom:16px">
        <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--muted);margin-bottom:4px">
          <span>AN TOÀN</span><span>ĐÁNG NGỜ</span><span>NGUY HIỂM</span>
        </div>
        <div style="height:6px;background:var(--bg1);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${score}%;background:${scoreColor};border-radius:3px;transition:width .6s ease"></div>
        </div>
      </div>

      <div class="ti-meta-grid" style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px">
        ${[
          ['Quốc gia', `${flag} ${d.country || '—'}`],
          ['ISP / ASN', d.isp || '—'],
          ['Loại', d.usage_type || '—'],
          ['Tor', d.is_tor ? '⚠️ Có' : '✓ Không'],
          ['VPN', d.is_vpn ? '⚠️ Có' : '✓ Không'],
          ['Báo cáo', `${Number(d.total_reports || 0).toLocaleString('vi-VN')} lần`],
        ].map(([label, value]) => `
          <div style="background:var(--bg1);border:1px solid var(--border-subtle);border-radius:6px;padding:8px 10px">
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px">${tiEsc(label)}</div>
            <div style="font-size:13px;color:var(--text)">${tiEsc(value)}</div>
          </div>
        `).join('')}
      </div>

      <div style="margin-bottom:16px">
        <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Phân loại mối đe dọa</div>
        <div>${categoryHtml}</div>
      </div>

      ${Number(d.so_canh_bao_wazuh || 0) > 0 ? `
        <div style="margin-bottom:12px;font-size:12px;color:var(--muted)">
          🛡 <strong style="color:var(--medium)">Wazuh</strong> đã ghi nhận
          <strong style="color:var(--text)">${Number(d.so_canh_bao_wazuh || 0).toLocaleString('vi-VN')}</strong> cảnh báo từ IP này
        </div>
      ` : ''}

      ${aiHtml ? `
        <div style="margin-bottom:12px">
          <span style="font-size:11px;color:var(--muted)">🤖 AI phát hiện: </span>${aiHtml}
        </div>
      ` : ''}

      ${noteHtml}

      <div style="display:flex;gap:8px;margin-top:16px;padding-top:16px;border-top:1px solid var(--border-subtle);flex-wrap:wrap">
        <button onclick="confirmBlockIP(${JSON.stringify(safeIp)}, 'Tra cứu Threat Intel')"
          style="padding:8px 16px;background:var(--bg);border:1px solid var(--red);color:var(--red);border-radius:6px;font-size:13px;cursor:pointer">
          🛡 Chặn IP
        </button>
        <button onclick="createIncidentFromIP(${JSON.stringify(safeIp)})"
          style="padding:8px 16px;background:var(--bg);border:1px solid var(--medium);color:var(--medium);border-radius:6px;font-size:13px;cursor:pointer">
          📋 Tạo vụ việc
        </button>
        <button onclick="openThreatHunting(${JSON.stringify(safeIp)})"
          style="padding:8px 16px;background:var(--bg1);border:1px solid var(--green);color:var(--green);border-radius:6px;font-size:13px;cursor:pointer">
          🔍 Threat Hunt
        </button>
      </div>
    </div>
  `;
}

async function loadIOCList() {
  const panel = document.getElementById('panel-ioc');
  if (!panel) return;
  panel.innerHTML = '<div style="color:var(--medium);font-size:13px;padding:20px 0">⏳ Đang tải IOC...</div>';

  let items = [];
  try {
    const res = await fetch('/api/threatintel/iocs?limit=200');
    const data = await res.json();
    items = Array.isArray(data) ? data : [];
  } catch (_error) {
    items = [];
  }

  // Fallback: nếu không có IOC từ endpoint cũ, lấy từ AI threat-intel
  if (!items.length) {
    try {
      const res2 = await fetch('/api/ai/threat-intel/iocs?limit=50');
      const d2 = await res2.json();
      if (d2 && Array.isArray(d2.iocs)) {
        items = d2.iocs.map((ioc, i) => ({
          ioc_id: `ai-${i}`,
          gia_tri: ioc.ip,
          loai: ioc.type || 'ip',
          muc_do: ioc.count > 500 ? 'cao' : ioc.count > 100 ? 'trung_binh' : 'thap',
          mo_ta: `${ioc.count} cảnh báo trong 24h`,
          nguon: d2.source || 'wazuh+suricata',
          lan_cuoi: new Date().toISOString(),
          da_kich_hoat: true,
        }));
      }
    } catch (_) {}
  }
  TI_STATE.iocItems = items;

  const typeColor = { ip: _css('--cyan')||'#00ccff', domain: _css('--purple')||'#a78bfa', hash: _css('--medium')||'#FFCC00', url: _css('--muted')||'#888' };
  const levelColor = { cao: _css('--red') || '#FF4444', trung_binh: _css('--medium') || '#FFCC00', thap: _css('--green') || '#00ff88' };
  const levelText = { cao: 'CAO', trung_binh: 'TRUNG BÌNH', thap: 'THẤP' };

  panel.innerHTML = `
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
      <select id="ioc-filter-type" onchange="filterIOC()"
        style="padding:6px 10px;background:var(--bg1);border:1px solid var(--border-subtle);color:var(--text);border-radius:4px;font-size:12px">
        <option value="">Tất cả loại</option>
        <option value="ip">IP</option>
        <option value="domain">Domain</option>
        <option value="hash">Hash</option>
        <option value="url">URL</option>
      </select>
      <select id="ioc-filter-level" onchange="filterIOC()"
        style="padding:6px 10px;background:var(--bg1);border:1px solid var(--border-subtle);color:var(--text);border-radius:4px;font-size:12px">
        <option value="">Tất cả mức độ</option>
        <option value="cao">Cao</option>
        <option value="trung_binh">Trung bình</option>
        <option value="thap">Thấp</option>
      </select>
      <span style="flex:1"></span>
      <button onclick="showAddIOCForm()"
        style="padding:6px 14px;background:var(--bg1);border:1px solid var(--green);color:var(--green);border-radius:4px;font-size:12px;cursor:pointer">
        + Thêm IOC
      </button>
    </div>

    <div id="add-ioc-form" style="display:none;margin-bottom:12px;padding:12px;background:var(--bg1);border:1px solid var(--border-subtle);border-radius:6px">
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <input id="new-ioc-value" placeholder="IP / domain / hash..."
          style="flex:1;min-width:200px;padding:6px 10px;background:var(--bg1);border:1px solid var(--border-subtle);color:var(--text);border-radius:4px;font-size:12px"/>
        <select id="new-ioc-type"
          style="padding:6px 10px;background:var(--bg1);border:1px solid var(--border-subtle);color:var(--text);border-radius:4px;font-size:12px">
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="hash">Hash</option>
        </select>
        <select id="new-ioc-level"
          style="padding:6px 10px;background:var(--bg1);border:1px solid var(--border-subtle);color:var(--text);border-radius:4px;font-size:12px">
          <option value="cao">Cao</option>
          <option value="trung_binh">Trung bình</option>
          <option value="thap">Thấp</option>
        </select>
        <input id="new-ioc-desc" placeholder="Mô tả ngắn..."
          style="flex:2;min-width:160px;padding:6px 10px;background:var(--bg1);border:1px solid var(--border-subtle);color:var(--text);border-radius:4px;font-size:12px"/>
        <button onclick="submitAddIOC()"
          style="padding:6px 14px;background:var(--bg1);border:1px solid var(--green);color:var(--green);border-radius:4px;font-size:12px;cursor:pointer">Lưu</button>
        <button onclick="document.getElementById('add-ioc-form').style.display='none'"
          style="padding:6px 10px;background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:4px;font-size:12px;cursor:pointer">Hủy</button>
      </div>
    </div>

    ${items.length === 0 ? `
      <div style="text-align:center;padding:40px 0;color:var(--muted);font-size:13px">
        Chưa có IOC nào. Nhấn "+ Thêm IOC" để thêm thủ công.
      </div>
    ` : `
      <table style="width:100%;border-collapse:collapse;font-size:12px" id="ioc-table">
        <thead>
          <tr style="color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-size:10px">
            <th style="padding:8px 10px;text-align:left;border-bottom:1px solid var(--border)">Loại</th>
            <th style="padding:8px 10px;text-align:left;border-bottom:1px solid var(--border)">Giá trị</th>
            <th style="padding:8px 10px;text-align:left;border-bottom:1px solid var(--border)">Mức độ</th>
            <th style="padding:8px 10px;text-align:left;border-bottom:1px solid var(--border)">Mô tả</th>
            <th style="padding:8px 10px;text-align:left;border-bottom:1px solid var(--border)">Nguồn</th>
            <th style="padding:8px 10px;text-align:left;border-bottom:1px solid var(--border)">Lần cuối</th>
            <th style="padding:8px 10px;text-align:center;border-bottom:1px solid var(--border)">Trạng thái</th>
            <th style="padding:8px 10px;text-align:center;border-bottom:1px solid var(--border)">Xóa</th>
          </tr>
        </thead>
        <tbody>
          ${items.map((item) => `
            <tr data-ioc-type="${tiEsc(item.loai)}" data-ioc-level="${tiEsc(item.muc_do)}"
                style="border-bottom:1px solid var(--border-subtle)" onmouseover="this.style.background='var(--bg1)'" onmouseout="this.style.background='transparent'">
              <td style="padding:8px 10px">
                <span class="ti-badge" style="background:var(--bg1);border:1px solid ${typeColor[item.loai] || '#555'};color:${typeColor[item.loai] || '#888'}">
                  ${tiEsc(String(item.loai || '').toUpperCase())}
                </span>
              </td>
              <td style="padding:8px 10px;font-family:monospace;color:var(--cyan)">
                ${tiEsc(item.gia_tri)}
                <span data-copy="${tiEsc(item.gia_tri)}"
                  style="color:var(--muted);cursor:pointer;margin-left:6px;font-size:11px" title="Copy">⎘</span>
              </td>
              <td style="padding:8px 10px">
                <span class="ti-badge" style="background:var(--bg);border:1px solid ${levelColor[item.muc_do] || '#555'};color:${levelColor[item.muc_do] || '#888'}">
                  ${tiEsc(levelText[item.muc_do] || item.muc_do)}
                </span>
              </td>
              <td style="padding:8px 10px;color:var(--muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                title="${tiEsc(item.mo_ta || '')}">${tiEsc(item.mo_ta || '—')}</td>
              <td style="padding:8px 10px;color:var(--muted)">${tiEsc(item.nguon || '—')}</td>
              <td style="padding:8px 10px;color:var(--muted)">${tiEsc(formatThoiGianTuongDoi(item.lan_cuoi) || '—')}</td>
              <td style="padding:8px 10px;text-align:center">
                <span style="width:28px;height:16px;border-radius:8px;display:inline-block;background:${item.da_kich_hoat ? 'var(--green)' : 'var(--border)'};cursor:pointer"
                  onclick="toggleIOC(${JSON.stringify(String(item.ioc_id || ''))}, this, ${!item.da_kich_hoat})"></span>
              </td>
              <td style="padding:8px 10px;text-align:center">
                <button onclick="deleteIOC(${JSON.stringify(String(item.ioc_id || ''))}, this.closest('tr'))"
                  style="background:transparent;border:none;color:var(--muted);cursor:pointer;font-size:14px" title="Xóa">✕</button>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
      <div style="margin-top:8px;color:var(--muted);font-size:11px">${items.length} IOC</div>
    `}
  `;

  panel.querySelectorAll('[data-copy]').forEach((el) => {
    el.addEventListener('click', async () => {
      const value = String(el.getAttribute('data-copy') || '');
      try {
        await navigator.clipboard.writeText(value);
        tiNotify('Đã copy IOC', 'ok');
      } catch (_error) {
        tiNotify('Không thể copy IOC', 'warn');
      }
    });
  });
}

function filterIOC() {
  const type = String(document.getElementById('ioc-filter-type')?.value || '');
  const level = String(document.getElementById('ioc-filter-level')?.value || '');
  document.querySelectorAll('#ioc-table tbody tr').forEach((row) => {
    const rowType = String(row.dataset.iocType || '');
    const rowLevel = String(row.dataset.iocLevel || '');
    const visible = (!type || rowType === type) && (!level || rowLevel === level);
    row.style.display = visible ? '' : 'none';
  });
}

function showAddIOCForm() {
  const form = document.getElementById('add-ioc-form');
  if (!form) return;
  form.style.display = form.style.display === 'none' ? 'block' : 'none';
}

async function submitAddIOC() {
  const value = String(document.getElementById('new-ioc-value')?.value || '').trim();
  const type = String(document.getElementById('new-ioc-type')?.value || 'ip');
  const level = String(document.getElementById('new-ioc-level')?.value || 'cao');
  const desc = String(document.getElementById('new-ioc-desc')?.value || '').trim();
  if (!value) return;

  try {
    await fetch('/api/threatintel/iocs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        gia_tri: value,
        loai: type,
        muc_do: level,
        mo_ta: desc,
        nguon: 'Thủ công',
      }),
    });
    tiNotify('Đã thêm IOC mới', 'ok');
  } catch (_error) {
    tiNotify('Không thể lưu IOC (đã lưu cục bộ giao diện)', 'warn');
  }

  await loadIOCList();
}

async function deleteIOC(id, row) {
  const safeId = String(id || '').trim();
  if (!safeId) return;
  if (!window.confirm('Xóa IOC này?')) return;

  try {
    await fetch(`/api/threatintel/iocs/${encodeURIComponent(safeId)}`, { method: 'DELETE' });
  } catch (_error) {
    tiNotify('API xóa IOC không phản hồi, đã xóa khỏi giao diện', 'warn');
  }

  if (row && typeof row.remove === 'function') row.remove();
}

async function toggleIOC(id, element, newState) {
  const safeId = String(id || '').trim();
  if (element) element.style.background = newState ? (_css('--green') || '#00ff88') : 'var(--border)';
  if (!safeId) return;

  try {
    await fetch(`/api/threatintel/iocs/${encodeURIComponent(safeId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ da_kich_hoat: Boolean(newState) }),
    });
  } catch (_error) {
    tiNotify('Không thể cập nhật trạng thái IOC', 'warn');
  }
}

function loadFeedSources() {
  const panel = document.getElementById('panel-feeds');
  if (!panel) return;

  const sources = [
    { ten: 'AbuseIPDB', icon: '🛡', mo_ta: 'IP reputation database', trang_thai: 'ket_noi', ioc_count: 1247, cap_nhat: '5 phút trước', color: 'var(--green)' },
    { ten: 'Emerging Threats', icon: '⚡', mo_ta: 'Suricata rule feed', trang_thai: 'ket_noi', ioc_count: 892, cap_nhat: '1 giờ trước', color: 'var(--green)' },
    { ten: 'AlienVault OTX', icon: '👾', mo_ta: 'Open threat exchange', trang_thai: 'ngat', ioc_count: 0, cap_nhat: 'Chưa kết nối', color: 'var(--muted)' },
    { ten: 'VirusTotal', icon: '🔬', mo_ta: 'File & URL malware scanner', trang_thai: 'ngat', ioc_count: 0, cap_nhat: 'Chưa kết nối', color: 'var(--muted)' },
  ];

  panel.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px">
      ${sources.map((s) => `
        <div class="ti-card" style="border-color:${s.color}">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
            <div style="display:flex;align-items:center;gap:10px">
              <span style="font-size:24px">${s.icon}</span>
              <div>
                <div style="font-size:14px;font-weight:600;color:var(--text)">${tiEsc(s.ten)}</div>
                <div style="font-size:11px;color:var(--muted)">${tiEsc(s.mo_ta)}</div>
              </div>
            </div>
            <span style="font-size:10px;font-weight:600;padding:3px 8px;border-radius:4px;
              background:${s.trang_thai === 'ket_noi' ? 'var(--bg1)' : 'var(--bg)'};
              color:${s.trang_thai === 'ket_noi' ? 'var(--green)' : 'var(--muted)'}">
              ${s.trang_thai === 'ket_noi' ? '● KẾT NỐI' : '● CHƯA KẾT NỐI'}
            </span>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;color:var(--muted);margin-bottom:12px">
            <span>${s.ioc_count > 0 ? `${s.ioc_count.toLocaleString('vi-VN')} IOC` : 'Chưa đồng bộ'}</span>
            <span>${tiEsc(s.cap_nhat)}</span>
          </div>
          <div style="display:flex;gap:8px">
            <button style="flex:1;padding:6px;background:transparent;border:1px solid var(--border-subtle);color:var(--muted);border-radius:4px;font-size:11px;cursor:pointer">
              ⚙ Cấu hình
            </button>
            ${s.trang_thai === 'ket_noi' ? `
              <button style="flex:1;padding:6px;background:var(--bg1);border:1px solid var(--green);color:var(--green);border-radius:4px;font-size:11px;cursor:pointer">
                🔄 Đồng bộ ngay
              </button>
            ` : ''}
          </div>
        </div>
      `).join('')}
    </div>

    <div style="margin-top:16px;padding:12px;background:var(--bg1);border:1px solid var(--border-subtle);border-radius:8px;font-size:12px;color:var(--muted)">
      💡 <strong style="color:var(--muted)">Gợi ý:</strong> Kết nối AbuseIPDB để tra cứu IP thật.
      Đăng ký tại <a href="https://www.abuseipdb.com" target="_blank" style="color:var(--green)">abuseipdb.com</a> → lấy API key → cấu hình trong Cài đặt.
    </div>
  `;
}

function formatThoiGianTuongDoi(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);

  const now = Date.now();
  const diffSec = Math.max(0, Math.floor((now - date.getTime()) / 1000));

  if (diffSec < 60) return `${diffSec}s trước`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m trước`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h trước`;
  return `${Math.floor(diffSec / 86400)} ngày trước`;
}

async function confirmBlockIP(ip, reason = 'Threat Intel') {
  const safeIp = String(ip || '').trim();
  if (!safeIp) return;

  if (typeof window.confirmBlockIP === 'function' && window.confirmBlockIP !== confirmBlockIP) {
    window.confirmBlockIP(safeIp, reason);
    return;
  }

  const ok = window.confirm(`Xác nhận chặn IP ${safeIp}?\nLý do: ${reason}`);
  if (!ok) return;

  try {
    const res = await fetch('/api/response', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'block_ip', ip: safeIp, reason }),
    });
    const data = await res.json();
    if (res.ok && data.success) {
      tiNotify(`Đã chặn IP ${safeIp}`, 'ok');
    } else {
      tiNotify(data.message || `Không thể chặn ${safeIp}`, 'err');
    }
  } catch (_error) {
    tiNotify('Không thể gọi API block IP', 'err');
  }
}

async function createIncidentFromIP(ip) {
  const safeIp = String(ip || '').trim();
  if (!safeIp) return;
  try {
    if (!window.socApi || typeof window.socApi.createCase !== 'function') {
      throw new Error('create_case_unavailable');
    }
    await window.socApi.createCase({
      title: `Threat Intel: IOC ${safeIp}`,
      severity: 'Medium',
      src_ip: safeIp,
      agent: 'Threat Intel',
      rule_id: 'THREAT-INTEL',
      rule_desc: `Tra cứu IOC từ Threat Intel cho ${safeIp}`,
      mitre_ids: [],
    });
    tiNotify('Đã tạo vụ việc từ Threat Intel', 'ok');
  } catch (_error) {
    tiNotify('Không thể tạo vụ việc', 'err');
  }
}

function openThreatHunting(ip) {
  const safeIp = String(ip || '').trim();
  if (!safeIp) return;
  if (typeof window.navigate === 'function') {
    window.navigate('hunting');
    setTimeout(() => {
      const input = document.getElementById('hunt-ip');
      if (input) input.value = safeIp;
      if (window.huntApp && typeof window.huntApp.search === 'function') {
        window.huntApp.search();
      }
    }, 120);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('page-threat-intel')?.classList.contains('active')) {
    initThreatIntel();
  }
  const page = document.getElementById('page-threat-intel');
  if (page) {
    const observer = new MutationObserver(() => {
      if (page.classList.contains('active')) {
        initThreatIntel();
      }
    });
    observer.observe(page, { attributes: true, attributeFilter: ['class'] });
  }
});

document.querySelectorAll('.nav-item[data-page="threat-intel"]').forEach((item) => {
  item.addEventListener('click', () => {
    setTimeout(initThreatIntel, 0);
  });
});

window.initThreatIntel = initThreatIntel;
window.renderThreatIntelLayout = renderThreatIntelLayout;
window.switchTab = switchTab;
window.doLookup = doLookup;
window.buildMockResult = buildMockResult;
window.renderIPResultCard = renderIPResultCard;
window.loadIOCList = loadIOCList;
window.filterIOC = filterIOC;
window.showAddIOCForm = showAddIOCForm;
window.submitAddIOC = submitAddIOC;
window.deleteIOC = deleteIOC;
window.toggleIOC = toggleIOC;
window.loadFeedSources = loadFeedSources;
window.formatThoiGianTuongDoi = formatThoiGianTuongDoi;
window.confirmBlockIP = window.confirmBlockIP || confirmBlockIP;
window.createIncidentFromIP = createIncidentFromIP;
window.openThreatHunting = openThreatHunting;
