/**
 * ai-engine.js
 * Render Động cơ AI theo layout chuẩn + init một đầu mối.
 */
(function () {
  'use strict';

  const STEPS = [
    { icon: '📥', ten: 'Thu thập', mo_ta: 'Wazuh + Suricata', giai_thich: 'Thu thập log từ toàn bộ máy chủ và thiết bị mạng theo thời gian thực' },
    { icon: '⚙', ten: 'Trích xuất', mo_ta: 'IP, port, tần suất', giai_thich: 'Tách thông tin quan trọng: IP tấn công, cổng, số lần thử, thời gian' },
    { icon: '🧠', ten: '4 Lớp phân tích', mo_ta: 'Phát hiện bất thường', giai_thich: '4 phương pháp chạy song song: hành vi bất thường, đột biến, leo thang âm thầm, dữ liệu ẩn' },
    { icon: '📊', ten: 'Tính điểm', mo_ta: 'Rủi ro 0.0 → 1.0', giai_thich: 'Tổng hợp kết quả thành 1 điểm rủi ro từ 0 (an toàn) đến 1 (nguy hiểm)' },
    { icon: '💬', ten: 'Giải thích', mo_ta: 'Lý do dễ hiểu', giai_thich: 'Chuyển kết quả kỹ thuật thành ngôn ngữ tự nhiên cho analyst' },
    { icon: '🛡', ten: 'Hành động', mo_ta: 'Chặn / Theo dõi', giai_thich: 'Đề xuất hoặc tự động thực hiện: theo dõi, tạo vụ việc, hoặc chặn IP' },
  ];

  const MODEL_CARDS = [
    { model: 'IsolationForest', label: 'Hành vi bất thường', icon: '🔍', mo_ta: 'Phát hiện IP hành xử khác biệt hoàn toàn. Như tìm người lạ trong đám đông.' },
    { model: 'EWMA', label: 'Đột biến lưu lượng', icon: '⚡', mo_ta: 'Phát hiện traffic tăng đột ngột. Như báo động khi lưu lượng tăng 500%.' },
    { model: 'CUSUM', label: 'Leo thang âm thầm', icon: '📈', mo_ta: 'Phát hiện tấn công tăng dần theo thời gian để né qua rule thông thường.' },
    { model: 'Entropy', label: 'Dữ liệu mã hóa / ẩn', icon: '🔐', mo_ta: 'Phát hiện file bị mã hóa hàng loạt hoặc dữ liệu ẩn trong DNS tunneling.' },
  ];

  const MONITORING = [
    { icon: '🔑', label: 'Đăng nhập bất thường', mo_ta: 'SSH brute force, đăng nhập thất bại nhiều lần', active: true, count: 99718 },
    { icon: '🌐', label: 'Lưu lượng mạng', mo_ta: 'Port scan, kết nối đến nhiều cổng lạ', active: true, count: 48386 },
    { icon: '📁', label: 'Thay đổi file', mo_ta: 'File bị sửa, xóa hoặc mã hóa hàng loạt', active: false, count: 0 },
    { icon: '⚙', label: 'Hành vi tiến trình', mo_ta: 'Tiến trình lạ, leo thang đặc quyền', active: false, count: 5 },
  ];

  const state = {
    initialized: false,
    refreshTimer: null,
    latestSnapshotAlerts: null,
    anomalyTotal: 0,
    anomalyList: [],
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function esc(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function scoreColor(score) {
    if (score < 0.3) return '#00ff88';
    if (score <= 0.6) return '#FFCC00';
    return '#FF4444';
  }

  function formatCount(value) {
    const n = Number(value || 0);
    if (typeof window.formatSoLan === 'function') {
      return window.formatSoLan(n);
    }
    return n.toLocaleString('vi-VN');
  }

  function normalizeAnomalyPayload(payload) {
    if (Array.isArray(payload)) {
      return { list: payload, total: payload.length };
    }
    if (payload && typeof payload === 'object') {
      const list = Array.isArray(payload.results)
        ? payload.results
        : Array.isArray(payload.items)
          ? payload.items
          : [];
      const rawTotal = Number(payload.total ?? payload.count ?? list.length);
      return {
        list,
        total: Number.isFinite(rawTotal) ? rawTotal : list.length,
      };
    }
    return { list: [], total: 0 };
  }

  function isAIPageActive() {
    const page = byId('page-ai');
    return !!page && page.classList.contains('active');
  }

  function setStepperTimestamp() {
    const ts = byId('ai-stepper-updated');
    if (!ts) return;
    ts.textContent = new Date().toLocaleString('vi-VN', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
    });
  }

  function renderStepper() {
    const wrap = byId('ai-stepper');
    if (!wrap) return;

    wrap.innerHTML = STEPS.map((step, idx) => `
      <div class="ai-step-item ${idx === 2 ? 'active' : ''}">
        <div class="ai-step-icon">${step.icon}</div>
        <div class="ai-step-name">${esc(step.ten)}</div>
        <div class="ai-step-desc">${esc(step.mo_ta)}</div>
        <div class="ai-step-tooltip">${esc(step.giai_thich)}</div>
      </div>
      ${idx < STEPS.length - 1 ? '<div class="ai-step-arrow">→</div>' : ''}
    `).join('');

    const items = wrap.querySelectorAll('.ai-step-item');
    items.forEach((el, idx) => {
      setTimeout(() => el.classList.add('lit'), idx * 200);
    });

    setStepperTimestamp();
  }

  async function fetchAIAlerts() {
    try {
      const res = await fetch('/api/alerts/ai?size=100');
      if (!res.ok) throw new Error('fetch_ai_alerts_failed');
      return await res.json();
    } catch (_error) {
      return Array.isArray(state.latestSnapshotAlerts) ? state.latestSnapshotAlerts : [];
    }
  }

  async function fetchAIAnomalies(limit = 500) {
    try {
      const res = await fetch(`/api/ai/anomalies?limit=${limit}&sort=risk_desc`);
      if (!res.ok) throw new Error('fetch_ai_anomalies_failed');
      return normalizeAnomalyPayload(await res.json());
    } catch (_error) {
      return {
        list: Array.isArray(state.anomalyList) ? state.anomalyList : [],
        total: Number(state.anomalyTotal || 0),
      };
    }
  }

  function loadMetricCards(alerts, totalOverride = null) {
    const totalFromApi = Number(totalOverride);
    const total = Number.isFinite(totalFromApi) && totalFromApi >= 0
      ? totalFromApi
      : alerts.length;
    const blocked = alerts.filter((a) => a && (
      a.da_chan === true
      || a.blocked === true
      || a.status === 'blocked'
    )).length;
    const avgBase = alerts.length;
    const avg = avgBase
      ? (alerts.reduce((sum, item) => sum + (Number(item.risk_score) || 0), 0) / avgBase)
      : 0;

    const totalEl = byId('ai-total');
    const blockedEl = byId('ai-blocked');
    const avgEl = byId('ai-avg');
    if (totalEl) totalEl.textContent = formatCount(total);
    if (blockedEl) blockedEl.textContent = formatCount(blocked);
    if (avgEl) avgEl.textContent = total ? avg.toFixed(3) : '—';
  }

  async function loadMonitorCards() {
    const wrap = byId('ai-model-status-grid');
    if (!wrap) return;
    wrap.innerHTML = '<div class="ai-empty">Đang tải trạng thái mô hình AI...</div>';

    let statusData = { threshold: 0.6, models: [] };
    try {
      const res = await fetch('/api/ai/models/status');
      if (res.ok) statusData = await res.json();
    } catch (_error) {}

    // Also fetch anomaly IPs for mini tables
    let anomalyIPs = [];
    try {
      const res2 = await fetch('/api/ai/anomalies?limit=10');
      if (res2.ok) anomalyIPs = await res2.json();
      if (!Array.isArray(anomalyIPs)) anomalyIPs = [];
    } catch (_) {}

    const threshold = Number(statusData.threshold ?? 0.6);
    const map = new Map((statusData.models || []).map((m) => [m.model, m]));

    wrap.innerHTML = MODEL_CARDS.map((card) => {
      const row = map.get(card.model) || {};
      const score = Number(row.score ?? 0);
      const running = row.running !== false;
      const detectionCount = Number(row.detections_today ?? 0);
      const color = scoreColor(score);

      let statusLabel = 'TẮT';
      let statusClass = 'stopped';
      if (running && score >= threshold) {
        statusLabel = 'CẢNH BÁO';
        statusClass = 'warning';
      } else if (running) {
        statusLabel = 'ĐANG CHẠY';
        statusClass = 'running';
      }

      // Mini anomaly table for this card
      const relevantIPs = anomalyIPs.filter(a => {
        const models = a.mo_hinh_kich_hoat || [];
        return models.includes(card.model.toLowerCase()) || models.includes(card.model);
      }).slice(0, 5);

      const miniTable = relevantIPs.length ? `
        <table style="width:100%;font-size:10px;margin-top:8px;border-collapse:collapse">
          <thead><tr style="color:#555">
            <th style="text-align:left;padding:2px 4px">IP</th>
            <th style="text-align:right;padding:2px 4px">Điểm</th>
            <th style="text-align:center;padding:2px 4px"></th>
          </tr></thead>
          <tbody>${relevantIPs.map(a => `
            <tr style="border-top:1px solid #1a2a1a">
              <td style="color:var(--cyan);padding:2px 4px;font-family:monospace">${esc(a.ip || '—')}</td>
              <td style="color:#FFCC00;text-align:right;padding:2px 4px">${(Number(a.diem_rui_ro || 0) * 100).toFixed(1)}%</td>
              <td style="text-align:center;padding:2px 4px">
                <button type="button" onclick='window.aiEngineApp.confirmBlockIP(${JSON.stringify(a.ip || "")})'
                  style="background:none;border:none;color:#FF4444;cursor:pointer;font-size:11px" title="Chặn IP">🚫</button>
              </td>
            </tr>
          `).join('')}</tbody>
        </table>
      ` : '';

      return `
        <div class="ai-model-card">
          <div class="ai-model-head">
            <div class="ai-model-title">${card.icon} ${esc(card.label)}</div>
            <span class="ai-model-status ${statusClass}">${statusLabel}</span>
          </div>
          <div class="ai-model-score" style="color:${color}">${score.toFixed(1)}</div>
          <div class="ai-model-desc">${esc(card.mo_ta)}</div>
          <div class="ai-model-bar">
            <span class="ai-model-fill" style="width:${Math.max(0, Math.min(100, score * 100))}%;background:${color}"></span>
          </div>
          <div class="ai-model-foot">Phát hiện ${detectionCount.toLocaleString('vi-VN')} bất thường hôm nay</div>
          ${miniTable}
        </div>
      `;
    }).join('');
  }

  function renderAnomalyRow(item) {
    const score = Number(item.risk_score || 0);
    const color = scoreColor(score);
    const ip = String(item.src_ip || item.ip || '—');
    const ts = item['@timestamp']
      ? new Date(item['@timestamp']).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
      : '—';
    const modelHtml = typeof window.renderModelBadges === 'function'
      ? window.renderModelBadges(item.triggered_models || [])
      : esc((item.triggered_models || []).join(', '));
    const isBlocked = item.da_chan === true || item.blocked === true || item.status === 'blocked';
    const actionBadge = isBlocked
      ? '<span class="badge badge-muted">ĐÃ CHẶN</span>'
      : typeof window.renderActionSuggestion === 'function'
        ? window.renderActionSuggestion(score)
        : (item.should_block ? '<span class="badge badge-critical">CẦN CHẶN</span>' : '<span class="badge badge-low">THEO DÕI</span>');
    const canBlock = ip !== '—';
    const blockBtn = canBlock && !isBlocked
      ? `<button type="button" onclick='window.aiEngineApp.confirmBlockIP(${JSON.stringify(ip)})'
          style="background:#1a0000;border:1px solid #FF4444;color:#FF4444;
                 padding:4px 10px;border-radius:4px;font-size:11px;cursor:pointer;margin-left:8px">
          🛡 Chặn
        </button>`
      : '';

    return `
      <tr data-ip="${esc(ip)}">
        <td class="mono">${ts}</td>
        <td style="color:var(--cyan);font-family:monospace">${esc(ip)}</td>
        <td style="color:${color};font-weight:700;font-family:'Share Tech Mono',monospace">${score.toFixed(3)}</td>
        <td>${modelHtml}</td>
        <td class="action-cell">${actionBadge}${blockBtn}</td>
      </tr>
    `;
  }

  function emitToast(type, title, message = '') {
    if (typeof window.showToast === 'function') {
      window.showToast(type, title, message);
      return;
    }
    if (typeof window.toast === 'function') {
      const mapped = type === 'thanh_cong' ? 'ok' : type === 'cao' ? 'err' : 'info';
      window.toast(`${title}${message ? ` — ${message}` : ''}`, mapped);
    }
  }

  function markIPAsBlocked(ip) {
    const safeIp = String(ip || '').trim();
    if (!safeIp) return;

    const escapedIp = (window.CSS && typeof window.CSS.escape === 'function')
      ? window.CSS.escape(safeIp)
      : safeIp.replace(/"/g, '\\"');

    document.querySelectorAll(`#tbl-ai tbody tr[data-ip="${escapedIp}"]`).forEach((row) => {
      row.style.opacity = '0.5';
      const actionCell = row.querySelector('.action-cell');
      if (actionCell) {
        actionCell.innerHTML = '<span style="color:#555;font-size:11px;border:1px solid #333;padding:3px 8px;border-radius:4px">ĐÃ CHẶN</span>';
      }
    });
  }

  async function confirmBlockIP(ip, reason = 'Manual block từ AI Engine') {
    const ok = window.confirm(`Xác nhận chặn IP ${ip}?\nLý do: ${reason}`);
    if (!ok) return;

    try {
      const res = await fetch('/api/response', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'block_ip', ip, reason }),
      });
      const data = await res.json();

      if (res.ok && data.success) {
        emitToast('thanh_cong', '✅ Đã chặn IP thành công', `${ip} → iptables DROP`);
        markIPAsBlocked(ip);
      } else {
        emitToast('cao', '❌ Không thể chặn IP', data.message || 'Lỗi không xác định');
      }
    } catch (err) {
      emitToast('cao', '❌ Lỗi kết nối', 'Không thể gọi API /api/response');
      console.error('Block IP error:', err);
    }
  }

  function loadAnomalyTable(alerts) {
    const tbody = document.querySelector('#tbl-ai tbody');
    if (!tbody) return;

    if (!alerts.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:32px">Không có bất thường AI</td></tr>';
      return;
    }

    tbody.innerHTML = alerts.map(renderAnomalyRow).join('');
  }

  function renderExplainableReasons(ly_do) {
    if (!ly_do || typeof ly_do !== 'object') {
      return '<p style="color:#666">Đang phân tích...</p>';
    }

    const reasons = [];
    const ports = Number(ly_do.unique_dest_ports || 0);
    const cusum = Number(ly_do.cusum_s || 0);
    const percentile = Number(ly_do.if_percentile || 0);
    const ifScore = Number(ly_do.if_score || 0);
    const perHour = Number(ly_do.so_canh_bao_1h || 0);
    const total = Number(ly_do.tong_canh_bao || 0);

    if (ports >= 10) {
      reasons.push({
        main: 'Kết nối đến NHIỀU cổng khác nhau — dấu hiệu đang quét tìm lỗ hổng',
        evidence: `Đã kết nối tới ${ports} cổng (bình thường < 5)`,
      });
    }
    if (cusum >= 5) {
      reasons.push({
        main: 'Hành vi leo thang liên tục — tăng dần trong 2 giờ qua',
        evidence: `Chỉ số tích lũy: ${cusum.toFixed(1)} (ngưỡng ≥ 5.0)`,
      });
    }
    if (percentile >= 90) {
      reasons.push({
        main: `Nằm trong top ${Math.max(1, 100 - Math.round(percentile))}% IP có hành vi khác biệt nhất`,
        evidence: `Điểm bất thường: ${ifScore.toFixed(3)} · percentile ${Math.round(percentile)}`,
      });
    }
    if (perHour >= 1000) {
      reasons.push({
        main: `Tấn công cường độ cao — ${perHour.toLocaleString('vi-VN')} lần trong 1 giờ`,
        evidence: `Tổng: ${total.toLocaleString('vi-VN')} lần`,
      });
    }

    if (!reasons.length) {
      return '<p style="color:#666">Đang phân tích...</p>';
    }

    return reasons.map((reason) => `
      <div class="ai-reason-row">
        <div class="ai-reason-main">● ${esc(reason.main)}</div>
        <div class="ai-reason-evidence">${esc(reason.evidence)}</div>
      </div>
    `).join('');
  }

  function bindTopRiskActions(ip, score) {
    const huntBtn = byId('ai-hunt-ip-btn');
    const caseBtn = byId('ai-case-ip-btn');
    const blockBtn = byId('ai-block-ip-btn');

    if (huntBtn) {
      huntBtn.onclick = () => {
        if (typeof window.navigate === 'function') {
          window.navigate('hunting');
          setTimeout(() => {
            const input = byId('hunt-ip');
            if (input) input.value = ip;
            if (window.huntApp && typeof window.huntApp.search === 'function') {
              window.huntApp.search();
            }
          }, 120);
        }
      };
    }

    if (caseBtn) {
      caseBtn.onclick = async () => {
        try {
          if (!window.socApi || typeof window.socApi.createCase !== 'function') {
            throw new Error('missing_create_case');
          }
          await window.socApi.createCase({
            title: `AI: Bất thường IP ${ip}`,
            severity: score >= 0.7 ? 'High' : 'Medium',
            src_ip: ip,
            agent: 'AI Engine',
            rule_id: 'AI-ANOMALY',
            rule_desc: 'AI Engine đánh dấu IP bất thường',
            mitre_ids: [],
          });
          window.toast?.(`Đã tạo vụ việc cho ${ip}`, 'ok');
        } catch (_error) {
          window.toast?.('Tạo vụ việc thất bại', 'err');
        }
      };
    }

    if (blockBtn) {
      blockBtn.onclick = () => {
        confirmBlockIP(ip, 'Manual block từ AI Engine');
      };
    }
  }

  async function loadTopRiskIP() {
    const wrap = byId('ai-explain-main');
    const mini = byId('ai-ip-mini-stats');
    if (!wrap || !mini) return;

    wrap.innerHTML = '<div class="ai-empty">Đang phân tích IP có mức rủi ro cao nhất...</div>';
    mini.innerHTML = '';

    let top = null;
    let anomalies = Array.isArray(state.anomalyList) ? state.anomalyList : [];
    if (!anomalies.length) {
      const payload = await fetchAIAnomalies(500);
      anomalies = payload.list;
      state.anomalyList = payload.list;
      state.anomalyTotal = payload.total;
    }
    if (Array.isArray(anomalies) && anomalies.length) {
      top = anomalies[0];
    }

    if (!top) {
      wrap.innerHTML = '<p style="color:#666">Đang phân tích...</p>';
      mini.innerHTML = '<div class="ai-empty">Không có dữ liệu.</div>';
      return;
    }

    const ly_do = top.ly_do || {};
    const score = Number(top.diem_rui_ro || 0);
    const color = scoreColor(score);
    const label = score >= 0.7 ? 'CHẶN NGAY' : score >= 0.35 ? 'THEO DÕI' : 'AN TOÀN';

    wrap.innerHTML = `
      <div class="ai-risk-head">
        <div class="ai-risk-ip">${esc(top.ip || '—')}</div>
        <div class="ai-risk-meta">${esc(top.quoc_gia || 'Unknown')} · <span class="ai-risk-badge" style="color:${color};border-color:${color}">${score.toFixed(3)} · ${label}</span></div>
      </div>
      <div class="ai-risk-bar-wrap">
        <div class="ai-risk-levels"><span>AN TOÀN</span><span>THEO DÕI</span><span>CHẶN NGAY</span></div>
        <div class="ai-risk-bar"><span class="ai-risk-fill" style="width:${Math.max(0, Math.min(100, score * 100))}%;background:${color}"></span></div>
      </div>
      <div class="ai-reason-list">${renderExplainableReasons(ly_do)}</div>
      <div class="ai-action-row">
        <button type="button" class="ai-action-btn hunt" id="ai-hunt-ip-btn">🔍 Threat Hunt IP này</button>
        <button type="button" class="ai-action-btn case" id="ai-case-ip-btn">📋 Tạo vụ việc</button>
        <button type="button" class="ai-action-btn block" id="ai-block-ip-btn">🛡 Chặn thủ công</button>
      </div>
    `;

    mini.innerHTML = `
      <div class="ai-mini-box"><div>Tổng cảnh báo</div><strong>${Number(ly_do.tong_canh_bao || 0).toLocaleString('vi-VN')}</strong></div>
      <div class="ai-mini-box"><div>Cổng khác nhau</div><strong>${Number(ly_do.unique_dest_ports || 0).toLocaleString('vi-VN')}</strong></div>
      <div class="ai-mini-box"><div>Leo thang quyền</div><strong>${Number(ly_do.leo_thang_quyen || 0).toLocaleString('vi-VN')}</strong></div>
      <div class="ai-mini-box"><div>File bị sửa</div><strong>${Number(ly_do.file_bi_sua || 0).toLocaleString('vi-VN')}</strong></div>
    `;

    bindTopRiskActions(top.ip || '', score);
  }

  function loadMonitoringWidget() {
    const wrap = byId('ai-monitoring-widget');
    if (!wrap) return;

    const anyActive = MONITORING.some((x) => x.active);
    wrap.innerHTML = `
      <div class="ai-monitor-widget">
        <div class="ai-monitor-header">
          <span class="ai-monitor-dot ${anyActive ? 'active' : ''}"></span>
          <span>AI ĐANG THEO DÕI</span>
        </div>
        <div class="ai-monitor-list">
          ${MONITORING.map((item) => `
            <div class="ai-monitor-row ${item.active ? '' : 'inactive'}" title="${esc(item.mo_ta)}">
              <div class="ai-monitor-left">
                <span>${item.icon}</span>
                <div>
                  <div class="ai-monitor-label">${esc(item.label)}</div>
                  <div class="ai-monitor-count">${Number(item.count || 0).toLocaleString('vi-VN')} sự kiện</div>
                </div>
              </div>
              <div class="ai-monitor-state ${item.active ? 'active' : 'idle'}">
                ${item.active ? 'ĐANG THEO DÕI' : 'Yên tĩnh'}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  async function fetchEngineStats() {
    try {
      const res = await fetch('/api/ai/engine-stats');
      if (!res.ok) return null;
      return await res.json();
    } catch (_error) {
      return null;
    }
  }

  function applyEngineStats(stats) {
    if (!stats) return;
    const totalEl = byId('ai-total');
    const blockedEl = byId('ai-blocked');
    const avgEl = byId('ai-avg');
    if (totalEl) totalEl.textContent = formatCount(stats.bat_thuong_ai_24h || 0);
    if (blockedEl) blockedEl.textContent = formatCount(stats.ip_tu_song_chan || 0);
    if (avgEl) avgEl.textContent = stats.diem_bui_ro_trung_binh ? stats.diem_bui_ro_trung_binh.toFixed(3) : '—';
  }

  async function refreshAIEngine() {
    const [alerts, anomalyPayload, engineStats] = await Promise.all([
      fetchAIAlerts(),
      fetchAIAnomalies(500),
      fetchEngineStats(),
    ]);
    state.anomalyList = anomalyPayload.list;
    state.anomalyTotal = anomalyPayload.total;

    loadMetricCards(alerts, anomalyPayload.total);
    if (engineStats) applyEngineStats(engineStats);
    loadAnomalyTable(alerts);
    await Promise.all([loadMonitorCards(), loadTopRiskIP()]);
    setStepperTimestamp();
  }

  async function initAIEngine() {
    if (state.initialized) return;
    state.initialized = true;

    renderStepper();
    loadMonitoringWidget();
    await refreshAIEngine();

    if (!state.refreshTimer) {
      state.refreshTimer = setInterval(() => {
        if (!isAIPageActive()) return;
        refreshAIEngine();
      }, 60000);
    }
  }

  function onPageActive() {
    initAIEngine().then(() => {
      refreshAIEngine();
    });
  }

  document.addEventListener('soc:data', (event) => {
    const payload = event.detail || {};
    if (payload.type !== 'snapshot' || !Array.isArray(payload.ai_alerts)) return;
    state.latestSnapshotAlerts = payload.ai_alerts;
    if (isAIPageActive()) {
      loadMetricCards(payload.ai_alerts, state.anomalyTotal);
      loadAnomalyTable(payload.ai_alerts);
    }
  });

  document.addEventListener('DOMContentLoaded', () => {
    if (isAIPageActive()) onPageActive();
  });

  window.aiEngineApp = {
    initAIEngine,
    onPageActive,
    refreshAIEngine,
    confirmBlockIP,
    markIPAsBlocked,
  };
  window.renderExplainableReasons = renderExplainableReasons;
})();
