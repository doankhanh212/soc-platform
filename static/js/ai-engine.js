/**
 * AI Engine Page Enhancements
 * Task 2.1 -> 2.4
 */
(function () {
  'use strict';

  const STEPS = [
    {
      icon: '📥',
      ten: 'Thu thập',
      mo_ta: 'Wazuh + Suricata',
      giai_thich: 'Thu thập log từ toàn bộ máy chủ và thiết bị mạng theo thời gian thực',
    },
    {
      icon: '⚙',
      ten: 'Trích xuất',
      mo_ta: 'IP, port, tần suất',
      giai_thich: 'Tách thông tin quan trọng: IP tấn công, cổng, số lần thử, thời gian',
    },
    {
      icon: '🧠',
      ten: '4 Lớp phân tích',
      mo_ta: 'Phát hiện bất thường',
      giai_thich: '4 phương pháp chạy song song: hành vi bất thường, đột biến, leo thang âm thầm, dữ liệu ẩn',
    },
    {
      icon: '📊',
      ten: 'Tính điểm',
      mo_ta: 'Rủi ro 0.0 → 1.0',
      giai_thich: 'Tổng hợp kết quả thành 1 điểm rủi ro từ 0 (an toàn) đến 1 (nguy hiểm)',
    },
    {
      icon: '💬',
      ten: 'Giải thích',
      mo_ta: 'Lý do dễ hiểu',
      giai_thich: 'Chuyển kết quả kỹ thuật thành ngôn ngữ tự nhiên cho analyst',
    },
    {
      icon: '🛡',
      ten: 'Hành động',
      mo_ta: 'Chặn / Theo dõi',
      giai_thich: 'Đề xuất hoặc tự động thực hiện: theo dõi, tạo vụ việc, hoặc chặn IP',
    },
  ];

  const MODEL_CARDS = [
    {
      model: 'IsolationForest',
      label: 'Hành vi bất thường',
      icon: '🔍',
      mo_ta: 'Phát hiện IP hành xử khác biệt hoàn toàn. Như tìm người lạ trong đám đông.',
    },
    {
      model: 'EWMA',
      label: 'Đột biến lưu lượng',
      icon: '⚡',
      mo_ta: 'Phát hiện traffic tăng đột ngột. Như báo động khi lưu lượng tăng 500%.',
    },
    {
      model: 'CUSUM',
      label: 'Leo thang âm thầm',
      icon: '📈',
      mo_ta: 'Phát hiện tấn công tăng dần theo thời gian để né qua rule thông thường.',
    },
    {
      model: 'Entropy',
      label: 'Dữ liệu mã hóa / ẩn',
      icon: '🔐',
      mo_ta: 'Phát hiện file bị mã hóa hàng loạt hoặc dữ liệu ẩn trong DNS tunneling.',
    },
  ];

  const MONITORING = [
    {
      icon: '🔑',
      label: 'Đăng nhập bất thường',
      mo_ta: 'SSH brute force, đăng nhập thất bại nhiều lần',
      active: true,
      count: 99718,
    },
    {
      icon: '🌐',
      label: 'Lưu lượng mạng',
      mo_ta: 'Port scan, kết nối đến nhiều cổng lạ',
      active: true,
      count: 48386,
    },
    {
      icon: '📁',
      label: 'Thay đổi file',
      mo_ta: 'File bị sửa, xóa hoặc mã hóa hàng loạt',
      active: false,
      count: 0,
    },
    {
      icon: '⚙',
      label: 'Hành vi tiến trình',
      mo_ta: 'Tiến trình lạ, leo thang đặc quyền',
      active: false,
      count: 5,
    },
  ];

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

  function initStepper() {
    const wrap = byId('ai-stepper');
    const ts = byId('ai-stepper-updated');
    if (!wrap) return;

    wrap.innerHTML = STEPS.map((step, idx) => `
      <div class="ai-step-item ${idx === 2 ? 'active' : ''}" data-step-index="${idx}">
        <div class="ai-step-icon">${step.icon}</div>
        <div class="ai-step-name">${esc(step.ten)}</div>
        <div class="ai-step-desc">${esc(step.mo_ta)}</div>
        <div class="ai-step-tooltip">${esc(step.giai_thich)}</div>
      </div>
      ${idx < STEPS.length - 1 ? '<div class="ai-step-arrow">→</div>' : ''}
    `).join('');

    const items = wrap.querySelectorAll('.ai-step-item');
    items.forEach((el, idx) => {
      setTimeout(() => {
        el.classList.add('lit');
      }, idx * 200);
    });

    if (ts) {
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
  }

  async function loadModelCards() {
    const wrap = byId('ai-model-status-grid');
    if (!wrap) return;
    wrap.innerHTML = '<div class="ai-empty">Đang tải trạng thái mô hình AI...</div>';

    let statusData = { threshold: 0.6, models: [] };
    try {
      const res = await fetch('/api/ai/models/status');
      if (res.ok) {
        statusData = await res.json();
      }
    } catch (_error) {}

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
          <div class="ai-model-foot">Phát hiện ${Number.isFinite(detectionCount) ? detectionCount.toLocaleString('vi-VN') : '0'} bất thường hôm nay</div>
        </div>
      `;
    }).join('');
  }

  function generateReasons(lyDo) {
    const reasons = [];
    const ports = Number(lyDo.unique_dest_ports || 0);
    const cusum = Number(lyDo.cusum_s || 0);
    const pct = Number(lyDo.if_percentile || 0);
    const ifScore = Number(lyDo.if_score || 0);
    const oneHour = Number(lyDo.so_canh_bao_1h || 0);
    const total = Number(lyDo.tong_canh_bao || 0);

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
    if (pct >= 90) {
      const topPct = Math.max(1, 100 - Math.round(pct));
      reasons.push({
        main: `Nằm trong top ${topPct}% IP có hành vi khác biệt nhất`,
        evidence: `Điểm bất thường: ${ifScore.toFixed(3)} · percentile ${Math.round(pct)}`,
      });
    }
    if (oneHour >= 1000) {
      reasons.push({
        main: `Tấn công cường độ cao — ${oneHour.toLocaleString('vi-VN')} lần trong 1 giờ`,
        evidence: `Tổng: ${total.toLocaleString('vi-VN')} lần`,
      });
    }
    if (!reasons.length) {
      reasons.push({
        main: 'IP này có hành vi lệch chuẩn so với baseline hệ thống',
        evidence: `Điểm rủi ro tổng hợp: ${(Number(lyDo.diem_rui_ro || 0)).toFixed(3)}`,
      });
    }
    return reasons;
  }

  async function loadExplainablePanel() {
    const wrap = byId('ai-explain-main');
    const mini = byId('ai-ip-mini-stats');
    if (!wrap || !mini) return;

    wrap.innerHTML = '<div class="ai-empty">Đang phân tích IP có mức rủi ro cao nhất...</div>';
    mini.innerHTML = '';

    let data = null;
    try {
      const res = await fetch('/api/ai/anomalies?limit=1&sort=risk_desc');
      if (res.ok) {
        const arr = await res.json();
        data = Array.isArray(arr) && arr.length ? arr[0] : null;
      }
    } catch (_error) {}

    if (!data) {
      wrap.innerHTML = '<div class="ai-empty">Chưa có bất thường AI để giải thích.</div>';
      mini.innerHTML = '<div class="ai-empty">Không có dữ liệu.</div>';
      return;
    }

    const lyDo = data.ly_do || {};
    const score = Number(data.diem_rui_ro || 0);
    const barColor = scoreColor(score);
    const reasons = generateReasons(lyDo);
    const riskLabel = score >= 0.7 ? 'CHẶN NGAY' : score >= 0.35 ? 'THEO DÕI' : 'AN TOÀN';

    wrap.innerHTML = `
      <div class="ai-risk-head">
        <div class="ai-risk-ip">${esc(data.ip)}</div>
        <div class="ai-risk-meta">${esc(data.quoc_gia || 'Unknown')} · <span class="ai-risk-badge" style="color:${barColor};border-color:${barColor}">${score.toFixed(3)} · ${riskLabel}</span></div>
      </div>
      <div class="ai-risk-bar-wrap">
        <div class="ai-risk-levels"><span>AN TOÀN</span><span>THEO DÕI</span><span>CHẶN NGAY</span></div>
        <div class="ai-risk-bar"><span class="ai-risk-fill" style="width:${Math.max(0, Math.min(100, score * 100))}%;background:${barColor}"></span></div>
      </div>
      <div class="ai-reason-list">
        ${reasons.map((r) => `
          <div class="ai-reason-row">
            <div class="ai-reason-main">● ${esc(r.main)}</div>
            <div class="ai-reason-evidence">${esc(r.evidence)}</div>
          </div>
        `).join('')}
      </div>
      <div class="ai-action-row">
        <button type="button" class="ai-action-btn hunt" id="ai-hunt-ip-btn">🔍 Threat Hunt IP này</button>
        <button type="button" class="ai-action-btn case" id="ai-case-ip-btn">📋 Tạo vụ việc</button>
        <button type="button" class="ai-action-btn block" id="ai-block-ip-btn">🛡 Chặn thủ công</button>
      </div>
    `;

    mini.innerHTML = `
      <div class="ai-mini-box"><div>Tổng cảnh báo</div><strong>${Number(lyDo.tong_canh_bao || 0).toLocaleString('vi-VN')}</strong></div>
      <div class="ai-mini-box"><div>Cổng khác nhau</div><strong>${Number(lyDo.unique_dest_ports || 0).toLocaleString('vi-VN')}</strong></div>
      <div class="ai-mini-box"><div>Leo thang quyền</div><strong>${Number(lyDo.leo_thang_quyen || 0).toLocaleString('vi-VN')}</strong></div>
      <div class="ai-mini-box"><div>File bị sửa</div><strong>${Number(lyDo.file_bi_sua || 0).toLocaleString('vi-VN')}</strong></div>
    `;

    bindExplainActions(data.ip, score);
  }

  function bindExplainActions(ip, score) {
    const huntBtn = byId('ai-hunt-ip-btn');
    const caseBtn = byId('ai-case-ip-btn');
    const blockBtn = byId('ai-block-ip-btn');

    if (huntBtn) {
      huntBtn.addEventListener('click', () => {
        if (typeof window.navigate === 'function') {
          window.navigate('hunting');
          setTimeout(() => {
            const input = byId('hunt-ip');
            if (input) input.value = ip;
            if (window.huntApp?.search) window.huntApp.search();
          }, 120);
        }
      });
    }

    if (caseBtn) {
      caseBtn.addEventListener('click', async () => {
        try {
          if (!window.socApi?.createCase) throw new Error('api_missing');
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
      });
    }

    if (blockBtn) {
      blockBtn.addEventListener('click', () => {
        if (typeof window.confirmBlockIP === 'function') {
          window.confirmBlockIP(ip, 'AI Engine');
          return;
        }
        fetch('/api/response', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'block_ip', ip }),
        })
          .then((r) => {
            if (!r.ok) throw new Error('block_failed');
            window.toast?.(`Đã gửi lệnh chặn ${ip}`, 'ok');
          })
          .catch(() => window.toast?.(`Không thể chặn ${ip}`, 'err'));
      });
    }
  }

  function renderMonitoringWidget() {
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

  function initAIPageEnhancements() {
    if (!byId('page-ai')) return;
    initStepper();
    loadModelCards();
    loadExplainablePanel();
    renderMonitoringWidget();

    setInterval(() => {
      loadModelCards();
      loadExplainablePanel();
      const ts = byId('ai-stepper-updated');
      if (ts) {
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
    }, 60000);
  }

  document.addEventListener('DOMContentLoaded', initAIPageEnhancements);
  window.generateReasons = generateReasons;
})();

