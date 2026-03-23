/**
 * app.js — Main application controller
 * Green cyberpunk SOC Dashboard
 */

/* ── Toast ─────────────────────────────────────── */
window.toast = function(msg, type='ok', ms=4000){
  const wrap = document.getElementById('toast-wrap');
  const t = document.createElement('div');
  const icons = {ok:'✓',err:'✗',warn:'⚠'};
  t.className = `toast toast-${type}`;
  t.innerHTML = `<span>${icons[type]||'ℹ'}</span><span>${msg}</span>`;
  wrap.appendChild(t);
  setTimeout(()=>t.remove(), ms);
};

/* ── Severity helpers ───────────────────────────── */
function sevBadge(level){
  const n = parseInt(level)||0;
  if(n>=12) return '<span class="badge badge-critical">NGHIÊM TRỌNG</span>';
  if(n>=7)  return '<span class="badge badge-high">CAO</span>';
  if(n>=4)  return '<span class="badge badge-medium">TRUNG BÌNH</span>';
  return    '<span class="badge badge-low">THẤP</span>';
}
function sevClass(level){
  const n=parseInt(level)||0;
  if(n>=12) return 'critical';
  if(n>=7)  return 'high';
  if(n>=4)  return 'medium';
  return 'low';
}
function fmtTime(iso){
  if(!iso) return '—';
  const d=new Date(iso);
  return d.toLocaleTimeString('vi-VN',{hour:'2-digit',minute:'2-digit'});
}
function fmtDate(iso){
  if(!iso) return '—';
  return new Date(iso).toLocaleDateString('vi-VN');
}

/* ── Navigation ─────────────────────────────────── */
function navigate(page){
  document.querySelectorAll('.nav-tab').forEach(t=>
    t.classList.toggle('active', t.dataset.page===page));
  document.querySelectorAll('.page').forEach(p=>
    p.classList.toggle('active', p.id===`page-${page}`));
  document.title = `HQG SOC — ${page.charAt(0).toUpperCase()+page.slice(1)}`;
}
window.navigate = navigate;

/* ── KPI rendering ──────────────────────────────── */
function renderKPIs(kpis, caseStats){
  const el = id => document.getElementById(id);
  if(el('kpi-total'))    el('kpi-total').textContent    = (kpis.total_alerts_24h||0).toLocaleString();
  if(el('kpi-critical')) el('kpi-critical').textContent = kpis.critical_alerts||0;
  if(el('kpi-high'))     el('kpi-high').textContent     = kpis.high_alerts||0;
  if(el('kpi-attackers'))el('kpi-attackers').textContent= kpis.unique_attackers||0;
  if(caseStats){
    if(el('kpi-triaged')) el('kpi-triaged').textContent = caseStats.triaged_today||0;
    if(el('kpi-tp'))      el('kpi-tp').textContent      = caseStats.true_positives||0;
    if(el('kpi-fp'))      el('kpi-fp').textContent      = caseStats.false_positives||0;
  }
}

/* ── Cases panel ────────────────────────────────── */
async function loadCases(){
  try{
    const cases = await window.socApi.getCases(null, 8);
    const wrap = document.getElementById('cases-list');
    if(!wrap) return;
    if(!cases.length){
      wrap.innerHTML='<div style="padding:16px;color:var(--muted);font-size:12px;text-align:center">Không có vụ việc đang mở</div>';
      return;
    }
    const btnMap = {
      'New':'triage','In Progress':'investigate',
      'Escalated':'monitor','Resolved':'close','Closed':'close',
    };
    const btnLabelMap = {
      triage: 'Phân loại',
      investigate: 'Điều tra',
      assign: 'Giao việc',
      monitor: 'Theo dõi',
      close: 'Đóng',
    };
    wrap.innerHTML = cases.map(c => {
      const st = c.status.replace(' ','-').toLowerCase();
      const btn = btnMap[c.status]||'triage';
      return `<div class="case-row">
        <span class="case-id">${c.case_id}</span>
        <span class="case-title" title="${c.title}">${c.title}</span>
        <span class="case-status status-${st.replace('in-progress','progress')}">${c.status}</span>
        <button class="case-btn ${btn}"
          onclick="window.openCaseTriage(${JSON.stringify(c).replace(/"/g,'&quot;')})">
          ${btnLabelMap[btn] || 'Phân loại'}
        </button>
      </div>`;
    }).join('');
  } catch(e){ console.error('Cases load failed',e); }
}

window.openCaseTriage = function(caseData){
  window.triageOpenModal(caseData);
};

/* ── Create case from alert ─────────────────────── */
window.createCaseFromAlert = async function(alert){
  const level = parseInt(alert?.rule?.level)||0;
  const sev = level>=12?'Critical':level>=7?'High':level>=4?'Medium':'Low';
  try{
    const c = await window.socApi.createCase({
      title:    alert?.rule?.description || 'Alert from Wazuh',
      severity: sev,
      src_ip:   alert?.data?.src_ip || '',
      agent:    alert?.agent?.name || '',
      rule_id:  String(alert?.rule?.id||''),
      rule_desc:alert?.rule?.description||'',
      mitre_ids: alert?.rule?.mitre?.id || [],
    });
    toast(`Vụ việc ${c.case_id} đã tạo`, 'ok');
    loadCases();
  } catch(e){ toast('Tạo vụ việc thất bại: '+e.message,'err'); }
};

/* ── Alerts stream ──────────────────────────────── */
function renderStream(alerts){
  const el = document.getElementById('stream-list');
  if(!el) return;
  if(!alerts.length){
    el.innerHTML='<div style="padding:16px;color:var(--muted);text-align:center;font-size:12px">Không có cảnh báo trong 24h qua</div>';
    return;
  }
  el.innerHTML = alerts.slice(0,12).map(a=>{
    const sev = sevClass(a?.rule?.level);
    const src = a?.data?.src_ip || a?.agent?.ip || '—';
    const desc = a?.rule?.description || '—';
    return `<div class="stream-row">
      <span class="stream-time">${fmtTime(a['@timestamp'])}</span>
      <div class="stream-body">
        <div class="stream-sev ${sev}">${sev.toUpperCase()}</div>
        <div class="stream-source">Nguồn: ${src}</div>
        <div class="stream-desc">${desc}</div>
      </div>
    </div>`;
  }).join('');
}

/* ── Full Alerts table ──────────────────────────── */
function renderAlertsTable(alerts){
  const tbody = document.querySelector('#tbl-wazuh tbody');
  if(!tbody) return;
  if(!alerts.length){
    tbody.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:24px">Không có cảnh báo trong 24h qua</td></tr>';
    return;
  }
  tbody.innerHTML = alerts.map(a=>`
    <tr>
      <td class="mono">${fmtTime(a['@timestamp'])}</td>
      <td class="agent-name">${a?.agent?.name||'—'}</td>
      <td title="${a?.rule?.description||''}" style="color:var(--text)">${(a?.rule?.description||'—').slice(0,50)}</td>
      <td>${sevBadge(a?.rule?.level)}</td>
      <td class="src">${a?.data?.src_ip||'—'}</td>
      <td class="mono" style="color:var(--purple)">${a?.rule?.mitre?.id?.[0]||'—'}</td>
      <td><button class="btn-create-case" onclick='window.createCaseFromAlert(${JSON.stringify(a)})'>+ Vụ việc</button></td>
    </tr>`).join('');
}

/* ── Suricata table ─────────────────────────────── */
function renderSuriTable(alerts){
  const tbody = document.querySelector('#tbl-suri tbody');
  if(!tbody) return;
  if(!alerts.length){
    tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">Không có cảnh báo IDS</td></tr>';
    return;
  }
  tbody.innerHTML = alerts.map(a=>{
    const sv = a?.data?.alert?.severity||3;
    const svc = sv<=1?'critical':sv===2?'high':'medium';
    return `<tr>
      <td class="mono">${fmtTime(a['@timestamp'])}</td>
      <td style="color:var(--text);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
        title="${a?.data?.alert?.signature||''}">${(a?.data?.alert?.signature||'—').slice(0,45)}</td>
      <td><span class="badge badge-${svc}">SEV ${sv}</span></td>
      <td class="src">${a?.data?.src_ip||'—'}</td>
      <td class="src">${a?.data?.dest_ip||'—'}</td>
      <td style="color:var(--muted);font-size:11px">${a?.data?.alert?.category||'—'}</td>
    </tr>`;
  }).join('');
}

/* ── Top IPs ────────────────────────────────────── */
function renderTopIPs(ips){
  const el = document.getElementById('top-ips-list');
  if(!el) return;
  if(!ips.length){ el.innerHTML='<p style="color:var(--muted);padding:8px;font-size:12px">Không có dữ liệu</p>'; return; }
  const max = ips[0].count||1;
  el.innerHTML = ips.map(r=>`
    <div class="ip-row">
      <span class="ip-addr">${r.ip}</span>
      <div class="ip-bar-bg"><div class="ip-bar" style="width:${(r.count/max*100).toFixed(1)}%"></div></div>
      <span class="ip-count">${r.count}</span>
      <button class="ip-block-btn" onclick="window.blockIP('${r.ip}')">CHẶN</button>
    </div>`).join('');
}

/* ── MITRE heatmap ──────────────────────────────── */
function renderMitre(techniques){
  const el = document.getElementById('mitre-grid');
  if(!el) return;
  if(!techniques.length){ el.innerHTML='<p style="color:var(--muted);padding:12px">Chưa có dữ liệu MITRE</p>'; return; }
  const max = Math.max(...techniques.map(t=>t.count),1);
  el.innerHTML = techniques.map(t=>{
    const r = t.count/max;
    const h = r>.75?'h4':r>.4?'h3':r>.15?'h2':'h1';
    return `<div class="mitre-cell ${h}" title="${t.id}: ${t.count}">
      <div class="tech-id">${t.id}</div>
      <div class="tech-cnt">${t.count}</div>
    </div>`;
  }).join('');
}

/* ── Block IP ───────────────────────────────────── */
window.blockIP = async function(ip){
  if(!confirm(`Chặn ${ip} bằng iptables?`)) return;
  try{
    await window.socApi.blockIP(ip);
    toast(`${ip} đã bị chặn`, 'ok');
  } catch(e){ toast('Chặn thất bại: '+e.message, 'err'); }
};

/* ── WebSocket data handler ─────────────────────── */
document.addEventListener('soc:data', e=>{
  const d = e.detail;
  if(d.type !== 'snapshot') return;

  document.getElementById('last-update').textContent =
    new Date().toLocaleTimeString('vi-VN');

  if(d.kpis) renderKPIs(d.kpis);
  if(d.recent_alerts){
    renderStream(d.recent_alerts);
    renderAlertsTable(d.recent_alerts);
    document.getElementById('badge-alerts').textContent = d.recent_alerts.length;
  }
  if(d.suricata_alerts) renderSuriTable(d.suricata_alerts);
  if(d.top_ips){
    renderTopIPs(d.top_ips);
    if(d.geo_ips && d.geo_ips.length > 0){
      window.socMap?.updateHotspots(d.geo_ips);
    } else {
      window.socMap?.updateHotspotsFromIPs(d.top_ips);
    }
  }
  if(d.top_rules) window.socCharts.updateRulesBarDirect(d.top_rules);
  if(d.suricata_sigs) window.socCharts.updateSuricataBarDirect(d.suricata_sigs);
});

/* ── Manual refresh ─────────────────────────────── */
async function fullRefresh(){
  try{
    const [kpis,tl,topIPs,mitre,sev,wazuh,suri,cStats] = await Promise.all([
      window.socApi.kpis(),
      window.socApi.timeline(),
      window.socApi.topIPs(10),
      window.socApi.mitre(),
      window.socApi.severity(),
      window.socApi.wazuhAlerts(100,4),
      window.socApi.suricataAlerts(100),
      window.socApi.caseStats(),
    ]);
    renderKPIs(kpis, cStats);
    window.socCharts.updateTimeline(tl);
    window.socCharts.updateSeverityDonut(sev);
    window.socCharts.updateTacticsBar(mitre.tactics||[]);
    window.socCharts.updateRulesBar(wazuh);
    window.socCharts.updateSuricataBar(suri);
    renderTopIPs(topIPs);
    renderAlertsTable(wazuh);
    renderSuriTable(suri);
    renderMitre(mitre.techniques||[]);
    renderStream(wazuh);
    window.socMap?.updateHotspotsFromIPs(topIPs);
    loadCases();
    toast('Đã làm mới','ok',1500);
  } catch(e){ toast('Lỗi làm mới: '+e.message,'err'); }
}

/* ── Init ────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', ()=>{
  // Nav
  document.querySelectorAll('.nav-tab[data-page]').forEach(t=>
    t.addEventListener('click', ()=>navigate(t.dataset.page)));

  // Refresh btn
  document.getElementById('refresh-btn')?.addEventListener('click', fullRefresh);

  // Charts
  window.socCharts.initTimeline('chart-timeline');
  window.socCharts.initSeverityDonut('chart-sev');
  window.socCharts.initTacticsBar('chart-tactics');
  window.socCharts.initRulesBar('chart-rules');
  window.socCharts.initSuricataBar('chart-suri');

  // Map
  window.socMap?.initMap('world-canvas');

  // Start
  navigate('dashboard');
  window.socWS.connect();
  setTimeout(fullRefresh, 800);
  setInterval(loadCases, 30000);
});

window.socApp = { loadCases, fullRefresh };
