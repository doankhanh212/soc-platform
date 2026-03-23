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

const PAGE_SIZE = 30;
let _wazuhAll = [], _suriAll = [];
let _wazuhPage = 1, _suriPage = 1;

function _pagRange(cur, total){
  if(total <= 7) return Array.from({length:total},(_,i)=>i+1);
  if(cur <= 4) return [1,2,3,4,5,'…',total];
  if(cur >= total-3) return [1,'…',total-4,total-3,total-2,total-1,total];
  return [1,'…',cur-1,cur,cur+1,'…',total];
}

function _renderPag(containerId, cur, total, fnName){
  const el = document.getElementById(containerId);
  if(!el) return;
  const pages = Math.ceil(total / PAGE_SIZE);
  if(pages <= 1){ el.innerHTML=''; return; }

  let h = `<button class="pag-btn" onclick="${fnName}(${cur-1})" ${cur===1?'disabled':''}>‹ Trước</button>`;

  _pagRange(cur, pages).forEach(p=>{
    if(p==='…') h += '<span class="pag-ellipsis">…</span>';
    else h += `<button class="pag-btn ${p===cur?'active':''}" onclick="${fnName}(${p})">${p}</button>`;
  });

  h += `<button class="pag-btn" onclick="${fnName}(${cur+1})" ${cur===pages?'disabled':''}>Sau ›</button>`;
  h += `<span class="pag-info">Trang ${cur}/${pages} · ${total} cảnh báo</span>`;
  el.innerHTML = h;
}

window.renderWazuhPage = function(page){
  _wazuhPage = Math.max(1, Math.min(page, Math.ceil(_wazuhAll.length / PAGE_SIZE) || 1));
  const slice = _wazuhAll.slice((_wazuhPage - 1) * PAGE_SIZE, _wazuhPage * PAGE_SIZE);
  renderAlertsTable(slice);
  _renderPag('wazuh-pag', _wazuhPage, _wazuhAll.length, 'renderWazuhPage');
  document.getElementById('tbl-wazuh')?.scrollIntoView({behavior:'smooth',block:'start'});
};

window.renderSuriPage = function(page){
  _suriPage = Math.max(1, Math.min(page, Math.ceil(_suriAll.length / PAGE_SIZE) || 1));
  const slice = _suriAll.slice((_suriPage - 1) * PAGE_SIZE, _suriPage * PAGE_SIZE);
  renderSuriTable(slice);
  _renderPag('suri-pag', _suriPage, _suriAll.length, 'renderSuriPage');
  document.getElementById('tbl-suri')?.scrollIntoView({behavior:'smooth',block:'start'});
};

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
    const cases = await fetch('/api/cases/open?limit=8').then(r=>r.json());
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
    tbody.innerHTML='<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:24px">Không có cảnh báo trong 24h qua</td></tr>';
    return;
  }
  tbody.innerHTML = alerts.map(a=>{
    const level = parseInt(a?.rule?.level || 0);
    const isCritical = level >= 12;
    const alertEncoded = encodeURIComponent(JSON.stringify(a));
    const checkboxCell = isCritical 
      ? `<td style="width:36px;text-align:center;font-size:11px;color:var(--muted)">⚡</td>`
      : `<td style="width:36px;padding:9px 8px">
           <input type="checkbox" class="alert-row-check"
             data-alert="${alertEncoded}"
             onchange="window.toggleAlertSelect(this, this.dataset.alert)"
             style="cursor:pointer">
         </td>`;
    return `<tr>
      ${checkboxCell}
      <td class="mono">${fmtTime(a['@timestamp'])}</td>
      <td class="agent-name">${a?.agent?.name||'—'}</td>
      <td title="${a?.rule?.description||''}" style="color:var(--text)">${(a?.rule?.description||'—').slice(0,50)}</td>
      <td>${sevBadge(a?.rule?.level)}</td>
      <td class="src">${a?.data?.src_ip||'—'}</td>
      <td class="mono" style="color:var(--purple)">${a?.rule?.mitre?.id?.[0]||'—'}</td>
      <td><button class="btn-create-case" onclick='window.createCaseFromAlert(${JSON.stringify(a)})'>+ Vụ việc</button></td>
    </tr>`;
  }).join('');
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

const COUNTRY_FLAGS = {
  'United States':'🇺🇸','China':'🇨🇳','Russia':'🇷🇺','Germany':'🇩🇪','France':'🇫🇷',
  'United Kingdom':'🇬🇧','Brazil':'🇧🇷','India':'🇮🇳','Netherlands':'🇳🇱','Singapore':'🇸🇬',
  'South Korea':'🇰🇷','Japan':'🇯🇵','Australia':'🇦🇺','Canada':'🇨🇦','Ukraine':'🇺🇦',
  'Iran':'🇮🇷','North Korea':'🇰🇵','Vietnam':'🇻🇳','Indonesia':'🇮🇩','Thailand':'🇹🇭',
  'Hong Kong':'🇭🇰','Taiwan':'🇹🇼','Pakistan':'🇵🇰','Bangladesh':'🇧🇩','Turkey':'🇹🇷',
};

function renderGeoTable(geoIPs, topIPs) {
  const el = document.getElementById('geo-attack-table');
  if(!el) return;

  let data = [];
  if(geoIPs && geoIPs.length) {
    data = geoIPs.map(g=>({
      country: g.country||'Unknown',
      city: g.city||'',
      ip: g.ip,
      count: g.count,
    }));
  } else if(topIPs && topIPs.length) {
    data = topIPs.map(t=>({country:'—', city:'', ip:t.ip, count:t.count}));
  }

  if(!data.length){
    el.innerHTML='<div style="text-align:center;padding:20px;color:var(--muted);font-size:12px">Chưa có dữ liệu tấn công</div>';
    return;
  }

  data.sort((a,b)=>b.count-a.count);
  const max = data[0].count || 1;

  let h = `<div class="geo-row" style="border-bottom:1px solid var(--border);margin-bottom:4px;padding-bottom:6px">
    <span class="geo-rank" style="color:var(--muted);font-size:10px">#</span>
    <span class="geo-country" style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em">Quốc gia</span>
    <span class="geo-ip" style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em">IP nguồn</span>
    <span style="flex:1"></span>
    <span class="geo-count" style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em">Số lần</span>
  </div>`;

  h += data.slice(0,12).map((d,i)=>{
    const pct = (d.count/max*100).toFixed(1);
    const barColor = d.count > 500 ? 'var(--red)' : d.count > 100 ? 'var(--amber)' : 'var(--green)';
    const countColor = d.count > 500 ? 'var(--red)' : d.count > 100 ? 'var(--amber)' : 'var(--text)';
    const flag = COUNTRY_FLAGS[d.country] || '🌐';
    const label = d.country !== '—' ? `${flag} ${d.country}${d.city?' · '+d.city:''}` : '—';
    return `<div class="geo-row">
      <span class="geo-rank">${i+1}</span>
      <span class="geo-country" title="${d.country}${d.city?' · '+d.city:''}">${label}</span>
      <span class="geo-ip">${d.ip}</span>
      <div class="geo-bar-wrap">
        <div class="geo-bar" style="width:${pct}%;background:${barColor}"></div>
      </div>
      <span class="geo-count" style="color:${countColor}">${d.count.toLocaleString()}</span>
    </div>`;
  }).join('');

  el.innerHTML = h;
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

const MITRE_TACTIC_MAP = {
  'T1110':'Credential Access','T1078':'Defense Evasion','T1548':'Privilege Escalation',
  'T1190':'Initial Access','T1059':'Execution','T1046':'Discovery',
  'T1105':'Command and Control','T1565':'Impact','T1098':'Persistence',
  'T1041':'Command and Control','T1003':'Credential Access','T1055':'Defense Evasion',
  'T1562':'Defense Evasion','T1070':'Defense Evasion','T1021':'Lateral Movement',
  'T1086':'Execution','T1071':'Command and Control','T1102':'Command and Control',
  'T1486':'Impact','T1082':'Discovery','T1057':'Discovery','T1018':'Discovery',
};

function renderMitreDetailTable(techniques){
  const tbody = document.querySelector('#mitre-detail-tbl tbody');
  if(!tbody) return;
  if(!techniques.length){
    tbody.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:20px">Chưa có dữ liệu kỹ thuật MITRE</td></tr>';
    return;
  }

  const max = Math.max(...techniques.map(t=>t.count),1);
  tbody.innerHTML = techniques.map(t=>{
    const pct = (t.count/max*100).toFixed(0);
    const tactic = MITRE_TACTIC_MAP[t.id] || MITRE_TACTIC_MAP[t.id?.split('.')[0]] || '—';
    const techId = t.id?.replace('.','/') || t.id || '';
    const url = `https://attack.mitre.org/techniques/${techId}`;
    return `<tr>
      <td style="font-family:monospace;color:var(--cyan)">
        <a href="${url}" target="_blank" rel="noopener noreferrer"
          style="color:var(--cyan);text-decoration:none">${t.id}</a>
        <button onclick="navigator.clipboard?.writeText('${t.id}')"
          style="background:none;border:none;color:var(--muted);cursor:pointer;
                 font-size:10px;padding:0 4px;opacity:.6" title="Sao chép">📋</button>
      </td>
      <td><span class="mitre-tactic-badge">${tactic}</span></td>
      <td style="font-family:monospace;color:var(--text)">${t.count.toLocaleString()}</td>
      <td>
        <div class="mitre-count-bar">
          <div class="mitre-bar-bg">
            <div class="mitre-bar-fill" style="width:${pct}%"></div>
          </div>
          <span style="font-size:10px;color:var(--muted);min-width:30px">${pct}%</span>
        </div>
      </td>
      <td></td>
    </tr>`;
  }).join('');
}

/* ── Block IP ───────────────────────────────────── */
window.blockIP = async function(ip){
  if(!ip || typeof ip !== 'string') return;
  if(!confirm(`Chặn IP ${ip} bằng iptables?\n\nLưu ý: cần AI_BLOCK_AUTO=true trong .env backend`)) return;
  try{
    const res = await fetch(`/api/response/block-ip?ip=${encodeURIComponent(ip)}`,{method:'POST'});
    const data = await res.json();
    if(!res.ok){
      if(res.status===403){
        window.toast('Chặn thất bại: AI_BLOCK_AUTO=false trong .env — bật lên true và restart','err',7000);
      } else {
        window.toast('Lỗi chặn IP: '+(data.detail||JSON.stringify(data)),'err');
      }
      return;
    }
    window.toast(`✓ Đã chặn IP ${ip}`,'ok');
    window.socApi.topIPs(10).then(ips=>renderTopIPs(ips)).catch(()=>{});
  }catch(e){
    window.toast('Lỗi kết nối: '+e.message,'err');
  }
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
    _wazuhAll = d.recent_alerts; _wazuhPage = 1; window.renderWazuhPage(1);
    document.getElementById('badge-alerts').textContent = d.recent_alerts.length;
  }
  if(d.suricata_alerts){
    _suriAll = d.suricata_alerts; _suriPage = 1; window.renderSuriPage(1);
  }
  if(d.top_ips){
    renderTopIPs(d.top_ips);
    renderGeoTable(d.geo_ips, d.top_ips);
  }
  if(d.top_rules) window.socCharts.updateRulesBarDirect(d.top_rules);
  if(d.suricata_sigs) window.socCharts.updateSuricataBarDirect(d.suricata_sigs);
  if(window.casesApp && d.case_stats){
    const cs = d.case_stats;
    const el = id => document.getElementById(id);
    if(el('cs-stat-esc'))    el('cs-stat-esc').textContent    = cs.escalated||0;
    if(el('cs-stat-prog'))   el('cs-stat-prog').textContent   = cs.in_progress||0;
    if(el('cs-stat-new'))    el('cs-stat-new').textContent    = cs.new||0;
    if(el('cs-stat-done'))   el('cs-stat-done').textContent   = cs.resolved||0;
    if(el('cs-stat-triaged'))el('cs-stat-triaged').textContent= cs.triaged_today||0;
  }
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
      window.socApi.wazuhAlerts(500,1),
      window.socApi.suricataAlerts(500),
      window.socApi.caseStats(),
    ]);
    renderKPIs(kpis, cStats);
    window.socCharts.updateTimeline(tl);
    window.socCharts.updateSeverityDonut(sev);
    window.socCharts.updateTacticsBar(mitre.tactics||[]);
    window.socCharts.updateRulesBar(wazuh);
    window.socCharts.updateSuricataBar(suri);
    renderTopIPs(topIPs);
    renderGeoTable([], topIPs);
    // Lấy thêm geo data
    window.socApi.geoStats?.().then(geo => renderGeoTable(geo, topIPs)).catch(()=>{});
    _wazuhAll = wazuh; _wazuhPage = 1; window.renderWazuhPage(1);
    _suriAll  = suri;  _suriPage = 1;  window.renderSuriPage(1);
    renderMitre(mitre.techniques||[]);
    renderMitreDetailTable(mitre.techniques||[]);
    renderStream(wazuh);
    loadCases();
    window.casesApp?.loadAll?.();
    toast('Đã làm mới','ok',1500);
  } catch(e){ toast('Lỗi làm mới: '+e.message,'err'); }
}

/* ── Init ────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', ()=>{
  // Nav
  document.querySelectorAll('.nav-tab[data-page]').forEach(t=>
    t.addEventListener('click', ()=>navigate(t.dataset.page)));

  document.querySelector('[data-page="mitre"]')?.addEventListener('click', async ()=>{
    try{
      const m = await window.socApi.mitre();
      window.socCharts.updateTacticsBar(m.tactics||[]);
      renderMitreDetailTable(m.techniques || []);
    } catch(_){}
  });

  // Refresh btn
  document.getElementById('refresh-btn')?.addEventListener('click', fullRefresh);

  // Charts
  window.socCharts.initTimeline('chart-timeline');
  window.socCharts.initSeverityDonut('chart-sev');
  window.socCharts.initTacticsBar('chart-tactics');
  window.socCharts.initRulesBar('chart-rules');
  window.socCharts.initSuricataBar('chart-suri');

  // Start
  navigate('dashboard');
  window.socWS.connect();
  setTimeout(fullRefresh, 800);
  setInterval(loadCases, 30000);
});

window.socApp = { loadCases, fullRefresh };

/* ═══════════════════════════════════════════════════════
   CASES PAGE — full logic
   ═══════════════════════════════════════════════════════ */
(function(){

let _allCases = [];
let _filtered = [];
let _activeFilter = null;
let _selectedCaseId = null;
let _activeDetailTab = 'overview';

// ── Helpers ──────────────────────────────────────────
function _sevClass(sev){
  return sev==='Critical'?'sev-critical':sev==='High'?'sev-high':
         sev==='Medium'?'sev-medium':'sev-low';
}
function _statusBadge(s){
  const m={
    'New':'<span class="badge b-new">Mới</span>',
    'In Progress':'<span class="badge b-prog">Đang xử lý</span>',
    'Escalated':'<span class="badge b-esc">Leo thang</span>',
    'Resolved':'<span class="badge b-done">Đã giải quyết</span>',
    'Closed':'<span class="badge" style="background:rgba(60,60,60,.3);color:#666">Đóng</span>',
  };
  return m[s]||`<span class="badge">${s}</span>`;
}
function _sevBadge(sev){
  const m={
    'Critical':'<span class="badge b-crit">Nghiêm trọng</span>',
    'High':'<span class="badge b-high">Cao</span>',
    'Medium':'<span class="badge b-med">Trung bình</span>',
    'Low':'<span class="badge badge-low">Thấp</span>',
  };
  return m[sev]||`<span class="badge">${sev}</span>`;
}
function _fmtTs(ts){
  if(!ts) return '—';
  const d = new Date(ts*1000);
  return d.toLocaleTimeString('vi-VN',{hour:'2-digit',minute:'2-digit'})+
         ' '+d.toLocaleDateString('vi-VN');
}
function _dotColor(action){
  if(action.includes('leo thang')||action.includes('escalat')) return 'red';
  if(action.includes('tạo')||action.includes('created')) return 'blue';
  if(action.includes('phân loại')||action.includes('triage')) return 'green';
  if(action.includes('giao')||action.includes('assign')) return 'amber';
  return 'purple';
}

// ── Load all cases ────────────────────────────────────
async function loadAll(){
  try{
    const res = await fetch('/api/cases/?limit=200');
    _allCases = await res.json();
    if (!_activeFilter) _activeFilter = 'New';
    _applyFilter();
    _updateStats();
  }catch(e){ window.toast('Lỗi tải vụ việc: '+e.message,'err'); }
}

function _updateStats(){
  const el = id => document.getElementById(id);
  const count = s => _allCases.filter(c=>c.status===s).length;
  if(el('cs-stat-esc'))    el('cs-stat-esc').textContent    = count('Escalated');
  if(el('cs-stat-prog'))   el('cs-stat-prog').textContent   = count('In Progress');
  if(el('cs-stat-new'))    el('cs-stat-new').textContent    = count('New');
  if(el('cs-stat-done'))   el('cs-stat-done').textContent   = count('Resolved');

  // triaged today
  const today = Date.now()/1000 - 86400;
  if(el('cs-stat-triaged'))
    el('cs-stat-triaged').textContent =
      _allCases.filter(c=>c.updated_at > today &&
        ['Resolved','Closed'].includes(c.status)).length;
}

// ── Filter + Search ───────────────────────────────────
function filterBy(status, btn){
  _activeFilter = status;
  document.querySelectorAll('#page-cases .filter-btn').forEach(b=>{
    b.classList.toggle('active', b===btn);
  });
  _applyFilter();
}

function searchCases(q){
  _applyFilter(q);
}

function _applyFilter(q){
  const query = (q||document.getElementById('case-search')?.value||'').toLowerCase();
  _filtered = _allCases.filter(c=>{
    const matchStatus = !_activeFilter || c.status === _activeFilter;
    const matchQuery  = !query ||
      c.title.toLowerCase().includes(query) ||
      (c.src_ip||'').includes(query) ||
      (c.rule_desc||'').toLowerCase().includes(query) ||
      c.case_id.includes(query);
    return matchStatus && matchQuery;
  });
  renderList();
}

// ── Render list ───────────────────────────────────────
function renderList(){
  const wrap = document.getElementById('cases-list-full');
  if(!wrap) return;
  if(!_filtered.length){
    wrap.innerHTML=`<div style="padding:40px;text-align:center;color:var(--muted)">
      <div style="font-size:28px;opacity:.3;margin-bottom:10px">🗂</div>
      <div style="font-size:13px;font-weight:600;margin-bottom:8px">Chưa có vụ việc nào</div>
      <div style="font-size:11px;line-height:1.8;max-width:260px;margin:0 auto">
        Vụ việc được tạo tự động từ Wazuh alert,<br>
        hoặc nhấn <b style="color:var(--green)">+ Tạo vụ việc</b> để thêm thủ công.
      </div>
    </div>`;
    return;
  }
  wrap.innerHTML = _filtered.map(c=>{
    const mitreTags = (c.mitre_ids||[]).map(m=>
      `<span class="mitre-tag-sm">${m}</span>`).join('');
    return `<div class="case-card ${_sevClass(c.severity)} ${_selectedCaseId===c.case_id?'selected':''}"
      onclick="window.casesApp.select('${c.case_id}')">
      <div class="case-top">
        <span class="case-id-lbl">${c.case_id}</span>
        <span class="case-title-lbl" title="${c.title}">${c.title}</span>
        ${_statusBadge(c.status)}
        ${_sevBadge(c.severity)}
      </div>
      <div class="case-desc-lbl">${c.rule_desc||c.title}</div>
      <div class="case-meta-row">
        <span>🕐 ${_fmtTs(c.created_at)}</span>
        <span>👤 ${c.assignee||'Chưa giao'}</span>
        ${c.src_ip?`<span>📍 IP: <span style="color:var(--cyan)">${c.src_ip}</span></span>`:''}
        <div class="case-tags-row">${mitreTags}</div>
      </div>
    </div>`;
  }).join('');
}

// ── Select case → show detail ─────────────────────────
async function selectCase(caseId){
  _selectedCaseId = caseId;
  renderList();
  const c = _allCases.find(x=>x.case_id===caseId);
  if(!c) return;
  document.getElementById('detail-case-id').textContent = `Chi tiết ${c.case_id}`;
  _activeDetailTab = 'overview';
  renderDetailPanel(c);

  // Load triage log for timeline
  try{
    const logs = await fetch(`/api/cases/${encodeURIComponent(caseId)}/triage`).then(r=>r.json());
    c._triageLogs = logs;
    renderDetailPanel(c);
  }catch{}
}

// ── Render detail panel ───────────────────────────────
function renderDetailPanel(c){
  const body = document.getElementById('case-detail-body');
  if(!body) return;

  const tabs = `
  <div class="detail-tabs">
    <div class="detail-tab ${_activeDetailTab==='overview'?'active':''}"
      onclick="window.casesApp.tab('overview','${c.case_id}')">Tổng quan</div>
    <div class="detail-tab ${_activeDetailTab==='triage'?'active':''}"
      onclick="window.casesApp.tab('triage','${c.case_id}')">Phân loại</div>
    <div class="detail-tab ${_activeDetailTab==='timeline'?'active':''}"
      onclick="window.casesApp.tab('timeline','${c.case_id}')">Lịch sử</div>
  </div>`;

  let content = '';

  if(_activeDetailTab === 'overview'){
    const sevColor = c.severity==='Critical'?'danger':c.severity==='High'?'warn':
                     c.severity==='Medium'?'':'ok';
    const stColor  = c.status==='Escalated'?'danger':c.status==='Resolved'?'ok':
                     c.status==='In Progress'?'warn':'';
    content = `
      <div class="info-row"><span class="info-key">Trạng thái</span>
        <span class="info-val ${stColor}">${c.status}</span></div>
      <div class="info-row"><span class="info-key">Mức độ</span>
        <span class="info-val ${sevColor}">${c.severity}</span></div>
      <div class="info-row"><span class="info-key">IP nguồn</span>
        <span class="info-val ip">${c.src_ip||'—'}</span></div>
      <div class="info-row"><span class="info-key">IP đích</span>
        <span class="info-val ip">${c.dest_ip||'103.98.152.187 (SOC Server)'}</span></div>
      <div class="info-row"><span class="info-key">Máy chủ agent</span>
        <span class="info-val ok">${c.agent||'—'}</span></div>
      <div class="info-row"><span class="info-key">Rule ID</span>
        <span class="info-val">${c.rule_id||'—'}</span></div>
      <div class="info-row"><span class="info-key">Mô tả rule</span>
        <span class="info-val" style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${c.rule_desc||''}">${c.rule_desc||'—'}</span></div>
      <div class="info-row"><span class="info-key">MITRE</span>
        <span class="info-val purple">${(c.mitre_ids||[]).join(', ')||'—'}</span></div>
      <div class="info-row"><span class="info-key">Tạo lúc</span>
        <span class="info-val">${_fmtTs(c.created_at)}</span></div>
      <div class="info-row"><span class="info-key">Cập nhật</span>
        <span class="info-val">${_fmtTs(c.updated_at)}</span></div>
      <div class="info-row"><span class="info-key">Phân tích viên</span>
        <span class="info-val warn">${c.assignee||'Chưa giao'}</span></div>
      <div class="case-actions">
        <div class="ca-btn ca-triage"
          onclick="window.triageOpenModal(${JSON.stringify(c).replace(/"/g,'&quot;')})">
          🛡 Phân loại</div>
        <div class="ca-btn ca-assign" onclick="window.casesApp.assign('${c.case_id}')">
          👤 Giao việc</div>
        <div class="ca-btn ca-close" onclick="window.casesApp.close('${c.case_id}')">
          ✕ Đóng</div>
      </div>`;
  }

  if(_activeDetailTab === 'triage'){
    const logs = c._triageLogs||[];
    if(!logs.length){
      content = `<div style="text-align:center;padding:30px;color:var(--muted);font-size:12px">
        Chưa có phân loại nào.<br>Nhấn nút "Phân loại" để bắt đầu.</div>`;
    } else {
      content = logs.map(l=>`
        <div style="background:var(--bg-hover);border:1px solid var(--border);
          border-radius:var(--r);padding:10px;margin-bottom:8px">
          <div style="display:flex;justify-content:space-between;margin-bottom:6px">
            <span style="font-weight:700;font-size:12px;color:${
              l.classification==='True Positive'?'var(--red)':
              l.classification==='False Positive'?'var(--amber)':'var(--green)'
            }">${l.classification}</span>
            <span style="font-size:10px;color:var(--muted);font-family:monospace">
              ${_fmtTs(l.created_at)}</span>
          </div>
          <div style="font-size:11px;color:var(--muted);margin-bottom:4px">
            Ảnh hưởng: <span style="color:var(--text)">${l.impact_level}</span>
          </div>
          ${l.analysis?`<div style="font-size:12px;color:var(--text);margin-bottom:4px">
            ${l.analysis}</div>`:''}
          ${l.recommendation?`<div style="font-size:11px;color:var(--muted);
            border-top:1px solid var(--border);padding-top:6px;margin-top:4px">
            💡 ${l.recommendation}</div>`:''}
        </div>`).join('');
    }
  }

  if(_activeDetailTab === 'timeline'){
    const logs = c._triageLogs||[];
    const events = [
      {action:'Vụ việc được tạo từ Wazuh alert', ts:c.created_at, dot:'blue'},
      ...logs.map(l=>({
        action:`Phân loại: ${l.classification} · ${l.impact_level}`,
        ts:l.created_at, dot:'green'
      })),
    ];
    if(c.status==='Escalated')
      events.push({action:'Vụ việc leo thang tự động', ts:c.updated_at, dot:'red'});
    if(['Resolved','Closed'].includes(c.status))
      events.push({action:'Vụ việc đã được đóng', ts:c.closed_at||c.updated_at, dot:'green'});

    events.sort((a,b)=>(b.ts||0)-(a.ts||0));

    content = `<div class="tl-section-title">Dòng thời gian</div>
      <div class="tl-list">` +
      events.map(ev=>`
        <div class="tl-item">
          <div class="tl-dot ${ev.dot}"></div>
          <div>
            <div class="tl-action">${ev.action}</div>
            <div class="tl-time">${_fmtTs(ev.ts)}</div>
          </div>
        </div>`).join('') +
      '</div>';
  }

  body.innerHTML = tabs +
    `<div class="detail-body">${content}</div>`;
}

// ── Tab switch ────────────────────────────────────────
function switchDetailTab(tab, caseId){
  _activeDetailTab = tab;
  const c = _allCases.find(x=>x.case_id===caseId);
  if(c) renderDetailPanel(c);
}

// ── Quick actions ─────────────────────────────────────
async function assignCase(caseId){
  const analyst = prompt('Giao cho analyst (nhập tên):');
  if(!analyst) return;
  try{
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/status`,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({status:'In Progress',assignee:analyst})
    });
    await loadAll();
    selectCase(caseId);
    window.toast(`Đã giao cho ${analyst}`,'ok');
  }catch(e){ window.toast('Lỗi: '+e.message,'err'); }
}

async function closeCase(caseId){
  if(!confirm(`Đóng vụ việc ${caseId}?`)) return;
  try{
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/status`,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({status:'Closed'})
    });
    await loadAll();
    _selectedCaseId = null;
    document.getElementById('case-detail-body').innerHTML = `
      <div class="no-case-selected">
        <div style="font-size:32px;margin-bottom:10px;opacity:.4">🔒</div>
        <div style="font-size:12px;color:var(--muted)">Vụ việc đã đóng.</div>
      </div>`;
    document.getElementById('detail-case-id').textContent = 'Chọn vụ việc để xem chi tiết';
    window.toast(`Đã đóng ${caseId}`,'ok');
  }catch(e){ window.toast('Lỗi: '+e.message,'err'); }
}

// ── Navigate to cases page → auto load ───────────────
document.querySelector('[data-page="cases"]')
  ?.addEventListener('click', ()=> loadAll());

// ── Public API ────────────────────────────────────────
window.casesApp = {
  loadAll,
  filter: filterBy,
  search: searchCases,
  select: selectCase,
  tab: switchDetailTab,
  assign: assignCase,
  close: closeCase,
};

// Override cũ nếu có
window.socApp = window.socApp || {};
window.socApp.loadCases = loadAll;
window.socApp.loadAllCases = (status) => {
  _activeFilter = status;
  loadAll();
};

// Refresh cases sau khi triage xong
const _origClose = window.triageClose;
window.triageClose = function(){
  if(_origClose) _origClose();
  loadAll().then(()=>{
    _selectedCaseId = null;
    const body = document.getElementById('case-detail-body');
    if(body) body.innerHTML = `
      <div class="no-case-selected">
        <div style="font-size:32px;margin-bottom:10px;opacity:.4">✅</div>
        <div style="font-size:12px;color:var(--muted)">
          Đã phân loại xong.<br>Chọn vụ việc khác để tiếp tục.
        </div>
      </div>`;
    const hdr = document.getElementById('detail-case-id');
    if(hdr) hdr.textContent = 'Chọn vụ việc để xem chi tiết';
    if(window.loadCases) loadCases();
  });
};

})();

/* ═════════════════════════════════════════════════════════════════
   BULK SELECT + MANUAL CASE CREATION
   ═════════════════════════════════════════════════════════════════ */
let _selectedAlerts = new Map(); // alertId → alertObject

function _updateBulkToolbar() {
  const count = _selectedAlerts.size;
  const toolbar = document.getElementById('bulk-toolbar');
  const countEl = document.getElementById('bulk-count');
  if (!toolbar) return;
  toolbar.style.display = count > 0 ? 'flex' : 'none';
  if (countEl) countEl.textContent = `${count} alert được chọn`;
}

window.toggleAlertSelect = function(checkbox, alertJson) {
  const alert = JSON.parse(decodeURIComponent(alertJson));
  const id = alert['@timestamp'] + (alert.rule?.id || '');
  if (checkbox.checked) {
    _selectedAlerts.set(id, alert);
  } else {
    _selectedAlerts.delete(id);
    document.getElementById('check-all').checked = false;
  }
  _updateBulkToolbar();
};

window.toggleAllAlerts = function(checked) {
  _selectedAlerts.clear();
  if (checked) {
    document.querySelectorAll('.alert-row-check').forEach(cb => {
      cb.checked = true;
      const alert = JSON.parse(decodeURIComponent(cb.dataset.alert));
      const id = alert['@timestamp'] + (alert.rule?.id || '');
      _selectedAlerts.set(id, alert);
    });
  } else {
    document.querySelectorAll('.alert-row-check').forEach(cb => cb.checked = false);
  }
  _updateBulkToolbar();
};

window.clearBulkSelect = function() {
  _selectedAlerts.clear();
  document.querySelectorAll('.alert-row-check').forEach(cb => cb.checked = false);
  const ca = document.getElementById('check-all');
  if (ca) ca.checked = false;
  _updateBulkToolbar();
};

window.bulkCreateCases = async function() {
  const alerts = [..._selectedAlerts.values()];
  if (!alerts.length) return;
  if (!confirm(`Tạo ${alerts.length} vụ việc từ các alert đã chọn?`)) return;
  try {
    const res = await fetch('/api/rules/bulk-create-cases', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({alerts}),
    });
    const data = await res.json();
    window.toast(`✓ Đã tạo ${data.created} vụ việc`, 'ok');
    window.clearBulkSelect();
    window.casesApp?.loadAll?.();
  } catch(e) {
    window.toast('Lỗi tạo case: ' + e.message, 'err');
  }
};

/* ═════════════════════════════════════════════════════════════════
   RULE ENGINE STATUS WIDGET
   ═════════════════════════════════════════════════════════════════ */
async function loadRuleStatus() {
  try {
    const rules = await fetch('/api/rules/').then(r => r.json());
    const el = document.getElementById('rule-engine-status');
    if (el) el.textContent = `${rules.length} rules đang hoạt động`;
  } catch(e) {}
}

window.triggerRuleEngine = async function() {
  try {
    await fetch('/api/rules/run-now', {method:'POST'});
    window.toast('Rule engine đã chạy — kiểm tra tab Vụ việc', 'ok');
    setTimeout(() => window.casesApp?.loadAll?.(), 2000);
  } catch(e) {
    window.toast('Lỗi: ' + e.message, 'err');
  }
};

document.addEventListener('DOMContentLoaded', () => {
  loadRuleStatus();
});
