/**
 * app.js — Main application controller
 * Green cyberpunk SOC Dashboard
 */

/* ── Toast (provided by toast.js — compatibility bridge) ── */
// window.toast is defined by toast.js with enhanced notifications
// If toast.js not loaded, provide minimal fallback
if (typeof window.toast !== 'function') {
  window.toast = function(msg, type='ok', ms=4000){
    const wrap = document.getElementById('toast-wrap');
    const t = document.createElement('div');
    const icons = {ok:'✓',err:'✗',warn:'⚠'};
    t.className = `toast toast-${type}`;
    t.innerHTML = `<span>${icons[type]||'ℹ'}</span><span>${msg}</span>`;
    wrap.appendChild(t);
    setTimeout(()=>t.remove(), ms);
  };
}

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

function formatBadgeCount(count){
  const n = Number(count || 0);
  if(typeof window.formatSoLan === 'function'){
    return window.formatSoLan(n);
  }
  return n.toLocaleString('vi-VN');
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
  document.getElementById('page-alerts')?.scrollTo({top: 0, behavior: 'smooth'});
};

window.renderSuriPage = function(page){
  _suriPage = Math.max(1, Math.min(page, Math.ceil(_suriAll.length / PAGE_SIZE) || 1));
  const slice = _suriAll.slice((_suriPage - 1) * PAGE_SIZE, _suriPage * PAGE_SIZE);
  renderSuriTable(slice);
  _renderPag('suri-pag', _suriPage, _suriAll.length, 'renderSuriPage');
  document.getElementById('page-alerts')?.scrollTo({top: 0, behavior: 'smooth'});
};

/* ── Navigation ─────────────────────────────────── */
function navigate(page) {
  document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.classList.toggle('active', item.dataset.page === page);
  });

  document.querySelectorAll('.page').forEach(p => {
    p.classList.toggle('active', p.id === `page-${page}`);
  });

  const titles = {
    'dashboard':    ['Dashboard', 'Tổng quan hệ thống'],
    'alerts':       ['Hàng đợi cảnh báo', 'SOC Level 1'],
    'cases':        ['Quản lý vụ việc', 'SOC Level 2'],
    'mitre':        ['MITRE ATT&CK', 'Kỹ thuật tấn công'],
    'threat-intel': ['Threat Intelligence', 'IOC & Enrichment'],
    'hunting':      ['Threat Hunting', 'Truy vết nâng cao'],
    'soar':         ['SOAR Playbook', 'Điều phối và phản ứng tự động'],
    'ai':           ['Động cơ AI', 'Phát hiện bất thường'],
    'blocked-ips':  ['IP bị chặn', 'Quản lý danh sách chặn'],
    'settings':     ['Cài đặt', 'Hệ thống'],
  };
  const [title, sub] = titles[page] || [page, ''];
  const titleEl = document.getElementById('page-title');
  const subEl   = document.getElementById('page-subtitle');
  if(titleEl) titleEl.textContent = title;
  if(subEl)   subEl.textContent   = sub;

  if(page === 'alerts' && window.alertQueue) {
    window.alertQueue.reload();
  }
  if(page === 'cases' && window.casesApp) {
    window.casesApp.loadAll();
  }
  if(page === 'ai' && window.aiEngineApp && typeof window.aiEngineApp.onPageActive === 'function') {
    window.aiEngineApp.onPageActive();
  }
  if(page === 'blocked-ips' && window.blockedIpsPage && typeof window.blockedIpsPage.onPageActive === 'function') {
    window.blockedIpsPage.onPageActive();
  }
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

const COUNTRY_CODES = {
  "Afghanistan":"af","Albania":"al","Algeria":"dz","Argentina":"ar",
  "Australia":"au","Austria":"at","Azerbaijan":"az","Bangladesh":"bd",
  "Belarus":"by","Belgium":"be","Bolivia":"bo","Brazil":"br",
  "Bulgaria":"bg","Cambodia":"kh","Canada":"ca","Chile":"cl",
  "China":"cn","Colombia":"co","Croatia":"hr","Czech Republic":"cz",
  "Denmark":"dk","Ecuador":"ec","Egypt":"eg","Estonia":"ee",
  "Ethiopia":"et","Finland":"fi","France":"fr","Georgia":"ge",
  "Germany":"de","Ghana":"gh","Greece":"gr","Guatemala":"gt",
  "Hong Kong":"hk","Hungary":"hu","India":"in","Indonesia":"id",
  "Iran":"ir","Iraq":"iq","Ireland":"ie","Israel":"il",
  "Italy":"it","Japan":"jp","Jordan":"jo","Kazakhstan":"kz",
  "Kenya":"ke","Latvia":"lv","Lebanon":"lb","Lithuania":"lt",
  "Luxembourg":"lu","Malaysia":"my","Mexico":"mx","Moldova":"md",
  "Mongolia":"mn","Morocco":"ma","Myanmar":"mm","Nepal":"np",
  "Netherlands":"nl","New Zealand":"nz","Nigeria":"ng","Norway":"no",
  "Pakistan":"pk","Palestine":"ps","Panama":"pa","Peru":"pe",
  "Philippines":"ph","Poland":"pl","Portugal":"pt","Romania":"ro",
  "Russia":"ru","Saudi Arabia":"sa","Serbia":"rs","Singapore":"sg",
  "Slovakia":"sk","Slovenia":"si","South Africa":"za","South Korea":"kr",
  "Spain":"es","Sri Lanka":"lk","Sweden":"se","Switzerland":"ch",
  "Syria":"sy","Taiwan":"tw","Thailand":"th","Turkey":"tr",
  "Ukraine":"ua","United Arab Emirates":"ae","United Kingdom":"gb",
  "United States":"us","Uruguay":"uy","Uzbekistan":"uz",
  "Venezuela":"ve","Vietnam":"vn","Yemen":"ye","Zimbabwe":"zw",
};

function _flagImg(country) {
  const code = COUNTRY_CODES[country];
  if (!code) return '<span style="font-size:16px;margin-right:6px">🌐</span>';
  return `<img src="https://flagcdn.com/20x15/${code}.png"
    width="20" height="15"
    style="margin-right:6px;vertical-align:middle;
           border-radius:2px;object-fit:cover;flex-shrink:0"
    onerror="this.style.display='none'"
    alt="${country}">`;
}

function renderGeoTable(geoIPs, topIPs) {
  const el = document.getElementById('geo-attack-table');
  if (!el) return;

  let data = (geoIPs && geoIPs.length)
    ? geoIPs
    : (topIPs || []).map(t => ({ip:t.ip, count:t.count, country:'', city:''}));

  if (!data.length) {
    el.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted);font-size:12px">Chưa có dữ liệu tấn công</div>';
    return;
  }

  data.sort((a, b) => b.count - a.count);
  const max = data[0].count || 1;

  const header = `
    <div style="display:flex;padding:0 0 6px;border-bottom:1px solid var(--border);
      font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
      color:var(--muted);margin-bottom:6px">
      <span style="min-width:24px">#</span>
      <span style="min-width:180px">Quốc gia</span>
      <span style="min-width:125px">IP nguồn</span>
      <span style="flex:1">Tần suất</span>
      <span style="min-width:55px;text-align:right">Số lần</span>
    </div>`;

  const rows = data.slice(0, 10).map((d, i) => {
    const pct   = (d.count / max * 100).toFixed(1);
    const color = d.count > 1000 ? 'var(--red)'
          : d.count > 300  ? 'var(--amber)': d.count > 50   ? 'var(--medium)'
          : 'var(--green)';

    // Hiển thị city nếu có
    const location = d.country
      ? (d.city ? `${d.country} · ${d.city}` : d.country)
      : 'Unknown';

    return `
      <div class="geo-row">
        <span class="geo-rank" style="min-width:24px;color:var(--muted);
          font-family:'Share Tech Mono',monospace;font-size:11px">${i + 1}</span>
        <span class="geo-country" style="min-width:180px;font-size:12px;
          color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${_flagImg(d.country)}
          ${location}
        </span>
        <span class="geo-ip" style="min-width:125px;font-family:'Share Tech Mono',
          monospace;font-size:11px;color:var(--cyan)">${d.ip}</span>
        <div class="geo-bar-wrap" style="flex:1;height:5px;background:var(--accent-08);
          border-radius:3px;overflow:hidden;margin:0 8px">
          <div class="geo-bar" style="width:${pct}%;height:100%;
            background:${color};border-radius:3px;transition:width .4s"></div>
        </div>
        <span class="geo-count" style="min-width:55px;text-align:right;
          font-family:'Share Tech Mono',monospace;font-size:11px;
          color:${color}">${d.count.toLocaleString()}</span>
      </div>`;
  }).join('');

  el.innerHTML = header + rows;
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

/* ── Block IP (enhanced by block_ip.js if loaded) ── */
window.blockIP = async function(ip){
  if(!ip || typeof ip !== 'string') return;
  // Use enhanced confirmBlockIP modal if block_ip.js is loaded
  if(typeof confirmBlockIP === 'function'){
    confirmBlockIP(ip, { analyst: 'admin' });
    return;
  }
  // Fallback: simple confirm dialog
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

  const nowLabel = new Date().toLocaleTimeString('vi-VN');
  const lastUpdateEl = document.getElementById('last-update');
  const aqUpdateEl = document.getElementById('aq-last-update');
  if (lastUpdateEl) lastUpdateEl.textContent = nowLabel;
  if (aqUpdateEl) aqUpdateEl.textContent = nowLabel;

  if(d.kpis) renderKPIs(d.kpis);
  if(d.recent_alerts){
    renderStream(d.recent_alerts);
    _wazuhAll = d.recent_alerts;
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
  if(d.kpis){
    const alertsBadge = document.getElementById('nav-badge-alerts');
    const notif = document.getElementById('notif-count');
    const critical = d.kpis.critical_alerts || 0;
    if(alertsBadge) alertsBadge.textContent = formatBadgeCount(d.kpis.total_alerts_24h || 0);
    if(notif){
      notif.textContent = critical;
      notif.style.display = critical > 0 ? 'block' : 'none';
    }
  }
  if(window.casesApp && d.case_stats){
    const cs = d.case_stats;
    const el = id => document.getElementById(id);
    if(el('cs-stat-esc'))    el('cs-stat-esc').textContent    = cs.escalated||0;
    if(el('cs-stat-prog'))   el('cs-stat-prog').textContent   = cs.in_progress||0;
    if(el('cs-stat-new'))    el('cs-stat-new').textContent    = cs.new||0;
    if(el('cs-stat-done'))   el('cs-stat-done').textContent   = cs.resolved||0;
    if(el('cs-stat-triaged'))el('cs-stat-triaged').textContent= cs.triaged_today||0;
    if(el('nav-badge-cases')) el('nav-badge-cases').textContent =
      formatBadgeCount((cs.new||0) + (cs.in_progress||0) + (cs.escalated||0));
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
    _suriAll  = suri;  _suriPage = 1;  window.renderSuriPage(1);
    renderMitre(mitre.techniques||[]);
    renderMitreDetailTable(mitre.techniques||[]);
    renderStream(wazuh);
    loadCases();
    window.casesApp?.loadAll?.();
    window.alertQueue?.reload?.();
    const alertsBadge = document.getElementById('nav-badge-alerts');
    const casesBadge = document.getElementById('nav-badge-cases');
    const notif = document.getElementById('notif-count');
    if (alertsBadge) alertsBadge.textContent = formatBadgeCount(kpis.total_alerts_24h || 0);
    if (casesBadge) casesBadge.textContent =
      formatBadgeCount((cStats.new||0) + (cStats.in_progress||0) + (cStats.escalated||0));
    if (notif) {
      notif.textContent = kpis.critical_alerts || 0;
      notif.style.display = (kpis.critical_alerts || 0) > 0 ? 'block' : 'none';
    }
    // Update blocked IPs badge
    fetch('/api/blocked-ips/count').then(r=>r.json()).then(d=>{
      const b = document.getElementById('nav-badge-blocked');
      if(b) b.textContent = d.count || 0;
    }).catch(()=>{});
    toast('Đã làm mới','ok',1500);
  } catch(e){ toast('Lỗi làm mới: '+e.message,'err'); }
}

/* ── Init ────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', ()=>{
  document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.addEventListener('click', () => navigate(item.dataset.page));
  });

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
  // NOTE: auth.js will call socWS.connect() after login
  // auth.js will also trigger fullRefresh after login
  setInterval(loadCases, 30000);

  // Poll /api/stats/today cho 3 counter AI
  function fetchStatsToday() {
    fetch('/api/stats/today')
      .then(r => r.json())
      .then(d => {
        const el = id => document.getElementById(id);
        if (el('kpi-triaged')) el('kpi-triaged').textContent = d.classified || 0;
        if (el('kpi-tp'))      el('kpi-tp').textContent      = d.threats_stopped || 0;
        if (el('kpi-fp'))      el('kpi-fp').textContent      = d.false_positives || 0;
      })
      .catch(() => {});
  }
  fetchStatsToday();
  setInterval(fetchStatsToday, 30000);
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
let _bulkSelected = new Set();

function _updateBulkBar() {
  const n = _bulkSelected.size;
  const tb = document.getElementById('case-bulk-toolbar');
  const ct = document.getElementById('case-bulk-count');
  if (tb) tb.style.display = n > 0 ? 'flex' : 'none';
  if (ct) ct.textContent = `${n} vụ việc được chọn`;
}

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
    'Resolved':'<span class="badge b-done">Đã phân loại</span>',
    'Closed':'<span class="badge" style="background:rgba(60,60,60,.3);color:var(--muted)">Đóng</span>',
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
    const ids = new Set(_allCases.map(c => c.case_id));
    _bulkSelected = new Set([..._bulkSelected].filter(id => ids.has(id)));
    if (!_activeFilter) _activeFilter = 'New';
    _applyFilter();
    _updateStats();
    _updateBulkBar();
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
  _updateBulkBar();
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
        <input type="checkbox" class="case-cb"
          ${_bulkSelected.has(c.case_id) ? 'checked' : ''}
          onchange="window.casesApp.toggleBulk(event,'${c.case_id}')"
          onclick="event.stopPropagation()"
          style="cursor:pointer;margin-right:4px;flex-shrink:0">
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
          <button onclick="window.casesApp.deleteTriageLog('${c.case_id}')"
            style="margin-top:8px;padding:4px 12px;background:var(--red2);
                   border:1px solid var(--red);border-radius:var(--r);
                   color:var(--red);font-size:11px;cursor:pointer;width:100%">
            🗑 Xóa phân loại này — reset về Mới
          </button>
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

function toggleBulk(e, caseId) {
  e.stopPropagation();
  _bulkSelected.has(caseId) ? _bulkSelected.delete(caseId) : _bulkSelected.add(caseId);
  _updateBulkBar();
}

function clearBulk() {
  _bulkSelected.clear();
  _updateBulkBar();
  renderList();
}

async function bulkTriage() {
  const ids = [..._bulkSelected];
  if (!ids.length) return;
  const classification = prompt(
    `Phân loại ${ids.length} vụ việc:\n` +
    `1. Mối đe dọa thực\n2. Báo động nhầm\n3. Vô hại\n` +
    `Nhập số (1/2/3):`
  );
  const map = {'1':'True Positive','2':'False Positive','3':'Benign'};
  const cls = map[classification?.trim()];
  if (!cls) { window.toast('Huỷ phân loại hàng loạt', 'warn'); return; }

  let ok = 0;
  for (const id of ids) {
    try {
      await fetch(`/api/cases/${encodeURIComponent(id)}/triage`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          classification: cls,
          reasons: [],
          mitre_mapping: [],
          impact_level: 'Medium',
          analysis: 'Phân loại hàng loạt',
          recommendation: '',
          analyst: 'analyst',
        }),
      });
      ok++;
    } catch {}
  }
  window.toast(`✓ Đã phân loại ${ok}/${ids.length} vụ việc`, 'ok');
  _bulkSelected.clear();
  await loadAll();
}

async function deleteTriageLog(caseId) {
  if (!confirm(`Xóa phân loại của ${caseId}?\nCase sẽ reset về trạng thái Mới.`)) return;
  try {
    await window.socApi.deleteTriage(caseId);
    window.toast(`Đã xóa phân loại ${caseId}`, 'ok');
    await loadAll();
    selectCase(caseId);
  } catch(e) {
    window.toast('Lỗi xóa: ' + e.message, 'err');
  }
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
  toggleBulk,
  clearBulk,
  bulkTriage,
  deleteTriageLog,
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

(function(){
  let _data = [], _filtered = [];
  let _selSev = null, _selStatus = null;
  let _searchQ = '', _timeHours = 24;
  let _selected = new Set();
  let _page = 1;
  const PAGE = 30;

  function _sevClass(lv) {
    const n = parseInt(lv)||0;
    if(n>=12) return 'critical';
    if(n>=7)  return 'high';
    if(n>=4)  return 'medium';
    return 'low';
  }
  function _alertType(a) {
    const grp = a?.rule?.groups||[];
    if(grp.includes('suricata')) return 'Mạng';
    if(grp.includes('syscheck'))  return 'FIM';
    if(grp.includes('authentication')||grp.includes('sshd')) return 'Xác thực';
    if(grp.includes('audit'))     return 'Audit';
    if(grp.includes('web'))       return 'Web';
    return 'Hệ thống';
  }
  function _fmtTs(iso){
    if(!iso) return '—';
    return new Date(iso).toLocaleTimeString('vi-VN',
      {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  }

  async function load(){
    try{
      const lv = document.getElementById('aq-level-select')?.value || 1;
      const data = await window.socApi.wazuhAlerts(500, parseInt(lv));
      _data = data;
      _page = 1;
      _apply();
    }catch(e){ window.toast('Lỗi tải alert: '+e.message,'err'); }
  }

  function _apply(){
    _filtered = _data.filter(a=>{
      const lv = parseInt(a?.rule?.level)||0;
      const sev = _sevClass(lv);
      if(_selSev && sev !== _selSev) return false;
      if(_selStatus){
        const currentStatus = (a?.status || 'new').toLowerCase();
        if(currentStatus !== _selStatus) return false;
      }
      if(_searchQ){
        const q = _searchQ.toLowerCase();
        if(!(a?.rule?.description||'').toLowerCase().includes(q) &&
           !(a?.data?.src_ip||a?.data?.srcip||'').includes(q) &&
           !(a?.agent?.name||'').toLowerCase().includes(q)) return false;
      }
      if(_timeHours){
        const ts = new Date(a?.['@timestamp'] || 0).getTime();
        const cutoff = Date.now() - (_timeHours * 3600 * 1000);
        if(ts < cutoff) return false;
      }
      return true;
    });
    _render();
  }

  function _render(){
    const tbody = document.getElementById('aq-tbody');
    const showEl = document.getElementById('aq-showing');
    if(!tbody) return;

    const total = _filtered.length;
    const pages = Math.ceil(total/PAGE);
    _page = Math.max(1, Math.min(_page, pages||1));
    const slice = _filtered.slice((_page-1)*PAGE, _page*PAGE);

    if(showEl) showEl.textContent =
      `Hiển thị ${slice.length}/${total} cảnh báo · Trang ${_page}/${pages||1}`;

    if(!slice.length){
      tbody.innerHTML = `<tr><td colspan="12"
        style="text-align:center;color:var(--muted);padding:32px">
        Không có cảnh báo nào
      </td></tr>`;
      _renderPag('wazuh-pag', _page, total, 'window.alertQueue.goPage');
      return;
    }

    const sevColors = {
      critical:'var(--red)', high:'var(--amber)',
      medium:'var(--medium)', low:'var(--green)'
    };
    const sevLabels = {
      critical:'NGHIÊM TRỌNG', high:'CAO',
      medium:'TRUNG BÌNH', low:'THẤP'
    };

    tbody.innerHTML = slice.map((a,i)=>{
      const idx = (_page-1)*PAGE + i;
      const lv   = parseInt(a?.rule?.level)||0;
      const sev  = _sevClass(lv);
      const col  = sevColors[sev];
      const src  = a?.data?.src_ip || a?.data?.srcip || '—';
      const mitre = a?.rule?.mitre?.id?.[0] || '—';
      const type  = _alertType(a);
      const alertId = `ALT-${new Date(a['@timestamp']).toISOString().slice(0,10).replace(/-/g,'')}-${String(idx+1).padStart(4,'0')}`;
      return `<tr>
        <td style="padding:8px">
          <input type="checkbox" class="aq-cb" data-idx="${idx}"
            ${_selected.has(idx)?'checked':''}
            onchange="window.alertQueue.toggleOne(${idx},this.checked)"
            onclick="event.stopPropagation()" style="cursor:pointer">
        </td>
        <td class="mono" style="color:var(--muted);font-size:10px">${alertId}</td>
        <td style="color:var(--text);max-width:220px;overflow:hidden;
          text-overflow:ellipsis;white-space:nowrap"
          title="${a?.rule?.description||''}">${(a?.rule?.description||'—').slice(0,40)}</td>
        <td>
          <span style="background:${col}22;color:${col};
            border:1px solid ${col}55;padding:2px 8px;
            border-radius:3px;font-size:10px;font-weight:700">
            ${sevLabels[sev]}
          </span>
        </td>
        <td><span class="aq-type-badge">${type}</span></td>
        <td class="mono" style="font-size:11px;color:var(--muted)">
          ${_fmtTs(a['@timestamp'])}
        </td>
        <td style="color:var(--green)">${a?.agent?.name||'—'}</td>
        <td class="mono" style="color:var(--cyan);font-size:11px">${src}</td>
        <td style="color:var(--purple);font-family:monospace;font-size:11px">
          ${mitre}
        </td>
        <td><span class="${(a?.status||'new').toLowerCase()==='assigned'?'aq-status-assigned':'aq-status-new'}">${(a?.status||'new').toLowerCase()==='assigned'?'Đã giao':'Mới'}</span></td>
        <td style="color:var(--muted);font-size:11px">${a?.assignee||'Chưa giao'}</td>
        <td>
          <button class="aq-action-btn aq-btn-investigate"
            onclick="window.alertQueue.investigate(${idx})">🔍</button>
          <button class="aq-action-btn aq-btn-case"
            onclick='window.createCaseFromAlert(${JSON.stringify(a)})'>+ Vụ việc</button>
          <button class="aq-action-btn aq-btn-fp"
            onclick="window.alertQueue.markFP(${idx})">✗ FP</button>
          ${src !== '—' ? `<button class="aq-action-btn" style="color:var(--cyan);font-size:10px"
            onclick="window.alertQueue.lookupIP('${src}')" title="Tra cứu AbuseIPDB">🔍 IP</button>
          <button class="aq-action-btn" style="color:var(--red);font-size:10px"
            onclick="confirmBlockIP('${src}',{ly_do:'Alert queue block'})" title="Chặn IP">🚫</button>` : ''}
        </td>
      </tr>`;
    }).join('');

    _renderPag('wazuh-pag', _page, total, 'window.alertQueue.goPage');
    _updateBulkBar();
  }

  function _updateBulkBar(){
    const n = _selected.size;
    const tb = document.getElementById('aq-bulk-bar');
    const ct = document.getElementById('aq-bulk-count');
    if(tb) tb.style.display = n>0?'flex':'none';
    if(ct) ct.textContent = `${n} alert đã chọn`;
  }

  function toggleOne(idx, checked){
    checked ? _selected.add(idx) : _selected.delete(idx);
    _updateBulkBar();
  }
  function toggleAll(checked){
    _selected.clear();
    if(checked){
      const total = _filtered.length;
      const pages = Math.ceil(total/PAGE);
      const slice = _filtered.slice((_page-1)*PAGE, _page*PAGE);
      slice.forEach((_,i)=>_selected.add((_page-1)*PAGE+i));
    }
    document.querySelectorAll('.aq-cb').forEach(cb=>cb.checked=checked);
    _updateBulkBar();
  }
  function clearBulk(){ _selected.clear(); _render(); }

  async function bulkAction(type){
    const alerts = [..._selected].map(i=>_filtered[i]).filter(Boolean);
    if(!alerts.length) return;

    if(type==='false-positive'){
      if(!confirm(`Đánh dấu ${alerts.length} alert là False Positive?`)) return;
      window.toast(`Đã đánh dấu ${alerts.length} alert là False Positive`,'ok');
      clearBulk();
      return;
    }
    if(type==='escalate'||type==='investigate'){
      const res = await fetch('/api/rules/bulk-create-cases',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({alerts})
      });
      const d = await res.json();
      window.toast(`Đã tạo ${d.created} vụ việc`,'ok');
      clearBulk();
      window.casesApp?.loadAll?.();
      return;
    }
    if(type==='assign'){
      const name = prompt('Giao cho analyst (nhập tên):');
      if(!name) return;
      window.toast(`Đã giao ${alerts.length} alert cho ${name}`,'ok');
      clearBulk();
    }
  }

  function investigate(idx){
    const a = _filtered[idx];
    if(!a) return;
    window.createCaseFromAlert(a);
    window.toast('Đã tạo vụ việc để điều tra','ok');
  }

  function markFP(idx){
    const a = _filtered[idx];
    if(!a) return;
    window.toast(`Alert ${a?.rule?.id} đã đánh dấu False Positive`,'ok');
  }

  function filterSev(sev, btn){
    _selSev = sev;
    btn.closest('#aq-filter-bar')
      .querySelectorAll('.aq-filter-btn')
      .forEach(b=>{
        if(b.parentElement === btn.parentElement)
          b.classList.toggle('active', b===btn);
      });
    _page=1; _apply();
  }

  function filterTime(h, btn){
    _timeHours = h;
    btn.closest('#aq-filter-bar')
      .querySelectorAll('.aq-filter-btn')
      .forEach(b=>{
        if(b.parentElement === btn.parentElement)
          b.classList.toggle('active', b===btn);
      });
    _page=1; load();
  }

  function filterStatus(s, btn){
    _selStatus=s;
    if (btn) {
      btn.closest('#aq-filter-bar')
        .querySelectorAll('.aq-filter-btn')
        .forEach(b=>{
          if(b.parentElement === btn.parentElement)
            b.classList.toggle('active', b===btn);
        });
    }
    _page=1; _apply();
  }
  function search(q){ _searchQ=q; _page=1; _apply(); }
  function goPage(p){ _page=p; _render(); window.scrollTo(0,0); }
  function reload(){ load(); }

  document.querySelector('[data-page="alerts"]')
    ?.addEventListener('click', ()=>{ if(!_data.length) load(); });

  document.addEventListener('soc:data', e=>{
    if(e.detail.type!=='snapshot') return;
    if(e.detail.recent_alerts){
      _data = e.detail.recent_alerts;
      if(document.getElementById('page-alerts')?.classList.contains('active')){
        _apply();
      }
    }
    const badge = document.getElementById('nav-badge-alerts');
    if(badge && e.detail.kpis){
      badge.textContent = formatBadgeCount(e.detail.kpis.total_alerts_24h || 0);
    }
    const notif = document.getElementById('notif-count');
    if(notif && e.detail.kpis){
      const crit = e.detail.kpis.critical_alerts||0;
      notif.textContent = crit;
      notif.style.display = crit>0?'block':'none';
    }
    const updateEl = document.getElementById('aq-last-update');
    if (updateEl) {
      updateEl.textContent = new Date().toLocaleTimeString('vi-VN');
    }
  });

  async function lookupIP(ip) {
    try {
      const res = await fetch(`/api/ai/lookup-ip?ip=${encodeURIComponent(ip)}`, { method: 'POST' });
      const data = await res.json();
      if (data.error) {
        window.toast?.(`Tra cứu lỗi: ${data.error}`, 'warn');
        return;
      }
      const modal = document.createElement('div');
      modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:99999';
      modal.innerHTML = `
        <div style="background:var(--bg1);border:1px solid var(--cyan);border-radius:8px;padding:20px;width:380px;max-width:90vw">
          <h3 style="color:var(--cyan);margin:0 0 12px">🔍 AbuseIPDB: ${data.ip}</h3>
          <p style="color:var(--text);font-size:13px">Điểm nguy hiểm: <strong style="color:var(--red)">${data.abuse_score || 0}%</strong></p>
          <p style="color:var(--muted);font-size:12px">Quốc gia: ${data.country || '—'}</p>
          <p style="color:var(--muted);font-size:12px">ISP: ${data.isp || '—'}</p>
          <p style="color:var(--muted);font-size:12px">Tor: ${data.is_tor ? '✅ Có' : '❌ Không'}</p>
          <p style="color:var(--muted);font-size:12px">Báo cáo: ${data.total_reports || 0} lần</p>
          <button onclick="this.closest('div[style]').remove()" style="margin-top:12px;padding:6px 16px;background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:4px;cursor:pointer">Đóng</button>
        </div>`;
      modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
      document.body.appendChild(modal);
    } catch (err) {
      window.toast?.('Lỗi tra cứu IP: ' + err.message, 'err');
    }
  }

  window.alertQueue = {
    load, reload, filterSev, filterTime, filterStatus,
    search, goPage, toggleOne, toggleAll,
    clearBulk, bulkAction, investigate, markFP, lookupIP
  };
})();

/* ═════════════════════════════════════════════════════════════════
   THREAT HUNTING PAGE
   ═════════════════════════════════════════════════════════════════ */
(function(){
  let _results = [];
  let _expandedRows = new Set();

  function _sevClass(lv){
    const n=parseInt(lv)||0;
    if(n>=12)return'critical';if(n>=7)return'high';
    if(n>=4)return'medium';return'low';
  }
  const _sevColors={
    critical:'var(--red)',high:'var(--amber)',
    medium:'var(--medium)', low:'var(--green)'
  };
  const _sevLabels={
    critical:'NGHIÊM TRỌNG',high:'CAO',
    medium:'TRUNG BÌNH',low:'THẤP'
  };
  function _fmtTs(iso){
    if(!iso)return'—';
    const d=new Date(iso);
    return d.toLocaleDateString('vi-VN')+' '+
           d.toLocaleTimeString('vi-VN',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  }

  async function search(){
    const q      = document.getElementById('hunt-query')?.value?.trim()||'';
    const hours  = document.getElementById('hunt-hours')?.value||24;
    const agent  = document.getElementById('hunt-agent')?.value?.trim()||'';
    const src_ip = document.getElementById('hunt-ip')?.value?.trim()||'';
    const rule_id= document.getElementById('hunt-ruleid')?.value?.trim()||'';
    const level  = document.getElementById('hunt-level')?.value||1;
    const size   = document.getElementById('hunt-size')?.value||100;

    // Show loading
    const infoEl = document.getElementById('hunt-result-info');
    const tableEl= document.getElementById('hunt-table');
    const emptyEl= document.getElementById('hunt-empty');
    if(infoEl) infoEl.textContent = '⏳ Đang tìm kiếm...';
    if(tableEl) tableEl.style.display='none';
    if(emptyEl) emptyEl.style.display='none';

    try {
      const [data, stats] = await Promise.all([
        window.socApi.hunt({q, hours, agent, src_ip,
          rule_id, min_level: level, size}),
        window.socApi.huntStats({q, hours}),
      ]);

      _results = data.results || [];

      // Update info
      if(infoEl) infoEl.textContent =
        `${data.total.toLocaleString()} kết quả · ` +
        `Hiển thị ${_results.length} · ` +
        `${data.took_ms}ms`;

      // Show/hide export
      const exportBtn = document.getElementById('hunt-export-btn');
      if(exportBtn) exportBtn.style.display = _results.length?'block':'none';

      // Render stats
      renderStats(stats);

      // Render table
      if(!_results.length){
        if(emptyEl){
          emptyEl.innerHTML=`<div style="font-size:28px;margin-bottom:12px;opacity:.3">🔍</div>
            <div style="font-size:14px">Không tìm thấy kết quả</div>
            <div style="font-size:12px;margin-top:6px;color:var(--muted)">
              Thử thay đổi bộ lọc hoặc mở rộng thời gian tìm kiếm
            </div>`;
          emptyEl.style.display='block';
        }
      } else {
        renderTable();
        if(tableEl) tableEl.style.display='table';
      }
    } catch(e) {
      if(infoEl) infoEl.textContent='❌ Lỗi: '+e.message;
      window.toast?.('Tìm kiếm thất bại: '+e.message,'err');
    }
  }

  function renderStats(stats){
    const row = document.getElementById('hunt-stats-row');
    if(row) row.style.display='block';

    const renderList = (containerId, items, keyField, valField, color) => {
      const el = document.getElementById(containerId);
      if(!el) return;
      if(!items || !items.length){
        el.innerHTML=`<div style="color:var(--muted);font-size:12px;
          text-align:center;padding:20px 0">Không có data</div>`;
        return;
      }
      const max = items[0][valField]||1;
      el.innerHTML = items.map((item,i)=>{
        const pct = (item[valField]/max*100).toFixed(1);
        const barColor = i===0 ? color :
                         i===1 ? color+'cc' :
                         i===2 ? color+'99' : color+'66';
        return `
          <div style="margin-bottom:10px">
            <div style="display:flex;justify-content:space-between;
              align-items:center;margin-bottom:4px">
              <span style="color:var(--text);font-size:12px;
                overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
                max-width:75%;flex:1" title="${item[keyField]}">
                ${item[keyField]}
              </span>
              <span style="color:var(--muted);font-family:monospace;
                font-size:11px;margin-left:8px;flex-shrink:0">
                ${item[valField].toLocaleString()}
              </span>
            </div>
            <div style="height:4px;background:var(--accent-08);
              border-radius:4px;overflow:hidden">
              <div style="height:100%;width:${pct}%;background:${barColor};
                border-radius:4px;transition:width .4s ease"></div>
            </div>
          </div>`;
      }).join('');
    };

    renderList('hunt-stat-agents', stats.top_agents, 'name',  'count', 'var(--green)');
    renderList('hunt-stat-rules',  stats.top_rules,  'rule',  'count', 'var(--blue)');
    renderList('hunt-stat-ips',    stats.top_ips,    'ip',    'count', 'var(--red)');
  }

  function _detailField(label, value, colorKey=''){
    const colors={
      green:'var(--green)', cyan:'var(--cyan)',
      muted:'var(--muted)', purple:'var(--purple)',
      red:'var(--red)',     amber:'var(--amber)',
    };
    const col = colors[colorKey]||'var(--text)';
    return `
      <div style="padding:6px 8px">
        <div style="font-size:10px;color:var(--muted);
          text-transform:uppercase;letter-spacing:.05em;
          margin-bottom:3px">${label}</div>
        <div style="font-size:12px;color:${col};
          font-family:${colorKey?'monospace':'inherit'};
          overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${value}">${value||'—'}</div>
      </div>`;
  }

  function renderTable(){
    const tbody = document.getElementById('hunt-tbody');
    if(!tbody) return;
    _expandedRows.clear();

    tbody.innerHTML = _results.map((a,i)=>{
      const lv   = parseInt(a?.rule?.level)||0;
      const sev  = _sevClass(lv);
      const col  = _sevColors[sev];
      const src  = a?.data?.src_ip||a?.data?.srcip||'—';
      const dst  = a?.data?.dest_ip||'—';
      const mitre= a?.rule?.mitre?.id?.[0]||'—';
      const geo  = a?.GeoLocation?.country_name||'—';
      return `
        <tr class="hunt-row" style="cursor:pointer"
          onmouseover="this.style.background='var(--bg-hover)'"
          onmouseout="this.style.background=''"
          onclick="window.huntApp.toggleRow(${i})">
          <td style="padding:8px;text-align:center">
            <div id="hunt-expand-${i}"
              style="width:20px;height:20px;border-radius:50%;
                     border:1px solid var(--border);display:flex;
                     align-items:center;justify-content:center;
                     font-size:9px;color:var(--muted);cursor:pointer;
                     transition:all .15s;margin:0 auto"
              onmouseover="this.style.borderColor='var(--green)';
                           this.style.color='var(--green)'"
              onmouseout="this.style.borderColor='var(--border)';
                          this.style.color='var(--muted)'">▶</div>
          </td>
          <td class="mono" style="font-size:11px;white-space:nowrap">
            ${_fmtTs(a['@timestamp'])}
          </td>
          <td style="color:var(--green)">${a?.agent?.name||'—'}</td>
          <td style="max-width:220px;overflow:hidden;
            text-overflow:ellipsis;white-space:nowrap;color:var(--text)"
            title="${a?.rule?.description||''}">
            ${(a?.rule?.description||'—').slice(0,40)}
          </td>
          <td>
            <span style="background:${col}22;color:${col};
              border:1px solid ${col}55;padding:2px 8px;
              border-radius:3px;font-size:10px;font-weight:700">
              ${_sevLabels[sev]}
            </span>
          </td>
          <td class="mono" style="color:var(--cyan);font-size:11px">${src}</td>
          <td class="mono" style="color:var(--muted);font-size:11px">${dst}</td>
          <td style="color:var(--purple);font-family:monospace;font-size:11px">
            ${mitre}
          </td>
          <td style="font-size:11px;color:var(--muted)">${geo}</td>
          <td>
            <button onclick="event.stopPropagation();
              window.createCaseFromAlert(${JSON.stringify(a).replace(/"/g,'&quot;')})"
              class="btn-create-case">+ Vụ việc</button>
          </td>
        </tr>
        <tr id="hunt-detail-${i}" style="display:none">
          <td colspan="10" style="padding:0;background:var(--bg)">
            <div style="margin:0 8px 8px;border:1px solid var(--border);
              border-radius:var(--r2);overflow:hidden">

              <!-- Tabs trong expand row -->
              <div style="display:flex;background:var(--bg1);
                border-bottom:1px solid var(--border)">
                <div style="padding:8px 16px;font-size:11px;font-weight:700;
                  color:var(--green);border-bottom:2px solid var(--green);
                  text-transform:uppercase;letter-spacing:.06em">
                  Chi tiết sự kiện
                </div>
                <div style="padding:8px 16px;font-size:11px;color:var(--muted);
                  text-transform:uppercase;letter-spacing:.06em">
                  Raw JSON
                </div>
              </div>

              <!-- Thông tin chính -->
              <div style="display:grid;grid-template-columns:repeat(3,1fr);
                gap:0;padding:12px 16px;background:var(--bg)">
                ${_detailField('Thời gian',     _fmtTs(a['@timestamp']))}
                ${_detailField('Agent',         a?.agent?.name||'—',     'green')}
                ${_detailField('Agent IP',      a?.agent?.ip||'—',       'cyan')}
                ${_detailField('Rule ID',       a?.rule?.id||'—')}
                ${_detailField('Rule Level',    a?.rule?.level||'—')}
                ${_detailField('Rule Groups',   (a?.rule?.groups||[]).join(', ')||'—')}
                ${_detailField('IP nguồn',      a?.data?.src_ip||a?.data?.srcip||'—','cyan')}
                ${_detailField('IP đích',       a?.data?.dest_ip||'—',  'muted')}
                ${_detailField('Port nguồn',    a?.data?.src_port||'—')}
                ${_detailField('Port đích',     a?.data?.dest_port||'—')}
                ${_detailField('Protocol',      a?.data?.proto||'—')}
                ${_detailField('Quốc gia',      a?.GeoLocation?.country_name||'—')}
                ${_detailField('MITRE ID',      (a?.rule?.mitre?.id||[]).join(', ')||'—','purple')}
                ${_detailField('MITRE Tactic',  (a?.rule?.mitre?.tactic||[]).join(', ')||'—','purple')}
                ${_detailField('Signature',     a?.data?.alert?.signature||a?.rule?.description||'—')}
              </div>

              <!-- Raw log -->
              ${a?.full_log ? `
              <div style="padding:8px 16px;border-top:1px solid var(--border);
                background:var(--bg1)">
                <div style="font-size:10px;color:var(--muted);
                  text-transform:uppercase;margin-bottom:6px">Full Log</div>
                <div style="font-family:monospace;font-size:11px;
                  color:var(--text);line-height:1.5;white-space:pre-wrap;
                  word-break:break-all">${a.full_log}</div>
              </div>` : ''}

              <!-- Raw JSON toggle -->
              <details style="padding:8px 16px;border-top:1px solid var(--border)">
                <summary style="font-size:11px;color:var(--muted);
                  cursor:pointer;list-style:none;display:flex;
                  align-items:center;gap:6px">
                  <span>▶</span> Xem Raw JSON
                </summary>
                <pre style="font-family:monospace;font-size:11px;
                  color:var(--text);white-space:pre-wrap;overflow-x:auto;
                  max-height:250px;overflow-y:auto;margin-top:8px;
                  background:var(--bg1);padding:10px;border-radius:var(--r)">
${JSON.stringify(a, null, 2)}</pre>
              </details>

              <!-- Actions -->
              <div style="padding:10px 16px;border-top:1px solid var(--border);
                display:flex;gap:8px;background:var(--bg1)">
                <button onclick="window.createCaseFromAlert(
                  ${JSON.stringify(a).replace(/"/g,'&quot;')})"
                  style="padding:5px 14px;background:var(--green3);
                         border:1px solid var(--green);border-radius:var(--r);
                         color:var(--green);font-size:11px;
                         font-weight:700;cursor:pointer">
                  📁 Tạo vụ việc
                </button>
                <button onclick="window.quickHunt('ip','${
                  a?.data?.src_ip||a?.data?.srcip||''}')"
                  style="padding:5px 14px;background:var(--bg-card);
                         border:1px solid var(--border);border-radius:var(--r);
                         color:var(--muted);font-size:11px;cursor:pointer">
                  🔍 Hunt IP này
                </button>
                <button onclick="window.quickHunt('agent','${a?.agent?.name||''}')"
                  style="padding:5px 14px;background:var(--bg-card);
                         border:1px solid var(--border);border-radius:var(--r);
                         color:var(--muted);font-size:11px;cursor:pointer">
                  🖥 Hunt Agent này
                </button>
                <button onclick="navigator.clipboard.writeText(
                  '${(a?.data?.src_ip||a?.data?.srcip||'').replace(/'/g,'')}');
                  window.toast('Đã copy IP','ok',1500)"
                  style="padding:5px 12px;background:var(--bg-card);
                         border:1px solid var(--border);border-radius:var(--r);
                         color:var(--muted);font-size:11px;cursor:pointer">
                  📋 Copy IP
                </button>
              </div>
            </div>
          </td>
        </tr>`;
    }).join('');
  }

  function toggleRow(i){
    const detailEl = document.getElementById(`hunt-detail-${i}`);
    const expandEl = document.getElementById(`hunt-expand-${i}`);
    if(!detailEl) return;
    const isOpen = detailEl.style.display !== 'none';
    detailEl.style.display = isOpen ? 'none' : 'table-row';
    if(expandEl){
      expandEl.style.transform = isOpen ? '' : 'rotate(90deg)';
      expandEl.style.transition = 'transform .2s';
    }
  }

  function reset(){
    document.getElementById('hunt-query').value  = '';
    document.getElementById('hunt-agent').value  = '';
    document.getElementById('hunt-ip').value     = '';
    document.getElementById('hunt-ruleid').value = '';
    document.getElementById('hunt-hours').value  = '24';
    document.getElementById('hunt-level').value  = '1';
    document.getElementById('hunt-size').value   = '100';
    _results = [];
    const tableEl = document.getElementById('hunt-table');
    const emptyEl = document.getElementById('hunt-empty');
    const infoEl  = document.getElementById('hunt-result-info');
    const statsRow= document.getElementById('hunt-stats-row');
    if(tableEl)  tableEl.style.display='none';
    if(statsRow) statsRow.style.display='none';
    if(infoEl)   infoEl.textContent='Nhập từ khóa và nhấn Tìm kiếm';
    if(emptyEl){
      emptyEl.innerHTML=`<div style="font-size:32px;margin-bottom:12px;opacity:.3">🔍</div>
        <div style="font-size:14px">Chưa có kết quả</div>
        <div style="font-size:12px;margin-top:6px">
          Nhập từ khóa hoặc bộ lọc rồi nhấn Tìm kiếm
        </div>`;
      emptyEl.style.display='block';
    }
  }

  function exportCSV(){
    if(!_results.length) return;
    const headers = ['Thời gian','Agent','Rule','Level','IP nguồn','IP đích','MITRE','Quốc gia'];
    const rows = _results.map(a=>[
      a['@timestamp']||'',
      a?.agent?.name||'',
      (a?.rule?.description||'').replace(/,/g,';'),
      a?.rule?.level||'',
      a?.data?.src_ip||a?.data?.srcip||'',
      a?.data?.dest_ip||'',
      a?.rule?.mitre?.id?.[0]||'',
      a?.GeoLocation?.country_name||'',
    ].join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob(['\uFEFF'+csv],{type:'text/csv;charset=utf-8;'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `soc-hunt-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    window.toast?.('Đã export CSV','ok');
  }

  // Quick hunt từ sidebar
  window.quickHunt = function(type, value){
    navigate('hunting');
    setTimeout(()=>{
      if(type==='ip'){
        document.getElementById('hunt-ip').value=value;
      } else if(type==='agent'){
        document.getElementById('hunt-agent').value=value;
      } else if(type==='rule'){
        document.getElementById('hunt-ruleid').value=value;
      } else {
        document.getElementById('hunt-query').value=value;
      }
      search();
    }, 200);
  };

  function quickFill(text){
    const el = document.getElementById('hunt-query');
    if(el){ el.value=text; el.focus(); }
  }

  window.huntApp = { search, reset, toggleRow, exportCSV, quickFill };
})();
