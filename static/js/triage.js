/**
 * triage.js — Triage modal logic
 * Opens from any alert row or case row.
 * Submits to POST /api/cases/{id}/triage
 */
(function(){

const MITRE_TECHNIQUES = [
  'T1110 - Brute Force','T1078 - Valid Accounts','T1548 - Priv Escalation',
  'T1059 - Command Interpreter','T1566 - Phishing','T1204 - User Execution',
  'T1055 - Process Injection','T1083 - File Discovery','T1021 - Remote Services',
  'T1190 - Exploit Public App','T1046 - Network Scan','T1041 - Exfiltration C2',
];

const REASONS = [
  'Phát hiện nội dung độc hại','Nguồn gửi/tên miền đáng ngờ',
  'Khớp chữ ký mối đe dọa đã biết','Hoạt động mạng bất thường',
  'Vi phạm chính sách','Xác thực thất bại nhiều lần',
  'Tiến trình hoạt động bất thường','Khớp IOC từ threat intelligence',
];

let currentCaseId = null;
let selectedClass  = null;
let selectedReasons = new Set();
let selectedMitre  = new Set();
let selectedImpact = 'Medium';
let _shouldEscalate = false;

function _renderEscalate(){
  const box = document.getElementById('escalate-box');
  const item = document.getElementById('escalate-check');
  if (box) box.innerHTML = _shouldEscalate ? '✓' : '';
  if (item) {
    item.classList.toggle('checked', _shouldEscalate);
    item.style.background = _shouldEscalate
      ? 'rgba(255,153,0,.12)' : 'rgba(255,153,0,.05)';
  }
}

function openModal(caseData){
  currentCaseId    = caseData.case_id || caseData.id;
  selectedClass    = null;
  selectedReasons  = new Set();
  selectedMitre    = new Set();
  selectedImpact   = 'Medium';
  _shouldEscalate  = false;

  // Fill case info bar
  document.getElementById('modal-case-id').textContent   = currentCaseId || '—';
  document.getElementById('modal-case-title').textContent = caseData.title || caseData.rule_desc || '—';
  document.getElementById('modal-case-src').textContent  = caseData.src_ip || '—';

  renderClassif();
  renderReasons();
  renderMitre();
  renderImpact();
  clearTextareas();
  _renderEscalate();

  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal(){
  document.getElementById('modal-overlay').classList.remove('open');
  currentCaseId = null;
}

function renderClassif(){
  const wrap = document.getElementById('classif-tabs');
  const opts = [
    { label:'Mối đe dọa thực',  cls:'tp' },
    { label:'Báo động nhầm',    cls:'fp' },
    { label:'Vô hại',           cls:'bn' },
    { label:'Chưa xác định',    cls:'un' },
  ];
  wrap.innerHTML = opts.map(o => `
    <div class="classif-tab ${selectedClass===o.label?'selected '+o.cls:''}"
         onclick="window.triageSelectClass('${o.label}','${o.cls}')">
      ${o.label}
    </div>`).join('');
}

function renderReasons(){
  const wrap = document.getElementById('reason-checks');
  wrap.innerHTML = REASONS.map(r => `
    <div class="check-item ${selectedReasons.has(r)?'checked':''}"
         onclick="window.triageToggleReason('${r}')">
      <div class="check-box">${selectedReasons.has(r)?'✓':''}</div>
      <span class="check-label">${r}</span>
    </div>`).join('');
}

function renderMitre(){
  const wrap = document.getElementById('mitre-tags');
  wrap.innerHTML = MITRE_TECHNIQUES.map(t => `
    <div class="mitre-tag ${selectedMitre.has(t)?'selected':''}"
         onclick="window.triageToggleMitre('${t}')">
      ${t}
    </div>`).join('');
}

function renderImpact(){
  document.getElementById('impact-select').value = selectedImpact;
}

function clearTextareas(){
  document.getElementById('analysis-text').value = '';
  document.getElementById('rec-text').value = '';
  updateCharCount('analysis-text','analysis-count',200);
  updateCharCount('rec-text','rec-count',500);
}

function updateCharCount(textareaId, countId, max){
  const ta = document.getElementById(textareaId);
  const el = document.getElementById(countId);
  if(!ta||!el) return;
  el.textContent = `${ta.value.length}/${max} ký tự`;
}

async function submitTriage(){
  if(!currentCaseId){ window.toast('Chưa chọn vụ việc','err'); return; }
  if(!selectedClass){ window.toast('Hãy chọn phân loại trước','warn'); return; }

  const body = {
    classification: selectedClass,
    reasons:        [...selectedReasons],
    mitre_mapping:  [...selectedMitre],
    impact_level:   document.getElementById('impact-select').value,
    analysis:       document.getElementById('analysis-text').value.trim(),
    recommendation: document.getElementById('rec-text').value.trim(),
    analyst:        'analyst',
    should_escalate: _shouldEscalate,
  };

  try {
    const id = encodeURIComponent(currentCaseId);
    const res = await fetch(`/api/cases/${id}/triage`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    if(!res.ok) throw new Error(await res.text());
    closeModal();
    window.toast(`Đã gửi phân loại — ${selectedClass}`, 'ok');
    // Refresh cases panel
    if(window.socApp && window.socApp.loadCases) window.socApp.loadCases();
  } catch(e){
    window.toast('Gửi phân loại thất bại: ' + e.message, 'err');
  }
}

async function generateAIRec(){
  const analysis = document.getElementById('analysis-text').value;
  if(!analysis){ window.toast('Vui lòng nhập phân tích trước','warn'); return; }
  // Simple heuristic recommendation (no external call needed)
  const recs = {
    'Brute Force':'Isolate source IP, enforce account lockout policy, enable MFA.',
    'Phishing':'Quarantine email, block sender domain, notify affected users, reset credentials.',
    'Scan':'Block source IP via firewall, review exposed services, check for follow-up exploitation.',
    'Malware':'Isolate affected host, capture memory dump, run full AV scan, reset credentials.',
    'Escalation':'Kill offending process, audit sudo rules, review user privileges.',
    'Exfiltration':'Block destination IP/domain, audit data access logs, notify DPO.',
  };
  let rec = 'Điều tra thêm, thu thập bằng chứng và thực hiện theo quy trình ứng phó sự cố.';
  for(const [k,v] of Object.entries(recs)){
    if(analysis.toLowerCase().includes(k.toLowerCase())){ rec=v; break; }
  }
  document.getElementById('rec-text').value = rec;
  updateCharCount('rec-text','rec-count',500);
}

// Exposed globals
window.triageSelectClass = function(label, cls){
  selectedClass = label;
  renderClassif();
};
window.triageToggleReason = function(r){
  selectedReasons.has(r) ? selectedReasons.delete(r) : selectedReasons.add(r);
  renderReasons();
};
window.triageToggleMitre = function(t){
  selectedMitre.has(t) ? selectedMitre.delete(t) : selectedMitre.add(t);
  renderMitre();
};
window.triageToggleEscalate = function() {
  _shouldEscalate = !_shouldEscalate;
  _renderEscalate();
};
window.triageSubmit   = submitTriage;
window.triageClose    = closeModal;
window.triageAIRec    = generateAIRec;
window.triageOpenModal = openModal;

// Char counters
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('analysis-text')?.addEventListener('input', () =>
    updateCharCount('analysis-text','analysis-count',200));
  document.getElementById('rec-text')?.addEventListener('input', () =>
    updateCharCount('rec-text','rec-count',500));
  // Close on overlay click
  document.getElementById('modal-overlay')?.addEventListener('click', e => {
    if(e.target.id === 'modal-overlay') closeModal();
  });
});

})();
