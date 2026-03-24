const BASE = window.SOC_API_BASE || '';
async function _get(p){const r=await fetch(BASE+p);if(!r.ok)throw new Error(`${p} → ${r.status}`);return r.json();}
async function _post(p,body=null,params={}){
  const qs=new URLSearchParams(params).toString();
  const url=`${BASE}${p}${qs?'?'+qs:''}`;
  const r=await fetch(url,{method:'POST',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):null});
  if(!r.ok)throw new Error(`${p} → ${r.status}: ${await r.text()}`);
  return r.json();
}
async function _patch(p,body){
  const r=await fetch(BASE+p,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r.ok)throw new Error(`${p} → ${r.status}`);return r.json();
}
window.socApi={
  kpis:            ()       => _get('/api/stats/kpis'),
  topIPs:          (n=10)   => _get(`/api/stats/top-ips?size=${n}`),
  timeline:        (h=24)   => _get(`/api/stats/timeline?hours=${h}`),
  mitre:           ()       => _get('/api/stats/mitre'),
  severity:        ()       => _get('/api/stats/severity'),
  wazuhAlerts:     (n=100,lv=1) => _get(`/api/alerts/wazuh?size=${n}&min_level=${lv}`),
  suricataAlerts:  (n=100)  => _get(`/api/alerts/suricata?size=${n}`),
  aiAlerts:        (n=50)   => _get(`/api/alerts/ai?size=${n}`),
  blockIP:         (ip)     => _post('/api/response/block-ip',null,{ip}),
  geoStats:        (n=12)    => _get(`/api/stats/top-ips-geo?size=${n}`),
  getOpenCases:    (limit=10) => _get(`/api/cases/open?limit=${limit}`),
  // Cases
  caseStats:       ()       => _get('/api/cases/stats'),
  getCases:        (status,limit=50) => _get(`/api/cases/${status?'?status='+status:''}${limit?'?limit='+limit:''}`),
  createCase:      (body)   => _post('/api/cases/',body),
  updateStatus:    (id,status,assignee='') => _patch(`/api/cases/${encodeURIComponent(id)}/status`,{status,assignee}),
  submitTriage:    (id,body)=> _post(`/api/cases/${encodeURIComponent(id)}/triage`,body),
  deleteTriage:    (id) => {
    return fetch(`/api/cases/${encodeURIComponent(id)}/triage`, {method:'DELETE'})
      .then(r => { if(!r.ok) throw new Error(r.status); return r.json(); });
  },
  // Threat Hunting
  hunt: (params) => {
    const qs = new URLSearchParams(params).toString();
    return _get(`/api/hunting/search?${qs}`);
  },
  huntStats: (params) => {
    const qs = new URLSearchParams(params).toString();
    return _get(`/api/hunting/stats?${qs}`);
  },
};
