(function(){
function _css(v){ return getComputedStyle(document.documentElement).getPropertyValue(v).trim(); }
function _G(){
  return {
    green:  _css('--green')  || '#00ff41',
    green2: _css('--green3') || 'rgba(0,255,65,.15)',
    green3: _css('--accent-08') || 'rgba(0,255,65,.08)',
    red:    _css('--red')    || '#ff3333',
    amber:  _css('--amber')  || '#ff9900',
    blue:   _css('--blue')   || '#00aaff',
    purple: _css('--purple') || '#cc44ff',
    medium: _css('--medium') || '#ffcc00',
    muted:  _css('--muted')  || '#3a6b40',
    grid:   _css('--grid-line') || 'rgba(0,255,65,.06)',
  };
}
let G = _G();
const BASE = {
  responsive:true, maintainAspectRatio:false,
  plugins:{legend:{display:false}},
  scales:{
    x:{grid:{color:G.grid},ticks:{color:G.muted,font:{size:10,family:'Share Tech Mono'}}},
    y:{grid:{color:G.grid},ticks:{color:G.muted,font:{size:10,family:'Share Tech Mono'}}},
  },
};

let _tl=null, _sev=null, _tactics=null, _rules=null, _suri=null;

function truncateLabel(str, max = 20){
  const text = String(str ?? '');
  return text.length > max ? `${text.substring(0, max)}...` : text;
}

/* ── Timeline ──────────────────────────────────── */
function initTimeline(id){
  const ctx=document.getElementById(id); if(!ctx) return;
  _tl=new Chart(ctx,{
    type:'line',
    data:{labels:[],datasets:[{
      data:[],borderColor:G.green,backgroundColor:G.green2,
      borderWidth:2,fill:true,tension:.4,pointRadius:2,
      pointBackgroundColor:G.green,
    }]},
    options:{...BASE,plugins:{...BASE.plugins,tooltip:{callbacks:{
      label:i=>` ${i.raw} cảnh báo`,
    }}}},
  });
}
function updateTimeline(data){
  if(!_tl) return;
  _tl.data.labels = data.map(d=>{
    const t=new Date(d.time);
    return `${String(t.getHours()).padStart(2,'0')}:${String(t.getMinutes()).padStart(2,'0')}`;
  });
  _tl.data.datasets[0].data = data.map(d=>d.count);
  _tl.update('none');
}

/* ── Severity donut ────────────────────────────── */
function initSeverityDonut(id){
  const ctx=document.getElementById(id); if(!ctx) return;
  _sev=new Chart(ctx,{
    type:'doughnut',
    data:{
      labels:['Nghiêm trọng','Cao','Trung bình','Thấp'],
      datasets:[{
        data:[0,0,0,0],
        backgroundColor:[G.red,G.amber,G.medium,G.green],
        borderColor:G.bg||'#010a03',borderWidth:3,hoverOffset:6,
      }],
    },
    options:{
      responsive:true,maintainAspectRatio:false,cutout:'68%',
      plugins:{
        legend:{display:true,position:'right',
          labels:{color:G.muted,font:{size:10,family:'Rajdhani'},boxWidth:10,padding:8}},
        tooltip:{callbacks:{label:i=>` ${i.label}: ${i.raw}`}},
      },
    },
  });
}
function updateSeverityDonut(lvlMap){
  if(!_sev) return;
  let c=0,h=0,m=0,l=0;
  for(const [k,v] of Object.entries(lvlMap)){
    const n=parseInt(k);
    if(n>=12)c+=v; else if(n>=7)h+=v; else if(n>=4)m+=v; else l+=v;
  }
  _sev.data.datasets[0].data=[c,h,m,l];
  _sev.update('none');
}

/* ── Tactics bar ───────────────────────────────── */
function initTacticsBar(id){
  const ctx=document.getElementById(id); if(!ctx) return;
  _tactics=new Chart(ctx,{
    type:'bar',
    data:{labels:[],datasets:[{
      data:[],
      backgroundColor:G.purple+'99',borderColor:G.purple,
      borderWidth:1,borderRadius:3,
    }]},
    options:{...BASE,indexAxis:'y'},
  });
}
function updateTacticsBar(tactics){
  if(!_tactics) return;
  const s=[...tactics].sort((a,b)=>b.count-a.count).slice(0,7);
  _tactics.data.labels=s.map(t=>t.name);
  _tactics.data.datasets[0].data=s.map(t=>t.count);
  _tactics.update('none');
}

/* ── Top rules bar ─────────────────────────────── */
function initRulesBar(id){
  const ctx=document.getElementById(id); if(!ctx) return;
  _rules=new Chart(ctx,{
    type:'bar',
    data:{labels:[],datasets:[{
      data:[],
      backgroundColor:G.green2,borderColor:G.green,
      borderWidth:1,borderRadius:3,
    }]},
    options:{
      ...BASE,
      scales:{
        ...BASE.scales,
        x:{
          ...BASE.scales.x,
          ticks:{
            ...(BASE.scales.x?.ticks || {}),
            maxRotation:0,
            minRotation:0,
            callback:function(value){
              const raw = this.getLabelForValue(value);
              return truncateLabel(raw, 18);
            },
          },
        },
      },
      plugins:{...BASE.plugins,tooltip:{callbacks:{
        title:i=>[i[0].label],
        label:i=>` Số lượng: ${i.raw}`,
      }}},
    },
  });
}
function updateRulesBar(alerts){
  if(!_rules) return;
  const counts={};
  alerts.forEach(a=>{
    const key = a?.rule?.description || 'Unknown';
    counts[key]=(counts[key]||0)+1;
  });
  const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,6);
  _rules.data.labels=sorted.map(e=>e[0]);
  _rules.data.datasets[0].data=sorted.map(e=>e[1]);
  _rules.update('none');
}

/* ── Suricata category bar ─────────────────────── */
function initSuricataBar(id){
  const ctx=document.getElementById(id); if(!ctx) return;
  _suri=new Chart(ctx,{
    type:'bar',
    data:{labels:[],datasets:[{
      data:[],
      backgroundColor:G.blue+'66',borderColor:G.blue,
      borderWidth:1,borderRadius:3,
    }]},
    options:{...BASE},
  });
}
function updateSuricataBar(alerts){
  if(!_suri) return;
  const counts={};
  alerts.forEach(a=>{
    const cat=a?.data?.alert?.category||'Không xác định';
    counts[cat]=(counts[cat]||0)+1;
  });
  const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,7);
  _suri.data.labels=sorted.map(e=>e[0]);
  _suri.data.datasets[0].data=sorted.map(e=>e[1]);
  _suri.update('none');
}

function updateRulesBarDirect(rules){
  if(!_rules) return;
  _rules.data.labels = rules.map(r => r?.rule || 'Không xác định');
  _rules.data.datasets[0].data = rules.map(r => r?.count || 0);
  _rules.update('none');
}

function updateSuricataBarDirect(sigs){
  if(!_suri) return;
  _suri.data.labels = sigs.map(s => {
    const name = s?.signature || 'Không xác định';
    return name.length > 30 ? `${name.slice(0,30)}…` : name;
  });
  _suri.data.datasets[0].data = sigs.map(s => s?.count || 0);
  _suri.update('none');
}

/* Re-read CSS vars after theme switch and recolor all active charts */
function refreshChartColors(){
  G = _G();
  if(_tl){
    _tl.data.datasets[0].borderColor = G.green;
    _tl.data.datasets[0].backgroundColor = G.green2;
    _tl.data.datasets[0].pointBackgroundColor = G.green;
    _tl.options.scales.x.grid.color = G.grid;
    _tl.options.scales.y.grid.color = G.grid;
    _tl.options.scales.x.ticks.color = G.muted;
    _tl.options.scales.y.ticks.color = G.muted;
    _tl.update('none');
  }
  if(_sev){
    _sev.data.datasets[0].backgroundColor = [G.red,G.amber,G.medium,G.green];
    _sev.options.plugins.legend.labels.color = G.muted;
    _sev.update('none');
  }
  if(_tactics){
    _tactics.data.datasets[0].backgroundColor = G.purple+'99';
    _tactics.data.datasets[0].borderColor = G.purple;
    _tactics.options.scales.x.grid.color = G.grid;
    _tactics.options.scales.y.grid.color = G.grid;
    _tactics.options.scales.x.ticks.color = G.muted;
    _tactics.options.scales.y.ticks.color = G.muted;
    _tactics.update('none');
  }
  if(_rules){
    _rules.data.datasets[0].backgroundColor = G.green2;
    _rules.data.datasets[0].borderColor = G.green;
    _rules.options.scales.x.grid.color = G.grid;
    _rules.options.scales.y.grid.color = G.grid;
    _rules.options.scales.x.ticks.color = G.muted;
    _rules.options.scales.y.ticks.color = G.muted;
    _rules.update('none');
  }
  if(_suri){
    _suri.data.datasets[0].borderColor = G.blue;
    _suri.options.scales.x.grid.color = G.grid;
    _suri.options.scales.y.grid.color = G.grid;
    _suri.options.scales.x.ticks.color = G.muted;
    _suri.options.scales.y.ticks.color = G.muted;
    _suri.update('none');
  }
}

window.socCharts={
  initTimeline,updateTimeline,
  initSeverityDonut,updateSeverityDonut,
  initTacticsBar,updateTacticsBar,
  initRulesBar,updateRulesBar,
  initSuricataBar,updateSuricataBar,
  updateRulesBarDirect,
  updateSuricataBarDirect,
  refreshChartColors,
};
})();
