(function(){
const WS_URL=(location.protocol==='https:'?'wss://':'ws://')+(window.SOC_WS_HOST||location.host)+'/ws';
let _ws=null,_delay=2000;
function connect(){
  _ws=new WebSocket(WS_URL);
  _ws.onopen=()=>{_delay=2000;_dot('connected');document.dispatchEvent(new CustomEvent('soc:ws-open'));};
  _ws.onmessage=e=>{try{document.dispatchEvent(new CustomEvent('soc:data',{detail:JSON.parse(e.data)}))}catch{}};
  _ws.onerror=()=>_dot('error');
  _ws.onclose=()=>{_dot('');setTimeout(connect,_delay);_delay=Math.min(_delay*1.5,30000);};
}
function _dot(s){
  const d=document.getElementById('ws-dot');
  const l=document.getElementById('ws-label');
  if(d){d.className=s}
  if(l) l.textContent=s==='connected'?'● TRỰC TIẾP':s==='error'?'LỖI KẾT NỐI':'ĐANG KẾT NỐI…';
}
window.socWS={connect};
})();
