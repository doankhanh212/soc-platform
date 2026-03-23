/**
 * map.js — World map với REAL GeoLocation từ OpenSearch.
 * GeoLocation.latitude/longitude có sẵn trong wazuh-alerts-4.x-*
 */
(function(){

const TARGET = { lat: 21.0278, lon: 105.8342 }; // Hanoi SOC

let canvas, ctx, W, H;
let hotspots = [];   // [{ip, lat, lon, country, city, count}]
let lines    = [];

function lonLatToXY(lon, lat, w, h){
  return [
    (lon + 180) / 360 * w,
    (90  - lat) / 180 * h,
  ];
}

function initMap(canvasId){
  canvas = document.getElementById(canvasId);
  if(!canvas) return;
  ctx = canvas.getContext('2d');
  resize();
  window.addEventListener('resize', resize);
  animate();
}

function resize(){
  if(!canvas) return;
  W = canvas.width  = canvas.parentElement.clientWidth;
  H = canvas.height = canvas.parentElement.clientHeight;
}

function updateHotspots(geoIPs){
  // geoIPs = [{ip, lat, lon, country, city, count}] — real data from OpenSearch
  if(!geoIPs || !geoIPs.length) return;
  hotspots = geoIPs;
  lines = hotspots.map(h => ({
    ...h,
    progress: Math.random(),
    speed:    0.003 + Math.random() * 0.005,
    color:    `rgba(255,${Math.floor(Math.random()*60)},0,`,
  }));
}

// Fallback: approximate positions when GeoLocation not available
function updateHotspotsFromIPs(topIPs){
  const APPROX = [
    [116,39],[139,35],[-74,40],[2,48],[37,55],[28,39],
    [103,1],[77,28],[-118,34],[151,-34],[149,-35],[103,14],
  ];
  hotspots = topIPs.slice(0,12).map((item,i) => {
    const [lon,lat] = APPROX[i % APPROX.length];
    return { ip: item.ip, lat, lon, country:'', city:'', count: item.count };
  });
  lines = hotspots.map(h => ({
    ...h,
    progress: Math.random(),
    speed:    0.003 + Math.random() * 0.005,
    color:    `rgba(255,${Math.floor(Math.random()*60)},0,`,
  }));
}

function drawGrid(){
  ctx.strokeStyle = 'rgba(0,255,65,0.04)';
  ctx.lineWidth = 0.5;
  // Lat lines
  for(let lat=-60; lat<=60; lat+=30){
    const y = (90-lat)/180*H;
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke();
  }
  // Lon lines
  for(let lon=-150; lon<=150; lon+=30){
    const x = (lon+180)/360*W;
    ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H); ctx.stroke();
  }
}

function drawLine(srcLon, srcLat, progress, colorBase){
  const [sx,sy] = lonLatToXY(srcLon, srcLat, W, H);
  const [dx,dy] = lonLatToXY(TARGET.lon, TARGET.lat, W, H);
  const mx = (sx+dx)/2;
  const my = Math.min(sy,dy) - 40 - Math.abs(dx-sx)*0.12;
  const steps = 40;

  ctx.beginPath();
  let first = true;
  for(let i=0; i<=steps*Math.min(progress,1); i++){
    const t = i/steps;
    const x = (1-t)*(1-t)*sx + 2*(1-t)*t*mx + t*t*dx;
    const y = (1-t)*(1-t)*sy + 2*(1-t)*t*my + t*t*dy;
    first ? (ctx.moveTo(x,y), first=false) : ctx.lineTo(x,y);
  }
  ctx.strokeStyle = colorBase + (0.3 + Math.min(progress,1)*0.5) + ')';
  ctx.lineWidth = 1;
  ctx.stroke();

  // Dot at tip
  const tp = Math.min(progress,1);
  const tx = (1-tp)*(1-tp)*sx + 2*(1-tp)*tp*mx + tp*tp*dx;
  const ty = (1-tp)*(1-tp)*sy + 2*(1-tp)*tp*my + tp*tp*dy;
  ctx.beginPath(); ctx.arc(tx,ty,2.5,0,Math.PI*2);
  ctx.fillStyle = colorBase + '0.9)'; ctx.fill();
}

function drawHotspot(lon, lat, count, label){
  const [x,y] = lonLatToXY(lon, lat, W, H);
  const r = Math.min(3 + count/30, 9);
  const pulse = (Date.now() % 2000)/2000;

  // Pulsing ring
  ctx.beginPath(); ctx.arc(x, y, r + pulse*12, 0, Math.PI*2);
  ctx.strokeStyle = `rgba(0,255,65,${0.2*(1-pulse)})`; ctx.lineWidth=1; ctx.stroke();

  // Core
  ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI*2);
  ctx.fillStyle = 'rgba(0,255,65,0.85)'; ctx.fill();

  // Label for larger hotspots
  if(count > 10 && label){
    ctx.font = '9px Share Tech Mono';
    ctx.fillStyle = 'rgba(0,255,65,0.7)';
    ctx.fillText(label, x+r+3, y+3);
  }
}

function drawTarget(){
  const [x,y] = lonLatToXY(TARGET.lon, TARGET.lat, W, H);
  const pulse = (Date.now() % 1500)/1500;

  [14, 22, 30].forEach((r,i) => {
    ctx.beginPath(); ctx.arc(x,y,r+pulse*4,0,Math.PI*2);
    ctx.strokeStyle = `rgba(0,170,255,${0.35-i*0.1})`; ctx.lineWidth=0.8; ctx.stroke();
  });
  // Crosshair
  ctx.strokeStyle = 'rgba(0,170,255,0.6)'; ctx.lineWidth=0.5;
  ctx.beginPath(); ctx.moveTo(x-20,y); ctx.lineTo(x+20,y); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(x,y-20); ctx.lineTo(x,y+20); ctx.stroke();

  ctx.beginPath(); ctx.arc(x,y,4,0,Math.PI*2);
  ctx.fillStyle = 'rgba(0,170,255,0.9)'; ctx.fill();
}

function animate(){
  if(!canvas) return;
  ctx.clearRect(0,0,W,H);

  // Scanline overlay
  for(let y=0; y<H; y+=3){
    ctx.fillStyle='rgba(0,0,0,0.03)'; ctx.fillRect(0,y,W,1);
  }

  drawGrid();

  lines.forEach(l => {
    l.progress += l.speed;
    if(l.progress > 1.4) l.progress = 0;
    drawLine(l.lon, l.lat, l.progress, l.color);
  });

  hotspots.forEach(h => drawHotspot(h.lon, h.lat, h.count, h.country));
  drawTarget();

  requestAnimationFrame(animate);
}

window.socMap = { initMap, updateHotspots, updateHotspotsFromIPs };
})();
