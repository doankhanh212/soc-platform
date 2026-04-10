(function(){

const THEMES = [
  {
    id: 'green-dark',
    name: 'Cyberpunk Xanh',
    emoji: '🟢',
    bg:     '#010a03',
    bg1:    '#0f1a0f',
    card:   'rgba(0,255,65,0.03)',
    accent: '#00ff41',
    text:   '#b0ffb8',
    muted:  '#3a6b40',
    border: 'rgba(0,255,65,0.2)',
    red:    '#ff3333',
    amber:  '#ff9900',
  },
  {
    id: 'blue-dark',
    name: 'Đại dương tối',
    emoji: '🔵',
    bg:     '#020814',
    bg1:    '#0a1628',
    card:   'rgba(59,130,246,0.04)',
    accent: '#3b82f6',
    text:   '#b0c8ff',
    muted:  '#2d4a7a',
    border: 'rgba(59,130,246,0.2)',
    red:    '#ef4444',
    amber:  '#f59e0b',
  },
  {
    id: 'white-blue',
    name: 'Trắng sáng',
    emoji: '⬜',
    bg:     '#f0f4ff',
    bg1:    '#ffffff',
    card:   'rgba(59,130,246,0.05)',
    accent: '#1d4ed8',
    text:   '#1e293b',
    muted:  '#94a3b8',
    border: 'rgba(59,130,246,0.2)',
    red:    '#dc2626',
    amber:  '#d97706',
  },
  {
    id: 'purple-dark',
    name: 'Tím hoàng hôn',
    emoji: '🟣',
    bg:     '#0d0514',
    bg1:    '#160a28',
    card:   'rgba(139,92,246,0.04)',
    accent: '#8b5cf6',
    text:   '#e0d0ff',
    muted:  '#4a2d7a',
    border: 'rgba(139,92,246,0.2)',
    red:    '#f43f5e',
    amber:  '#f59e0b',
  },
  {
    id: 'red-dark',
    name: 'Đỏ lửa',
    emoji: '🔴',
    bg:     '#0f0202',
    bg1:    '#1a0505',
    card:   'rgba(239,68,68,0.04)',
    accent: '#ef4444',
    text:   '#ffb0b0',
    muted:  '#7a2d2d',
    border: 'rgba(239,68,68,0.2)',
    red:    '#ff6666',
    amber:  '#ff9900',
  },
  {
    id: 'cyan-dark',
    name: 'Xanh băng',
    emoji: '🩵',
    bg:     '#01080f',
    bg1:    '#051525',
    card:   'rgba(6,182,212,0.04)',
    accent: '#06b6d4',
    text:   '#b0eeff',
    muted:  '#1a5a6b',
    border: 'rgba(6,182,212,0.2)',
    red:    '#ff4444',
    amber:  '#ffaa00',
  },
  {
    id: 'amber-dark',
    name: 'Vàng hổ phách',
    emoji: '🟡',
    bg:     '#0f0900',
    bg1:    '#1a1000',
    card:   'rgba(245,158,11,0.04)',
    accent: '#f59e0b',
    text:   '#fff0b0',
    muted:  '#7a5a00',
    border: 'rgba(245,158,11,0.2)',
    red:    '#ef4444',
    amber:  '#fbbf24',
  },
  {
    id: 'white-dark',
    name: 'Xám tối giản',
    emoji: '⚫',
    bg:     '#0a0a0a',
    bg1:    '#141414',
    card:   'rgba(255,255,255,0.03)',
    accent: '#e2e8f0',
    text:   '#e2e8f0',
    muted:  '#475569',
    border: 'rgba(255,255,255,0.12)',
    red:    '#f87171',
    amber:  '#fbbf24',
  },
];

const STORAGE_KEY = 'soc-theme';
let _current = null;

function _hexRgb(hex) {
  const h = (hex || '#000').replace('#', '');
  if (h.length === 3) return [parseInt(h[0]+h[0],16), parseInt(h[1]+h[1],16), parseInt(h[2]+h[2],16)];
  return [parseInt(h.slice(0,2),16), parseInt(h.slice(2,4),16), parseInt(h.slice(4,6),16)];
}

function applyTheme(theme) {
  _current = theme;
  const root = document.documentElement;

  root.style.setProperty('--bg',     theme.bg);
  root.style.setProperty('--bg0',    theme.bg);
  root.style.setProperty('--bg1',    theme.bg1);
  root.style.setProperty('--bg2',    theme.bg1);
  root.style.setProperty('--bg-card',theme.card);
  root.style.setProperty('--bg-hover',theme.card);
  root.style.setProperty('--green',  theme.accent);
  root.style.setProperty('--green2', theme.accent);
  root.style.setProperty('--green3', theme.card);
  root.style.setProperty('--text',   theme.text);
  root.style.setProperty('--muted',  theme.muted);
  root.style.setProperty('--border', theme.border);
  root.style.setProperty('--border2',theme.border.replace('0.2','0.4'));
  root.style.setProperty('--red',    theme.red);
  root.style.setProperty('--amber',  theme.amber);

  // ── Derived accent/bg rgba bands ─────────────────────────────
  const [ar,ag,ab] = _hexRgb(theme.accent);
  const [br,bgr,bb] = _hexRgb(theme.bg);
  const ac = `${ar},${ag},${ab}`;
  const bc = `${br},${bgr},${bb}`;
  root.style.setProperty('--glow',          `0 0 8px rgba(${ac},0.3)`);
  root.style.setProperty('--glow2',         `0 0 20px rgba(${ac},0.15)`);
  root.style.setProperty('--glow-strong',   `0 0 20px rgba(${ac},0.4)`);
  root.style.setProperty('--topnav-bg',     `rgba(${bc},0.95)`);
  root.style.setProperty('--grid-line',     `rgba(${ac},0.03)`);
  root.style.setProperty('--border-subtle', `rgba(${ac},0.05)`);
  root.style.setProperty('--dim',           `rgba(${ac},0.12)`);
  root.style.setProperty('--accent-04',     `rgba(${ac},0.04)`);
  root.style.setProperty('--accent-08',     `rgba(${ac},0.08)`);
  root.style.setProperty('--accent-10',     `rgba(${ac},0.10)`);
  root.style.setProperty('--accent-12',     `rgba(${ac},0.12)`);
  root.style.setProperty('--accent-20',     `rgba(${ac},0.20)`);

  // Body background
  document.body.style.background = theme.bg;
  document.body.style.color = theme.text;

  // Lưu vào localStorage
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(theme)); } catch{}

  // Refresh chart colors to match new theme
  if (window.socCharts && typeof window.socCharts.refreshChartColors === 'function') {
    window.socCharts.refreshChartColors();
  }

  // Update active state trong grid
  document.querySelectorAll('.theme-card').forEach(el => {
    el.classList.toggle('active', el.dataset.themeId === theme.id);
  });

  updatePreview(theme);
  updateCustomInputs(theme);
}

function updatePreview(theme) {
  const el = document.getElementById('theme-preview');
  if(!el) return;
  el.style.background = theme.bg;
  el.innerHTML = `
    <div style="display:flex;height:100%">
      <!-- Mini sidebar -->
      <div style="width:60px;background:${theme.bg1};border-right:1px solid ${theme.border};
        display:flex;flex-direction:column;align-items:center;padding:10px 0;gap:12px">
        <div style="width:28px;height:28px;border-radius:6px;background:${theme.accent};
          opacity:.9;font-size:12px;display:flex;align-items:center;
          justify-content:center;font-weight:900;color:${theme.bg}">⬡</div>
        <div style="width:24px;height:3px;border-radius:2px;background:${theme.accent}"></div>
        <div style="width:24px;height:3px;border-radius:2px;background:${theme.muted}"></div>
        <div style="width:24px;height:3px;border-radius:2px;background:${theme.muted}"></div>
        <div style="width:24px;height:3px;border-radius:2px;background:${theme.muted}"></div>
      </div>
      <!-- Mini content -->
      <div style="flex:1;padding:10px;display:flex;flex-direction:column;gap:8px">
        <!-- KPI row -->
        <div style="display:flex;gap:6px">
          <div style="flex:1;padding:6px 8px;border-radius:6px;
            border:1px solid ${theme.border};background:${theme.card}">
            <div style="font-size:8px;color:${theme.muted}">CẢNH BÁO</div>
            <div style="font-size:16px;font-weight:700;color:${theme.red}">1,245</div>
          </div>
          <div style="flex:1;padding:6px 8px;border-radius:6px;
            border:1px solid ${theme.border};background:${theme.card}">
            <div style="font-size:8px;color:${theme.muted}">ĐÃ XỬ LÝ</div>
            <div style="font-size:16px;font-weight:700;color:${theme.accent}">876</div>
          </div>
          <div style="flex:1;padding:6px 8px;border-radius:6px;
            border:1px solid ${theme.border};background:${theme.card}">
            <div style="font-size:8px;color:${theme.muted}">SLA</div>
            <div style="font-size:16px;font-weight:700;color:${theme.amber}">98.5%</div>
          </div>
        </div>
        <!-- Mini table row -->
        <div style="padding:6px 8px;border-radius:6px;
          border:1px solid ${theme.border};background:${theme.card}">
          <div style="display:flex;gap:8px;align-items:center">
            <div style="width:6px;height:6px;border-radius:50%;
              background:${theme.red};flex-shrink:0"></div>
            <div style="font-size:9px;color:${theme.text};flex:1">
              SSH Brute Force từ 3.144.77.222
            </div>
            <div style="font-size:8px;color:${theme.accent};
              padding:1px 5px;border-radius:2px;
              border:1px solid ${theme.border}">T1110</div>
          </div>
        </div>
      </div>
    </div>
  `;
}

function updateCustomInputs(theme) {
  const fields = {
    'custom-bg':       ['custom-bg-text',     theme.bg],
    'custom-accent':   ['custom-accent-text', theme.accent],
    'custom-text':     ['custom-text-text',   theme.text],
  };
  for(const [colorId, [textId, val]] of Object.entries(fields)){
    const c = document.getElementById(colorId);
    const t = document.getElementById(textId);
    if(c) c.value = val;
    if(t) t.value = val;
  }
}

function renderGrid() {
  const grid = document.getElementById('theme-grid');
  if(!grid) return;
  grid.innerHTML = THEMES.map(t => `
    <div class="theme-card ${_current?.id===t.id?'active':''}"
      data-theme-id="${t.id}"
      onclick="window.themeApp.apply('${t.id}')"
      style="padding:10px;border-radius:var(--r2);cursor:pointer;
             border:2px solid ${_current?.id===t.id ? t.accent : 'var(--border)'};
             background:${t.bg};transition:all .2s;position:relative">
      <!-- Mini preview -->
      <div style="height:50px;border-radius:6px;background:${t.bg1};
        border:1px solid ${t.border};margin-bottom:8px;overflow:hidden;
        display:flex;align-items:center;justify-content:center;gap:6px">
        <div style="width:8px;height:8px;border-radius:50%;background:${t.red}"></div>
        <div style="width:20px;height:3px;border-radius:2px;background:${t.accent}"></div>
        <div style="width:12px;height:3px;border-radius:2px;background:${t.muted}"></div>
      </div>
      <div style="font-size:11px;font-weight:600;color:${t.text};
        text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
        ${t.emoji} ${t.name}
      </div>
      ${_current?.id===t.id ? `
        <div style="position:absolute;top:4px;right:4px;width:16px;height:16px;
          border-radius:50%;background:${t.accent};display:flex;align-items:center;
          justify-content:center;font-size:10px;color:${t.bg}">✓</div>
      ` : ''}
    </div>
  `).join('');
}

// Public API
const themeApp = {
  apply(themeId) {
    const t = THEMES.find(x => x.id === themeId);
    if(t) applyTheme(t);
    renderGrid();
  },
  reset() {
    themeApp.apply('green-dark');
  },
  customColor(type, val) {
    const textId = `custom-${type}-text`;
    const el = document.getElementById(textId);
    if(el) el.value = val;
  },
  customColorText(type, val) {
    if(!/^#[0-9a-fA-F]{6}$/.test(val)) return;
    const colorId = `custom-${type}`;
    const el = document.getElementById(colorId);
    if(el) el.value = val;
  },
  applyCustom() {
    const bg     = document.getElementById('custom-bg')?.value     || '#010a03';
    const accent = document.getElementById('custom-accent')?.value || '#00ff41';
    const text   = document.getElementById('custom-text')?.value   || '#b0ffb8';
    applyTheme({
      id: 'custom',
      name: 'Tùy chỉnh',
      bg, bg1: bg,
      card: accent + '08',
      accent, text,
      muted: accent + '60',
      border: accent + '33',
      red: getComputedStyle(document.documentElement).getPropertyValue('--red').trim() || '#FF4444',
      amber: getComputedStyle(document.documentElement).getPropertyValue('--amber').trim() || '#ff9900',
    });
    renderGrid();
    window.toast('Đã áp dụng màu tùy chỉnh', 'ok');
  },
  renderGrid,
  getThemes: () => THEMES,
};

// Load saved theme on startup
function loadSaved() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if(saved) {
      const t = JSON.parse(saved);
      applyTheme(t);
      return;
    }
  } catch{}
  // Default
  applyTheme(THEMES[0]);
}

document.addEventListener('DOMContentLoaded', () => {
  loadSaved();
  // Re-render grid when settings page is shown
  document.querySelector('[data-page="settings"]')
    ?.addEventListener('click', () => {
      setTimeout(renderGrid, 50);
      setTimeout(() => updatePreview(_current || THEMES[0]), 50);
    });
});

window.themeApp = themeApp;
})();