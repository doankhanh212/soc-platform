(function(){

let _currentUser = null;

// ── Login / Logout ─────────────────────────────────────
async function login() {
  const username = document.getElementById('login-username')?.value?.trim();
  const password = document.getElementById('login-password')?.value;
  const errEl = document.getElementById('login-error');

  if(!username || !password) {
    if(errEl){ errEl.textContent='Vui lòng nhập đầy đủ thông tin'; errEl.style.display='block'; }
    return;
  }

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      credentials: 'include',
      body: JSON.stringify({username, password}),
    });
    if(!res.ok) {
      const d = await res.json();
      if(errEl){ errEl.textContent = d.detail || 'Đăng nhập thất bại'; errEl.style.display='block'; }
      return;
    }
    const user = await res.json();
    _setCurrentUser(user);
    _showApp();
  } catch(e) {
    if(errEl){ errEl.textContent='Lỗi kết nối server'; errEl.style.display='block'; }
  }
}

async function logout() {
  try {
    await fetch('/api/auth/logout', {method:'POST', credentials:'include'});
  } catch{}
  _currentUser = null;
  _showLogin();
  hideUserMenu();
}

// ── Session check on load ──────────────────────────────
async function checkSession() {
  try {
    const res = await fetch('/api/auth/me', {credentials:'include'});
    if(res.ok) {
      const user = await res.json();
      _setCurrentUser(user);
      _showApp();
    } else {
      _showLogin();
    }
  } catch {
    _showLogin();
  }
}

// ── UI switch ──────────────────────────────────────────
function _showLogin() {
  document.getElementById('login-page').style.display  = 'flex';
  document.getElementById('app').style.display         = 'none';
  document.getElementById('login-username').value      = '';
  document.getElementById('login-password').value      = '';
  document.getElementById('login-error').style.display = 'none';
}

function _showApp() {
  document.getElementById('login-page').style.display = 'none';
  document.getElementById('app').style.display        = 'flex';
  // Init WebSocket sau khi login
  if(window.socWS) window.socWS.connect();
  // Load dashboard data
  setTimeout(() => document.getElementById('refresh-btn')?.click(), 500);
}

function _setCurrentUser(user) {
  _currentUser = user;

  // Update avatar
  const nameEl  = document.getElementById('avatar-name');
  const roleEl  = document.getElementById('avatar-role');
  const circleEl = document.getElementById('avatar-circle');
  const roleColors = {
    admin:'#ff9900', soc2:'#8b5cf6', soc1:'#3b82f6', viewer:'#6b7280'
  };
  const roleLabels = {
    admin:'Admin', soc2:'SOC Level 2', soc1:'SOC Level 1', viewer:'Viewer'
  };

  if(nameEl)   nameEl.textContent   = user.full_name || user.username;
  if(roleEl)   roleEl.textContent   = roleLabels[user.role] || user.role;
  if(circleEl){
    circleEl.textContent            = (user.username||'A')[0].toUpperCase();
    circleEl.style.borderColor      = roleColors[user.role] || 'var(--green)';
    circleEl.style.color            = roleColors[user.role] || 'var(--green)';
    circleEl.style.background       = (roleColors[user.role]||'#00ff41') + '20';
  }

  // Update user menu
  const mnFull = document.getElementById('menu-fullname');
  const mnRole = document.getElementById('menu-role');
  if(mnFull) mnFull.textContent = user.full_name || user.username;
  if(mnRole) mnRole.textContent = roleLabels[user.role] || user.role;

  // Show/hide admin features
  const adminCard = document.getElementById('user-mgmt-card');
  if(adminCard) adminCard.style.display = user.role==='admin' ? 'block' : 'none';

  // Apply role-based UI restrictions
  _applyPermissions(user.role, user.permissions || []);
}

function _applyPermissions(role, permissions) {
  // Ẩn block IP nếu không có quyền
  if(!permissions.includes('block_ip')) {
    document.querySelectorAll('.ip-block-btn,.aq-btn-block').forEach(
      el => el.style.display = 'none'
    );
  }
  // Viewer: ẩn nút tạo case
  if(!permissions.includes('create_case')) {
    document.querySelectorAll('.btn-create-case,.aq-btn-case').forEach(
      el => el.style.display = 'none'
    );
  }
}

// ── User menu dropdown ─────────────────────────────────
function toggleUserMenu() {
  const m = document.getElementById('user-menu');
  if(m) m.style.display = m.style.display==='block' ? 'none' : 'block';
}
function hideUserMenu() {
  const m = document.getElementById('user-menu');
  if(m) m.style.display = 'none';
}

// Close menu khi click bên ngoài
document.addEventListener('click', e => {
  if(!document.getElementById('user-avatar')?.contains(e.target))
    hideUserMenu();
});

// ── User Management ────────────────────────────────────
async function loadUsers() {
  try {
    const res = await fetch('/api/auth/users', {credentials:'include'});
    if(!res.ok) return;
    const users = await res.json();
    const tbody = document.getElementById('users-tbody');
    if(!tbody) return;
    const roleLabels = {
      admin:'Admin', soc2:'SOC L2', soc1:'SOC L1', viewer:'Viewer'
    };
    const roleColors = {
      admin:'var(--amber)', soc2:'var(--purple)',
      soc1:'var(--blue)', viewer:'var(--muted)'
    };
    tbody.innerHTML = users.map(u => `
      <tr>
        <td style="font-family:monospace;color:var(--cyan)">${u.username}</td>
        <td style="color:var(--text)">${u.full_name||'—'}</td>
        <td><span style="color:${roleColors[u.role]};font-size:11px;
          font-weight:700">${roleLabels[u.role]||u.role}</span></td>
        <td><span style="color:${u.is_active?'var(--green)':'var(--red)'};
          font-size:11px">${u.is_active?'● Hoạt động':'○ Vô hiệu'}</span></td>
        <td style="font-size:11px;color:var(--muted)">
          ${u.last_login
            ? new Date(u.last_login*1000).toLocaleString('vi-VN')
            : 'Chưa đăng nhập'}
        </td>
        <td>
          ${u.username!=='admin'?`
          <button onclick="window.authApp.toggleActive(${u.id},${u.is_active})"
            style="padding:3px 8px;background:var(--bg-card);
                   border:1px solid var(--border);border-radius:3px;
                   color:var(--muted);font-size:10px;cursor:pointer;
                   margin-right:4px">
            ${u.is_active?'Vô hiệu':'Kích hoạt'}
          </button>
          <button onclick="window.authApp.deleteUser(${u.id},'${u.username}')"
            style="padding:3px 8px;background:rgba(255,51,51,.1);
                   border:1px solid rgba(255,51,51,.3);border-radius:3px;
                   color:var(--red);font-size:10px;cursor:pointer">Xóa</button>
          `:'<span style="color:var(--muted);font-size:11px">Mặc định</span>'}
        </td>
      </tr>
    `).join('');
  } catch(e) {
    window.toast?.('Lỗi tải users: '+e.message,'err');
  }
}

function showAddUser() {
  const m = document.getElementById('add-user-modal');
  if(m) m.style.display = 'flex';
}
function hideAddUser() {
  const m = document.getElementById('add-user-modal');
  if(m) m.style.display = 'none';
}

async function createUser() {
  const username  = document.getElementById('new-username')?.value?.trim();
  const password  = document.getElementById('new-password')?.value;
  const full_name = document.getElementById('new-fullname')?.value?.trim();
  const email     = document.getElementById('new-email')?.value?.trim();
  const role      = document.getElementById('new-role')?.value;
  if(!username || !password) {
    window.toast?.('Vui lòng nhập tên đăng nhập và mật khẩu','warn');
    return;
  }
  try {
    const res = await fetch('/api/auth/users', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username,password,role,full_name,email}),
    });
    if(!res.ok) throw new Error((await res.json()).detail);
    window.toast?.(`Đã tạo người dùng ${username}`,'ok');
    hideAddUser();
    loadUsers();
  } catch(e) {
    window.toast?.('Lỗi: '+e.message,'err');
  }
}

async function toggleActive(userId, currentActive) {
  try {
    await fetch(`/api/auth/users/${userId}`, {
      method:'PATCH', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({is_active: currentActive ? 0 : 1}),
    });
    loadUsers();
    window.toast?.('Đã cập nhật trạng thái','ok');
  } catch(e) { window.toast?.('Lỗi: '+e.message,'err'); }
}

async function deleteUser(userId, username) {
  if(!confirm(`Xóa người dùng ${username}?`)) return;
  try {
    await fetch(`/api/auth/users/${userId}`, {
      method:'DELETE', credentials:'include'
    });
    loadUsers();
    window.toast?.(`Đã xóa ${username}`,'ok');
  } catch(e) { window.toast?.('Lỗi: '+e.message,'err'); }
}

// Auto-load users khi vào settings
document.addEventListener('DOMContentLoaded', () => {
  checkSession();
  document.querySelector('[data-page="settings"]')
    ?.addEventListener('click', () => {
      if(_currentUser?.role === 'admin') loadUsers();
    });
});

window.authApp = {
  login, logout, checkSession,
  toggleUserMenu, hideUserMenu,
  showAddUser, hideAddUser, createUser,
  toggleActive, deleteUser,
  getCurrentUser: () => _currentUser,
  hasPermission: (perm) =>
    _currentUser?.permissions?.includes(perm) || false,
};

})();
