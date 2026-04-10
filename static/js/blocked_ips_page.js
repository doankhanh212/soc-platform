/*
 * blocked_ips_page.js — Trang "IP bị chặn"
 * Vanilla JS, CSS vars only
 */
(function () {
  'use strict';

  const state = {
    items: [],
    filterText: '',
  };

  function esc(v) {
    return String(v ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function byId(id) { return document.getElementById(id); }

  function isPageActive() {
    const p = byId('page-blocked-ips');
    return !!p && p.classList.contains('active');
  }

  async function refresh() {
    const tbody = document.querySelector('#blocked-ip-table tbody');
    const countEl = byId('blocked-ip-count');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:24px">Đang tải...</td></tr>';

    try {
      const res = await fetch('/api/blocked-ips');
      const data = await res.json();
      state.items = Array.isArray(data.ips) ? data.ips : [];
    } catch (_) {
      state.items = [];
    }

    if (countEl) countEl.textContent = state.items.length;
    renderTable();
  }

  function renderTable() {
    const tbody = document.querySelector('#blocked-ip-table tbody');
    if (!tbody) return;

    const q = state.filterText.toLowerCase();
    const filtered = q
      ? state.items.filter(i => String(i.ip || '').includes(q) || String(i.reason || '').toLowerCase().includes(q))
      : state.items;

    if (!filtered.length) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:24px">${
        state.items.length ? 'Không có kết quả khớp bộ lọc' : 'Không có IP nào đang bị chặn'
      }</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map((item, idx) => {
      const ip = String(item.ip || item || '');
      const blockedAt = item.blocked_at || '';
      const reason = item.reason || '';
      return `
        <tr style="border-bottom:1px solid var(--border-subtle)"
            onmouseover="this.style.background='var(--bg1)'"
            onmouseout="this.style.background='transparent'">
          <td style="padding:10px 12px;font-family:monospace;color:var(--cyan)">${esc(ip)}</td>
          <td style="padding:10px 12px;color:var(--muted);font-size:12px">${esc(blockedAt)}</td>
          <td style="padding:10px 12px;color:var(--muted);font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
              title="${esc(reason)}">${esc(reason || '—')}</td>
          <td style="padding:10px 12px;text-align:center">
            <button onclick="window.blockedIpsPage.unblock('${esc(ip)}')"
              style="padding:5px 14px;background:var(--bg);border:1px solid var(--green);color:var(--green);
                     border-radius:4px;font-size:11px;cursor:pointer">
              🔓 Bỏ chặn
            </button>
            <button onclick="window.blockedIpsPage.lookup('${esc(ip)}')"
              style="padding:5px 14px;background:var(--bg);border:1px solid var(--cyan);color:var(--cyan);
                     border-radius:4px;font-size:11px;cursor:pointer;margin-left:4px">
              🔍 Tra cứu
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function filterIPs() {
    const input = byId('blocked-ip-filter');
    state.filterText = String(input?.value || '').trim();
    renderTable();
  }

  async function unblock(ip) {
    if (!ip) return;
    if (!window.confirm(`Xác nhận bỏ chặn IP ${ip}?`)) return;

    try {
      const res = await fetch(`/api/blocked-ips/${encodeURIComponent(ip)}`, { method: 'DELETE' });
      const data = await res.json();
      const status = String(data.status || '').toLowerCase();
      if (status === 'unblocked' || status === 'already_unblocked') {
        if (typeof window.toast === 'function') window.toast(`Đã bỏ chặn ${ip}`, 'ok');
        await refresh();
      } else {
        if (typeof window.toast === 'function') window.toast(data.message || 'Bỏ chặn thất bại', 'err');
      }
    } catch (_) {
      if (typeof window.toast === 'function') window.toast('Không thể kết nối API', 'err');
    }
  }

  function lookup(ip) {
    if (!ip) return;
    if (typeof window.navigate === 'function') {
      window.navigate('threat-intel');
      setTimeout(() => {
        const input = document.getElementById('ti-search-input');
        if (input) {
          input.value = ip;
          if (typeof window.doLookup === 'function') window.doLookup();
        }
      }, 150);
    }
  }

  function onPageActive() {
    refresh();
  }

  window.blockedIpsPage = { refresh, unblock, lookup, filterIPs, onPageActive };
})();
