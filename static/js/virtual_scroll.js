/**
 * VIRTUAL_SCROLL.JS — Bảng cuộn ảo hiệu năng cao
 * Render 20 rows + buffer 5 trên/dưới. Row height 44px.
 * Hỗ trợ 10.000+ rows không giật lag.
 */

// ═══════════════════════════════════════════════════════════════════════════
// STYLES
// ═══════════════════════════════════════════════════════════════════════════

function _injectVSStyles() {
  if (document.getElementById('vs-styles')) return;
  const s = document.createElement('style');
  s.id = 'vs-styles';
  s.textContent = `
    .vs-wrapper {
      display: flex;
      flex-direction: column;
      overflow: hidden;
      background: #0a0f0a;
      border: 1px solid #1a3a1a;
      border-radius: 6px;
      font-size: 12px;
    }

    /* ── Header ── */
    .vs-header-row {
      display: flex;
      align-items: center;
      padding: 0 8px;
      background: #060e06;
      border-bottom: 1px solid #1a3a1a;
      flex-shrink: 0;
      user-select: none;
    }
    .vs-header-cell {
      display: flex;
      align-items: center;
      gap: 4px;
      padding: 0 6px;
      height: 36px;
      font-size: 10px;
      font-weight: 700;
      color: #555;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      cursor: pointer;
      white-space: nowrap;
      overflow: hidden;
      transition: color 150ms;
      flex-shrink: 0;
    }
    .vs-header-cell:hover { color: #00ff88; }
    .vs-header-cell.sort-asc::after  { content: ' ↑'; color: #00ff88; }
    .vs-header-cell.sort-desc::after { content: ' ↓'; color: #00ff88; }

    /* ── Scroll area ── */
    .vs-scroll-outer {
      flex: 1;
      overflow-y: auto;
      overflow-x: hidden;
      position: relative;
      will-change: transform;
    }
    .vs-scroll-outer::-webkit-scrollbar { width: 5px; }
    .vs-scroll-outer::-webkit-scrollbar-track { background: #050a05; }
    .vs-scroll-outer::-webkit-scrollbar-thumb { background: #1a3a1a; border-radius: 3px; }
    .vs-scroll-outer::-webkit-scrollbar-thumb:hover { background: #00ff8844; }

    /* Inner spacer creates accurate total scrollbar height */
    .vs-scroll-inner {
      position: relative;
      width: 100%;
    }

    /* Each row is absolutely positioned */
    .vs-row {
      position: absolute;
      left: 0;
      right: 0;
      height: 44px;
      display: flex;
      align-items: center;
      padding: 0 8px;
      border-bottom: 1px solid #0d1a0d;
      transition: background 100ms;
      cursor: pointer;
      box-sizing: border-box;
    }
    .vs-row:hover { background: #0d1a0d; }
    .vs-row.selected { background: #001a0d; border-color: #00ff8833; }
    .vs-row.flash-new {
      animation: vsRowFlash 1.2s ease-out;
    }
    @keyframes vsRowFlash {
      0%   { background: #00330d; }
      100% { background: transparent; }
    }
    .vs-row.flash-critical {
      animation: vsRowCritical 1.5s ease-out;
    }
    @keyframes vsRowCritical {
      0%   { background: #330000; box-shadow: inset 0 0 0 1px #ff220066; }
      100% { background: transparent; box-shadow: none; }
    }

    .vs-cell {
      flex-shrink: 0;
      padding: 0 6px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: #aaa;
    }

    /* ── Footer stats ── */
    .vs-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 6px 12px;
      background: #060e06;
      border-top: 1px solid #1a3a1a;
      font-size: 10px;
      color: #555;
      flex-shrink: 0;
    }
    .vs-footer-count { color: #00ff8888; }

    /* ── Empty state ── */
    .vs-empty {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 120px;
      color: #333;
      font-size: 12px;
      gap: 8px;
    }
    .vs-empty-icon { font-size: 32px; }

    /* ── Loading overlay ── */
    .vs-loading {
      position: absolute;
      inset: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0a0f0a99;
      z-index: 10;
      font-size: 12px;
      color: #00ff8888;
      gap: 8px;
    }
    .vs-spinner {
      width: 16px;
      height: 16px;
      border: 2px solid #1a3a1a;
      border-top-color: #00ff88;
      border-radius: 50%;
      animation: vsSpin 0.7s linear infinite;
    }
    @keyframes vsSpin { to { transform: rotate(360deg); } }
  `;
  document.head.appendChild(s);
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN CLASS
// ═══════════════════════════════════════════════════════════════════════════

class VirtualScrollTable {
  /**
   * @param {string}   containerId   — ID phần tử chứa bảng
   * @param {Array}    columns       — [{key, label, width, render}]
   * @param {Object}   [options]
   * @param {number}   [options.rowHeight=44]
   * @param {number}   [options.visibleCount=20]
   * @param {number}   [options.bufferSize=5]
   * @param {Function} [options.onRowClick]  cb(rowData, index)
   * @param {string}   [options.emptyText]
   * @param {Function} [options.getRowClass]  cb(rowData) → extra class string
   */
  constructor(containerId, columns, options = {}) {
    this.container    = document.getElementById(containerId);
    this.columns      = columns;
    this.rowHeight    = options.rowHeight    ?? 44;
    this.visibleCount = options.visibleCount ?? 20;
    this.bufferSize   = options.bufferSize   ?? 5;
    this.onRowClick   = options.onRowClick   ?? null;
    this.emptyText    = options.emptyText    ?? 'Không có dữ liệu';
    this.getRowClass  = options.getRowClass  ?? null;

    this.data          = [];
    this.filteredData  = [];
    this.selectedIndex = -1;
    this.sortKey       = null;
    this.sortDir       = 'asc';
    this._scrollTop    = 0;
    this._ticking      = false;
    this._renderedStart = -1;
    this._renderedEnd   = -1;

    if (!this.container) {
      console.warn(`[VirtualScrollTable] Container #${containerId} không tìm thấy`);
      return;
    }

    _injectVSStyles();
    this._build();
  }

  // ─────────────────────────────────────────────
  // BUILD DOM
  // ─────────────────────────────────────────────

  _build() {
    this.container.innerHTML = '';
    this.container.className = 'vs-wrapper';

    // Header row
    this._headerRow = document.createElement('div');
    this._headerRow.className = 'vs-header-row';
    this.columns.forEach(col => {
      const cell = document.createElement('div');
      cell.className = 'vs-header-cell';
      cell.style.width = (col.width || 120) + 'px';
      cell.dataset.key = col.key;
      cell.textContent = col.label;
      if (col.sortable !== false) {
        cell.addEventListener('click', () => this._toggleSort(col.key));
      }
      this._headerRow.appendChild(cell);
    });

    // Scroll outer
    this._outer = document.createElement('div');
    this._outer.className = 'vs-scroll-outer';

    // Inner spacer (height drives the scrollbar)
    this._inner = document.createElement('div');
    this._inner.className = 'vs-scroll-inner';

    this._outer.appendChild(this._inner);

    // Footer
    this._footer = document.createElement('div');
    this._footer.className = 'vs-footer';
    this._footerCount = document.createElement('span');
    this._footerCount.className = 'vs-footer-count';
    this._footerCount.textContent = '0 bản ghi';
    this._footer.appendChild(this._footerCount);

    this.container.appendChild(this._headerRow);
    this.container.appendChild(this._outer);
    this.container.appendChild(this._footer);

    // Scroll event with rAF throttle
    this._outer.addEventListener('scroll', () => {
      this._scrollTop = this._outer.scrollTop;
      if (!this._ticking) {
        this._ticking = true;
        requestAnimationFrame(() => {
          this._renderVisible();
          this._ticking = false;
        });
      }
    }, { passive: true });

    this._showEmpty();
  }

  // ─────────────────────────────────────────────
  // DATA LOADING
  // ─────────────────────────────────────────────

  /**
   * Tải toàn bộ dữ liệu mới (reset scroll về đầu)
   * @param {Array} rows
   */
  loadData(rows) {
    this.data = rows || [];
    this._applyFilter(this._currentFilter);
    this._outer.scrollTop = 0;
    this._scrollTop = 0;
    this._renderedStart = -1;
    this._renderedEnd = -1;
    this._render();
  }

  /**
   * Thêm dữ liệu mới vào cuối, giữ vị trí scroll
   * @param {Array} newRows
   * @param {boolean} [flashNew=true] — highlight rows mới thêm
   */
  appendData(newRows, flashNew = true) {
    if (!newRows || !newRows.length) return;
    const prevLen = this.filteredData.length;
    this.data = this.data.concat(newRows);
    this._applyFilter(this._currentFilter);
    this._updateTotalHeight();
    this._updateFooter();
    this._renderVisible();

    if (flashNew) {
      // Schedule flash on newly appended rows after render
      requestAnimationFrame(() => {
        for (let i = prevLen; i < this.filteredData.length; i++) {
          const el = this._inner.querySelector(`[data-vs-index="${i}"]`);
          if (el) {
            const isHighLevel = this.filteredData[i]?.rule?.level >= 15;
            el.classList.add(isHighLevel ? 'flash-critical' : 'flash-new');
          }
        }
      });
    }
  }

  /**
   * Xóa toàn bộ data và reset bảng
   */
  clear() {
    this.data = [];
    this.filteredData = [];
    this._render();
  }

  // ─────────────────────────────────────────────
  // FILTER & SORT
  // ─────────────────────────────────────────────

  /**
   * Lọc dữ liệu. predicate(row) → boolean
   * @param {Function|null} predicate
   */
  filter(predicate) {
    this._currentFilter = predicate;
    this._applyFilter(predicate);
    this._outer.scrollTop = 0;
    this._scrollTop = 0;
    this._renderedStart = -1;
    this._render();
  }

  _applyFilter(predicate) {
    this.filteredData = predicate
      ? this.data.filter(predicate)
      : [...this.data];
    if (this.sortKey) this._sortData();
  }

  _toggleSort(key) {
    if (this.sortKey === key) {
      this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      this.sortKey = key;
      this.sortDir = 'asc';
    }
    // Update header visual
    this._headerRow.querySelectorAll('.vs-header-cell').forEach(el => {
      el.classList.remove('sort-asc', 'sort-desc');
      if (el.dataset.key === key) el.classList.add(`sort-${this.sortDir}`);
    });
    this._sortData();
    this._outer.scrollTop = 0;
    this._scrollTop = 0;
    this._renderedStart = -1;
    this._render();
  }

  _sortData() {
    const key = this.sortKey;
    const dir = this.sortDir === 'asc' ? 1 : -1;
    this.filteredData.sort((a, b) => {
      const va = _deepGet(a, key) ?? '';
      const vb = _deepGet(b, key) ?? '';
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
      return String(va).localeCompare(String(vb), 'vi') * dir;
    });
  }

  // ─────────────────────────────────────────────
  // RENDER ENGINE
  // ─────────────────────────────────────────────

  _render() {
    this._inner.innerHTML = '';
    this._renderedStart = -1;
    this._renderedEnd = -1;

    if (!this.filteredData.length) {
      this._inner.style.height = '0px';
      this._showEmpty();
      this._updateFooter();
      return;
    }

    this._hideEmpty();
    this._updateTotalHeight();
    this._renderVisible();
    this._updateFooter();
  }

  _renderVisible() {
    const total = this.filteredData.length;
    if (!total) return;

    const start = Math.max(0, Math.floor(this._scrollTop / this.rowHeight) - this.bufferSize);
    const end   = Math.min(total, start + this.visibleCount + this.bufferSize * 2);

    // Nothing changed
    if (start === this._renderedStart && end === this._renderedEnd) return;

    // Remove rows outside new range
    const existing = this._inner.querySelectorAll('.vs-row');
    existing.forEach(el => {
      const i = parseInt(el.dataset.vsIndex, 10);
      if (i < start || i >= end) el.remove();
    });

    // Add rows in new range
    for (let i = start; i < end; i++) {
      if (this._inner.querySelector(`[data-vs-index="${i}"]`)) continue;
      const rowEl = this._createRow(i, this.filteredData[i]);
      this._inner.appendChild(rowEl);
    }

    this._renderedStart = start;
    this._renderedEnd   = end;
  }

  _createRow(index, rowData) {
    const row = document.createElement('div');
    row.className = 'vs-row';
    row.dataset.vsIndex = index;
    row.style.top = (index * this.rowHeight) + 'px';

    // Extra class from consumer
    if (this.getRowClass) {
      const extra = this.getRowClass(rowData);
      if (extra) row.classList.add(...extra.split(' ').filter(Boolean));
    }

    // Selected state
    if (index === this.selectedIndex) row.classList.add('selected');

    // Cells
    this.columns.forEach(col => {
      const cell = document.createElement('div');
      cell.className = 'vs-cell';
      cell.style.width = (col.width || 120) + 'px';

      if (col.render) {
        const html = col.render(rowData, index);
        if (typeof html === 'string') {
          cell.innerHTML = html;
        } else if (html instanceof HTMLElement) {
          cell.appendChild(html);
        }
      } else {
        const val = _deepGet(rowData, col.key);
        cell.textContent = val !== undefined && val !== null ? String(val) : '—';
      }

      row.appendChild(cell);
    });

    row.addEventListener('click', () => {
      this.selectedIndex = index;
      this._inner.querySelectorAll('.vs-row').forEach(r => r.classList.remove('selected'));
      row.classList.add('selected');
      if (this.onRowClick) this.onRowClick(rowData, index);
    });

    return row;
  }

  _updateTotalHeight() {
    this._inner.style.height = (this.filteredData.length * this.rowHeight) + 'px';
  }

  _updateFooter() {
    const total    = this.data.length;
    const filtered = this.filteredData.length;
    if (total === filtered) {
      this._footerCount.textContent = `${total.toLocaleString('vi-VN')} bản ghi`;
    } else {
      this._footerCount.textContent = `${filtered.toLocaleString('vi-VN')} / ${total.toLocaleString('vi-VN')} bản ghi`;
    }
  }

  // ─────────────────────────────────────────────
  // EMPTY STATE
  // ─────────────────────────────────────────────

  _showEmpty() {
    let el = this._outer.querySelector('.vs-empty');
    if (!el) {
      el = document.createElement('div');
      el.className = 'vs-empty';
      const icon = document.createElement('div');
      icon.className = 'vs-empty-icon';
      icon.textContent = '📭';
      const txt = document.createElement('div');
      txt.textContent = this.emptyText;
      el.appendChild(icon);
      el.appendChild(txt);
      this._outer.appendChild(el);
    }
  }

  _hideEmpty() {
    this._outer.querySelector('.vs-empty')?.remove();
  }

  // ─────────────────────────────────────────────
  // LOADING INDICATOR
  // ─────────────────────────────────────────────

  showLoading(show = true) {
    let el = this._outer.querySelector('.vs-loading');
    if (show) {
      if (!el) {
        el = document.createElement('div');
        el.className = 'vs-loading';
        const spinner = document.createElement('div');
        spinner.className = 'vs-spinner';
        const txt = document.createElement('span');
        txt.textContent = 'Đang tải...';
        el.appendChild(spinner);
        el.appendChild(txt);
        this._outer.appendChild(el);
      }
    } else {
      el?.remove();
    }
  }

  // ─────────────────────────────────────────────
  // PUBLIC HELPERS
  // ─────────────────────────────────────────────

  /**
   * Cuộn đến row theo index (đưa vào giữa viewport)
   * @param {number} index
   */
  scrollToIndex(index) {
    const outerH = this._outer.clientHeight;
    const top    = index * this.rowHeight - outerH / 2 + this.rowHeight / 2;
    this._outer.scrollTop = Math.max(0, top);
  }

  /**
   * Cuộn xuống cuối bảng (dùng khi có alert mới thêm)
   */
  scrollToBottom() {
    this._outer.scrollTop = this._inner.scrollHeight;
  }

  /**
   * Lấy row data được chọn hiện tại
   */
  getSelectedRow() {
    return this.filteredData[this.selectedIndex] ?? null;
  }

  /**
   * Tổng số rows
   */
  get totalRows() { return this.filteredData.length; }
}

// ─────────────────────────────────────────────
// UTIL
// ─────────────────────────────────────────────

function _deepGet(obj, path) {
  return path.split('.').reduce((acc, k) => (acc && acc[k] !== undefined ? acc[k] : undefined), obj);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { VirtualScrollTable };
}
