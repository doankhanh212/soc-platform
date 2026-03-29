/* SOAR Playbook Builder - PlaybookCanvas controller */
window.soarApp = (function() {
  'use strict';

  const MAX_UNDO_STEPS = 20;
  const HISTORY_KEY = 'soar.run.history.v1';
  const PLAYBOOK_DRAFT_KEY = 'soar.playbook.draft.v1';

  class PlaybookCanvas {
    constructor() {
      this.canvas = null;
      this.viewport = null;
      this.nodesLayer = null;
      this.arrowsLayer = null;
      this.zoomLabel = null;
      this.statusEl = null;
      this.historyEl = null;
      this.logPanel = null;
      this.logBody = null;
      this.logStatus = null;
      this.logFooter = null;
      this.runModal = null;
      this.templateSelect = null;
      this.toggleBtn = null;
      this.toggleDot = null;
      this.autoBadge = null;
      this.deleteConnectionButton = null;

      this.nodes = new Map();
      this.connections = [];
      this.nodeCounter = 0;
      this.connectionCounter = 0;

      this.scale = 1;
      this.offsetX = 0;
      this.offsetY = 0;
      this.minScale = 0.5;
      this.maxScale = 2;

      this.spacePressed = false;
      this.isPanning = false;
      this.panStartX = 0;
      this.panStartY = 0;
      this.panOffsetStartX = 0;
      this.panOffsetStartY = 0;

      this.dragNodeId = null;
      this.dragNodeStartX = 0;
      this.dragNodeStartY = 0;
      this.dragPointerStartX = 0;
      this.dragPointerStartY = 0;

      this.drawingConnection = null;
      this.tempPointer = { x: 0, y: 0 };

      this.selectedNodes = new Set();
      this.selectedConnectionId = null;

      this.undoStack = [];
      this.suspendUndo = false;

      this.isAutoEnabled = false;
      this.isRunning = false;
      this.runLogs = [];
      this.runHistory = [];
      this.lastAlertPayload = null;

      this.boundWsHandler = this.onWebsocketData.bind(this);
      this.boundKeyDown = this.onKeyDown.bind(this);
      this.boundKeyUp = this.onKeyUp.bind(this);
      this.boundPointerMove = this.onPointerMove.bind(this);
      this.boundPointerUp = this.onPointerUp.bind(this);
    }

    init() {
      this.canvas = document.getElementById('playbook-canvas');
      this.viewport = document.getElementById('canvas-viewport');
      this.nodesLayer = document.getElementById('nodes-layer');
      this.arrowsLayer = document.getElementById('arrows-layer');
      this.zoomLabel = document.getElementById('soar-zoom-level');
      this.statusEl = document.getElementById('soar-status');
      this.historyEl = document.getElementById('soar-history');
      this.logPanel = document.getElementById('run-log-panel');
      this.logBody = document.getElementById('log-body');
      this.logStatus = document.getElementById('log-status');
      this.logFooter = document.getElementById('log-footer');
      this.runModal = document.getElementById('soar-run-modal');
      this.templateSelect = document.getElementById('soar-template-select');
      this.toggleBtn = document.getElementById('soar-toggle-btn');
      this.toggleDot = document.getElementById('soar-toggle-dot');
      this.autoBadge = document.getElementById('soar-auto-badge');

      if (!this.canvas || !this.viewport || !this.nodesLayer || !this.arrowsLayer) {
        return;
      }

      this.createConnectionDeleteButton();
      this.ensureSvgDefs();
      this.bindCanvasEvents();
      this.bindShortcuts();
      this.applyViewportTransform();
      this.updateZoomLabel();
      this.loadHistoryFromStorage();
      this.loadDraftFromStorage();
      this.renderHistory();
      this.updateStatus('Sẵn sàng');
      this.pushUndoState();
    }

    bindCanvasEvents() {
      this.canvas.addEventListener('dragover', event => {
        event.preventDefault();
        event.dataTransfer.dropEffect = 'copy';
      });

      this.canvas.addEventListener('drop', event => {
        event.preventDefault();
        const type = event.dataTransfer.getData('componentType') || event.dataTransfer.getData('type');
        if (!type) {
          return;
        }
        const connectorName = event.dataTransfer.getData('connectorName') || '';
        const pos = this.screenToCanvas(event.clientX, event.clientY);
        this.createNode(type, pos.x, pos.y, { connectorName });
      });

      this.canvas.addEventListener('mousedown', event => {
        if (event.button !== 0) {
          return;
        }
        const hitNode = event.target.closest('.playbook-node');
        if (hitNode) {
          return;
        }
        this.startPan(event);
      });

      this.canvas.addEventListener('click', event => {
        if (event.target === this.canvas || event.target === this.arrowsLayer) {
          this.clearSelection();
        }
      });

      this.canvas.addEventListener('wheel', event => {
        event.preventDefault();
        this.zoomAtPointer(event.clientX, event.clientY, event.deltaY < 0 ? 1.1 : 0.9);
      }, { passive: false });

      window.addEventListener('mousemove', this.boundPointerMove);
      window.addEventListener('mouseup', this.boundPointerUp);

      this.canvas.addEventListener('mousemove', event => {
        if (!this.drawingConnection) {
          return;
        }
        const pos = this.screenToCanvas(event.clientX, event.clientY);
        this.tempPointer.x = pos.x;
        this.tempPointer.y = pos.y;
        this.renderConnections();
      });
    }

    bindShortcuts() {
      document.addEventListener('keydown', this.boundKeyDown);
      document.addEventListener('keyup', this.boundKeyUp);
      document.addEventListener('soc:data', this.boundWsHandler);
    }

    createConnectionDeleteButton() {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'soar-conn-delete-btn';
      button.textContent = '✕';
      button.style.display = 'none';
      button.addEventListener('click', () => {
        if (this.selectedConnectionId) {
          this.deleteConnection(this.selectedConnectionId);
        }
      });
      this.viewport.appendChild(button);
      this.deleteConnectionButton = button;
    }

    ensureSvgDefs() {
      this.arrowsLayer.innerHTML = `
        <defs>
          <marker id="soar-arrow-head" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto" markerUnits="strokeWidth">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#00ff88"></path>
          </marker>
        </defs>
      `;
    }

    onDragStart(event) {
      const source = event.target.closest('.soar-component, .soar-external-link');
      if (!source) {
        return;
      }

      let componentType = source.dataset.type || 'connector';
      const connectorName = source.dataset.target || '';
      if (source.classList.contains('soar-external-link')) {
        componentType = 'connector';
      }

      event.dataTransfer.effectAllowed = 'copy';
      event.dataTransfer.setData('componentType', componentType);
      event.dataTransfer.setData('type', componentType);
      if (connectorName) {
        event.dataTransfer.setData('connectorName', connectorName);
      }
    }

    screenToCanvas(clientX, clientY) {
      const rect = this.canvas.getBoundingClientRect();
      const x = (clientX - rect.left - this.offsetX) / this.scale;
      const y = (clientY - rect.top - this.offsetY) / this.scale;
      return { x: Math.max(0, Math.round(x)), y: Math.max(0, Math.round(y)) };
    }

    applyViewportTransform() {
      this.viewport.style.transform = `translate(${this.offsetX}px, ${this.offsetY}px) scale(${this.scale})`;
    }

    zoomAtPointer(clientX, clientY, factor) {
      const oldScale = this.scale;
      const nextScale = Math.min(this.maxScale, Math.max(this.minScale, oldScale * factor));
      if (nextScale === oldScale) {
        return;
      }

      const rect = this.canvas.getBoundingClientRect();
      const pointerX = clientX - rect.left;
      const pointerY = clientY - rect.top;
      const worldX = (pointerX - this.offsetX) / oldScale;
      const worldY = (pointerY - this.offsetY) / oldScale;

      this.scale = nextScale;
      this.offsetX = pointerX - (worldX * this.scale);
      this.offsetY = pointerY - (worldY * this.scale);

      this.applyViewportTransform();
      this.updateZoomLabel();
    }

    updateZoomLabel() {
      if (this.zoomLabel) {
        this.zoomLabel.textContent = `${Math.round(this.scale * 100)}%`;
      }
    }

    startPan(event) {
      if (!this.spacePressed && event.target !== this.canvas) {
        return;
      }
      this.isPanning = true;
      this.panStartX = event.clientX;
      this.panStartY = event.clientY;
      this.panOffsetStartX = this.offsetX;
      this.panOffsetStartY = this.offsetY;
      this.canvas.classList.add('is-panning');
    }

    onPointerMove(event) {
      if (this.isPanning) {
        this.offsetX = this.panOffsetStartX + (event.clientX - this.panStartX);
        this.offsetY = this.panOffsetStartY + (event.clientY - this.panStartY);
        this.applyViewportTransform();
      }

      if (this.dragNodeId) {
        const node = this.nodes.get(this.dragNodeId);
        if (!node) {
          return;
        }
        const dx = (event.clientX - this.dragPointerStartX) / this.scale;
        const dy = (event.clientY - this.dragPointerStartY) / this.scale;
        node.x = Math.max(0, Math.round(this.dragNodeStartX + dx));
        node.y = Math.max(0, Math.round(this.dragNodeStartY + dy));
        this.positionNodeElement(node.id, node.x, node.y);
        this.renderConnections();
      }
    }

    onPointerUp() {
      if (this.isPanning) {
        this.isPanning = false;
        this.canvas.classList.remove('is-panning');
      }
      if (this.dragNodeId) {
        this.dragNodeId = null;
        this.pushUndoState();
      }
    }

    createNode(type, x, y, extra = {}) {
      const id = `n${++this.nodeCounter}`;
      const labels = {
        action: 'Hành động',
        condition: 'Điều kiện',
        trigger: 'Kích hoạt',
        connector: 'Kết nối'
      };

      const connectorName = extra.connectorName || '';
      const node = {
        id,
        type,
        x,
        y,
        title: connectorName ? this.connectorLabel(connectorName) : `${labels[type] || 'Node'} ${this.nodeCounter}`,
        input: '',
        action: connectorName ? this.connectorApiHint(connectorName) : '',
        output: '',
        connectorName,
        status: 'idle'
      };

      this.nodes.set(id, node);
      this.nodesLayer.appendChild(this.renderNode(node));
      this.selectSingleNode(id);
      this.renderConnections();
      this.updateStatus(`+ Tạo node ${node.title}`);
      this.pushUndoState();
    }

    connectorLabel(target) {
      const map = {
        firewall: 'Tường lửa',
        edr: 'EDR',
        threat_intel: 'Threat Intel'
      };
      return map[target] || 'Connector';
    }

    connectorApiHint(target) {
      const map = {
        firewall: '/api/response',
        edr: '/api/edr',
        threat_intel: '/api/threatintel'
      };
      return map[target] || '';
    }

    renderNode(node) {
      const el = document.createElement('div');
      el.className = `playbook-node soar-node ${node.type}`;
      el.dataset.nodeId = node.id;
      el.id = `playbook-node-${node.id}`;
      this.positionNodeElement(node.id, node.x, node.y, el);

      el.innerHTML = `
        <div class="soar-node-hdr node-drag-handle">
          <div class="soar-node-title">
            <span>${this.nodeIcon(node.type)}</span>
            <span class="node-title-text">${node.title}</span>
          </div>
          <button type="button" class="soar-node-menu" data-node-menu="${node.id}">⋮</button>
        </div>
        <div class="soar-port in" data-port="in" data-node-id="${node.id}"></div>
        <div class="soar-port out" data-port="out" data-node-id="${node.id}"></div>

        <div class="soar-section">
          <label class="soar-section-label">Đầu vào</label>
          <textarea class="soar-textarea" data-field="input">${node.input}</textarea>
        </div>
        <div class="soar-section">
          <label class="soar-section-label">Hành động</label>
          <textarea class="soar-textarea" data-field="action">${node.action}</textarea>
        </div>
        <div class="soar-section">
          <label class="soar-section-label">Đầu ra</label>
          <textarea class="soar-textarea" data-field="output">${node.output}</textarea>
        </div>
      `;

      const menuButton = el.querySelector('[data-node-menu]');
      if (menuButton) {
        menuButton.addEventListener('click', event => {
          event.stopPropagation();
          this.openNodeMenu(node.id);
        });
      }

      const textareas = el.querySelectorAll('textarea[data-field]');
      textareas.forEach(area => {
        area.addEventListener('change', event => {
          const field = event.target.dataset.field;
          const data = this.nodes.get(node.id);
          if (!data) {
            return;
          }
          data[field] = event.target.value;
          this.pushUndoState();
        });
      });

      const handle = el.querySelector('.node-drag-handle');
      if (handle) {
        handle.addEventListener('mousedown', event => {
          if (event.button !== 0) {
            return;
          }
          event.stopPropagation();
          this.dragNodeId = node.id;
          this.dragNodeStartX = node.x;
          this.dragNodeStartY = node.y;
          this.dragPointerStartX = event.clientX;
          this.dragPointerStartY = event.clientY;
          this.selectSingleNode(node.id);
        });
      }

      el.addEventListener('click', event => {
        event.stopPropagation();
        if (event.shiftKey) {
          this.toggleNodeSelection(node.id);
          return;
        }
        this.selectSingleNode(node.id);
      });

      el.addEventListener('dblclick', () => {
        const data = this.nodes.get(node.id);
        if (!data) {
          return;
        }
        const name = prompt('Tên node mới:', data.title);
        if (!name) {
          return;
        }
        data.title = name;
        const text = el.querySelector('.node-title-text');
        if (text) {
          text.textContent = name;
        }
        this.pushUndoState();
      });

      const outPort = el.querySelector('.soar-port.out');
      if (outPort) {
        outPort.addEventListener('click', event => {
          event.stopPropagation();
          this.beginConnection(node.id);
        });
      }

      const inPort = el.querySelector('.soar-port.in');
      if (inPort) {
        inPort.addEventListener('click', event => {
          event.stopPropagation();
          this.finishConnection(node.id);
        });
      }

      return el;
    }

    nodeIcon(type) {
      const icons = {
        action: '≡',
        condition: '⚠',
        trigger: '⚡',
        connector: '→'
      };
      return icons[type] || '□';
    }

    positionNodeElement(nodeId, x, y, existingElement) {
      const el = existingElement || document.getElementById(`playbook-node-${nodeId}`);
      if (!el) {
        return;
      }
      el.style.left = `${x}px`;
      el.style.top = `${y}px`;
    }

    beginConnection(fromId) {
      this.drawingConnection = { fromId };
      const fromNode = this.nodes.get(fromId);
      if (fromNode) {
        this.tempPointer = { x: fromNode.x + 240, y: fromNode.y + 80 };
      }
      this.renderConnections();
    }

    finishConnection(toId) {
      if (!this.drawingConnection) {
        return;
      }
      const fromId = this.drawingConnection.fromId;
      this.drawingConnection = null;

      if (fromId === toId) {
        this.renderConnections();
        return;
      }

      this.createConnection(fromId, toId);
      this.renderConnections();
    }

    createConnection(fromId, toId) {
      const duplicated = this.connections.some(conn => conn.from === fromId && conn.to === toId);
      if (duplicated) {
        return false;
      }
      const id = `c${++this.connectionCounter}`;
      this.connections.push({ id, from: fromId, to: toId });
      this.pushUndoState();
      return true;
    }

    cancelConnectionDrawing() {
      this.drawingConnection = null;
      this.renderConnections();
    }

    calcArrowPath(fromX, fromY, toX, toY) {
      const dx = Math.abs(toX - fromX) * 0.5;
      return `M ${fromX},${fromY} C ${fromX + dx},${fromY} ${toX - dx},${toY} ${toX},${toY}`;
    }

    getPortPosition(nodeId, side) {
      const node = this.nodes.get(nodeId);
      if (!node) {
        return null;
      }
      const el = document.getElementById(`playbook-node-${nodeId}`);
      const width = el ? el.offsetWidth : 240;
      const height = el ? el.offsetHeight : 220;
      return {
        x: side === 'out' ? node.x + width : node.x,
        y: node.y + (height * 0.5)
      };
    }

    renderConnections() {
      if (!this.arrowsLayer) {
        return;
      }

      this.arrowsLayer.innerHTML = '';
      this.ensureSvgDefs();
      this.hideConnectionDeleteButton();

      for (const conn of this.connections) {
        const from = this.getPortPosition(conn.from, 'out');
        const to = this.getPortPosition(conn.to, 'in');
        if (!from || !to) {
          continue;
        }

        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', this.calcArrowPath(from.x, from.y, to.x, to.y));
        path.setAttribute('class', 'soar-conn-path');
        path.setAttribute('marker-end', 'url(#soar-arrow-head)');
        path.dataset.connectionId = conn.id;

        if (conn.id === this.selectedConnectionId) {
          path.classList.add('selected');
        }

        path.addEventListener('mouseenter', () => {
          path.classList.add('hovered');
          this.showConnectionDeleteButton(path, conn.id);
        });

        path.addEventListener('mouseleave', () => {
          path.classList.remove('hovered');
        });

        path.addEventListener('click', event => {
          event.stopPropagation();
          this.selectConnection(conn.id);
          this.showConnectionDeleteButton(path, conn.id);
        });

        this.arrowsLayer.appendChild(path);
      }

      if (this.drawingConnection) {
        const from = this.getPortPosition(this.drawingConnection.fromId, 'out');
        if (from) {
          const tempPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          tempPath.setAttribute('d', this.calcArrowPath(from.x, from.y, this.tempPointer.x, this.tempPointer.y));
          tempPath.setAttribute('class', 'soar-conn-path temp');
          this.arrowsLayer.appendChild(tempPath);
        }
      }
    }

    showConnectionDeleteButton(pathElement, connectionId) {
      if (!this.deleteConnectionButton || !pathElement) {
        return;
      }
      const pathLength = pathElement.getTotalLength();
      const point = pathElement.getPointAtLength(pathLength / 2);
      this.deleteConnectionButton.style.left = `${point.x - 10}px`;
      this.deleteConnectionButton.style.top = `${point.y - 10}px`;
      this.deleteConnectionButton.style.display = 'inline-flex';
      this.selectedConnectionId = connectionId;
    }

    hideConnectionDeleteButton() {
      if (this.deleteConnectionButton) {
        this.deleteConnectionButton.style.display = 'none';
      }
    }

    selectConnection(connectionId) {
      this.selectedConnectionId = connectionId;
      this.selectedNodes.clear();
      this.updateSelectionVisuals();
      this.renderConnections();
    }

    deleteConnection(connectionId) {
      const before = this.connections.length;
      this.connections = this.connections.filter(conn => conn.id !== connectionId);
      if (this.connections.length !== before) {
        this.selectedConnectionId = null;
        this.hideConnectionDeleteButton();
        this.renderConnections();
        this.pushUndoState();
      }
    }

    updateSelectionVisuals() {
      const nodeElements = this.nodesLayer.querySelectorAll('.playbook-node');
      nodeElements.forEach(el => {
        const nodeId = el.dataset.nodeId;
        el.classList.toggle('selected', this.selectedNodes.has(nodeId));
      });
    }

    selectSingleNode(nodeId) {
      this.selectedNodes.clear();
      this.selectedNodes.add(nodeId);
      this.selectedConnectionId = null;
      this.hideConnectionDeleteButton();
      this.updateSelectionVisuals();
      this.renderConnections();
    }

    toggleNodeSelection(nodeId) {
      if (this.selectedNodes.has(nodeId)) {
        this.selectedNodes.delete(nodeId);
      } else {
        this.selectedNodes.add(nodeId);
      }
      this.selectedConnectionId = null;
      this.hideConnectionDeleteButton();
      this.updateSelectionVisuals();
    }

    selectAllNodes() {
      this.selectedNodes = new Set(this.nodes.keys());
      this.selectedConnectionId = null;
      this.hideConnectionDeleteButton();
      this.updateSelectionVisuals();
    }

    clearSelection() {
      this.selectedNodes.clear();
      this.selectedConnectionId = null;
      this.hideConnectionDeleteButton();
      this.updateSelectionVisuals();
      this.cancelConnectionDrawing();
    }

    openNodeMenu(nodeId) {
      const node = this.nodes.get(nodeId);
      if (!node) {
        return;
      }
      const choice = prompt('Chọn hành động:\n0: Đổi tên\n1: Nhân bản\n2: Xóa node', '0');
      if (choice === '0') {
        const name = prompt('Tên mới:', node.title);
        if (name) {
          node.title = name;
          const title = document.querySelector(`#playbook-node-${nodeId} .node-title-text`);
          if (title) {
            title.textContent = name;
          }
          this.pushUndoState();
        }
      } else if (choice === '1') {
        this.createNode(node.type, node.x + 40, node.y + 40, { connectorName: node.connectorName || '' });
        const cloneId = `n${this.nodeCounter}`;
        const clone = this.nodes.get(cloneId);
        if (clone) {
          clone.title = `${node.title} (copy)`;
          clone.input = node.input;
          clone.action = node.action;
          clone.output = node.output;
          const cloneEl = document.getElementById(`playbook-node-${clone.id}`);
          if (cloneEl) {
            const text = cloneEl.querySelector('.node-title-text');
            if (text) {
              text.textContent = clone.title;
            }
            cloneEl.querySelector('textarea[data-field="input"]').value = clone.input;
            cloneEl.querySelector('textarea[data-field="action"]').value = clone.action;
            cloneEl.querySelector('textarea[data-field="output"]').value = clone.output;
          }
          this.pushUndoState();
        }
      } else if (choice === '2') {
        this.deleteNode(nodeId);
      }
    }

    deleteNode(nodeId) {
      if (!this.nodes.has(nodeId)) {
        return;
      }
      this.nodes.delete(nodeId);
      this.connections = this.connections.filter(conn => conn.from !== nodeId && conn.to !== nodeId);
      const el = document.getElementById(`playbook-node-${nodeId}`);
      if (el) {
        el.remove();
      }
      this.selectedNodes.delete(nodeId);
      this.renderConnections();
      this.pushUndoState();
    }

    deleteSelection() {
      if (this.selectedConnectionId) {
        this.deleteConnection(this.selectedConnectionId);
        return;
      }

      if (this.selectedNodes.size > 0) {
        const ids = Array.from(this.selectedNodes);
        ids.forEach(nodeId => this.deleteNode(nodeId));
        this.selectedNodes.clear();
        this.updateSelectionVisuals();
        this.pushUndoState();
      }
    }

    pushUndoState() {
      if (this.suspendUndo) {
        return;
      }
      const snapshot = JSON.stringify({
        nodeCounter: this.nodeCounter,
        connectionCounter: this.connectionCounter,
        nodes: Array.from(this.nodes.values()),
        connections: this.connections,
        transform: {
          scale: this.scale,
          offsetX: this.offsetX,
          offsetY: this.offsetY
        }
      });

      if (this.undoStack[this.undoStack.length - 1] === snapshot) {
        return;
      }

      this.undoStack.push(snapshot);
      if (this.undoStack.length > MAX_UNDO_STEPS) {
        this.undoStack.shift();
      }
    }

    undo() {
      if (this.undoStack.length <= 1) {
        return;
      }
      this.undoStack.pop();
      const snapshot = this.undoStack[this.undoStack.length - 1];
      this.restoreSnapshot(snapshot);
    }

    restoreSnapshot(snapshot) {
      let data = null;
      try {
        data = JSON.parse(snapshot);
      } catch (_error) {
        return;
      }

      this.suspendUndo = true;
      this.clearCanvas();
      this.nodeCounter = data.nodeCounter || 0;
      this.connectionCounter = data.connectionCounter || 0;

      const nodeList = data.nodes || [];
      nodeList.forEach(node => {
        this.nodes.set(node.id, { ...node });
        this.nodesLayer.appendChild(this.renderNode(node));
      });

      this.connections = (data.connections || []).map(conn => ({ ...conn }));

      if (data.transform) {
        this.scale = data.transform.scale || 1;
        this.offsetX = data.transform.offsetX || 0;
        this.offsetY = data.transform.offsetY || 0;
      }

      this.applyViewportTransform();
      this.updateZoomLabel();
      this.renderConnections();
      this.clearSelection();
      this.suspendUndo = false;
    }

    serializePlaybook() {
      return {
        ten: 'Playbook #1',
        nodes: Array.from(this.nodes.values()).map(node => ({
          id: node.id,
          type: node.type,
          x: node.x,
          y: node.y,
          input: node.input,
          action: node.action,
          output: node.output,
          title: node.title,
          connectorName: node.connectorName || ''
        })),
        connections: this.connections.map(conn => ({ from: conn.from, to: conn.to }))
      };
    }

    loadPlaybook(json) {
      if (!json) {
        return;
      }

      let payload = json;
      if (typeof json === 'string') {
        const trimmed = json.trim();
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
          payload = JSON.parse(trimmed);
        } else {
          showToast('✗ Không thể tải playbook theo định dạng hiện tại', 'err');
          return;
        }
      }
      this.suspendUndo = true;
      this.clearCanvas();

      const nodes = payload.nodes || [];
      const connections = payload.connections || [];
      nodes.forEach(node => {
        const nodeData = {
          id: node.id || `n${++this.nodeCounter}`,
          type: node.type || 'action',
          x: Number(node.x) || 0,
          y: Number(node.y) || 0,
          title: node.title || 'Node',
          input: node.input || '',
          action: node.action || '',
          output: node.output || '',
          connectorName: node.connectorName || '',
          status: 'idle'
        };
        this.nodes.set(nodeData.id, nodeData);
        this.nodesLayer.appendChild(this.renderNode(nodeData));

        const numeric = Number(String(nodeData.id).replace('n', ''));
        if (!Number.isNaN(numeric)) {
          this.nodeCounter = Math.max(this.nodeCounter, numeric);
        }
      });

      this.connections = connections.map(conn => {
        this.connectionCounter += 1;
        return {
          id: `c${this.connectionCounter}`,
          from: conn.from,
          to: conn.to
        };
      });

      this.renderConnections();
      this.suspendUndo = false;
      this.pushUndoState();
      this.saveDraftToStorage(payload);
      this.updateStatus('Đã tải playbook');
    }

    save() {
      if (this.nodes.size === 0) {
        showToast('⚠ Không có node để lưu', 'warn');
        return;
      }
      const body = this.serializePlaybook();
      this.saveDraftToStorage(body);
      showToast('💾 Đã lưu playbook', 'ok');
      this.updateStatus('Đã lưu playbook');
      return;
      window.api.post('/api/playbooks', body)
        .then(() => {
          showToast('💾 Đã lưu playbook', 'ok');
          this.updateStatus('Đã lưu playbook');
        })
        .catch(() => {
          showToast('✗ Không thể lưu playbook', 'err');
        });
    }

    loadTemplate() {
      if (!this.templateSelect) {
        return;
      }
      const key = this.templateSelect.value;
      if (!key) {
        showToast('ℹ Chọn mẫu trước khi nạp', 'warn');
        return;
      }
      const template = this.getTemplates()[key];
      if (!template) {
        return;
      }
      this.loadPlaybook(template);
    }

    getTemplates() {
      return {
        ssh_bruteforce: {
          ten: 'Phản ứng SSH Brute Force',
          nodes: [
            { id: 'n1', type: 'trigger', x: 120, y: 120, title: 'Nhận cảnh báo SSH', input: 'new_alert SSH', action: 'Bắt sự kiện', output: 'src_ip' },
            { id: 'n2', type: 'condition', x: 470, y: 120, title: 'Kiểm tra mức độ', input: 'rule.level >= 12', action: 'Rẽ nhánh', output: 'cao/thấp' },
            { id: 'n3', type: 'action', x: 820, y: 120, title: 'Kích hoạt phản ứng', input: 'src_ip', action: 'block_ip', output: 'đã chặn' }
          ],
          connections: [
            { from: 'n1', to: 'n2' },
            { from: 'n2', to: 'n3' }
          ]
        },
        malicious_ip: {
          ten: 'Kiểm tra IP độc hại',
          nodes: [
            { id: 'n1', type: 'trigger', x: 120, y: 260, title: 'Nhận IOC', input: 'src_ip', action: 'đưa vào playbook', output: 'ip' },
            { id: 'n2', type: 'connector', x: 460, y: 240, title: 'Threat Intel', input: 'ip', action: '/api/threatintel', output: 'score' },
            { id: 'n3', type: 'condition', x: 780, y: 260, title: 'Điểm độc hại > 80', input: 'score', action: 'đánh giá', output: 'true/false' }
          ],
          connections: [
            { from: 'n1', to: 'n2' },
            { from: 'n2', to: 'n3' }
          ]
        },
        suricata_alert: {
          ten: 'Cảnh báo Suricata',
          nodes: [
            { id: 'n1', type: 'trigger', x: 120, y: 420, title: 'Suricata Alert', input: 'event=suricata', action: 'nhận log', output: 'src_ip,dst_ip' },
            { id: 'n2', type: 'action', x: 470, y: 420, title: 'Ghi case', input: 'alert', action: 'create_case', output: 'case_id' },
            { id: 'n3', type: 'connector', x: 820, y: 420, title: 'Tường lửa', input: 'src_ip', action: '/api/response', output: 'blocked' }
          ],
          connections: [
            { from: 'n1', to: 'n2' },
            { from: 'n2', to: 'n3' }
          ]
        },
        nmap_scan: {
          ten: '🔍 Phản ứng Quét Nmap Suricata',
          mo_ta: 'Xử lý khi Suricata phát hiện Nmap SYN Scan (rule 86601)',
          nodes: [
            {
              id: 'n1',
              type: 'trigger',
              x: 80,
              y: 180,
              title: 'Phát hiện Nmap Scan',
              input: 'Suricata alert — data.alert.signature_id = 1000001',
              action: 'Kích hoạt khi Suricata ghi nhận SOC LAB Nmap SYN Scan',
              output: 'data.src_ip, data.dest_port, flow.pkts_toserver'
            },
            {
              id: 'n2',
              type: 'action',
              x: 440,
              y: 180,
              title: 'Tương quan cảnh báo',
              input: 'src_ip, khung thời gian ±30 phút',
              action: 'Query /api/hunt?q={src_ip}&hours=1 — đếm số port đã quét',
              output: 'ports_scanned, so_canh_bao_lien_quan'
            },
            {
              id: 'n3',
              type: 'action',
              x: 800,
              y: 180,
              title: 'Tạo vụ việc điều tra',
              input: 'ports_scanned, so_canh_bao_lien_quan',
              action: "POST /api/incidents {title:'Nmap Scan từ {src_ip}', severity:'medium'}",
              output: 'incident_id, trang_thai'
            }
          ],
          connections: [
            { from: 'n1', to: 'n2' },
            { from: 'n2', to: 'n3' }
          ]
        },
        ai_anomaly: {
          ten: '🤖 Phản ứng AI Bất thường',
          mo_ta: 'Tự động phản ứng khi AI Engine phát hiện điểm rủi ro >= 0.5',
          nodes: [
            {
              id: 'n1',
              type: 'trigger',
              x: 80,
              y: 200,
              title: 'AI: Bất thường phát hiện',
              input: 'WebSocket event type=ai_anomaly',
              action: 'Kích hoạt khi diem_rui_ro >= 0.5 (Hành vi bất thường + Tăng đột biến)',
              output: 'ip, diem_rui_ro, so_canh_bao_1h'
            },
            {
              id: 'n2',
              type: 'condition',
              x: 460,
              y: 200,
              title: 'Đánh giá mức rủi ro',
              input: 'diem_rui_ro, so_canh_bao_1h',
              action: 'IF diem_rui_ro > 0.7 THEN chặn ngay\nELSE tạo vụ việc',
              output: 'quyet_dinh: chan_ngay | tao_vu_viec'
            },
            {
              id: 'n3',
              type: 'action',
              x: 840,
              y: 100,
              title: 'Chặn IP tự động',
              input: 'quyet_dinh = chan_ngay',
              action: "POST /api/response {action:'block_ip', ip, reason:'AI score > 0.7'}",
              output: 'block_status, iptables_rule_id'
            },
            {
              id: 'n4',
              type: 'action',
              x: 840,
              y: 320,
              title: 'Tạo vụ việc điều tra',
              input: 'quyet_dinh = tao_vu_viec',
              action: "POST /api/incidents {title:'AI: Bất thường IP {ip}', severity:'high'}",
              output: 'incident_id'
            }
          ],
          connections: [
            { from: 'n1', to: 'n2' },
            { from: 'n2', to: 'n3' },
            { from: 'n2', to: 'n4' }
          ]
        }
      };
    }

    deleteAll() {
      if (!confirm('Xóa toàn bộ node và kết nối?')) {
        return;
      }
      this.clearCanvas();
      this.clearDraftStorage();
      this.pushUndoState();
      this.updateStatus('Canvas đã được dọn sạch');
    }

    clearCanvas() {
      this.nodes.clear();
      this.connections = [];
      this.nodeCounter = 0;
      this.connectionCounter = 0;
      this.selectedNodes.clear();
      this.selectedConnectionId = null;
      if (this.nodesLayer) {
        this.nodesLayer.innerHTML = '';
      }
      this.renderConnections();
      this.hideConnectionDeleteButton();
    }

    run() {
      if (this.nodes.size === 0) {
        showToast('⚠ Không có node để chạy', 'warn');
        return;
      }
      this.openRunModal();
    }

    openRunModal() {
      if (!this.runModal) {
        return;
      }
      this.runModal.classList.add('active');
      this.runModal.setAttribute('aria-hidden', 'false');
    }

    closeRunModal() {
      if (!this.runModal) {
        return;
      }
      this.runModal.classList.remove('active');
      this.runModal.setAttribute('aria-hidden', 'true');
    }

    confirmRun(mode) {
      this.closeRunModal();
      this.executeRun(mode === 'real' ? 'real' : 'simulate', null);
    }

    async executeRun(mode, alertPayload) {
      if (this.isRunning || this.nodes.size === 0) {
        return;
      }

      this.isRunning = true;
      this.lastAlertPayload = alertPayload || this.lastAlertPayload;
      this.runLogs = [];
      this.openLogPanel();
      this.updateStatus(`Đang chạy ${mode === 'real' ? 'thật' : 'mô phỏng'}...`);

      const orderedNodeIds = this.topologicalSort();
      const startTime = Date.now();
      let successCount = 0;
      let failedCount = 0;

      for (const nodeId of orderedNodeIds) {
        const node = this.nodes.get(nodeId);
        if (!node) {
          continue;
        }

        this.addLogLine('⏳', node.title, 'Đợi đến lượt xử lý');
        this.setNodeRunState(nodeId, 'processing', 'Đang xử lý...');
        this.addLogLine('ℹ️', node.title, 'Bắt đầu xử lý');

        await this.sleep(1200);

        const failedByRule = /(fail|lỗi|error)/i.test(`${node.title} ${node.action} ${node.input}`);
        const isSuccess = !failedByRule;
        if (isSuccess) {
          successCount += 1;
          this.setNodeRunState(nodeId, 'success', 'Thành công');
          this.addLogLine('✅', node.title, 'Thành công');
        } else {
          failedCount += 1;
          this.setNodeRunState(nodeId, 'failed', 'Thất bại: điều kiện mô phỏng');
          this.addLogLine('❌', node.title, 'Thất bại: điều kiện mô phỏng');
        }

        this.animateOutgoingConnections(nodeId);
      }

      if (mode === 'real') {
        await this.tryExecuteRealAction(orderedNodeIds);
      }

      const elapsed = Date.now() - startTime;
      this.finishLog(successCount, orderedNodeIds.length, Number((elapsed / 1000).toFixed(1)));
      this.updateStatus('Chạy playbook hoàn tất');

      this.saveRunHistory({
        ten: 'Playbook #1',
        thoi_gian: 'vừa xong',
        ket_qua: failedCount === 0 ? 'thanh_cong' : 'that_bai',
        so_node_thanh_cong: successCount,
        so_node_that_bai: failedCount,
        thoi_gian_chay_ms: elapsed,
        nodeIds: orderedNodeIds
      });

      this.isRunning = false;
    }

    async tryExecuteRealAction(orderedNodeIds) {
      const lastId = orderedNodeIds[orderedNodeIds.length - 1];
      const lastNode = this.nodes.get(lastId);
      if (!lastNode) {
        return;
      }

      const actionText = `${lastNode.title} ${lastNode.action}`.toLowerCase();
      const shouldBlock = actionText.includes('block') || actionText.includes('chặn') || actionText.includes('phan ung');
      if (!shouldBlock) {
        return;
      }

      let ip = this.extractIp(lastNode.input) || this.extractIp(lastNode.output);
      if (!ip && this.lastAlertPayload && this.lastAlertPayload.data) {
        ip = this.lastAlertPayload.data.src_ip || '';
      }
      if (!ip) {
        return;
      }

      try {
        if (window.socApi && typeof window.socApi.blockIP === 'function') {
          await window.socApi.blockIP(ip);
        } else {
          await window.api.post('/api/response', { action: 'block_ip', ip });
        }
        showToast(`🛡 Playbook đã chặn IP ${ip} tự động`, 'ok');
        this.appendLog('✅', lastNode.title, `Đã gọi API chặn IP ${ip}`, 'ok');
      } catch (_error) {
        this.appendLog('❌', lastNode.title, `Không thể gọi API chặn IP ${ip}`, 'err');
      }
    }

    extractIp(text) {
      if (!text) {
        return '';
      }
      const match = String(text).match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      return match ? match[0] : '';
    }

    topologicalSort() {
      const ids = Array.from(this.nodes.keys());
      const incoming = new Map(ids.map(id => [id, 0]));
      const outgoing = new Map(ids.map(id => [id, []]));

      this.connections.forEach(conn => {
        if (!incoming.has(conn.to) || !outgoing.has(conn.from)) {
          return;
        }
        incoming.set(conn.to, incoming.get(conn.to) + 1);
        outgoing.get(conn.from).push(conn.to);
      });

      const queue = ids.filter(id => incoming.get(id) === 0);
      const sorted = [];

      while (queue.length > 0) {
        const id = queue.shift();
        sorted.push(id);
        const nextList = outgoing.get(id) || [];
        nextList.forEach(next => {
          incoming.set(next, incoming.get(next) - 1);
          if (incoming.get(next) === 0) {
            queue.push(next);
          }
        });
      }

      if (sorted.length < ids.length) {
        ids.forEach(id => {
          if (!sorted.includes(id)) {
            sorted.push(id);
          }
        });
      }

      return sorted;
    }

    animateOutgoingConnections(fromNodeId) {
      const targets = this.connections.filter(conn => conn.from === fromNodeId);
      targets.forEach(conn => {
        const path = this.arrowsLayer.querySelector(`path[data-connection-id="${conn.id}"]`);
        if (!path) {
          return;
        }
        path.classList.add('flowing');
        setTimeout(() => path.classList.remove('flowing'), 1100);
      });
    }

    setNodeRunState(nodeId, state, description) {
      const el = document.getElementById(`playbook-node-${nodeId}`);
      if (!el) {
        return;
      }

      el.classList.remove('run-processing', 'run-success', 'run-failed');
      if (state === 'processing') {
        el.classList.add('run-processing');
      } else if (state === 'success') {
        el.classList.add('run-success');
      } else if (state === 'failed') {
        el.classList.add('run-failed');
      }

      let badge = el.querySelector('.node-run-badge');
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'node-run-badge';
        const hdr = el.querySelector('.soar-node-hdr');
        if (hdr) {
          hdr.appendChild(badge);
        }
      }

      if (state === 'processing') {
        badge.textContent = '⏳ Đang xử lý...';
      } else if (state === 'success') {
        badge.textContent = '✅ Thành công';
      } else if (state === 'failed') {
        badge.textContent = `❌ ${description}`;
      } else {
        badge.textContent = '';
      }
    }

    openLogPanel() {
      if (this.logPanel) {
        this.logPanel.classList.remove('hidden');
        this.logPanel.classList.add('visible');
      }
      if (this.logBody) {
        this.logBody.innerHTML = '';
      }
      if (this.logFooter) {
        this.logFooter.textContent = '';
      }
      if (this.logStatus) {
        this.logStatus.textContent = 'Đang chạy...';
        this.logStatus.style.color = '#FFCC00';
      }
    }

    closeLogPanel() {
      if (this.logPanel) {
        this.logPanel.classList.add('hidden');
        this.logPanel.classList.remove('visible');
      }
    }

    _logTypeByIcon(icon) {
      if (icon === '⏳') return 'warn';
      if (icon === '✅') return 'ok';
      if (icon === '❌') return 'err';
      return 'info';
    }

    addLogLine(icon, nodeName, message) {
      const now = new Date();
      const time = now.toLocaleTimeString('vi-VN');
      const lineText = `[${time}] ${icon} ${nodeName}: ${message}`;
      this.runLogs.push(lineText);

      if (!this.logBody) {
        return;
      }

      const line = document.createElement('div');
      line.className = `soar-log-line ${this._logTypeByIcon(icon)}`;
      line.textContent = lineText;
      this.logBody.appendChild(line);
      this.logBody.scrollTop = this.logBody.scrollHeight;
    }

    appendLog(icon, nodeName, message) {
      this.addLogLine(icon, nodeName, message);
    }

    downloadLog() {
      if (!this.runLogs.length) {
        showToast('ℹ Chưa có log để tải', 'warn');
        return;
      }
      const blob = new Blob([this.runLogs.join('\n')], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      anchor.download = `playbook-log-${stamp}.txt`;
      anchor.click();
      URL.revokeObjectURL(url);
    }

    finishLog(success, total, elapsed) {
      const hasError = success < total;
      this.addLogLine('ℹ️', 'Tổng kết', '═'.repeat(50));
      this.addLogLine('ℹ️', 'Tổng kết', `HOÀN THÀNH: ${success}/${total} node thành công · Thời gian: ${elapsed}s`);

      if (this.logFooter) {
        this.logFooter.textContent = `HOÀN THÀNH: ${success}/${total} node thành công · Thời gian: ${elapsed}s`;
      }
      if (this.logStatus) {
        this.logStatus.textContent = hasError ? 'Có lỗi ✗' : 'Hoàn thành ✓';
        this.logStatus.style.color = hasError ? '#FF4444' : '#00ff88';
      }
    }

    togglePlaybook() {
      this.isAutoEnabled = !this.isAutoEnabled;

      if (this.toggleBtn) {
        this.toggleBtn.style.background = this.isAutoEnabled ? 'rgba(0,255,65,.2)' : '#2a4a2a';
      }
      if (this.toggleDot) {
        this.toggleDot.classList.toggle('active', this.isAutoEnabled);
        this.toggleDot.style.background = this.isAutoEnabled ? 'var(--green)' : 'var(--muted)';
      }
      if (this.autoBadge) {
        this.autoBadge.style.display = this.isAutoEnabled ? 'inline-flex' : 'none';
      }

      this.updateStatus(this.isAutoEnabled ? 'Tự động chạy theo alert: BẬT' : 'Tự động chạy theo alert: TẮT');
    }

    onWebsocketData(event) {
      const payload = event.detail || {};
      const level = Number(payload && payload.rule ? payload.rule.level : 0);
      if (!this.isAutoEnabled || this.isRunning) {
        return;
      }

      if (payload.type === 'new_alert' && level >= 12) {
        this.lastAlertPayload = payload;
        this.appendLog('ℹ️', 'AUTO', `Nhận alert mức ${level}, tự động chạy playbook`, 'info');
        this.executeRun('simulate', payload);
      }
    }

    loadHistoryFromStorage() {
      try {
        const raw = localStorage.getItem(HISTORY_KEY);
        this.runHistory = raw ? JSON.parse(raw) : [];
      } catch (_error) {
        this.runHistory = [];
      }
    }

    loadDraftFromStorage() {
      try {
        const raw = localStorage.getItem(PLAYBOOK_DRAFT_KEY);
        if (!raw || this.nodes.size > 0) {
          return;
        }
        this.loadPlaybook(JSON.parse(raw));
        this.updateStatus('Đã khôi phục bản nháp');
      } catch (_error) {
        this.clearDraftStorage();
      }
    }

    saveHistoryToStorage() {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(this.runHistory.slice(0, 50)));
    }

    saveDraftToStorage(playbook = this.serializePlaybook()) {
      localStorage.setItem(PLAYBOOK_DRAFT_KEY, JSON.stringify(playbook));
    }

    clearDraftStorage() {
      localStorage.removeItem(PLAYBOOK_DRAFT_KEY);
    }

    saveRunHistory(entry) {
      const runItem = {
        id: Date.now(),
        ...entry
      };
      this.runHistory.unshift(runItem);
      if (this.runHistory.length > 50) {
        this.runHistory = this.runHistory.slice(0, 50);
      }
      this.saveHistoryToStorage();
      this.renderHistory();
    }

    renderHistory() {
      if (!this.historyEl) {
        return;
      }

      if (!this.runHistory.length) {
        this.historyEl.innerHTML = '<div style="padding:12px;text-align:center;color:#666;font-size:9px">Chưa có lịch sử chạy</div>';
        return;
      }

      const items = this.runHistory.slice(0, 5);
      this.historyEl.innerHTML = items.map(item => {
        const ok = item.ket_qua === 'thanh_cong';
        const dot = ok ? '#00ff88' : '#ff3333';
        const timeText = item.thoi_gian || this.relativeTime(item.id);
        return `
          <div class="soar-history-item" data-run-id="${item.id}" style="padding:8px;padding-left:6px;border-bottom:1px solid #1a3a1a;font-size:9px;display:flex;align-items:center;gap:6px;border-left:3px solid ${dot}">
            <span style="color:${dot};font-size:10px;font-weight:700">●</span>
            <div style="flex:1;min-width:0">
              <div style="color:#ccc;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${item.ten}</div>
              <div style="color:#666;font-size:8px">${timeText}</div>
            </div>
            <div style="color:${dot};font-size:8px;font-weight:700">${item.so_node_thanh_cong || 0}/${(item.so_node_thanh_cong || 0) + (item.so_node_that_bai || 0)}</div>
          </div>
        `;
      }).join('');

      const rowEls = this.historyEl.querySelectorAll('.soar-history-item');
      rowEls.forEach(row => {
        row.addEventListener('click', () => {
          const runId = Number(row.dataset.runId);
          this.highlightHistoryNodes(runId);
        });
      });
    }

    relativeTime(timestamp) {
      const diffMs = Date.now() - Number(timestamp || Date.now());
      const min = Math.floor(diffMs / 60000);
      if (min <= 0) {
        return 'vừa xong';
      }
      if (min < 60) {
        return `${min} phút trước`;
      }
      const hr = Math.floor(min / 60);
      return `${hr} giờ trước`;
    }

    highlightHistoryNodes(runId) {
      const item = this.runHistory.find(run => run.id === runId);
      const targetIds = item && item.nodeIds ? item.nodeIds : [];
      const nodeEls = this.nodesLayer.querySelectorAll('.playbook-node');
      nodeEls.forEach(el => {
        const selected = targetIds.length === 0 ? true : targetIds.includes(el.dataset.nodeId);
        el.style.opacity = selected ? '1' : '0.25';
      });
      setTimeout(() => {
        nodeEls.forEach(el => {
          el.style.opacity = '1';
        });
      }, 1600);
    }

    loadPlaybookList() {
      this.renderHistory();
      return;
      window.api.get('/api/playbooks/current/history')
        .then(historyList => {
          if (!Array.isArray(historyList) || historyList.length === 0) {
            return;
          }

          const normalized = historyList.slice(0, 20).map(item => ({
            id: item.id || Date.now() + Math.floor(Math.random() * 9999),
            ten: item.ten || item.name || 'Playbook',
            thoi_gian: item.thoi_gian || 'vừa xong',
            ket_qua: item.ket_qua || 'thanh_cong',
            so_node_thanh_cong: item.so_node_thanh_cong || item.so_buoc || 0,
            so_node_that_bai: item.so_node_that_bai || 0,
            thoi_gian_chay_ms: item.thoi_gian_chay_ms || 0,
            nodeIds: item.nodeIds || []
          }));

          this.runHistory = [...normalized, ...this.runHistory].slice(0, 50);
          this.saveHistoryToStorage();
          this.renderHistory();
        })
        .catch(() => {
          this.renderHistory();
        });
    }

    showAllHistory() {
      if (!this.runHistory.length) {
        showToast('ℹ Chưa có lịch sử chạy', 'warn');
        return;
      }
      const lines = this.runHistory.slice(0, 20).map(item => {
        const summary = `${item.ten} | ${item.ket_qua} | ${(item.thoi_gian_chay_ms || 0)}ms`;
        return summary;
      });
      alert(lines.join('\n'));
    }

    onKeyDown(event) {
      const tag = document.activeElement ? document.activeElement.tagName : '';
      const isTyping = tag === 'INPUT' || tag === 'TEXTAREA';

      if (event.key === ' ') {
        this.spacePressed = true;
        this.canvas.classList.add('pan-mode');
        return;
      }

      if (isTyping) {
        if (event.key === 'Escape') {
          this.clearSelection();
        }
        return;
      }

      if ((event.key === 'Delete' || event.key === 'Backspace') && this.nodes.size > 0) {
        event.preventDefault();
        this.deleteSelection();
        return;
      }

      if (event.ctrlKey && event.key.toLowerCase() === 'z') {
        event.preventDefault();
        this.undo();
        return;
      }

      if (event.ctrlKey && event.key.toLowerCase() === 's') {
        event.preventDefault();
        this.save();
        return;
      }

      if (event.ctrlKey && event.key.toLowerCase() === 'a') {
        event.preventDefault();
        this.selectAllNodes();
        return;
      }

      if (event.key === 'Escape') {
        this.clearSelection();
      }
    }

    onKeyUp(event) {
      if (event.key === ' ') {
        this.spacePressed = false;
        this.canvas.classList.remove('pan-mode');
      }
    }

    sleep(ms) {
      return new Promise(resolve => setTimeout(resolve, ms));
    }

    updateStatus(message) {
      if (this.statusEl) {
        this.statusEl.textContent = message;
      }
    }
  }

  const controller = new PlaybookCanvas();

  const api = {
    init() {
      document.addEventListener('DOMContentLoaded', () => {
        controller.init();
        controller.loadPlaybookList();
      });
    },
    onDragStart(event) {
      controller.onDragStart(event);
    },
    togglePlaybook() {
      controller.togglePlaybook();
    },
    save() {
      controller.save();
    },
    run() {
      controller.run();
    },
    confirmRun(mode) {
      controller.confirmRun(mode);
    },
    closeRunModal() {
      controller.closeRunModal();
    },
    deleteAll() {
      controller.deleteAll();
    },
    loadTemplate() {
      controller.loadTemplate();
    },
    loadPlaybook(payload) {
      controller.loadPlaybook(payload);
    },
    serializePlaybook() {
      return controller.serializePlaybook();
    },
    loadPlaybookList() {
      controller.loadPlaybookList();
    },
    showAllHistory() {
      controller.showAllHistory();
    },
    highlightHistoryNodes(runId) {
      controller.highlightHistoryNodes(runId);
    },
    closeLogPanel() {
      controller.closeLogPanel();
    },
    downloadLog() {
      controller.downloadLog();
    }
  };

  return api;
})();

function showToast(msg, type = 'ok') {
  if (window.toast) {
    window.toast(msg, type);
    return;
  }
  const wrap = document.getElementById('toast-wrap');
  if (!wrap) {
    return;
  }
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  wrap.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

window.soarApp.init();
window.downloadLog = function() {
  window.soarApp.downloadLog();
};
window.closeLogPanel = function() {
  window.soarApp.closeLogPanel();
};
