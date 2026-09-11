const $ = (selector) => document.querySelector(selector);
const MODE_STORAGE_KEY = 'home-center.interface-mode';
const HEALTHY_NODE_STATES = new Set(['ready', 'healthy', 'online', 'managed']);

function getSavedMode() {
  try {
    const saved = localStorage.getItem(MODE_STORAGE_KEY);
    return saved === 'full' ? 'full' : 'cozy';
  } catch (_) {
    return 'cozy';
  }
}

function saveMode(mode) {
  try {
    localStorage.setItem(MODE_STORAGE_KEY, mode);
  } catch (_) {
    // Browser-local preference is optional; the interface must still work.
  }
}

function setMode(mode, {persist = true, focus = false} = {}) {
  const normalized = mode === 'full' ? 'full' : 'cozy';
  const cozy = $('#cozy-view');
  const full = $('#full-view');
  const cozyButton = $('#mode-cozy');
  const fullButton = $('#mode-full');

  cozy.hidden = normalized !== 'cozy';
  full.hidden = normalized !== 'full';
  cozyButton.setAttribute('aria-selected', String(normalized === 'cozy'));
  fullButton.setAttribute('aria-selected', String(normalized === 'full'));
  cozyButton.classList.toggle('active', normalized === 'cozy');
  fullButton.classList.toggle('active', normalized === 'full');
  cozyButton.tabIndex = normalized === 'cozy' ? 0 : -1;
  fullButton.tabIndex = normalized === 'full' ? 0 : -1;
  document.documentElement.dataset.interfaceMode = normalized;

  if (persist) saveMode(normalized);
  if (focus) (normalized === 'cozy' ? cozyButton : fullButton).focus();
}

function card(node) {
  const el = document.createElement('article');
  el.className = 'node-card';

  const name = document.createElement('strong');
  name.textContent = node.name || node.hostname || node.node_id || node.id || 'Узел';

  const meta = document.createElement('small');
  const role = node.role || 'managed';
  const state = node.status || node.state || 'unknown';
  const address = node.address || node.management_address || 'адрес определяется при подключении';
  meta.textContent = `${role} · ${state} · ${address}`;

  el.append(name, meta);
  return el;
}

function renderNodes(nodes) {
  const root = $('#nodes');
  root.replaceChildren();
  if (!Array.isArray(nodes) || nodes.length === 0) {
    root.textContent = 'Узлы ещё не обнаружены или не подключены.';
    return;
  }
  nodes.forEach((node) => root.append(card(node)));
}

function renderCapabilities(values) {
  const root = $('#capabilities');
  root.replaceChildren();
  if (!Array.isArray(values) || values.length === 0) {
    root.textContent = 'Данные появятся после discovery/enrollment.';
    return;
  }
  values.forEach((value) => {
    const item = document.createElement('span');
    item.className = 'capability-pill';
    item.textContent = String(value);
    root.append(item);
  });
}

function classifyNode(node) {
  const raw = String(node.status || node.state || '').trim().toLowerCase();
  if (!raw) return 'unknown';
  return HEALTHY_NODE_STATES.has(raw) ? 'healthy' : raw;
}

function renderCozy(data) {
  const nodes = Array.isArray(data.nodes) ? data.nodes : [];
  const capabilities = Array.isArray(data.capabilities) ? data.capabilities : [];
  const attentionNodes = nodes.filter((node) => classifyNode(node) !== 'healthy');

  $('#cozy-nodes').textContent = nodes.length ? String(nodes.length) : 'Пока нет';
  $('#cozy-capabilities').textContent = capabilities.length ? String(capabilities.length) : 'Пока нет';

  const state = $('#cozy-state');
  if (!nodes.length) {
    $('#cozy-health').textContent = 'Нужна первичная настройка';
    $('#cozy-health-copy').textContent = 'Подключите первый сервер — Home Center заполнит состояние дома автоматически.';
    state.textContent = 'Настройка';
    state.className = 'state-pill neutral';
    return;
  }

  if (attentionNodes.length > 0) {
    $('#cozy-health').textContent = 'Есть что проверить';
    $('#cozy-health-copy').textContent = `${attentionNodes.length} узл. не подтверждены как здоровые. Подробности доступны в полном режиме.`;
    state.textContent = 'Требует внимания';
    state.className = 'state-pill warn';
    return;
  }

  $('#cozy-health').textContent = 'Дома всё в порядке';
  $('#cozy-health-copy').textContent = 'Все обнаруженные серверы подтверждены как доступные, Home Center получает актуальное состояние.';
  state.textContent = 'Всё хорошо';
  state.className = 'state-pill good';
}

function renderState(data) {
  renderNodes(data.nodes || []);
  renderCapabilities(data.capabilities || []);
  renderCozy(data);
  if (data.version) $('#version').textContent = String(data.version);
}

function renderUnavailable() {
  renderNodes([]);
  renderCapabilities([]);
  $('#cozy-health').textContent = 'Home Center недоступен';
  $('#cozy-health-copy').textContent = 'Не удалось получить состояние. Проверьте соединение или откройте полный режим для диагностики.';
  $('#cozy-nodes').textContent = '—';
  $('#cozy-capabilities').textContent = '—';
  const state = $('#cozy-state');
  state.textContent = 'Нет связи';
  state.className = 'state-pill warn';
}

async function loadState() {
  try {
    const response = await fetch('/api/v1/infrastructure', {
      headers: {'Accept': 'application/json'},
      cache: 'no-store',
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    renderState(data);
  } catch (_) {
    renderUnavailable();
  }
}

const modeButtons = Array.from(document.querySelectorAll('[data-mode]'));
modeButtons.forEach((button) => {
  button.addEventListener('click', () => setMode(button.dataset.mode));
  button.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    event.preventDefault();
    const next = button.dataset.mode === 'cozy' ? 'full' : 'cozy';
    setMode(next, {focus: true});
  });
});

$('#refresh-button').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await loadState();
  } finally {
    button.disabled = false;
  }
});

setMode(getSavedMode(), {persist: false});
loadState();
