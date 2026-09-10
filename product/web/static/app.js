const $ = (selector) => document.querySelector(selector);
const MODE_STORAGE_KEY = 'home-center.interface-mode';

function getSavedMode() {
  try {
    const saved = localStorage.getItem(MODE_STORAGE_KEY);
    return saved === 'full' ? 'full' : 'cozy';
  } catch (_) {
    return 'cozy';
  }
}

function saveMode(mode) {
  try { localStorage.setItem(MODE_STORAGE_KEY, mode); } catch (_) {}
}

function setMode(mode, {persist = true} = {}) {
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
  document.documentElement.dataset.interfaceMode = normalized;
  if (persist) saveMode(normalized);
}

function card(node) {
  const el = document.createElement('article');
  el.className = 'node-card';
  const name = document.createElement('strong');
  name.textContent = node.name || node.hostname || node.node_id || node.id || 'Узел';
  const meta = document.createElement('small');
  const role = node.role || node.state || 'managed';
  const address = node.address || node.management_address || 'адрес определяется при подключении';
  meta.textContent = `${role} · ${address}`;
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
    item.textContent = value;
    root.append(item);
  });
}

function renderCozy(data) {
  const nodes = Array.isArray(data.nodes) ? data.nodes : [];
  const capabilities = Array.isArray(data.capabilities) ? data.capabilities : [];
  const unavailable = nodes.filter((node) => {
    const state = String(node.status || node.state || '').toLowerCase();
    return state && !['ready', 'healthy', 'online', 'managed'].includes(state);
  }).length;

  $('#cozy-nodes').textContent = nodes.length ? `${nodes.length}` : 'Пока нет';
  $('#cozy-capabilities').textContent = capabilities.length ? `${capabilities.length}` : 'Пока нет';

  const state = $('#cozy-state');
  if (!nodes.length) {
    $('#cozy-health').textContent = 'Нужна первичная настройка';
    $('#cozy-health-copy').textContent = 'Подключите первый сервер — Home Center заполнит состояние дома автоматически.';
    state.textContent = 'Настройка';
    state.className = 'state-pill neutral';
    return;
  }
  if (unavailable > 0) {
    $('#cozy-health').textContent = 'Есть что проверить';
    $('#cozy-health-copy').textContent = `${unavailable} узл. требуют внимания. Подробности доступны в полном режиме.`;
    state.textContent = 'Требует внимания';
    state.className = 'state-pill warn';
    return;
  }
  $('#cozy-health').textContent = 'Дома всё в порядке';
  $('#cozy-health-copy').textContent = 'Подключённые серверы отвечают, Home Center получает актуальное состояние.';
  state.textContent = 'Всё хорошо';
  state.className = 'state-pill good';
}

function renderState(data) {
  renderNodes(data.nodes || []);
  renderCapabilities(data.capabilities || []);
  renderCozy(data);
  if (data.version) $('#version').textContent = data.version;
}

async function loadState() {
  try {
    const response = await fetch('/api/v1/infrastructure', {headers: {'Accept': 'application/json'}});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    renderState(data);
  } catch (_) {
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
}

document.querySelectorAll('[data-mode]').forEach((button) => {
  button.addEventListener('click', () => setMode(button.dataset.mode));
});

$('#refresh-button').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try { await loadState(); } finally { button.disabled = false; }
});

setMode(getSavedMode(), {persist: false});
loadState();
