const $ = (selector) => document.querySelector(selector);
const MODE_STORAGE_KEY = 'home-center.interface-mode';
const SECTION_STORAGE_KEY = 'home-center.cozy-section';
const VALID_SECTIONS = new Set(['home', 'family', 'house']);

const HOME_SERVICE_CATALOG = [
  {id: 'internet', title: 'Интернет', description: 'Подключение, DNS, VPN и доступ в сеть.', keywords: ['internet', 'network', 'dns', 'vpn', 'wireguard']},
  {id: 'smart-home', title: 'Умный дом', description: 'Домашние устройства, сценарии и автоматизация.', keywords: ['smart', 'zigbee', 'yandex', 'home-assistant', 'iot']},
  {id: 'media', title: 'Фильмы и музыка', description: 'Домашняя медиатека и потоковые сервисы.', keywords: ['media', 'torr', 'movie', 'music', 'stream']},
  {id: 'games', title: 'Игры', description: 'Игровые серверы и домашние игровые сервисы.', keywords: ['game', 'minecraft']},
  {id: 'files', title: 'Файлы', description: 'Общие файлы, домашние каталоги и хранилище.', keywords: ['file', 'smb', 'share', 'storage', 'profile']},
  {id: 'server', title: 'Сервер', description: 'Состояние серверов Home Center.', keywords: ['node', 'server', 'compute']},
  {id: 'backups', title: 'Резервные копии', description: 'Защита данных и возможность восстановления.', keywords: ['backup', 'restore', 'recovery']},
];

function getSavedMode() {
  try {
    const saved = localStorage.getItem(MODE_STORAGE_KEY);
    return saved === 'full' ? 'full' : 'cozy';
  } catch (_) {
    return 'cozy';
  }
}

function getSavedSection() {
  try {
    const saved = localStorage.getItem(SECTION_STORAGE_KEY);
    return VALID_SECTIONS.has(saved) ? saved : 'home';
  } catch (_) {
    return 'home';
  }
}

function persist(key, value) {
  try { localStorage.setItem(key, value); } catch (_) {}
}

function setMode(mode, {persistChoice = true} = {}) {
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
  if (persistChoice) persist(MODE_STORAGE_KEY, normalized);
}

function setCozySection(section, {persistChoice = true} = {}) {
  const normalized = VALID_SECTIONS.has(section) ? section : 'home';
  document.querySelectorAll('[data-cozy-section]').forEach((button) => {
    const active = button.dataset.cozySection === normalized;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll('[data-cozy-panel]').forEach((panel) => {
    panel.hidden = panel.dataset.cozyPanel !== normalized;
  });
  if (persistChoice) persist(SECTION_STORAGE_KEY, normalized);
}

function fullNodeCard(node) {
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
  nodes.forEach((node) => root.append(fullNodeCard(node)));
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

function normalizedNodeState(node) {
  return String(node.status || node.state || '').toLowerCase();
}

function nodeIsUnavailable(node) {
  const state = normalizedNodeState(node);
  return Boolean(state) && !['ready', 'healthy', 'online', 'managed', 'active'].includes(state);
}

function renderHomeSummary(data) {
  const nodes = Array.isArray(data.nodes) ? data.nodes : [];
  const capabilities = Array.isArray(data.capabilities) ? data.capabilities : [];
  const unavailable = nodes.filter(nodeIsUnavailable);

  $('#cozy-nodes').textContent = nodes.length ? `${nodes.length}` : 'Пока нет';
  $('#cozy-capabilities').textContent = capabilities.length ? `${capabilities.length}` : 'Пока нет';

  const state = $('#cozy-state');
  if (!nodes.length) {
    $('#cozy-health').textContent = 'Нужна первичная настройка';
    $('#cozy-health-copy').textContent = 'Подключите первый сервер — Home Center заполнит состояние дома автоматически.';
    state.textContent = 'Настройка';
    state.className = 'state-pill neutral';
  } else if (unavailable.length) {
    $('#cozy-health').textContent = 'Есть что проверить';
    $('#cozy-health-copy').textContent = `${unavailable.length} узл. требуют внимания. Подробности доступны в полном режиме.`;
    state.textContent = 'Требует внимания';
    state.className = 'state-pill warn';
  } else {
    $('#cozy-health').textContent = 'Дома всё в порядке';
    $('#cozy-health-copy').textContent = 'Подключённые серверы отвечают, Home Center получает актуальное состояние.';
    state.textContent = 'Всё хорошо';
    state.className = 'state-pill good';
  }

  renderAttention(nodes, unavailable);
}

function attentionItem(title, copy, kind = 'neutral') {
  const item = document.createElement('article');
  item.className = `attention-item ${kind}`;
  const dot = document.createElement('span');
  dot.className = 'attention-dot';
  dot.setAttribute('aria-hidden', 'true');
  const body = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = title;
  const text = document.createElement('p');
  text.textContent = copy;
  body.append(strong, text);
  item.append(dot, body);
  return item;
}

function renderAttention(nodes, unavailable) {
  const root = $('#cozy-attention');
  root.replaceChildren();
  if (!nodes.length) {
    root.append(attentionItem('Подключите сервер', 'После подключения Home Center автоматически покажет состояние дома и доступные возможности.'));
    return;
  }
  if (unavailable.length) {
    unavailable.slice(0, 3).forEach((node) => {
      const name = node.name || node.hostname || node.node_id || node.id || 'Сервер';
      root.append(attentionItem(name, 'Сервер требует внимания. Технические подробности доступны в полном интерфейсе.', 'warn'));
    });
    return;
  }
  root.append(attentionItem('Ничего срочного', 'Home Center не видит проблем, требующих немедленного действия.', 'good'));
}

function roleLabel(role) {
  return ({parent: 'Родитель', child: 'Ребёнок', guest: 'Гость'})[role] || 'Член семьи';
}

function renderFamily(data) {
  const root = $('#family-members');
  root.replaceChildren();
  const household = data && typeof data.household === 'object' ? data.household : null;
  const members = Array.isArray(household?.members) ? household.members : [];

  if (!members.length) {
    const empty = document.createElement('article');
    empty.className = 'family-card empty-family-card';
    const title = document.createElement('strong');
    title.textContent = 'Семья пока не настроена';
    const copy = document.createElement('p');
    copy.textContent = 'Экран уже является частью «Уютного» интерфейса. Создание людей и применение RolePreset/PolicyBundle будет подключено через защищённые Household/Intent действия, без ручной настройки низкоуровневых параметров.';
    empty.append(title, copy);
    root.append(empty);
    return;
  }

  members.forEach((member) => {
    const card = document.createElement('article');
    card.className = 'family-card';
    const avatar = document.createElement('span');
    avatar.className = 'family-avatar';
    avatar.textContent = String(member.name || '?').trim().slice(0, 1).toUpperCase() || '?';
    const body = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = member.name || 'Член семьи';
    const meta = document.createElement('p');
    const devices = Array.isArray(member.devices) ? member.devices.length : Number(member.device_count || 0);
    meta.textContent = `${roleLabel(member.role)} · устройств: ${Number.isFinite(devices) ? devices : 0}`;
    body.append(name, meta);
    card.append(avatar, body);
    root.append(card);
  });
}

function capabilityMatches(capabilities, keywords) {
  return capabilities.some((capability) => {
    const normalized = String(capability).toLowerCase();
    return keywords.some((keyword) => normalized.includes(keyword));
  });
}

function renderHomeServices(data) {
  const root = $('#home-services');
  root.replaceChildren();
  const capabilities = Array.isArray(data.capabilities) ? data.capabilities : [];
  const nodes = Array.isArray(data.nodes) ? data.nodes : [];

  HOME_SERVICE_CATALOG.forEach((service) => {
    const available = service.id === 'server' ? nodes.length > 0 : capabilityMatches(capabilities, service.keywords);
    const card = document.createElement('article');
    card.className = 'home-service-card';
    const icon = document.createElement('span');
    icon.className = 'service-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = service.title.slice(0, 1);
    const body = document.createElement('div');
    const titleRow = document.createElement('div');
    titleRow.className = 'service-title-row';
    const title = document.createElement('strong');
    title.textContent = service.title;
    const badge = document.createElement('span');
    badge.className = `service-state ${available ? 'available' : 'pending'}`;
    badge.textContent = available ? 'Доступно' : 'Не подключено';
    titleRow.append(title, badge);
    const copy = document.createElement('p');
    copy.textContent = service.description;
    body.append(titleRow, copy);
    card.append(icon, body);
    root.append(card);
  });
}

function renderState(data) {
  renderNodes(data.nodes || []);
  renderCapabilities(data.capabilities || []);
  renderHomeSummary(data);
  renderFamily(data);
  renderHomeServices(data);
  if (data.version) $('#version').textContent = data.version;
}

function renderUnavailable() {
  renderNodes([]);
  renderCapabilities([]);
  renderFamily({});
  renderHomeServices({});
  $('#cozy-health').textContent = 'Home Center недоступен';
  $('#cozy-health-copy').textContent = 'Не удалось получить состояние. Проверьте соединение или откройте полный режим для диагностики.';
  $('#cozy-nodes').textContent = '—';
  $('#cozy-capabilities').textContent = '—';
  const state = $('#cozy-state');
  state.textContent = 'Нет связи';
  state.className = 'state-pill warn';
  const attention = $('#cozy-attention');
  attention.replaceChildren(attentionItem('Нет связи с Home Center', 'Повторите попытку или откройте полный интерфейс для технической диагностики.', 'warn'));
}

async function loadState() {
  try {
    const response = await fetch('/api/v1/infrastructure', {headers: {'Accept': 'application/json'}});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderState(await response.json());
  } catch (_) {
    renderUnavailable();
  }
}

document.querySelectorAll('[data-mode]').forEach((button) => {
  button.addEventListener('click', () => setMode(button.dataset.mode));
});

document.querySelectorAll('[data-cozy-section]').forEach((button) => {
  button.addEventListener('click', () => setCozySection(button.dataset.cozySection));
});

$('#refresh-button').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try { await loadState(); } finally { button.disabled = false; }
});

setMode(getSavedMode(), {persistChoice: false});
setCozySection(getSavedSection(), {persistChoice: false});
loadState();
