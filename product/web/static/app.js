const $ = (selector) => document.querySelector(selector);
const MODE_STORAGE_KEY = 'home-center.interface-mode';
const SECTION_STORAGE_KEY = 'home-center.cozy-section';
const VALID_SECTIONS = ['home', 'family', 'house'];
const HEALTHY_NODE_STATES = new Set(['ready', 'healthy', 'online', 'managed', 'active']);

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
    return VALID_SECTIONS.includes(saved) ? saved : 'home';
  } catch (_) {
    return 'home';
  }
}

function persist(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch (_) {
    // Browser-local preferences are optional; the interface must still work.
  }
}

function setMode(mode, {persistChoice = true, focus = false} = {}) {
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

  if (persistChoice) persist(MODE_STORAGE_KEY, normalized);
  if (focus) (normalized === 'cozy' ? cozyButton : fullButton).focus();
}

function setCozySection(section, {persistChoice = true, focus = false} = {}) {
  const normalized = VALID_SECTIONS.includes(section) ? section : 'home';
  document.querySelectorAll('[data-cozy-section]').forEach((button) => {
    const active = button.dataset.cozySection === normalized;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
    if (active && focus) button.focus();
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
  name.textContent = String(node.name || node.hostname || node.node_id || node.id || 'Узел');
  const meta = document.createElement('small');
  const role = String(node.role || 'managed');
  const state = String(node.status || node.state || 'unknown');
  const address = String(node.address || node.management_address || 'адрес определяется при подключении');
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
    item.textContent = String(value);
    root.append(item);
  });
}

function classifyNode(node) {
  const raw = String(node.status || node.state || '').trim().toLowerCase();
  if (!raw) return 'unknown';
  return HEALTHY_NODE_STATES.has(raw) ? 'healthy' : raw;
}

function attentionItem(title, copy, kind = 'neutral') {
  const item = document.createElement('article');
  item.className = `attention-item ${kind}`;
  const dot = document.createElement('span');
  dot.className = 'attention-dot';
  dot.setAttribute('aria-hidden', 'true');
  const body = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = String(title);
  const text = document.createElement('p');
  text.textContent = String(copy);
  body.append(strong, text);
  item.append(dot, body);
  return item;
}

function renderAttention(nodes, attentionNodes) {
  const root = $('#cozy-attention');
  root.replaceChildren();
  if (!nodes.length) {
    root.append(attentionItem('Подключите сервер', 'После подключения Home Center автоматически покажет состояние дома и доступные возможности.'));
    return;
  }
  if (attentionNodes.length) {
    attentionNodes.slice(0, 3).forEach((node) => {
      const name = node.name || node.hostname || node.node_id || node.id || 'Сервер';
      root.append(attentionItem(name, 'Сервер не подтверждён как здоровый. Технические подробности доступны в полном интерфейсе.', 'warn'));
    });
    return;
  }
  root.append(attentionItem('Ничего срочного', 'Home Center не видит проблем, требующих немедленного действия.', 'good'));
}

function renderHomeSummary(data) {
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
  } else if (attentionNodes.length) {
    $('#cozy-health').textContent = 'Есть что проверить';
    $('#cozy-health-copy').textContent = `${attentionNodes.length} узл. не подтверждены как здоровые. Подробности доступны в полном режиме.`;
    state.textContent = 'Требует внимания';
    state.className = 'state-pill warn';
  } else {
    $('#cozy-health').textContent = 'Дома всё в порядке';
    $('#cozy-health-copy').textContent = 'Все обнаруженные серверы подтверждены как доступные, Home Center получает актуальное состояние.';
    state.textContent = 'Всё хорошо';
    state.className = 'state-pill good';
  }

  renderAttention(nodes, attentionNodes);
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
    name.textContent = String(member.name || 'Член семьи');
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
  if (data.version) $('#version').textContent = String(data.version);
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
    const response = await fetch('/api/v1/infrastructure', {
      headers: {'Accept': 'application/json'},
      cache: 'no-store',
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderState(await response.json());
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

const sectionButtons = Array.from(document.querySelectorAll('[data-cozy-section]'));
sectionButtons.forEach((button) => {
  button.addEventListener('click', () => setCozySection(button.dataset.cozySection));
  button.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    event.preventDefault();
    const current = VALID_SECTIONS.indexOf(button.dataset.cozySection);
    const delta = event.key === 'ArrowRight' ? 1 : -1;
    const next = VALID_SECTIONS[(current + delta + VALID_SECTIONS.length) % VALID_SECTIONS.length];
    setCozySection(next, {focus: true});
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

setMode(getSavedMode(), {persistChoice: false});
setCozySection(getSavedSection(), {persistChoice: false});
loadState();
