const $ = (selector) => document.querySelector(selector);
const MODE_STORAGE_KEY = 'home-center.interface-mode';
const SECTION_STORAGE_KEY = 'home-center.cozy-section';
const VALID_SECTIONS = new Set(['home', 'family', 'house']);
let pendingMemberProposal = null;

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
  try { return localStorage.getItem(MODE_STORAGE_KEY) === 'full' ? 'full' : 'cozy'; }
  catch (_) { return 'cozy'; }
}

function getSavedSection() {
  try {
    const saved = localStorage.getItem(SECTION_STORAGE_KEY);
    return VALID_SECTIONS.has(saved) ? saved : 'home';
  } catch (_) { return 'home'; }
}

function persist(key, value) {
  try { localStorage.setItem(key, value); } catch (_) {}
}

function setServiceState(text, kind = 'neutral') {
  const badge = $('#service-state');
  badge.textContent = text;
  badge.className = `status-badge ${kind}`;
}

function setVersion(value) {
  $('#version').textContent = value || 'Home Center';
}

function showTopbarWorkspace(enabled) {
  $('#mode-switch').hidden = !enabled;
  $('#logout-button').hidden = !enabled;
}

function showAppView(selector) {
  for (const id of ['#loading-view', '#login-view', '#password-view', '#workspace-view']) {
    $(id).hidden = id !== selector;
  }
  showTopbarWorkspace(selector === '#workspace-view');
}

function setMode(mode, {persistChoice = true} = {}) {
  const normalized = mode === 'full' ? 'full' : 'cozy';
  $('#cozy-view').hidden = normalized !== 'cozy';
  $('#full-view').hidden = normalized !== 'full';
  document.querySelectorAll('[data-mode]').forEach((button) => {
    const active = button.dataset.mode === normalized;
    button.setAttribute('aria-selected', String(active));
    button.classList.toggle('active', active);
  });
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

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, {...options, headers, credentials: 'same-origin'});
  let data = null;
  if ((response.headers.get('content-type') || '').includes('application/json')) {
    try { data = await response.json(); } catch (_) { data = null; }
  }
  return {response, data};
}

function errorMessage(data, fallback) {
  return data?.error?.message || fallback;
}

async function loadProviders() {
  try {
    const {response, data} = await request('/api/v1/auth/providers');
    if (!response.ok || !Array.isArray(data?.providers)) return;
    const labels = {local: 'Локальный администратор', ad: 'Доменная учётная запись'};
    const enabled = data.providers.filter((item) => item?.enabled === true && labels[item.id]);
    if (!enabled.length) return;
    $('#provider').replaceChildren(...enabled.map((item) => {
      const option = document.createElement('option');
      option.value = item.id;
      option.textContent = labels[item.id];
      return option;
    }));
  } catch (_) {}
}

function fullNodeCard(node) {
  const el = document.createElement('article');
  el.className = 'node-card';
  const name = document.createElement('strong');
  name.textContent = node.name || node.hostname || node.node_id || node.id || 'Узел';
  const meta = document.createElement('small');
  meta.textContent = `${node.role || node.state || 'managed'} · ${node.address || node.management_address || 'адрес определяется при подключении'}`;
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
  } else if (unavailable.length) {
    unavailable.slice(0, 3).forEach((node) => root.append(attentionItem(
      node.name || node.hostname || node.node_id || node.id || 'Сервер',
      'Сервер требует внимания. Технические подробности доступны в полном интерфейсе.',
      'warn',
    )));
  } else {
    root.append(attentionItem('Ничего срочного', 'Home Center не видит проблем, требующих немедленного действия.', 'good'));
  }
}

function renderHomeSummary(data) {
  const nodes = Array.isArray(data?.nodes) ? data.nodes : [];
  const capabilities = Array.isArray(data?.capabilities) ? data.capabilities : [];
  const unavailable = nodes.filter(nodeIsUnavailable);
  $('#cozy-nodes').textContent = nodes.length ? `${nodes.length}` : 'Пока нет';
  $('#cozy-capabilities').textContent = capabilities.length ? `${capabilities.length}` : 'Пока нет';
  const state = $('#cozy-state');
  if (!nodes.length) {
    $('#cozy-health').textContent = 'Нужна первичная настройка';
    $('#cozy-health-copy').textContent = 'Подключите первый сервер — Home Center заполнит состояние дома автоматически.';
    state.textContent = 'Настройка'; state.className = 'state-pill neutral'; setServiceState('Сервис доступен', 'neutral');
  } else if (unavailable.length) {
    $('#cozy-health').textContent = 'Есть что проверить';
    $('#cozy-health-copy').textContent = `${unavailable.length} узл. требуют внимания. Подробности доступны в полном режиме.`;
    state.textContent = 'Требует внимания'; state.className = 'state-pill warn'; setServiceState('Требует внимания', 'warn');
  } else {
    $('#cozy-health').textContent = 'Дома всё в порядке';
    $('#cozy-health-copy').textContent = 'Подключённые серверы отвечают, Home Center получает актуальное состояние.';
    state.textContent = 'Всё хорошо'; state.className = 'state-pill good'; setServiceState('Система в норме', 'good');
  }
  renderAttention(nodes, unavailable);
}

function roleLabel(role) {
  return ({parent: 'Родитель', child: 'Ребёнок', guest: 'Гость'})[role] || 'Член семьи';
}

function clearMemberConfirmation() {
  pendingMemberProposal = null;
  $('#member-confirm-card').hidden = true;
  $('#member-confirm-message').textContent = '';
  $('#member-confirm-copy').textContent = '—';
}

function renderFamily(runtimeState) {
  const root = $('#family-members');
  const configured = runtimeState?.configured === true;
  $('#household-bootstrap-card').hidden = configured;
  $('#add-person-card').hidden = !configured;
  root.replaceChildren();

  const household = configured ? runtimeState?.snapshot?.household : null;
  const members = Array.isArray(household?.members) ? household.members : [];
  const devices = Array.isArray(household?.devices) ? household.devices : [];
  if (!configured) {
    clearMemberConfirmation();
    const empty = document.createElement('article');
    empty.className = 'family-card empty-family-card';
    const title = document.createElement('strong');
    title.textContent = 'Семья ещё не настроена';
    const copy = document.createElement('p');
    copy.textContent = 'Укажите имя первого родителя выше. Home Center сохранит семью и привяжет к ней текущий авторизованный аккаунт.';
    empty.append(title, copy);
    root.append(empty);
    return;
  }

  members.forEach((member) => {
    const card = document.createElement('article');
    card.className = 'family-card';
    const avatar = document.createElement('span');
    avatar.className = 'family-avatar';
    avatar.textContent = String(member.display_name || '?').trim().slice(0, 1).toUpperCase() || '?';
    const body = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = member.display_name || 'Член семьи';
    const meta = document.createElement('p');
    meta.textContent = `${roleLabel(member.role)} · устройств: ${devices.filter((device) => device.member_id === member.member_id).length}`;
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
  const capabilities = Array.isArray(data?.capabilities) ? data.capabilities : [];
  const nodes = Array.isArray(data?.nodes) ? data.nodes : [];
  HOME_SERVICE_CATALOG.forEach((service) => {
    const available = service.id === 'server' ? nodes.length > 0 : capabilityMatches(capabilities, service.keywords);
    const card = document.createElement('article');
    card.className = 'home-service-card';
    const icon = document.createElement('span');
    icon.className = 'service-icon'; icon.setAttribute('aria-hidden', 'true'); icon.textContent = service.title.slice(0, 1);
    const body = document.createElement('div');
    const titleRow = document.createElement('div'); titleRow.className = 'service-title-row';
    const title = document.createElement('strong'); title.textContent = service.title;
    const badge = document.createElement('span'); badge.className = `service-state ${available ? 'available' : 'pending'}`; badge.textContent = available ? 'Доступно' : 'Не подключено';
    titleRow.append(title, badge);
    const copy = document.createElement('p'); copy.textContent = service.description;
    body.append(titleRow, copy); card.append(icon, body); root.append(card);
  });
}

function renderInfrastructure(data) {
  renderNodes(data?.nodes || []); renderCapabilities(data?.capabilities || []); renderHomeSummary(data || {}); renderHomeServices(data || {});
  if (data?.version) setVersion(data.version);
}

function renderInfrastructureUnavailable(message) {
  renderNodes([]); renderCapabilities([]); renderHomeServices({});
  $('#cozy-health').textContent = 'Данные инфраструктуры недоступны';
  $('#cozy-health-copy').textContent = message || 'Не удалось получить состояние. Откройте полный режим для диагностики.';
  $('#cozy-nodes').textContent = '—'; $('#cozy-capabilities').textContent = '—';
  $('#cozy-state').textContent = 'Нет данных'; $('#cozy-state').className = 'state-pill warn';
  $('#cozy-attention').replaceChildren(attentionItem('Нет актуальных данных', 'Повторите обновление или проверьте полный интерфейс.', 'warn'));
  setServiceState('Ошибка данных', 'warn');
}

async function refreshHousehold() {
  const result = await request('/api/v1/household');
  if (result.response.status === 401) { showAppView('#login-view'); return false; }
  if (result.response.status === 403 && result.data?.error?.code === 'password_change_required') { showAppView('#password-view'); return false; }
  if (!result.response.ok || !result.data) return false;
  renderFamily(result.data);
  return true;
}

async function loadWorkspace() {
  $('#dashboard-message').textContent = '';
  const [infraResult, householdResult] = await Promise.allSettled([request('/api/v1/infrastructure'), request('/api/v1/household')]);
  const infra = infraResult.status === 'fulfilled' ? infraResult.value : null;
  const household = householdResult.status === 'fulfilled' ? householdResult.value : null;
  for (const item of [infra, household]) {
    if (item?.response?.status === 401) { showAppView('#login-view'); setServiceState('Нужен вход', 'warn'); return; }
    if (item?.response?.status === 403 && item?.data?.error?.code === 'password_change_required') { showAppView('#password-view'); setServiceState('Смените пароль', 'warn'); return; }
  }
  if (infra?.response?.ok && infra.data) renderInfrastructure(infra.data);
  else renderInfrastructureUnavailable(errorMessage(infra?.data, 'Не удалось получить состояние инфраструктуры.'));
  if (household?.response?.ok && household.data) renderFamily(household.data);
  else {
    renderFamily({configured: false}); $('#household-bootstrap-card').hidden = true;
    $('#family-members').replaceChildren(attentionItem('Семья недоступна', errorMessage(household?.data, 'Состояние семьи временно недоступно.'), 'warn'));
  }
}

async function handleSession(data) {
  if (data?.password_change_required) { showAppView('#password-view'); setServiceState('Смените пароль', 'warn'); $('#current-password').focus(); return; }
  showAppView('#workspace-view'); setMode(getSavedMode(), {persistChoice: false}); setCozySection(getSavedSection(), {persistChoice: false}); setServiceState('Сервис доступен', 'good'); await loadWorkspace();
}

async function checkSession() {
  try {
    const {response, data} = await request('/api/v1/session');
    if (response.ok && data?.authenticated) { await handleSession(data); return; }
    if (response.status !== 401) setServiceState('Сервис доступен', 'neutral');
  } catch (_) { setServiceState('Нет связи', 'bad'); }
  showAppView('#login-view'); $('#password').focus();
}

document.querySelectorAll('[data-mode]').forEach((button) => button.addEventListener('click', () => setMode(button.dataset.mode)));
document.querySelectorAll('[data-cozy-section]').forEach((button) => button.addEventListener('click', () => setCozySection(button.dataset.cozySection)));

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button = event.submitter; const message = $('#login-message'); message.textContent = ''; button.disabled = true;
  try {
    const {response, data} = await request('/api/v1/session', {method: 'POST', body: JSON.stringify({provider: $('#provider').value, username: $('#username').value.trim(), password: $('#password').value})});
    if (!response.ok || !data?.authenticated) { message.textContent = errorMessage(data, 'Не удалось выполнить вход.'); setServiceState('Вход отклонён', 'warn'); return; }
    $('#password').value = ''; await handleSession(data);
  } catch (_) { message.textContent = 'Home Center сейчас недоступен. Проверьте соединение и повторите попытку.'; setServiceState('Нет связи', 'bad'); }
  finally { button.disabled = false; }
});

$('#password-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button = event.submitter; const message = $('#password-message'); const currentPassword = $('#current-password').value; const newPassword = $('#new-password').value; const confirmPassword = $('#confirm-password').value; message.textContent = '';
  if (newPassword !== confirmPassword) { message.textContent = 'Новые пароли не совпадают.'; return; }
  button.disabled = true;
  try {
    const {response, data} = await request('/api/v1/auth/local-admin/password/change', {method: 'POST', body: JSON.stringify({schema: 'home-center.local-admin-password-change.v1', current_password: currentPassword, new_password: newPassword})});
    if (!response.ok) { message.textContent = errorMessage(data, 'Не удалось сменить пароль.'); return; }
    $('#current-password').value = ''; $('#new-password').value = ''; $('#confirm-password').value = ''; await checkSession();
  } catch (_) { message.textContent = 'Не удалось связаться с Home Center.'; }
  finally { button.disabled = false; }
});

$('#household-bootstrap-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button = event.submitter; const message = $('#household-message'); const displayName = $('#parent-display-name').value.trim(); message.textContent = ''; button.disabled = true;
  try {
    const {response, data} = await request('/api/v1/household/bootstrap', {method: 'POST', body: JSON.stringify({schema: 'home-center.household-bootstrap.v1', display_name: displayName})});
    if (response.status === 401) { showAppView('#login-view'); return; }
    if (!response.ok) { message.textContent = errorMessage(data, 'Не удалось настроить семью.'); return; }
    $('#parent-display-name').value = ''; await refreshHousehold(); setCozySection('family');
  } catch (_) { message.textContent = 'Не удалось связаться с Home Center.'; }
  finally { button.disabled = false; }
});

$('#member-plan-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button = event.submitter; const message = $('#member-plan-message'); message.textContent = ''; clearMemberConfirmation(); button.disabled = true;
  try {
    const {response, data} = await request('/api/v1/household/members/plan', {method: 'POST', body: JSON.stringify({schema: 'home-center.household-member-add-plan.v1', display_name: $('#member-display-name').value.trim(), role: $('#member-role').value})});
    if (!response.ok || !data?.proposal_id) { message.textContent = errorMessage(data, 'Не удалось подготовить изменение.'); return; }
    pendingMemberProposal = data;
    $('#member-confirm-copy').textContent = `${data.member.display_name} — ${roleLabel(data.member.role)}. Изменение относится к версии семьи ${data.generation} и будет применено только после подтверждения.`;
    $('#member-confirm-card').hidden = false; $('#member-confirm-button').focus();
  } catch (_) { message.textContent = 'Не удалось связаться с Home Center.'; }
  finally { button.disabled = false; }
});

$('#member-cancel-button').addEventListener('click', () => clearMemberConfirmation());

$('#member-confirm-button').addEventListener('click', async (event) => {
  if (!pendingMemberProposal?.proposal_id) return;
  const button = event.currentTarget; const message = $('#member-confirm-message'); message.textContent = ''; button.disabled = true;
  try {
    const {response, data} = await request('/api/v1/household/members/confirm', {method: 'POST', body: JSON.stringify({schema: 'home-center.household-member-add-confirm.v1', proposal_id: pendingMemberProposal.proposal_id, confirmed: true})});
    if (response.status === 409 && data?.error?.code === 'household_member_change_stale') {
      message.textContent = 'Семья изменилась после подготовки. Ничего не применено — сформируйте план заново.';
      pendingMemberProposal = null; await refreshHousehold(); return;
    }
    if (!response.ok) { message.textContent = errorMessage(data, 'Не удалось применить изменение.'); return; }
    clearMemberConfirmation(); $('#member-display-name').value = ''; $('#member-role').value = 'child'; await refreshHousehold();
    $('#member-plan-message').textContent = data?.outcome === 'already-applied' ? 'Человек уже был добавлен ранее.' : 'Человек добавлен в семью.';
  } catch (_) { message.textContent = 'Не удалось связаться с Home Center.'; }
  finally { button.disabled = false; }
});

$('#logout-button').addEventListener('click', async () => {
  try { await request('/api/v1/session/logout', {method: 'POST'}); } catch (_) {}
  clearMemberConfirmation(); showAppView('#login-view'); setServiceState('Нужен вход', 'neutral'); $('#password').value = ''; $('#password').focus();
});

$('#refresh-button').addEventListener('click', async (event) => { const button = event.currentTarget; button.disabled = true; try { await loadWorkspace(); } finally { button.disabled = false; } });

showAppView('#loading-view');
Promise.allSettled([loadProviders(), checkSession()]);
