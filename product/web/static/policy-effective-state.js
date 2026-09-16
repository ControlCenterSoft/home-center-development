(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  const POLICY_ENDPOINT = '/api/v1/household/policy/effective-state';
  const HOUSEHOLD_ENDPOINT = '/api/v1/household';
  const SAFE_REPAIR_HISTORY_ENDPOINT = '/api/v1/household/safe-repair/history';
  const SAFE_REPAIR_RESPONSE_SCHEMA = 'home-center.safe-auto-repair-history-response.v1';
  const SAFE_REPAIR_ITEM_SCHEMA = 'home-center.safe-auto-repair-history-projection.v1';
  const SHA256 = /^[0-9a-f]{64}$/;
  let safeRepairHistoryRefreshSequence = 0;

  function stateLabel(value) {
    if (value === 'verified') return ['Правила применены', 'available'];
    if (value === 'pending-reconciliation') return ['Ожидают проверки', 'pending'];
    return ['По роли', 'neutral'];
  }

  function safePolicyRows(policy) {
    if (!policy || typeof policy !== 'object') return [];
    return [
      ['Интернет', String(policy.internet_policy || '—')],
      ['VPN', policy.vpn_allowed === true ? 'разрешён' : 'запрещён'],
      ['Управляемое устройство', policy.managed_device_required === true ? 'обязательно' : 'не обязательно'],
      ['Домашние файлы', policy.home_files_allowed === true ? 'доступны' : 'недоступны'],
      ['Умный дом', policy.smart_home_control_allowed === true ? 'управление разрешено' : 'управление запрещено'],
      ['Администрирование', policy.administration_allowed === true ? 'разрешено' : 'запрещено'],
      ['Внешняя публикация', 'запрещена'],
    ];
  }

  async function json(url) {
    const response = await fetch(url, {
      method: 'GET',
      credentials: 'same-origin',
      headers: {'Accept': 'application/json'},
      cache: 'no-store',
    });
    let data = null;
    try {
      data = await response.json();
    } catch (_) {
      data = null;
    }
    return {response, data};
  }

  function cozyRoot() {
    const family = $('#cozy-family');
    if (!family) return null;
    let root = $('#family-policy-state-card');
    if (root) return root;
    root = document.createElement('section');
    root.id = 'family-policy-state-card';
    root.className = 'setup-card';
    root.hidden = true;

    const heading = document.createElement('div');
    const eyebrow = document.createElement('span');
    eyebrow.className = 'eyebrow';
    eyebrow.textContent = 'Семейные правила';
    const title = document.createElement('h2');
    title.textContent = 'Что сейчас действует';
    const copy = document.createElement('p');
    copy.textContent = 'Home Center показывает «применено» только после отдельной проверки фактического состояния.';
    heading.append(eyebrow, title, copy);

    const list = document.createElement('div');
    list.id = 'family-policy-state-list';
    list.className = 'family-grid';
    list.setAttribute('aria-live', 'polite');
    root.append(heading, list);

    const addPerson = $('#add-person-card');
    family.insertBefore(root, addPerson || null);
    return root;
  }

  function fullRoot() {
    const full = $('#full-view');
    if (!full) return null;
    let root = $('#full-policy-state');
    if (root) return root;
    root = document.createElement('section');
    root.id = 'full-policy-state';
    root.className = 'section-block';
    root.hidden = true;

    const heading = document.createElement('div');
    heading.className = 'section-heading';
    const title = document.createElement('h2');
    title.textContent = 'Семейные политики';
    const copy = document.createElement('p');
    copy.textContent = 'Read-only Desired/Actual State без права изменять инфраструктуру.';
    heading.append(title, copy);
    const list = document.createElement('div');
    list.id = 'full-policy-state-list';
    list.className = 'capability-list';
    list.setAttribute('aria-live', 'polite');
    root.append(heading, list);

    const dashboardMessage = $('#dashboard-message');
    full.insertBefore(root, dashboardMessage || null);
    return root;
  }

  function cozyCard(member, state) {
    const card = document.createElement('article');
    card.className = 'family-card';
    const body = document.createElement('div');
    const titleRow = document.createElement('div');
    titleRow.className = 'service-title-row';
    const name = document.createElement('strong');
    name.textContent = String(member.display_name || 'Член семьи');
    const badge = document.createElement('span');
    const [label, className] = stateLabel(state.state);
    badge.className = `service-state ${className}`;
    badge.textContent = label;
    titleRow.append(name, badge);
    const explanation = document.createElement('p');
    explanation.textContent = String(state.explanation_ru || 'Состояние правил недоступно.');
    body.append(titleRow, explanation);
    card.append(body);
    return card;
  }

  function fullCard(member, state) {
    const card = document.createElement('article');
    card.className = 'capability-item';
    const title = document.createElement('strong');
    title.textContent = `${String(member.display_name || member.member_id)} · generation ${state.desired_generation}`;
    const status = document.createElement('p');
    status.textContent = `state=${state.state}; source=${state.source}; enforcement_verified=${state.enforcement_verified === true ? 'true' : 'false'}`;
    card.append(title, status);
    safePolicyRows(state.technical_policy).forEach(([key, value]) => {
      const row = document.createElement('p');
      row.textContent = `${key}: ${value}`;
      card.append(row);
    });
    if (state.verified_evidence && typeof state.verified_evidence === 'object') {
      const evidence = document.createElement('p');
      evidence.textContent = `evidence: ${String(state.verified_evidence.evidence_id || '—')} · ${String(state.verified_evidence.observed_at || '—')}`;
      card.append(evidence);
    }
    return card;
  }

  function errorCard(member, message) {
    const card = document.createElement('article');
    card.className = 'family-card';
    const body = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = String(member.display_name || 'Член семьи');
    const copy = document.createElement('p');
    copy.textContent = message;
    body.append(name, copy);
    card.append(body);
    return card;
  }

  function safeRepairCozyRoot() {
    const home = $('#cozy-home');
    if (!home) return null;
    let root = $('#cozy-safe-repair-history');
    if (root) return root;
    root = document.createElement('section');
    root.id = 'cozy-safe-repair-history';
    root.className = 'cozy-block';
    root.hidden = true;
    root.setAttribute('aria-busy', 'false');

    const heading = document.createElement('div');
    heading.className = 'section-heading cozy-section-heading';
    const headingText = document.createElement('div');
    const eyebrow = document.createElement('span');
    eyebrow.className = 'eyebrow';
    eyebrow.textContent = 'Безопасные исправления';
    const title = document.createElement('h2');
    title.textContent = 'История исправлений';
    const copy = document.createElement('p');
    copy.textContent = 'Статус «Исправлено» появляется только после подтверждённой проверки результата.';
    headingText.append(eyebrow, title, copy);
    heading.append(headingText);

    const list = document.createElement('div');
    list.id = 'cozy-safe-repair-history-list';
    list.className = 'attention-list';
    list.setAttribute('aria-live', 'polite');
    root.append(heading, list);
    home.append(root);
    return root;
  }

  function safeRepairFullRoot() {
    const full = $('#full-view');
    if (!full) return null;
    let root = $('#full-safe-repair-history');
    if (root) return root;
    root = document.createElement('section');
    root.id = 'full-safe-repair-history';
    root.className = 'section-block';
    root.hidden = true;
    root.setAttribute('aria-busy', 'false');

    const heading = document.createElement('div');
    heading.className = 'section-heading';
    const title = document.createElement('h2');
    title.textContent = 'История безопасных исправлений';
    const copy = document.createElement('p');
    copy.textContent = 'Read-only evidence: интерфейс не запускает и не повторяет исправления.';
    heading.append(title, copy);
    const list = document.createElement('div');
    list.id = 'full-safe-repair-history-list';
    list.className = 'capability-list';
    list.setAttribute('aria-live', 'polite');
    root.append(heading, list);

    const dashboardMessage = $('#dashboard-message');
    full.insertBefore(root, dashboardMessage || null);
    return root;
  }

  function verifiedFixed(item) {
    return item?.schema === SAFE_REPAIR_ITEM_SCHEMA
      && item.status === 'fixed'
      && item.repair_verified === true
      && typeof item.post_condition_evidence_sha256 === 'string'
      && SHA256.test(item.post_condition_evidence_sha256);
  }

  function safeRepairLabel(item) {
    if (verifiedFixed(item)) return ['Исправлено', 'available'];
    const mapping = {
      blocked: ['Нужно вручную', 'pending'],
      suggested: ['Предложено', 'neutral'],
      queued: ['Подготовлено', 'neutral'],
      'in-progress': ['Выполняется', 'pending'],
      verifying: ['Проверяется', 'pending'],
      failed: ['Не исправлено', 'pending'],
      'needs-review': ['Нужна проверка', 'pending'],
    };
    return mapping[item?.status] || ['Статус не подтверждён', 'pending'];
  }

  function safeRepairCozyCard(item) {
    const card = document.createElement('article');
    const fixed = verifiedFixed(item);
    card.className = `attention-item ${fixed ? 'good' : item?.status === 'failed' || item?.status === 'needs-review' ? 'warn' : 'neutral'}`;
    const dot = document.createElement('span');
    dot.className = 'attention-dot';
    dot.setAttribute('aria-hidden', 'true');
    const body = document.createElement('div');
    const title = document.createElement('strong');
    const [label] = safeRepairLabel(item);
    title.textContent = label;
    const copy = document.createElement('p');
    copy.textContent = typeof item?.cozy_message === 'string' && item.cozy_message.trim()
      ? item.cozy_message
      : 'Статус исправления временно недоступен.';
    body.append(title, copy);
    card.append(dot, body);
    return card;
  }

  function safeRepairFullCard(item) {
    const card = document.createElement('article');
    card.className = 'capability-item';
    const titleRow = document.createElement('div');
    titleRow.className = 'service-title-row';
    const title = document.createElement('strong');
    title.textContent = String(item?.resource_id || 'Ресурс');
    const badge = document.createElement('span');
    const [label, className] = safeRepairLabel(item);
    badge.className = `service-state ${className}`;
    badge.textContent = label;
    titleRow.append(title, badge);
    const detail = document.createElement('p');
    detail.textContent = `action=${String(item?.action || '—')}; generation=${String(item?.resource_generation ?? '—')}; verified=${verifiedFixed(item) ? 'true' : 'false'}`;
    card.append(titleRow, detail);
    return card;
  }

  function safeRepairError(list, message) {
    const card = document.createElement('article');
    card.className = 'attention-item warn';
    const dot = document.createElement('span');
    dot.className = 'attention-dot';
    dot.setAttribute('aria-hidden', 'true');
    const body = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = 'История недоступна';
    const copy = document.createElement('p');
    copy.textContent = message;
    body.append(title, copy);
    card.append(dot, body);
    list.append(card);
  }

  async function refreshSafeRepairHistory() {
    const cozy = safeRepairCozyRoot();
    const full = safeRepairFullRoot();
    if (!cozy || !full) return;
    const cozyList = $('#cozy-safe-repair-history-list');
    const fullList = $('#full-safe-repair-history-list');
    if (!cozyList || !fullList) return;

    const refreshSequence = ++safeRepairHistoryRefreshSequence;
    const ownsRefresh = () => refreshSequence === safeRepairHistoryRefreshSequence;
    cozy.setAttribute('aria-busy', 'true');
    full.setAttribute('aria-busy', 'true');

    try {
      let result;
      try {
        result = await json(SAFE_REPAIR_HISTORY_ENDPOINT);
      } catch (_) {
        if (!ownsRefresh()) return;
        cozyList.replaceChildren();
        fullList.replaceChildren();
        safeRepairError(cozyList, 'Не удалось получить подтверждённую историю исправлений.');
        cozy.hidden = false;
        full.hidden = true;
        return;
      }

      if (!ownsRefresh()) return;
      if (result.response.status === 401 || result.response.status === 403 || result.response.status === 404) {
        cozy.hidden = true;
        full.hidden = true;
        cozyList.replaceChildren();
        fullList.replaceChildren();
        return;
      }
      if (!result.response.ok || result.data?.schema !== SAFE_REPAIR_RESPONSE_SCHEMA || !Array.isArray(result.data?.items)) {
        cozyList.replaceChildren();
        fullList.replaceChildren();
        safeRepairError(cozyList, 'Ответ не прошёл безопасную проверку. Статус исправлений не изменён.');
        cozy.hidden = false;
        full.hidden = true;
        return;
      }

      const items = result.data.items.filter((item) => item?.schema === SAFE_REPAIR_ITEM_SCHEMA).slice(0, 20);
      cozyList.replaceChildren();
      fullList.replaceChildren();
      if (!items.length) {
        const empty = document.createElement('article');
        empty.className = 'attention-item neutral';
        const dot = document.createElement('span');
        dot.className = 'attention-dot';
        dot.setAttribute('aria-hidden', 'true');
        const body = document.createElement('div');
        const title = document.createElement('strong');
        title.textContent = 'История пока пуста';
        const copy = document.createElement('p');
        copy.textContent = 'Подтверждённых записей безопасного исправления пока нет.';
        body.append(title, copy);
        empty.append(dot, body);
        cozyList.append(empty);
        cozy.hidden = false;
        full.hidden = true;
        return;
      }

      items.slice(0, 5).forEach((item) => cozyList.append(safeRepairCozyCard(item)));
      items.forEach((item) => fullList.append(safeRepairFullCard(item)));
      cozy.hidden = false;
      full.hidden = false;
    } finally {
      if (ownsRefresh()) {
        cozy.setAttribute('aria-busy', 'false');
        full.setAttribute('aria-busy', 'false');
      }
    }
  }

  async function refresh() {
    const cozy = cozyRoot();
    const full = fullRoot();
    if (!cozy || !full) return;
    const cozyList = $('#family-policy-state-list');
    const fullList = $('#full-policy-state-list');
    if (!cozyList || !fullList) return;

    const household = await json(HOUSEHOLD_ENDPOINT);
    if (!household.response.ok || household.data?.configured !== true) {
      cozy.hidden = true;
      full.hidden = true;
      cozyList.replaceChildren();
      fullList.replaceChildren();
      return;
    }
    const members = Array.isArray(household.data?.snapshot?.household?.members)
      ? household.data.snapshot.household.members.filter((item) => item?.enabled !== false)
      : [];
    if (!members.length) {
      cozy.hidden = true;
      full.hidden = true;
      return;
    }

    const results = await Promise.all(members.map(async (member) => {
      const params = new URLSearchParams({member_id: String(member.member_id || '')});
      return {member, result: await json(`${POLICY_ENDPOINT}?${params.toString()}`)};
    }));

    cozyList.replaceChildren();
    fullList.replaceChildren();
    let visible = 0;
    results.forEach(({member, result}) => {
      if (result.response.ok && result.data?.schema === 'home-center.household-policy-effective-state.v1') {
        cozyList.append(cozyCard(member, result.data));
        fullList.append(fullCard(member, result.data));
        visible += 1;
        return;
      }
      if (result.response.status === 403) return;
      const message = String(result.data?.error?.message || 'Состояние правил временно недоступно.');
      cozyList.append(errorCard(member, message));
      visible += 1;
    });
    cozy.hidden = visible === 0;
    full.hidden = fullList.childElementCount === 0;
  }

  document.addEventListener('DOMContentLoaded', () => {
    cozyRoot();
    fullRoot();
    safeRepairCozyRoot();
    safeRepairFullRoot();
    const homeTab = $('#cozy-tab-home');
    const familyTab = $('#cozy-tab-family');
    const fullMode = $('#mode-full');
    const refreshButton = $('#refresh-button');
    homeTab?.addEventListener('click', () => { void refreshSafeRepairHistory(); });
    familyTab?.addEventListener('click', () => { void refresh(); });
    fullMode?.addEventListener('click', () => {
      void refresh();
      void refreshSafeRepairHistory();
    });
    refreshButton?.addEventListener('click', () => {
      void refresh();
      void refreshSafeRepairHistory();
    });
    window.addEventListener('homecenter:member-change-completed', () => { void refresh(); });
    void refresh();
    void refreshSafeRepairHistory();
  });
})();
