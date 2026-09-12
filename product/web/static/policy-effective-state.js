(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  const POLICY_ENDPOINT = '/api/v1/household/policy/effective-state';
  const HOUSEHOLD_ENDPOINT = '/api/v1/household';

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
    const familyTab = $('#cozy-tab-family');
    const fullMode = $('#mode-full');
    const refreshButton = $('#refresh-button');
    familyTab?.addEventListener('click', () => { void refresh(); });
    fullMode?.addEventListener('click', () => { void refresh(); });
    refreshButton?.addEventListener('click', () => { void refresh(); });
    window.addEventListener('homecenter:member-change-completed', () => { void refresh(); });
    void refresh();
  });
})();
