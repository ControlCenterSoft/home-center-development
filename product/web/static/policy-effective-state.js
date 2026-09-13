(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  const POLICY_ENDPOINT = '/api/v1/household/policy/effective-state';
  const PARENTAL_ENDPOINT = '/api/v1/household/parental-internet/desired';
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

  function parentalCozy(wrapper) {
    if (
      !wrapper ||
      wrapper.schema !== 'home-center.parental-internet-policy-desired-read.v1' ||
      wrapper.state !== 'present' ||
      !wrapper.value ||
      typeof wrapper.value !== 'object'
    ) return null;
    return wrapper.value;
  }

  function parentalFull(wrapper) {
    if (
      !wrapper ||
      wrapper.schema !== 'home-center.parental-internet-policy-desired-read.v1' ||
      wrapper.state !== 'present' ||
      !wrapper.value ||
      typeof wrapper.value !== 'object' ||
      !wrapper.value.policy ||
      typeof wrapper.value.policy !== 'object'
    ) return null;
    return wrapper.value;
  }

  function appendParentalCozy(body, wrapper) {
    const value = parentalCozy(wrapper);
    if (!value) return;
    const heading = document.createElement('p');
    heading.textContent = `Интернет: ${String(value.status || 'правила сохранены')}`;
    const limits = document.createElement('p');
    const daily = value.daily_quota_minutes == null ? 'без дневного лимита' : `${value.daily_quota_minutes} мин/день`;
    const weekly = value.weekly_quota_minutes == null ? 'без недельного лимита' : `${value.weekly_quota_minutes} мин/неделю`;
    const session = value.continuous_session_minutes == null ? 'без лимита сессии' : `${value.continuous_session_minutes} мин подряд`;
    limits.textContent = `${daily} · ${weekly} · ${session}`;
    const safety = document.createElement('p');
    safety.textContent = value.enforcement_verified === true
      ? 'Фактическое применение подтверждено.'
      : 'Правила сохранены, но фактическое применение ещё не подтверждено.';
    body.append(heading, limits, safety);
  }

  function appendParentalFull(card, wrapper) {
    const value = parentalFull(wrapper);
    if (!value) return;
    const policy = value.policy;
    const heading = document.createElement('p');
    heading.textContent = `parental-internet generation=${value.generation}; reconciliation_required=${value.reconciliation_required === true ? 'true' : 'false'}`;
    const source = document.createElement('p');
    source.textContent = `rule-source=${String(policy.rule_source_id || '—')}@${String(policy.rule_source_version || '—')}`;
    const limits = document.createElement('p');
    limits.textContent = `daily=${String(policy.daily_quota_minutes ?? 'none')}; weekly=${String(policy.weekly_quota_minutes ?? 'none')}; continuous=${String(policy.continuous_session_minutes ?? 'none')}; break=${String(policy.break_minutes ?? 0)}`;
    const rules = document.createElement('p');
    rules.textContent = `domains allow=${Array.isArray(policy.allow_domains) ? policy.allow_domains.length : 0} deny=${Array.isArray(policy.deny_domains) ? policy.deny_domains.length : 0}; categories allow=${Array.isArray(policy.allow_categories) ? policy.allow_categories.length : 0} deny=${Array.isArray(policy.deny_categories) ? policy.deny_categories.length : 0}; schedule=${Array.isArray(policy.schedule) ? policy.schedule.length : 0}`;
    const authority = document.createElement('p');
    authority.textContent = 'provider_execution_authorized=false; external_publication_authorized=false';
    card.append(heading, source, limits, rules, authority);
  }

  function cozyCard(member, state, parental) {
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
    appendParentalCozy(body, parental);
    card.append(body);
    return card;
  }

  function fullCard(member, state, parental) {
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
    appendParentalFull(card, parental);
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

  async function parental(member, view) {
    if (String(member?.role || '').toLowerCase() !== 'child') return null;
    const params = new URLSearchParams({
      member_id: String(member.member_id || ''),
      view,
    });
    const result = await json(`${PARENTAL_ENDPOINT}?${params.toString()}`);
    if (!result.response.ok) return null;
    return result.data;
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
      const [result, parentalCozyResult, parentalFullResult] = await Promise.all([
        json(`${POLICY_ENDPOINT}?${params.toString()}`),
        parental(member, 'cozy'),
        parental(member, 'full'),
      ]);
      return {member, result, parentalCozyResult, parentalFullResult};
    }));

    cozyList.replaceChildren();
    fullList.replaceChildren();
    let visible = 0;
    results.forEach(({member, result, parentalCozyResult, parentalFullResult}) => {
      if (result.response.ok && result.data?.schema === 'home-center.household-policy-effective-state.v1') {
        cozyList.append(cozyCard(member, result.data, parentalCozyResult));
        fullList.append(fullCard(member, result.data, parentalFullResult));
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
