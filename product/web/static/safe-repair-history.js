(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  const HISTORY_ENDPOINT = '/api/v1/household/safe-repair/history?limit=25';
  const HISTORY_RESPONSE_SCHEMA = 'home-center.safe-auto-repair-history-response.v1';
  const SHA256 = /^[0-9a-f]{64}$/;

  const STATUS = Object.freeze({
    blocked: {label: 'Нужна помощь', kind: 'warn'},
    suggested: {label: 'Можно исправить', kind: 'neutral'},
    queued: {label: 'Подготовлено', kind: 'neutral'},
    'in-progress': {label: 'Исправляется', kind: 'neutral'},
    verifying: {label: 'Проверяем', kind: 'neutral'},
    fixed: {label: 'Исправлено', kind: 'good'},
    failed: {label: 'Не исправлено', kind: 'warn'},
    'needs-review': {label: 'Нужна проверка', kind: 'warn'},
  });

  function responseAuthorityClosed(data) {
    return data?.mutation_authorized === false
      && data?.execution_authorized === false
      && data?.provider_execution_authorized === false
      && data?.infrastructure_mutation_authorized === false
      && data?.external_publication_authorized === false;
  }

  function itemAuthorityClosed(item) {
    return item?.execution_authorized === false
      && item?.provider_execution_authorized === false
      && item?.infrastructure_mutation_authorized === false
      && item?.external_publication_authorized === false;
  }

  function verifiedEvidence(item) {
    return item?.repair_verified === true
      && SHA256.test(String(item?.post_condition_evidence_sha256 || ''));
  }

  function normalizedStatus(item) {
    const raw = String(item?.status || '');
    if (!STATUS[raw] || !itemAuthorityClosed(item)) return 'needs-review';
    if (raw === 'fixed') return verifiedEvidence(item) ? 'fixed' : 'needs-review';
    if (item?.repair_verified === true || item?.post_condition_evidence_sha256 != null) {
      return 'needs-review';
    }
    return raw;
  }

  function safeMessage(item, status) {
    if (status !== String(item?.status || '')) {
      return 'Результат не подтверждён достаточными доказательствами. Home Center не считает исправление завершённым.';
    }
    const message = String(item?.cozy_message || '').trim();
    return message || 'Состояние исправления зафиксировано Home Center.';
  }

  function formatObservedAt(value) {
    if (!Number.isInteger(value) || value < 0) return 'время не указано';
    try {
      return new Date(value * 1000).toLocaleString('ru-RU');
    } catch (_) {
      return 'время не указано';
    }
  }

  function cozyRoot() {
    const panel = $('#cozy-home');
    if (!panel) return null;
    let root = $('#cozy-safe-repair-history');
    if (root) return root;

    root = document.createElement('section');
    root.id = 'cozy-safe-repair-history';
    root.className = 'cozy-block';
    root.hidden = true;

    const heading = document.createElement('div');
    heading.className = 'section-heading cozy-section-heading';
    const copy = document.createElement('div');
    const eyebrow = document.createElement('span');
    eyebrow.className = 'eyebrow';
    eyebrow.textContent = 'Безопасные исправления';
    const title = document.createElement('h2');
    title.textContent = 'Что Home Center исправлял';
    const description = document.createElement('p');
    description.textContent = '«Исправлено» показывается только после отдельной проверки результата.';
    copy.append(eyebrow, title, description);
    heading.append(copy);

    const list = document.createElement('div');
    list.id = 'cozy-safe-repair-history-list';
    list.className = 'attention-list';
    list.setAttribute('aria-live', 'polite');
    root.append(heading, list);
    panel.append(root);
    return root;
  }

  function fullRoot() {
    const panel = $('#full-view');
    if (!panel) return null;
    let root = $('#full-safe-repair-history');
    if (root) return root;

    root = document.createElement('section');
    root.id = 'full-safe-repair-history';
    root.className = 'section-block';
    root.hidden = true;

    const heading = document.createElement('div');
    heading.className = 'section-heading';
    const title = document.createElement('h2');
    title.textContent = 'История безопасных исправлений';
    const copy = document.createElement('p');
    copy.textContent = 'Read-only evidence: рекомендация, Job и результат post-condition проверки. Запуск и повтор из этого экрана недоступны.';
    heading.append(title, copy);

    const list = document.createElement('div');
    list.id = 'full-safe-repair-history-list';
    list.className = 'capability-list';
    list.setAttribute('aria-live', 'polite');
    root.append(heading, list);

    const dashboardMessage = $('#dashboard-message');
    panel.insertBefore(root, dashboardMessage || null);
    return root;
  }

  function cozyCard(item) {
    const status = normalizedStatus(item);
    const meta = STATUS[status];
    const card = document.createElement('article');
    card.className = `attention-item ${meta.kind}`;

    const dot = document.createElement('span');
    dot.className = 'attention-dot';
    dot.setAttribute('aria-hidden', 'true');
    const body = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = meta.label;
    const copy = document.createElement('p');
    copy.textContent = safeMessage(item, status);
    const detail = document.createElement('small');
    detail.textContent = `${String(item?.resource_id || 'ресурс')} · ${formatObservedAt(item?.recorded_at_epoch)}`;
    body.append(title, copy, detail);
    card.append(dot, body);
    return card;
  }

  function fullCard(item) {
    const status = normalizedStatus(item);
    const meta = STATUS[status];
    const card = document.createElement('article');
    card.className = 'capability-item';

    const title = document.createElement('strong');
    title.textContent = `${meta.label} · ${String(item?.resource_id || 'unknown-resource')}`;
    const state = document.createElement('p');
    state.textContent = `status=${status}; action=${String(item?.action || 'unknown')}; risk=${String(item?.risk || 'unknown')}; generation=${String(item?.resource_generation ?? '—')}`;
    const ids = document.createElement('p');
    ids.textContent = `recommendation=${String(item?.recommendation_id || '—')}; job=${String(item?.job_id || '—')}`;
    const time = document.createElement('p');
    time.textContent = `recorded=${formatObservedAt(item?.recorded_at_epoch)}; job_updated=${formatObservedAt(item?.job_updated_at_epoch)}`;
    card.append(title, state, ids, time);

    if (status === 'fixed' && verifiedEvidence(item)) {
      const evidence = document.createElement('p');
      evidence.textContent = `post-condition evidence sha256=${String(item.post_condition_evidence_sha256)}`;
      card.append(evidence);
    } else if (String(item?.status || '') === 'fixed') {
      const warning = document.createElement('p');
      warning.textContent = 'Защитная проверка UI отклонила неподтверждённый статус fixed.';
      card.append(warning);
    }
    return card;
  }

  function emptyCozyCard() {
    const card = document.createElement('article');
    card.className = 'attention-item good';
    const dot = document.createElement('span');
    dot.className = 'attention-dot';
    dot.setAttribute('aria-hidden', 'true');
    const body = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = 'История пока пуста';
    const copy = document.createElement('p');
    copy.textContent = 'Home Center ещё не зафиксировал рекомендаций или безопасных исправлений для этого дома.';
    body.append(title, copy);
    card.append(dot, body);
    return card;
  }

  function unavailableCard(message) {
    const card = document.createElement('article');
    card.className = 'attention-item warn';
    const dot = document.createElement('span');
    dot.className = 'attention-dot';
    dot.setAttribute('aria-hidden', 'true');
    const body = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = 'История временно недоступна';
    const copy = document.createElement('p');
    copy.textContent = message;
    body.append(title, copy);
    card.append(dot, body);
    return card;
  }

  function clearAndHide() {
    const cozy = cozyRoot();
    const full = fullRoot();
    $('#cozy-safe-repair-history-list')?.replaceChildren();
    $('#full-safe-repair-history-list')?.replaceChildren();
    if (cozy) cozy.hidden = true;
    if (full) full.hidden = true;
  }

  async function fetchHistory() {
    const response = await fetch(HISTORY_ENDPOINT, {
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

  async function refresh() {
    const workspace = $('#workspace-view');
    if (!workspace || workspace.hidden) {
      clearAndHide();
      return;
    }
    const cozy = cozyRoot();
    const full = fullRoot();
    const cozyList = $('#cozy-safe-repair-history-list');
    const fullList = $('#full-safe-repair-history-list');
    if (!cozy || !full || !cozyList || !fullList) return;

    try {
      const {response, data} = await fetchHistory();
      if (response.status === 401 || response.status === 403 || response.status === 404) {
        clearAndHide();
        return;
      }
      cozyList.replaceChildren();
      fullList.replaceChildren();

      if (!response.ok) {
        cozyList.append(unavailableCard('Home Center не смог прочитать подтверждённую историю. Повторите позже.'));
        cozy.hidden = false;
        full.hidden = true;
        return;
      }
      if (data?.schema !== HISTORY_RESPONSE_SCHEMA || !Array.isArray(data?.items) || !responseAuthorityClosed(data)) {
        cozyList.append(unavailableCard('Ответ не прошёл проверку безопасности и не будет отображён как история исправлений.'));
        cozy.hidden = false;
        full.hidden = true;
        return;
      }

      const items = data.items.slice(0, 25);
      if (!items.length) {
        cozyList.append(emptyCozyCard());
      } else {
        items.forEach((item) => {
          cozyList.append(cozyCard(item));
          fullList.append(fullCard(item));
        });
      }
      cozy.hidden = false;
      full.hidden = items.length === 0;
    } catch (_) {
      cozyList.replaceChildren(unavailableCard('Не удалось связаться с Home Center.'));
      fullList.replaceChildren();
      cozy.hidden = false;
      full.hidden = true;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    cozyRoot();
    fullRoot();
    const workspace = $('#workspace-view');
    if (workspace) {
      const observer = new MutationObserver(() => {
        if (workspace.hidden) clearAndHide();
        else void refresh();
      });
      observer.observe(workspace, {attributes: true, attributeFilter: ['hidden']});
    }
    $('#cozy-tab-home')?.addEventListener('click', () => { void refresh(); });
    $('#mode-full')?.addEventListener('click', () => { void refresh(); });
    $('#refresh-button')?.addEventListener('click', () => { void refresh(); });
    if (workspace && !workspace.hidden) void refresh();
  });
})();
