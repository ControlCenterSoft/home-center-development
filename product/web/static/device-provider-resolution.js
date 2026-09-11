(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  let confirmedEnrollment = null;
  let resolutionPlan = null;
  let selectionProposal = null;

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (options.body) headers.set('Content-Type', 'application/json');
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

  function safeCandidate(candidate) {
    return typeof candidate?.provider_id === 'string'
      && typeof candidate?.display_name === 'string'
      && Array.isArray(candidate?.supported_platforms)
      && Array.isArray(candidate?.enrollment_modes)
      && candidate?.ready === true
      && candidate?.execution_authorized === false;
  }

  function safePlan(plan) {
    return typeof plan?.plan_id === 'string'
      && plan?.enrollment_proposal_id === confirmedEnrollment?.proposal_id
      && plan?.platform_claim_source === 'user'
      && plan?.platform_verified === false
      && plan?.provider_selection_required === true
      && plan?.selected_provider_id === null
      && plan?.provider_execution_authorized === false
      && plan?.policy_application_authorized === false
      && plan?.managed_state_change_authorized === false
      && plan?.infrastructure_mutation_authorized === false
      && plan?.external_publication_authorized === false
      && Array.isArray(plan?.candidates)
      && plan.candidates.every(safeCandidate);
  }

  function safeSelectionProposal(proposal, providerId) {
    return typeof proposal?.proposal_id === 'string'
      && proposal?.resolution_plan_id === resolutionPlan?.plan_id
      && proposal?.enrollment_proposal_id === confirmedEnrollment?.proposal_id
      && proposal?.catalog_id === resolutionPlan?.catalog_id
      && proposal?.device_id === resolutionPlan?.device_id
      && proposal?.member_id === resolutionPlan?.member_id
      && proposal?.device_platform === resolutionPlan?.device_platform
      && proposal?.platform_claim_source === 'user'
      && proposal?.platform_verified === false
      && proposal?.proposed_provider_id === providerId
      && proposal?.provider_ready === true
      && proposal?.platform_supported === true
      && proposal?.confirmation_required === true
      && proposal?.provider_selected === false
      && proposal?.provider_execution_authorized === false
      && proposal?.credential_access_authorized === false
      && proposal?.enrollment_authorized === false
      && proposal?.policy_application_authorized === false
      && proposal?.managed_state_change_authorized === false
      && proposal?.infrastructure_mutation_authorized === false
      && proposal?.external_publication_authorized === false;
  }

  function safeSelectionReceipt(receipt) {
    return typeof receipt?.proposal_id === 'string'
      && receipt?.proposal_id === selectionProposal?.proposal_id
      && receipt?.resolution_plan_id === selectionProposal?.resolution_plan_id
      && receipt?.enrollment_proposal_id === selectionProposal?.enrollment_proposal_id
      && receipt?.selected_provider_id === selectionProposal?.proposed_provider_id
      && receipt?.catalog_id === selectionProposal?.catalog_id
      && receipt?.provider_selected === true
      && receipt?.provider_execution_authorized === false
      && receipt?.credential_access_authorized === false
      && receipt?.enrollment_authorized === false
      && receipt?.policy_application_authorized === false
      && receipt?.managed_state_change_authorized === false
      && receipt?.infrastructure_mutation_authorized === false
      && receipt?.external_publication_authorized === false;
  }

  function buildUi() {
    const enrollment = $('#device-enrollment-card');
    const family = $('#cozy-family');
    if (!family || $('#device-provider-resolution-card')) return;

    const card = document.createElement('section');
    card.id = 'device-provider-resolution-card';
    card.className = 'setup-card';
    card.hidden = true;
    card.setAttribute('aria-live', 'polite');
    card.innerHTML = `
      <div>
        <span class="eyebrow">Способ управления</span>
        <h2>Найти подходящий способ</h2>
        <p>Укажите тип устройства. Это только ваша подсказка Home Center и пока не считается автоматически проверенной характеристикой устройства.</p>
      </div>
      <form id="device-provider-resolution-form" class="member-form" autocomplete="off">
        <label><span>Тип устройства</span>
          <select id="device-platform" required>
            <option value="android">Android</option>
            <option value="ios">iPhone / iPad</option>
            <option value="windows">Windows</option>
            <option value="linux">Linux</option>
            <option value="other">Другое</option>
          </select>
        </label>
        <button class="primary-button" type="submit">Найти способ управления</button>
      </form>
      <div id="device-provider-candidates" class="family-grid" aria-live="polite"></div>
      <section id="device-provider-selection-confirm" class="confirm-card" hidden>
        <div>
          <span class="eyebrow">Подтверждение выбора</span>
          <h3>Выбрать способ управления?</h3>
          <p id="device-provider-selection-copy">—</p>
        </div>
        <div class="confirm-actions">
          <button id="device-provider-selection-confirm-button" class="primary-button" type="button">Подтвердить выбор</button>
          <button id="device-provider-selection-cancel-button" class="secondary-button" type="button">Отмена</button>
        </div>
      </section>
      <p id="device-provider-resolution-message" class="form-message" role="status"></p>`;

    if (enrollment) enrollment.insertAdjacentElement('afterend', card);
    else family.append(card);
    $('#device-provider-resolution-form').addEventListener('submit', resolveProviders);
    $('#device-provider-selection-confirm-button').addEventListener('click', confirmSelection);
    $('#device-provider-selection-cancel-button').addEventListener('click', cancelSelection);
  }

  function reset() {
    confirmedEnrollment = null;
    resolutionPlan = null;
    selectionProposal = null;
    const card = $('#device-provider-resolution-card');
    if (card) card.hidden = true;
    const candidates = $('#device-provider-candidates');
    if (candidates) candidates.replaceChildren();
    const confirm = $('#device-provider-selection-confirm');
    if (confirm) confirm.hidden = true;
    const message = $('#device-provider-resolution-message');
    if (message) message.textContent = '';
  }

  function cancelSelection() {
    selectionProposal = null;
    $('#device-provider-selection-confirm').hidden = true;
    $('#device-provider-resolution-message').textContent = 'Выбор не изменён. Никаких действий с устройством не выполнено.';
  }

  function renderCandidates(plan) {
    const list = $('#device-provider-candidates');
    list.replaceChildren();
    for (const candidate of plan.candidates) {
      const row = document.createElement('article');
      row.className = 'family-card';
      const body = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = candidate.display_name;
      const meta = document.createElement('p');
      const modes = candidate.enrollment_modes.join(', ');
      meta.textContent = modes ? `Доступен · варианты подключения: ${modes}` : 'Доступен';
      body.append(name, meta);

      const choose = document.createElement('button');
      choose.className = 'secondary-button';
      choose.type = 'button';
      choose.textContent = 'Выбрать';
      choose.dataset.providerId = candidate.provider_id;
      choose.addEventListener('click', () => prepareSelection(candidate));

      row.append(body, choose);
      list.append(row);
    }
  }

  function resultCopy(plan) {
    if (plan.state === 'unavailable') {
      return 'Для этого типа устройства сейчас нет доступного способа управления. Ничего не будет установлено.';
    }
    if (plan.state === 'single-candidate') {
      return 'Найден один доступный способ. Он ещё не выбран. Home Center не выбирает его автоматически — выбор нужно сделать отдельно.';
    }
    if (plan.state === 'choice-required') {
      return 'Найдено несколько способов. Выберите один явно; само подключение всё равно не запускается.';
    }
    return 'Результат не распознан и не будет использован.';
  }

  async function resolveProviders(event) {
    event.preventDefault();
    if (!confirmedEnrollment?.proposal_id) return;
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    const message = $('#device-provider-resolution-message');
    const candidates = $('#device-provider-candidates');
    button.disabled = true;
    message.textContent = '';
    candidates.replaceChildren();
    $('#device-provider-selection-confirm').hidden = true;
    selectionProposal = null;
    try {
      const {response, data} = await request('/api/v1/household/devices/enrollment/provider-resolution/plan', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.device-management-provider-resolution-request.v1',
          enrollment_proposal_id: confirmedEnrollment.proposal_id,
          device_platform: $('#device-platform').value,
        }),
      });
      if (!response.ok) {
        resolutionPlan = null;
        message.textContent = errorMessage(data, 'Не удалось проверить доступные способы управления.');
        return;
      }
      if (!safePlan(data) || !['unavailable', 'single-candidate', 'choice-required'].includes(data?.state)) {
        resolutionPlan = null;
        message.textContent = 'Результат отклонён интерфейсом: безопасные границы выбора не подтверждены.';
        return;
      }
      resolutionPlan = data;
      renderCandidates(data);
      message.textContent = resultCopy(data);
    } catch (_) {
      resolutionPlan = null;
      message.textContent = 'Home Center сейчас не смог получить список способов управления. Повторите позже.';
    } finally {
      button.disabled = false;
    }
  }

  async function prepareSelection(candidate) {
    if (!resolutionPlan?.plan_id || !confirmedEnrollment?.proposal_id || !safeCandidate(candidate)) return;
    const message = $('#device-provider-resolution-message');
    message.textContent = '';
    selectionProposal = null;
    $('#device-provider-selection-confirm').hidden = true;
    try {
      const {response, data} = await request('/api/v1/household/devices/enrollment/provider-selection/plan', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.device-management-provider-selection-plan-request.v1',
          resolution_plan_id: resolutionPlan.plan_id,
          enrollment_proposal_id: confirmedEnrollment.proposal_id,
          device_platform: resolutionPlan.device_platform,
          provider_id: candidate.provider_id,
        }),
      });
      if (!response.ok) {
        message.textContent = errorMessage(data, 'Не удалось подготовить безопасный выбор способа управления.');
        return;
      }
      if (!safeSelectionProposal(data, candidate.provider_id)) {
        message.textContent = 'Предложение выбора отклонено интерфейсом: границы безопасности не подтверждены.';
        return;
      }
      selectionProposal = data;
      $('#device-provider-selection-copy').textContent = `Будет сохранён выбор «${candidate.display_name}». Credentials не передаются, подключение и политики не запускаются, устройство пока не становится управляемым.`;
      $('#device-provider-selection-confirm').hidden = false;
      $('#device-provider-selection-confirm-button').focus();
    } catch (_) {
      message.textContent = 'Не удалось подготовить выбор. Повторите поиск и попробуйте снова.';
    }
  }

  async function confirmSelection() {
    if (!selectionProposal?.proposal_id) return;
    const button = $('#device-provider-selection-confirm-button');
    const message = $('#device-provider-resolution-message');
    button.disabled = true;
    message.textContent = '';
    try {
      const {response, data} = await request('/api/v1/household/devices/enrollment/provider-selection/confirm', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.device-management-provider-selection-confirm-request.v1',
          proposal_id: selectionProposal.proposal_id,
          confirmed: true,
        }),
      });
      if (!response.ok) {
        message.textContent = errorMessage(data, 'Выбор не подтверждён. При изменении состояния сформируйте его заново.');
        return;
      }
      if (!safeSelectionReceipt(data)) {
        message.textContent = 'Подтверждение выбора отклонено интерфейсом: границы безопасности не подтверждены.';
        return;
      }
      message.textContent = 'Способ управления выбран. Подключение ещё не выполняется, credentials не запрашиваются, устройство остаётся неуправляемым до отдельного будущего шага.';
      $('#device-provider-selection-confirm').hidden = true;
      for (const choose of document.querySelectorAll('#device-provider-candidates button[data-provider-id]')) {
        choose.disabled = true;
      }
      selectionProposal = null;
    } catch (_) {
      message.textContent = 'Не удалось подтвердить выбор. Повторите позже.';
    } finally {
      button.disabled = false;
    }
  }

  function onEnrollmentConfirmed(event) {
    const receipt = event?.detail;
    if (
      !receipt?.proposal_id
      || !receipt?.device_id
      || receipt?.provider_resolution_required !== true
      || receipt?.provider_selected !== false
      || receipt?.provider_execution_authorized !== false
      || receipt?.policy_application_authorized !== false
      || receipt?.managed_state_change_authorized !== false
      || receipt?.infrastructure_mutation_authorized !== false
      || receipt?.external_publication_authorized !== false
    ) {
      reset();
      return;
    }
    confirmedEnrollment = receipt;
    resolutionPlan = null;
    selectionProposal = null;
    $('#device-provider-candidates').replaceChildren();
    $('#device-provider-selection-confirm').hidden = true;
    $('#device-provider-resolution-message').textContent = '';
    $('#device-provider-resolution-card').hidden = false;
  }

  function init() {
    buildUi();
    document.addEventListener('homecenter:device-enrollment-confirmed', onEnrollmentConfirmed);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
