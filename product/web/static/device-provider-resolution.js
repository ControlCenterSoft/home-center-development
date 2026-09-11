(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  let confirmedEnrollment = null;

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
      <p id="device-provider-resolution-message" class="form-message" role="status"></p>`;

    if (enrollment) enrollment.insertAdjacentElement('afterend', card);
    else family.append(card);
    $('#device-provider-resolution-form').addEventListener('submit', resolveProviders);
  }

  function reset() {
    confirmedEnrollment = null;
    const card = $('#device-provider-resolution-card');
    if (card) card.hidden = true;
    const candidates = $('#device-provider-candidates');
    if (candidates) candidates.replaceChildren();
    const message = $('#device-provider-resolution-message');
    if (message) message.textContent = '';
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
      row.append(body);
      list.append(row);
    }
  }

  function resultCopy(plan) {
    if (plan.state === 'unavailable') {
      return 'Для этого типа устройства сейчас нет доступного способа управления. Ничего не будет установлено.';
    }
    if (plan.state === 'single-candidate') {
      return 'Найден один доступный способ. Он ещё не выбран и ничего не запускает.';
    }
    if (plan.state === 'choice-required') {
      return 'Найдено несколько способов. Выбор будет отдельным шагом; сейчас ни один не выбран.';
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
        message.textContent = errorMessage(data, 'Не удалось проверить доступные способы управления.');
        return;
      }
      if (!safePlan(data) || !['unavailable', 'single-candidate', 'choice-required'].includes(data?.state)) {
        message.textContent = 'Результат отклонён интерфейсом: безопасные границы выбора не подтверждены.';
        return;
      }
      renderCandidates(data);
      message.textContent = resultCopy(data);
    } catch (_) {
      message.textContent = 'Home Center сейчас не смог получить список способов управления. Повторите позже.';
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
    $('#device-provider-candidates').replaceChildren();
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
