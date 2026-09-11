(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  let managementPlan = null;
  let enrollmentProposal = null;

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

  function safeBoundary(value) {
    return value?.provider_resolution_required === true
      && value?.provider_selected === false
      && value?.provider_execution_authorized === false
      && value?.policy_application_authorized === false
      && value?.managed_state_change_authorized === false
      && value?.infrastructure_mutation_authorized === false
      && value?.external_publication_authorized === false;
  }

  function buildUi() {
    const management = $('#device-management-card');
    const family = $('#cozy-family');
    if (!family || $('#device-enrollment-card')) return;

    const card = document.createElement('section');
    card.id = 'device-enrollment-card';
    card.className = 'confirm-card';
    card.hidden = true;
    card.setAttribute('aria-live', 'polite');
    card.innerHTML = `
      <div>
        <span class="eyebrow">Следующий шаг</span>
        <h2>Подготовить подключение управления</h2>
        <p id="device-enrollment-copy">—</p>
      </div>
      <div class="confirm-actions">
        <button id="device-enrollment-plan-button" class="primary-button" type="button">Подготовить подключение</button>
        <button id="device-enrollment-cancel-button" class="secondary-button" type="button">Не сейчас</button>
      </div>
      <section id="device-enrollment-confirm" hidden>
        <p id="device-enrollment-confirm-copy">—</p>
        <div class="confirm-actions">
          <button id="device-enrollment-confirm-button" class="primary-button" type="button">Подтвердить переход к настройке</button>
          <button id="device-enrollment-back-button" class="secondary-button" type="button">Назад</button>
        </div>
      </section>
      <p id="device-enrollment-message" class="form-message" role="status"></p>`;

    if (management) management.insertAdjacentElement('afterend', card);
    else family.append(card);

    $('#device-enrollment-plan-button').addEventListener('click', prepareEnrollment);
    $('#device-enrollment-confirm-button').addEventListener('click', confirmEnrollment);
    $('#device-enrollment-cancel-button').addEventListener('click', reset);
    $('#device-enrollment-back-button').addEventListener('click', backToPlan);
  }

  function reset() {
    managementPlan = null;
    enrollmentProposal = null;
    const card = $('#device-enrollment-card');
    if (card) card.hidden = true;
    const confirm = $('#device-enrollment-confirm');
    if (confirm) confirm.hidden = true;
    const message = $('#device-enrollment-message');
    if (message) message.textContent = '';
  }

  function backToPlan() {
    enrollmentProposal = null;
    $('#device-enrollment-confirm').hidden = true;
    $('#device-enrollment-message').textContent = '';
  }

  async function prepareEnrollment() {
    if (!managementPlan?.device_id || managementPlan?.state !== 'required') return;
    const button = $('#device-enrollment-plan-button');
    const message = $('#device-enrollment-message');
    button.disabled = true;
    message.textContent = '';
    try {
      const {response, data} = await request('/api/v1/household/devices/enrollment/plan', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-device-enrollment-plan-request.v1',
          device_id: managementPlan.device_id,
        }),
      });
      if (!response.ok) {
        message.textContent = errorMessage(data, 'Не удалось подготовить переход к настройке управления.');
        return;
      }
      if (!safeBoundary(data) || data?.confirmation_required !== true) {
        message.textContent = 'Предложение отклонено интерфейсом: безопасные границы не подтверждены.';
        return;
      }
      enrollmentProposal = data;
      $('#device-enrollment-confirm-copy').textContent = 'Home Center сохранит только ваше согласие перейти к подбору способа управления. Провайдер ещё не выбран, устройство останется неуправляемым, ничего не устанавливается.';
      $('#device-enrollment-confirm').hidden = false;
      $('#device-enrollment-confirm-button').focus();
    } catch (_) {
      message.textContent = 'Home Center сейчас не смог подготовить предложение. Повторите позже.';
    } finally {
      button.disabled = false;
    }
  }

  async function confirmEnrollment() {
    if (!enrollmentProposal?.proposal_id) return;
    const button = $('#device-enrollment-confirm-button');
    const message = $('#device-enrollment-message');
    button.disabled = true;
    message.textContent = '';
    try {
      const proposalId = enrollmentProposal.proposal_id;
      const {response, data} = await request('/api/v1/household/devices/enrollment/confirm', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-device-enrollment-confirm-request.v1',
          proposal_id: proposalId,
          confirmed: true,
        }),
      });
      if (!response.ok) {
        message.textContent = errorMessage(data, 'Подтверждение не сохранено. При изменении состояния сформируйте предложение заново.');
        return;
      }
      if (!safeBoundary(data) || data?.proposal_id !== proposalId) {
        message.textContent = 'Подтверждение отклонено интерфейсом: безопасные границы не подтверждены.';
        return;
      }
      message.textContent = 'Согласие сохранено. Управление ещё не включено; следующий этап — подобрать подходящий способ управления.';
      $('#device-enrollment-confirm').hidden = true;
      enrollmentProposal = null;
      document.dispatchEvent(new CustomEvent('homecenter:device-enrollment-confirmed', {detail: data}));
    } catch (_) {
      message.textContent = 'Не удалось сохранить подтверждение. Повторите позже.';
    } finally {
      button.disabled = false;
    }
  }

  function onManagementPlan(event) {
    const plan = event?.detail;
    if (!plan || plan.state !== 'required' || plan.managed !== false || plan.management_required !== true) {
      reset();
      return;
    }
    if (
      plan.provider_selected !== false
      || plan.provider_execution_authorized !== false
      || plan.policy_application_authorized !== false
      || plan.infrastructure_mutation_authorized !== false
      || plan.external_publication_authorized !== false
    ) {
      reset();
      return;
    }
    managementPlan = plan;
    enrollmentProposal = null;
    $('#device-enrollment-copy').textContent = 'Управление требуется, но ещё не настроено. Можно отдельно подтвердить переход к следующему этапу — подбору способа управления.';
    $('#device-enrollment-confirm').hidden = true;
    $('#device-enrollment-message').textContent = '';
    $('#device-enrollment-card').hidden = false;
  }

  function init() {
    buildUi();
    document.addEventListener('homecenter:device-management-plan', onManagementPlan);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
