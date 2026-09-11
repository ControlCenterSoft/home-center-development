(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  let currentProposal = null;

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    const response = await fetch(path, {
      ...options,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
    });
    let data = null;
    if ((response.headers.get('content-type') || '').includes('application/json')) {
      try { data = await response.json(); } catch (_) { data = null; }
    }
    return {response, data};
  }

  function errorMessage(data, fallback) {
    return data?.error?.message || fallback;
  }

  function authenticationChanged(response, data) {
    return response.status === 401 || (response.status === 403 && data?.error?.code === 'password_change_required');
  }

  function clearConfirmation() {
    currentProposal = null;
    const card = $('#device-confirm-card');
    const message = $('#device-confirm-message');
    const copy = $('#device-confirm-copy');
    const policy = $('#device-policy-copy');
    if (card) card.hidden = true;
    if (message) message.textContent = '';
    if (copy) copy.textContent = '—';
    if (policy) policy.textContent = '';
  }

  function buildUi() {
    const family = $('#cozy-family');
    if (!family || $('#device-registration-card')) return;

    const card = document.createElement('section');
    card.id = 'device-registration-card';
    card.className = 'setup-card';
    card.hidden = true;
    card.innerHTML = `
      <div>
        <span class="eyebrow">Устройство</span>
        <h2>Добавить устройство</h2>
        <p>Home Center зарегистрирует устройство за выбранным человеком. Это не включает MDM, VPN, фильтрацию или другие политики управления.</p>
      </div>
      <form id="device-plan-form" class="member-form" autocomplete="off">
        <label><span>Чьё устройство</span><select id="device-subject" required></select></label>
        <label><span>Название</span><input id="device-display-name" type="text" maxlength="80" placeholder="Например, Телефон" required></label>
        <button class="primary-button" type="submit">Проверить и продолжить</button>
      </form>
      <p id="device-plan-message" class="form-message" role="status"></p>`;

    const confirm = document.createElement('section');
    confirm.id = 'device-confirm-card';
    confirm.className = 'confirm-card';
    confirm.hidden = true;
    confirm.setAttribute('aria-live', 'polite');
    confirm.innerHTML = `
      <div>
        <span class="eyebrow">Подтверждение</span>
        <h2>Проверьте устройство</h2>
        <p id="device-confirm-copy">—</p>
        <p id="device-policy-copy"></p>
      </div>
      <div class="confirm-actions">
        <button id="device-confirm-button" class="primary-button" type="button">Подтвердить регистрацию</button>
        <button id="device-cancel-button" class="secondary-button" type="button">Отмена</button>
      </div>
      <p id="device-confirm-message" class="form-message" role="status"></p>`;

    const memberConfirm = $('#member-confirm-card');
    if (memberConfirm) {
      memberConfirm.insertAdjacentElement('afterend', confirm);
      confirm.insertAdjacentElement('afterend', card);
    } else {
      family.append(card, confirm);
    }

    $('#device-plan-form').addEventListener('submit', planDevice);
    $('#device-confirm-button').addEventListener('click', confirmDevice);
    $('#device-cancel-button').addEventListener('click', cancelDevice);
  }

  async function syncPeople() {
    const card = $('#device-registration-card');
    const select = $('#device-subject');
    if (!card || !select || $('#workspace-view')?.hidden) return;
    try {
      const {response, data} = await request('/api/v1/household');
      if (authenticationChanged(response, data)) {
        window.location.reload();
        return;
      }
      if (!response.ok || data?.configured !== true) {
        card.hidden = true;
        clearConfirmation();
        return;
      }
      const members = Array.isArray(data?.snapshot?.household?.members)
        ? data.snapshot.household.members.filter((member) => member?.enabled === true && typeof member?.member_id === 'string')
        : [];
      if (!members.length) {
        card.hidden = true;
        clearConfirmation();
        return;
      }
      const previous = select.value;
      select.replaceChildren(...members.map((member) => {
        const option = document.createElement('option');
        option.value = member.member_id;
        const role = ({parent: 'Родитель', child: 'Ребёнок', guest: 'Гость'})[member.role] || 'Член семьи';
        option.textContent = `${member.display_name} — ${role}`;
        return option;
      }));
      if ([...select.options].some((option) => option.value === previous)) select.value = previous;
      card.hidden = false;
    } catch (_) {
      card.hidden = true;
    }
  }

  async function planDevice(event) {
    event.preventDefault();
    const message = $('#device-plan-message');
    const button = event.submitter || event.currentTarget.querySelector('button[type="submit"]');
    const subject = $('#device-subject');
    const displayName = $('#device-display-name');
    if (!message || !button || !subject || !displayName) return;

    message.textContent = '';
    clearConfirmation();
    button.disabled = true;
    try {
      const {response, data} = await request('/api/v1/household/devices/plan', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-device-add-plan.v1',
          subject_member_id: subject.value,
          display_name: displayName.value.trim(),
        }),
      });
      if (authenticationChanged(response, data)) {
        window.location.reload();
        return;
      }
      if (
        !response.ok
        || typeof data?.proposal_id !== 'string'
        || typeof data?.device?.display_name !== 'string'
        || typeof data?.management_required !== 'boolean'
        || data?.managed_after_registration !== false
        || data?.provider_execution_authorized !== false
        || data?.infrastructure_mutation_authorized !== false
        || data?.external_publication_authorized !== false
      ) {
        message.textContent = errorMessage(data, 'Не удалось подготовить безопасную регистрацию устройства.');
        return;
      }
      currentProposal = data;
      const person = subject.selectedOptions[0]?.textContent || 'член семьи';
      $('#device-confirm-copy').textContent = `«${data.device.display_name}» будет зарегистрировано за: ${person}.`;
      $('#device-policy-copy').textContent = data.management_required === true
        ? 'Для этой роли управление устройством требуется. Сейчас устройство будет только зарегистрировано; применение MDM и политик не выполняется.'
        : 'Устройство будет зарегистрировано как известное. MDM, VPN, фильтрация и другие provider-настройки этим действием не меняются.';
      $('#device-confirm-message').textContent = '';
      $('#device-confirm-card').hidden = false;
      $('#device-confirm-button').focus();
    } catch (_) {
      message.textContent = 'Не удалось связаться с Home Center.';
    } finally {
      button.disabled = false;
    }
  }

  async function confirmDevice() {
    if (!currentProposal?.proposal_id) return;
    const button = $('#device-confirm-button');
    const message = $('#device-confirm-message');
    if (!button || !message) return;
    button.disabled = true;
    message.textContent = '';
    try {
      const proposalId = currentProposal.proposal_id;
      const {response, data} = await request('/api/v1/household/devices/confirm', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-device-add-confirm.v1',
          proposal_id: proposalId,
          confirmed: true,
        }),
      });
      if (authenticationChanged(response, data)) {
        window.location.reload();
        return;
      }
      if (response.status === 409 && data?.error?.code === 'household_device_change_stale') {
        currentProposal = null;
        message.textContent = 'Семья изменилась после подготовки. Ничего не применено — сформируйте план устройства заново.';
        await syncPeople();
        return;
      }
      if (!response.ok || data?.managed !== false || data?.device?.managed !== false) {
        message.textContent = errorMessage(data, 'Регистрация не выполнена. Сформируйте план заново.');
        return;
      }
      const outcome = data?.outcome;
      const managementRequired = data?.management_required === true;
      currentProposal = null;
      message.textContent = outcome === 'already-applied'
        ? 'Устройство уже было зарегистрировано ранее.'
        : managementRequired
          ? 'Устройство зарегистрировано. Управление требуется, но ещё не применено.'
          : 'Устройство зарегистрировано без изменения системных политик.';
      window.setTimeout(() => window.location.reload(), 350);
    } catch (_) {
      message.textContent = 'Не удалось связаться с Home Center.';
    } finally {
      button.disabled = false;
    }
  }

  function cancelDevice() {
    clearConfirmation();
    const message = $('#device-plan-message');
    if (message) message.textContent = 'Регистрация отменена. Данные семьи не менялись.';
  }

  function init() {
    buildUi();
    syncPeople();
    const workspace = $('#workspace-view');
    if (workspace) {
      new MutationObserver(() => syncPeople()).observe(workspace, {attributes: true, attributeFilter: ['hidden']});
    }
    document.querySelectorAll('[data-cozy-section="family"]').forEach((button) => {
      button.addEventListener('click', () => syncPeople());
    });
    const refreshButton = $('#refresh-button');
    if (refreshButton) refreshButton.addEventListener('click', clearConfirmation);
    const logoutButton = $('#logout-button');
    if (logoutButton) logoutButton.addEventListener('click', clearConfirmation);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
