(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  let currentProposal = null;

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
        <p>Home Center зарегистрирует устройство за выбранным человеком. Это ещё не включает MDM, VPN, фильтрацию или другие политики управления.</p>
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
      if (!response.ok || data?.configured !== true) {
        card.hidden = true;
        return;
      }
      const members = Array.isArray(data?.snapshot?.household?.members)
        ? data.snapshot.household.members.filter((member) => member?.enabled === true)
        : [];
      if (!members.length) {
        card.hidden = true;
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
    const button = event.currentTarget.querySelector('button[type="submit"]');
    message.textContent = '';
    button.disabled = true;
    try {
      const body = {
        schema: 'home-center.household-device-add-plan.v1',
        subject_member_id: $('#device-subject').value,
        display_name: $('#device-display-name').value,
      };
      const {response, data} = await request('/api/v1/household/devices/plan', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        message.textContent = errorMessage(data, 'Не удалось подготовить регистрацию устройства.');
        return;
      }
      currentProposal = data;
      const device = data?.device || {};
      const person = $('#device-subject').selectedOptions[0]?.textContent || 'член семьи';
      $('#device-confirm-copy').textContent = `«${device.display_name || 'Устройство'}» будет зарегистрировано за: ${person}.`;
      $('#device-policy-copy').textContent = data?.management_required === true
        ? 'Для этой роли управление устройством требуется. Сейчас устройство будет только зарегистрировано; применение MDM/политики ещё не выполнено.'
        : 'Устройство будет зарегистрировано как известное. MDM, VPN, фильтрация и другие provider-настройки этим действием не меняются.';
      $('#device-confirm-message').textContent = '';
      $('#device-confirm-card').hidden = false;
      $('#device-confirm-button').focus();
    } finally {
      button.disabled = false;
    }
  }

  async function confirmDevice() {
    if (!currentProposal?.proposal_id) return;
    const button = $('#device-confirm-button');
    const message = $('#device-confirm-message');
    button.disabled = true;
    message.textContent = '';
    try {
      const {response, data} = await request('/api/v1/household/devices/confirm', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-device-add-confirm.v1',
          proposal_id: currentProposal.proposal_id,
          confirmed: true,
        }),
      });
      if (!response.ok) {
        message.textContent = errorMessage(data, 'Регистрация не выполнена. Сформируйте план заново.');
        return;
      }
      message.textContent = data?.management_required === true
        ? 'Устройство зарегистрировано. Управление требуется, но ещё не применено.'
        : 'Устройство зарегистрировано без изменения системных политик.';
      currentProposal = null;
      window.setTimeout(() => window.location.reload(), 250);
    } finally {
      button.disabled = false;
    }
  }

  function cancelDevice() {
    currentProposal = null;
    $('#device-confirm-card').hidden = true;
    $('#device-confirm-message').textContent = '';
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
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
