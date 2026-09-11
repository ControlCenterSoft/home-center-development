(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);

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
    if (!family || $('#device-management-card')) return;

    const card = document.createElement('section');
    card.id = 'device-management-card';
    card.className = 'setup-card';
    card.hidden = true;

    const heading = document.createElement('div');
    const eyebrow = document.createElement('span');
    eyebrow.className = 'eyebrow';
    eyebrow.textContent = 'Управление устройствами';
    const title = document.createElement('h2');
    title.textContent = 'Нужно ли настраивать управление?';
    const copy = document.createElement('p');
    copy.textContent = 'Home Center может проверить требование роли и подготовить следующий безопасный шаг. Проверка ничего не устанавливает и не включает сама.';
    heading.append(eyebrow, title, copy);

    const list = document.createElement('div');
    list.id = 'device-management-list';
    list.className = 'family-grid';
    list.setAttribute('aria-live', 'polite');

    const result = document.createElement('p');
    result.id = 'device-management-message';
    result.className = 'form-message';
    result.setAttribute('role', 'status');

    card.append(heading, list, result);
    const registration = $('#device-registration-card');
    if (registration) registration.insertAdjacentElement('afterend', card);
    else family.append(card);
  }

  function stateCopy(plan) {
    if (plan?.state === 'satisfied') {
      return 'Управление этим устройством уже подтверждено в состоянии Home Center. Дополнительный план не требуется.';
    }
    if (plan?.state === 'required') {
      return 'Для этой роли управление требуется. Следующий шаг — отдельно выбрать подходящий способ управления и подтвердить его. Сейчас ничего не установлено и не применено.';
    }
    return 'Для этой роли обязательное управление не требуется. Устройство можно оставить зарегистрированным без дополнительных действий.';
  }

  async function planManagement(deviceId, button) {
    const message = $('#device-management-message');
    message.textContent = '';
    button.disabled = true;
    try {
      const {response, data} = await request('/api/v1/household/devices/management/plan', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-device-management-plan-request.v1',
          device_id: deviceId,
        }),
      });
      if (!response.ok) {
        message.textContent = errorMessage(data, 'Не удалось проверить необходимость управления устройством.');
        return;
      }
      if (
        data?.provider_selected !== false ||
        data?.provider_execution_authorized !== false ||
        data?.policy_application_authorized !== false ||
        data?.infrastructure_mutation_authorized !== false ||
        data?.external_publication_authorized !== false
      ) {
        message.textContent = 'План отклонён интерфейсом: безопасные границы управления не подтверждены.';
        return;
      }
      message.textContent = stateCopy(data);
      document.dispatchEvent(new CustomEvent('homecenter:device-management-plan', {detail: data}));
    } catch (_) {
      message.textContent = 'Home Center сейчас не смог подготовить план управления. Повторите проверку позже.';
    } finally {
      button.disabled = false;
    }
  }

  async function syncDevices() {
    const card = $('#device-management-card');
    const list = $('#device-management-list');
    if (!card || !list || $('#workspace-view')?.hidden) return;
    try {
      const {response, data} = await request('/api/v1/household');
      const household = response.ok && data?.configured === true ? data?.snapshot?.household : null;
      const devices = Array.isArray(household?.devices) ? household.devices : [];
      const members = Array.isArray(household?.members) ? household.members : [];
      if (!devices.length) {
        card.hidden = true;
        list.replaceChildren();
        return;
      }

      const memberNames = new Map(members.map((member) => [member.member_id, member.display_name || 'Член семьи']));
      const rows = devices.map((device) => {
        const row = document.createElement('article');
        row.className = 'family-card';
        const body = document.createElement('div');
        const name = document.createElement('strong');
        name.textContent = device.display_name || 'Устройство';
        const meta = document.createElement('p');
        const owner = memberNames.get(device.member_id) || 'Член семьи';
        meta.textContent = `${owner} · ${device.managed === true ? 'управление подтверждено' : 'управление не подтверждено'}`;
        const button = document.createElement('button');
        button.className = 'secondary-button compact-button';
        button.type = 'button';
        button.textContent = 'Проверить необходимость';
        button.addEventListener('click', () => planManagement(device.device_id, button));
        body.append(name, meta, button);
        row.append(body);
        return row;
      });
      list.replaceChildren(...rows);
      card.hidden = false;
    } catch (_) {
      card.hidden = true;
    }
  }

  function init() {
    buildUi();
    syncDevices();
    const workspace = $('#workspace-view');
    if (workspace) {
      new MutationObserver(() => syncDevices()).observe(workspace, {attributes: true, attributeFilter: ['hidden']});
    }
    document.querySelectorAll('[data-cozy-section="family"]').forEach((button) => {
      button.addEventListener('click', () => syncDevices());
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
