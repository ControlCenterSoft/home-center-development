(() => {
  'use strict';

  const $member = (selector) => document.querySelector(selector);
  let pendingMemberProposal = null;
  let memberOperationInFlight = false;

  async function memberRequest(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    const response = await fetch(path, {...options, headers, credentials: 'same-origin', cache: 'no-store'});
    let data = null;
    if ((response.headers.get('content-type') || '').includes('application/json')) {
      try { data = await response.json(); } catch (_) { data = null; }
    }
    return {response, data};
  }

  function memberErrorMessage(data, fallback) {
    return data?.error?.message || fallback;
  }

  function memberRoleLabel(role) {
    return ({parent: 'Родитель', child: 'Ребёнок', guest: 'Гость'})[role] || 'Член семьи';
  }

  function clearMemberConfirmation() {
    pendingMemberProposal = null;
    const card = $member('#member-confirm-card');
    const message = $member('#member-confirm-message');
    const copy = $member('#member-confirm-copy');
    if (card) card.hidden = true;
    if (message) message.textContent = '';
    if (copy) copy.textContent = '—';
  }

  async function refreshMemberWorkspace() {
    clearMemberConfirmation();
    if (typeof loadWorkspace === 'function') {
      await loadWorkspace();
      return;
    }
    window.location.reload();
  }

  const planForm = $member('#member-plan-form');
  const confirmButton = $member('#member-confirm-button');
  const cancelButton = $member('#member-cancel-button');

  if (!planForm || !confirmButton || !cancelButton) return;

  function setMemberOperationBusy(busy) {
    memberOperationInFlight = busy;
    planForm.setAttribute('aria-busy', busy ? 'true' : 'false');
    const confirmCard = $member('#member-confirm-card');
    if (confirmCard) confirmCard.setAttribute('aria-busy', busy ? 'true' : 'false');
    planForm.querySelectorAll('input, select, button').forEach((control) => {
      control.disabled = busy;
    });
    confirmButton.disabled = busy;
    cancelButton.disabled = busy;
  }

  planForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (memberOperationInFlight) return;
    const button = event.submitter;
    const message = $member('#member-plan-message');
    const displayName = $member('#member-display-name');
    const role = $member('#member-role');
    if (!button || !message || !displayName || !role) return;

    let focusConfirmAfterBusy = false;
    message.textContent = '';
    clearMemberConfirmation();
    setMemberOperationBusy(true);
    try {
      const {response, data} = await memberRequest('/api/v1/household/members/plan', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-member-add-plan.v1',
          display_name: displayName.value.trim(),
          role: role.value,
        }),
      });
      if (response.status === 401 || (response.status === 403 && data?.error?.code === 'password_change_required')) {
        window.location.reload();
        return;
      }
      if (!response.ok || !data?.proposal_id || !data?.member) {
        message.textContent = memberErrorMessage(data, 'Не удалось подготовить изменение.');
        return;
      }
      pendingMemberProposal = data;
      $member('#member-confirm-copy').textContent = `${String(data.member.display_name)} — ${memberRoleLabel(data.member.role)}. Изменение относится к версии семьи ${String(data.generation)} и будет применено только после подтверждения.`;
      $member('#member-confirm-card').hidden = false;
      focusConfirmAfterBusy = true;
    } catch (_) {
      message.textContent = 'Не удалось связаться с Home Center.';
    } finally {
      setMemberOperationBusy(false);
      if (focusConfirmAfterBusy) confirmButton.focus();
    }
  });

  cancelButton.addEventListener('click', () => {
    if (memberOperationInFlight) return;
    clearMemberConfirmation();
    $member('#member-plan-message').textContent = 'Изменение отменено. Данные семьи не менялись.';
  });

  confirmButton.addEventListener('click', async () => {
    if (memberOperationInFlight || !pendingMemberProposal?.proposal_id) return;
    const message = $member('#member-confirm-message');
    message.textContent = '';
    setMemberOperationBusy(true);
    try {
      const proposalId = pendingMemberProposal.proposal_id;
      const {response, data} = await memberRequest('/api/v1/household/members/confirm', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-member-add-confirm.v1',
          proposal_id: proposalId,
          confirmed: true,
        }),
      });
      if (response.status === 401 || (response.status === 403 && data?.error?.code === 'password_change_required')) {
        window.location.reload();
        return;
      }
      if (response.status === 409 && data?.error?.code === 'household_member_change_stale') {
        pendingMemberProposal = null;
        message.textContent = 'Семья изменилась после подготовки. Ничего не применено — сформируйте план заново.';
        if (typeof loadWorkspace === 'function') await loadWorkspace();
        return;
      }
      if (!response.ok) {
        message.textContent = memberErrorMessage(data, 'Не удалось применить изменение.');
        return;
      }
      const outcome = data?.outcome;
      await refreshMemberWorkspace();
      const planMessage = $member('#member-plan-message');
      if (planMessage) planMessage.textContent = outcome === 'already-applied' ? 'Человек уже был добавлен ранее.' : 'Человек добавлен в семью.';
      const displayName = $member('#member-display-name');
      const role = $member('#member-role');
      if (displayName) displayName.value = '';
      if (role) role.value = 'child';
    } catch (_) {
      message.textContent = 'Не удалось связаться с Home Center.';
    } finally {
      setMemberOperationBusy(false);
    }
  });

  const refreshButton = $member('#refresh-button');
  if (refreshButton) refreshButton.addEventListener('click', clearMemberConfirmation);
  const logoutButton = $member('#logout-button');
  if (logoutButton) logoutButton.addEventListener('click', clearMemberConfirmation);
})();
