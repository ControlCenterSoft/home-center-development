(() => {
  'use strict';

  const $member = (selector) => document.querySelector(selector);
  let pendingMemberProposal = null;
  let memberOperationSerial = 0;
  let activeMemberOperation = 0;

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

  function setMemberFlowBusy(busy) {
    const confirmCard = $member('#member-confirm-card');
    if (busy) {
      planForm.setAttribute('aria-busy', 'true');
      if (confirmCard) confirmCard.setAttribute('aria-busy', 'true');
    } else {
      planForm.removeAttribute('aria-busy');
      if (confirmCard) confirmCard.removeAttribute('aria-busy');
    }
    Array.from(planForm.elements).forEach((control) => {
      control.disabled = busy;
    });
    confirmButton.disabled = busy;
    cancelButton.disabled = busy;
  }

  function beginMemberOperation() {
    if (activeMemberOperation !== 0) return 0;
    const operationId = ++memberOperationSerial;
    activeMemberOperation = operationId;
    setMemberFlowBusy(true);
    return operationId;
  }

  function ownsMemberOperation(operationId) {
    return operationId !== 0 && activeMemberOperation === operationId;
  }

  function finishMemberOperation(operationId) {
    if (!ownsMemberOperation(operationId)) return;
    activeMemberOperation = 0;
    setMemberFlowBusy(false);
  }

  function resetMemberFlowForNavigation() {
    activeMemberOperation = 0;
    setMemberFlowBusy(false);
    clearMemberConfirmation();
  }

  planForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.submitter;
    const message = $member('#member-plan-message');
    const displayName = $member('#member-display-name');
    const role = $member('#member-role');
    if (!button || !message || !displayName || !role) return;

    const operationId = beginMemberOperation();
    if (!operationId) return;
    const plannedDisplayName = displayName.value.trim();
    const plannedRole = role.value;
    message.textContent = '';
    clearMemberConfirmation();
    try {
      const {response, data} = await memberRequest('/api/v1/household/members/plan', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-member-add-plan.v1',
          display_name: plannedDisplayName,
          role: plannedRole,
        }),
      });
      if (!ownsMemberOperation(operationId)) return;
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
      confirmButton.focus();
    } catch (_) {
      if (!ownsMemberOperation(operationId)) return;
      message.textContent = 'Не удалось связаться с Home Center.';
    } finally {
      finishMemberOperation(operationId);
    }
  });

  cancelButton.addEventListener('click', () => {
    if (activeMemberOperation !== 0) return;
    clearMemberConfirmation();
    $member('#member-plan-message').textContent = 'Изменение отменено. Данные семьи не менялись.';
  });

  confirmButton.addEventListener('click', async () => {
    if (!pendingMemberProposal?.proposal_id || activeMemberOperation !== 0) return;
    const message = $member('#member-confirm-message');
    const proposalId = pendingMemberProposal.proposal_id;
    const operationId = beginMemberOperation();
    if (!operationId) return;
    message.textContent = '';
    try {
      const {response, data} = await memberRequest('/api/v1/household/members/confirm', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-member-add-confirm.v1',
          proposal_id: proposalId,
          confirmed: true,
        }),
      });
      if (!ownsMemberOperation(operationId)) return;
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
      if (!ownsMemberOperation(operationId)) return;
      const planMessage = $member('#member-plan-message');
      if (planMessage) planMessage.textContent = outcome === 'already-applied' ? 'Человек уже был добавлен ранее.' : 'Человек добавлен в семью.';
      const displayName = $member('#member-display-name');
      const role = $member('#member-role');
      if (displayName) displayName.value = '';
      if (role) role.value = 'child';
    } catch (_) {
      if (!ownsMemberOperation(operationId)) return;
      message.textContent = 'Не удалось связаться с Home Center.';
    } finally {
      finishMemberOperation(operationId);
    }
  });

  const refreshButton = $member('#refresh-button');
  if (refreshButton) refreshButton.addEventListener('click', resetMemberFlowForNavigation);
  const logoutButton = $member('#logout-button');
  if (logoutButton) logoutButton.addEventListener('click', resetMemberFlowForNavigation);
})();
