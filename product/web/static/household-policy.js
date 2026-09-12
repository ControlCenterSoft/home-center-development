(() => {
  'use strict';

  const byId = (id) => document.getElementById(id);
  let activeProposalId = null;
  let activePolicyResourceKey = null;
  let latestHistory = null;
  let pendingRollback = null;
  let loadingMembers = false;

  function message(text, kind = '') {
    const node = byId('policy-message');
    if (!node) return;
    node.textContent = text || '';
    node.dataset.kind = kind;
  }

  function historyMessage(text, kind = '') {
    const node = byId('policy-history-message');
    if (!node) return;
    node.textContent = text || '';
    node.dataset.kind = kind;
  }

  function setComposerVisible(visible) {
    const card = byId('policy-composer-card');
    if (card) card.hidden = !visible;
  }

  function clearRollbackConfirmation() {
    pendingRollback = null;
    const card = byId('policy-rollback-confirm');
    const copy = byId('policy-rollback-copy');
    if (card) card.hidden = true;
    if (copy) copy.textContent = '';
  }

  function clearHistory() {
    latestHistory = null;
    const list = byId('policy-history-list');
    if (list) list.replaceChildren();
    historyMessage('');
    clearRollbackConfirmation();
  }

  function resetPreview() {
    activeProposalId = null;
    activePolicyResourceKey = null;
    const preview = byId('policy-preview');
    const summary = byId('policy-summary');
    const technical = byId('policy-technical');
    const fullInspector = byId('full-policy-inspector');
    if (preview) preview.hidden = true;
    if (summary) summary.replaceChildren();
    if (technical) technical.textContent = '';
    if (fullInspector) fullInspector.hidden = true;
    const fullEvidence = byId('full-policy-evidence');
    if (fullEvidence) fullEvidence.textContent = '';
    const confirm = byId('policy-confirm-button');
    if (confirm) confirm.disabled = true;
    clearHistory();
  }

  function optionFor(member) {
    const option = document.createElement('option');
    option.value = String(member.member_id || '');
    const role = ({parent: 'Родитель', child: 'Ребёнок', guest: 'Гость'})[member.role] || 'Член семьи';
    option.textContent = `${String(member.display_name || 'Член семьи')} · ${role}`;
    return option;
  }

  async function loadMembers() {
    if (loadingMembers || typeof request !== 'function') return;
    loadingMembers = true;
    try {
      const {response, data} = await request('/api/v1/household');
      if (!response.ok || data?.configured !== true) {
        setComposerVisible(false);
        resetPreview();
        return;
      }
      const members = data?.snapshot?.household?.members;
      if (!Array.isArray(members) || !members.length) {
        setComposerVisible(false);
        resetPreview();
        return;
      }
      const select = byId('policy-member');
      const previous = select?.value;
      if (select) {
        select.replaceChildren(...members.filter((member) => member?.enabled !== false).map(optionFor));
        if (previous && Array.from(select.options).some((item) => item.value === previous)) select.value = previous;
      }
      setComposerVisible(true);
    } catch (_) {
      // The main workspace owns connectivity/session messaging. Policy UI stays quiet here.
    } finally {
      loadingMembers = false;
    }
  }

  function authorityDenied(value) {
    return value?.provider_execution_authorized === false
      && value?.infrastructure_mutation_authorized === false
      && value?.external_publication_authorized === false;
  }

  function safePlanResponse(data) {
    const proposal = data?.proposal;
    const presentation = data?.presentation;
    const cozy = presentation?.cozy;
    const full = presentation?.full;
    const technical = full?.technical_policy;
    return data?.schema === 'home-center.household-policy-plan-result.v1'
      && data?.confirmation_required === true
      && data?.desired_state_materialized === false
      && authorityDenied(data)
      && proposal?.schema === 'home-center.household-policy-composition-proposal.v1'
      && typeof proposal?.proposal_id === 'string'
      && proposal?.confirmation_required === true
      && proposal?.desired_state_write_authorized === false
      && proposal?.infrastructure_mutation_authorized === false
      && proposal?.external_publication_authorized === false
      && presentation?.schema === 'home-center.household-policy-presentation.v1'
      && presentation?.proposal_id === proposal?.proposal_id
      && presentation?.bundle_id === proposal?.bundle?.bundle_id
      && presentation?.same_policy_evidence === true
      && presentation?.confirmation_required === true
      && presentation?.mutation_started === false
      && presentation?.infrastructure_mutation_authorized === false
      && presentation?.external_publication_authorized === false
      && cozy?.confirmation_required === true
      && cozy?.mutation_started === false
      && cozy?.external_publication_enabled === false
      && full?.proposal_id === proposal?.proposal_id
      && full?.bundle_id === proposal?.bundle?.bundle_id
      && full?.confirmation_required === true
      && full?.desired_state_write_authorized === false
      && full?.infrastructure_mutation_authorized === false
      && full?.external_publication_authorized === false
      && technical?.external_publication_allowed === false
      && technical?.production_mutation_enabled === false;
  }

  function safeHistoryResponse(data, resourceKey) {
    if (
      data?.schema !== 'home-center.household-policy-history-overview.v1'
      || data?.resource_key !== resourceKey
      || !Number.isInteger(data?.current_generation)
      || data.current_generation < 1
      || typeof data?.current_bundle_id !== 'string'
      || !Number.isInteger(data?.window_start_generation)
      || data.window_start_generation < 1
      || data.window_start_generation > data.current_generation
      || !Array.isArray(data?.revisions)
      || !authorityDenied(data)
    ) return false;

    const expectedCount = data.current_generation - data.window_start_generation + 1;
    if (data.revisions.length !== expectedCount) return false;
    for (let index = 0; index < data.revisions.length; index += 1) {
      const revision = data.revisions[index];
      if (
        revision?.generation !== data.window_start_generation + index
        || typeof revision?.bundle_id !== 'string'
        || !/^[0-9a-f]{64}$/.test(String(revision?.evidence_sha256 || ''))
        || typeof revision?.audit_event_id !== 'string'
        || !revision.audit_event_id
      ) return false;
    }
    const current = data.revisions[data.revisions.length - 1];
    return current?.generation === data.current_generation && current?.bundle_id === data.current_bundle_id;
  }

  function safeApplyResponse(data, proposalId, resourceKey) {
    const confirmation = data?.confirmation;
    const receipt = data?.receipt;
    return data?.schema === 'home-center.household-policy-confirm-apply-result.v1'
      && data?.desired_state_materialized === true
      && authorityDenied(data)
      && /^[0-9a-f]{64}$/.test(String(data?.history_evidence_sha256 || ''))
      && typeof data?.history_audit_event_id === 'string'
      && Boolean(data.history_audit_event_id)
      && confirmation?.proposal_id === proposalId
      && confirmation?.desired_state_write_ready === true
      && confirmation?.desired_state_write_authorized === false
      && confirmation?.infrastructure_mutation_authorized === false
      && confirmation?.external_publication_authorized === false
      && receipt?.schema === 'home-center.household-policy-apply-receipt.v1'
      && receipt?.proposal_id === proposalId
      && receipt?.confirmation_id === confirmation?.confirmation_id
      && receipt?.bundle_id === confirmation?.bundle_id
      && receipt?.resource_key === resourceKey
      && receipt?.desired_state_materialized === true
      && authorityDenied(receipt);
  }

  function safeRollbackResponse(data, requestBody, targetBundleId) {
    const outcome = data?.outcome;
    const generationMatches = outcome === 'already-current'
      ? data?.generation === requestBody.expected_generation
      : Number.isInteger(data?.generation) && data.generation > requestBody.expected_generation;
    return data?.schema === 'home-center.household-policy-rollback-receipt.v1'
      && data?.resource_key === requestBody.resource_key
      && data?.target_history_generation === requestBody.target_generation
      && data?.target_history_bundle_id === targetBundleId
      && generationMatches
      && data?.desired_state_materialized === true
      && authorityDenied(data)
      && ['rolled-back', 'already-current', 'already-rolled-back'].includes(outcome);
  }

  function historyRevisionNode(revision, history) {
    const item = document.createElement('article');
    item.className = 'policy-history-item';

    const head = document.createElement('div');
    head.className = 'policy-history-head';
    const title = document.createElement('strong');
    title.textContent = `Ревизия ${String(revision.generation)}`;
    const badge = document.createElement('span');
    badge.className = 'state-pill neutral';
    badge.textContent = revision.generation === history.current_generation ? 'Текущая' : 'История';
    head.append(title, badge);

    const evidence = document.createElement('p');
    const shortBundle = String(revision.bundle_id || '').slice(0, 16);
    evidence.textContent = `Bundle ${shortBundle}… · ${String(revision.recorded_at || '')}`;
    item.append(head, evidence);

    if (revision.rollback_target === true) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'secondary-button compact-button';
      button.textContent = `Вернуть ревизию ${String(revision.generation)}`;
      button.addEventListener('click', () => prepareRollback(revision.generation));
      item.append(button);
    }
    return item;
  }

  function renderHistory(data) {
    const list = byId('policy-history-list');
    if (!list) return;
    list.replaceChildren();
    const revisions = [...data.revisions].reverse();
    revisions.forEach((revision) => list.append(historyRevisionNode(revision, data)));
    if (!revisions.some((revision) => revision?.rollback_target === true)) {
      const empty = document.createElement('p');
      empty.textContent = 'Предыдущих сохранённых ревизий пока нет.';
      list.append(empty);
    }
    if (data?.truncated === true) {
      const note = document.createElement('p');
      note.textContent = `Показаны последние 100 ревизий, начиная с ${String(data.window_start_generation)}.`;
      list.append(note);
    }
  }

  async function loadHistory(resourceKey) {
    if (!resourceKey) return;
    historyMessage('Проверяем историю правил…');
    try {
      const {response, data} = await request(
        `/api/v1/household/policies/history?resource_key=${encodeURIComponent(resourceKey)}`,
      );
      if (!response.ok) {
        latestHistory = null;
        byId('policy-history-list')?.replaceChildren();
        if (response.status === 404 && data?.error?.code === 'household_policy_desired_state_missing') {
          historyMessage('История появится после первого сохранения правил.');
        } else {
          historyMessage(errorMessage(data, 'Не удалось проверить целостность истории правил.'), 'error');
        }
        return;
      }
      if (!safeHistoryResponse(data, resourceKey)) {
        latestHistory = null;
        byId('policy-history-list')?.replaceChildren();
        historyMessage('Home Center вернул непроверяемую историю правил.', 'error');
        return;
      }
      latestHistory = data;
      renderHistory(data);
      historyMessage('История подтверждена локальным evidence и Audit.');
    } catch (_) {
      latestHistory = null;
      historyMessage('Не удалось проверить историю правил.', 'error');
    }
  }

  function prepareRollback(targetGeneration) {
    if (!latestHistory || !Number.isInteger(targetGeneration)) return;
    const revision = latestHistory.revisions.find((item) => item?.generation === targetGeneration);
    if (!revision || revision.rollback_target !== true) return;
    pendingRollback = {
      resource_key: latestHistory.resource_key,
      expected_generation: latestHistory.current_generation,
      expected_bundle_id: latestHistory.current_bundle_id,
      target_generation: targetGeneration,
    };
    const copy = byId('policy-rollback-copy');
    if (copy) {
      copy.textContent = `Home Center сохранит правила из ревизии ${String(targetGeneration)} как новую ревизию после текущей ${String(latestHistory.current_generation)}. Управление устройствами автоматически не запускается.`;
    }
    const card = byId('policy-rollback-confirm');
    if (card) card.hidden = false;
    byId('policy-rollback-confirm-button')?.focus();
  }

  async function confirmRollback(event) {
    const button = event.currentTarget;
    if (!pendingRollback || !latestHistory) return;
    const requestBody = {...pendingRollback};
    const target = latestHistory.revisions.find((item) => item?.generation === requestBody.target_generation);
    const targetBundleId = target?.bundle_id;
    if (typeof targetBundleId !== 'string' || !targetBundleId) {
      clearRollbackConfirmation();
      historyMessage('Не удалось доказать целевую ревизию. Обновите историю правил.', 'error');
      return;
    }
    button.disabled = true;
    historyMessage('Возвращаем подтверждённую ревизию…');
    try {
      const {response, data} = await request('/api/v1/household/policies/rollback', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-policy-rollback-request.v1',
          ...requestBody,
          confirmed: true,
        }),
      });
      if (!response.ok || !safeRollbackResponse(data, requestBody, targetBundleId)) {
        historyMessage(errorMessage(data, 'Не удалось вернуть ревизию. Обновите историю и повторите проверку.'), 'error');
        return;
      }
      clearRollbackConfirmation();
      activeProposalId = null;
      const confirm = byId('policy-confirm-button');
      if (confirm) confirm.disabled = true;
      const fullEvidence = byId('full-policy-evidence');
      if (fullEvidence) fullEvidence.textContent = 'Policy Desired State изменён rollback-операцией. Сформируйте новый план, чтобы получить актуальное exact-state evidence.';
      message('История правил изменена. Сформируйте новый план перед следующим применением.', 'success');
      historyMessage('Предыдущие правила сохранены как новая ревизия. Устройства автоматически не изменялись.', 'success');
      await loadHistory(requestBody.resource_key);
    } catch (_) {
      historyMessage('Не удалось подтвердить rollback. Текущую историю нужно проверить заново.', 'error');
    } finally {
      button.disabled = false;
    }
  }

  function renderPlan(data) {
    if (!safePlanResponse(data)) throw new Error('invalid_policy_plan_response');
    const proposal = data.proposal;
    const presentation = data.presentation;
    const cozy = presentation.cozy;
    const full = presentation.full;

    activeProposalId = proposal.proposal_id;
    activePolicyResourceKey = full.desired_state_resource_key || null;
    byId('policy-preview-title').textContent = cozy.title || 'Правила';
    byId('policy-preview-role').textContent = cozy.role_label || cozy.role || '';
    const summary = byId('policy-summary');
    summary.replaceChildren();
    const items = Array.isArray(cozy.summary) ? cozy.summary : [];
    items.forEach((value) => {
      const item = document.createElement('li');
      item.textContent = String(value);
      summary.append(item);
    });
    byId('policy-technical').textContent = JSON.stringify(full.technical_policy || {}, null, 2);
    byId('policy-preview').hidden = false;
    byId('policy-confirm-button').disabled = false;

    const fullInspector = byId('full-policy-inspector');
    const fullEvidence = byId('full-policy-evidence');
    if (fullInspector && fullEvidence) {
      fullEvidence.textContent = JSON.stringify({
        proposal_id: full.proposal_id,
        bundle_id: full.bundle_id,
        household_id: full.household_id,
        member_id: full.member_id,
        role: full.role,
        snapshot_id: full.snapshot_id,
        resource_version: full.resource_version,
        generation: full.generation,
        desired_state_resource_key: full.desired_state_resource_key,
        expected_desired_state_generation: full.expected_desired_state_generation,
        expected_desired_state_bundle_id: full.expected_desired_state_bundle_id,
        technical_policy: full.technical_policy,
        confirmation_required: full.confirmation_required,
        desired_state_write_authorized: full.desired_state_write_authorized,
        infrastructure_mutation_authorized: full.infrastructure_mutation_authorized,
        external_publication_authorized: full.external_publication_authorized,
      }, null, 2);
      fullInspector.hidden = false;
    }
    clearRollbackConfirmation();
    if (activePolicyResourceKey) loadHistory(activePolicyResourceKey);
    message('Проверьте правила. Изменения ещё не применены.');
  }

  async function planPolicy(event) {
    event.preventDefault();
    const button = event.submitter;
    const memberId = byId('policy-member')?.value;
    if (!memberId) return;
    resetPreview();
    message('Формируем точный план…');
    button.disabled = true;
    try {
      const {response, data} = await request('/api/v1/household/policies/plan', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-policy-plan-request.v1',
          member_id: memberId,
        }),
      });
      if (!response.ok) {
        message(errorMessage(data, 'Не удалось подготовить правила.'), 'error');
        return;
      }
      renderPlan(data);
    } catch (_) {
      resetPreview();
      message('Home Center вернул непроверяемый план или соединение недоступно.', 'error');
    } finally {
      button.disabled = false;
    }
  }

  async function confirmPolicy(event) {
    const button = event.currentTarget;
    if (!activeProposalId || !activePolicyResourceKey) return;
    const proposalId = activeProposalId;
    const resourceKey = activePolicyResourceKey;
    button.disabled = true;
    message('Применяем подтверждённые правила…');
    try {
      const {response, data} = await request('/api/v1/household/policies/confirm', {
        method: 'POST',
        body: JSON.stringify({
          schema: 'home-center.household-policy-confirm-request.v1',
          proposal_id: proposalId,
          confirmed: true,
        }),
      });
      if (!response.ok) {
        message(errorMessage(data, 'Правила не применены. Сформируйте план заново.'), 'error');
        return;
      }
      if (!safeApplyResponse(data, proposalId, resourceKey)) {
        message('Home Center не подтвердил безопасное сохранение точной ревизии правил.', 'error');
        return;
      }
      activeProposalId = null;
      button.disabled = true;
      message('Правила сохранены. Техническое выполнение на устройствах этим действием не запускается.', 'success');
      await loadHistory(resourceKey);
    } catch (_) {
      message('Не удалось связаться с Home Center. Повторное подтверждение безопасно и идемпотентно.', 'error');
    }
  }

  const form = byId('policy-plan-form');
  const confirm = byId('policy-confirm-button');
  const familyTab = byId('cozy-tab-family');
  const memberSelect = byId('policy-member');
  const rollbackConfirm = byId('policy-rollback-confirm-button');
  const rollbackCancel = byId('policy-rollback-cancel-button');
  if (!form || !confirm || !familyTab || !memberSelect || !rollbackConfirm || !rollbackCancel) return;

  form.addEventListener('submit', planPolicy);
  confirm.addEventListener('click', confirmPolicy);
  memberSelect.addEventListener('change', resetPreview);
  familyTab.addEventListener('click', loadMembers);
  rollbackConfirm.addEventListener('click', confirmRollback);
  rollbackCancel.addEventListener('click', clearRollbackConfirmation);
  window.addEventListener('load', loadMembers, {once: true});
})();