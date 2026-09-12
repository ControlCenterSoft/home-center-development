(() => {
  'use strict';

  const byId = (id) => document.getElementById(id);
  let activeProposalId = null;
  let loadingMembers = false;

  function message(text, kind = '') {
    const node = byId('policy-message');
    if (!node) return;
    node.textContent = text || '';
    node.dataset.kind = kind;
  }

  function setComposerVisible(visible) {
    const card = byId('policy-composer-card');
    if (card) card.hidden = !visible;
  }

  function resetPreview() {
    activeProposalId = null;
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

  function renderPlan(data) {
    const proposal = data?.proposal;
    const presentation = data?.presentation;
    const cozy = presentation?.cozy;
    const full = presentation?.full;
    if (!proposal?.proposal_id || !cozy || !full || presentation?.same_policy_evidence !== true) {
      throw new Error('invalid_policy_plan_response');
    }
    activeProposalId = proposal.proposal_id;
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
      message('Не удалось связаться с Home Center.', 'error');
    } finally {
      button.disabled = false;
    }
  }

  async function confirmPolicy(event) {
    const button = event.currentTarget;
    if (!activeProposalId) return;
    const proposalId = activeProposalId;
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
      if (data?.desired_state_materialized !== true) {
        message('Home Center не подтвердил сохранение правил.', 'error');
        return;
      }
      activeProposalId = null;
      button.disabled = true;
      message('Правила сохранены. Техническое выполнение на устройствах этим действием не запускается.', 'success');
    } catch (_) {
      message('Не удалось связаться с Home Center. Повторное подтверждение безопасно и идемпотентно.', 'error');
    }
  }

  const form = byId('policy-plan-form');
  const confirm = byId('policy-confirm-button');
  const familyTab = byId('cozy-tab-family');
  const memberSelect = byId('policy-member');
  if (!form || !confirm || !familyTab || !memberSelect) return;

  form.addEventListener('submit', planPolicy);
  confirm.addEventListener('click', confirmPolicy);
  memberSelect.addEventListener('change', resetPreview);
  familyTab.addEventListener('click', loadMembers);
  window.addEventListener('load', loadMembers, {once: true});
})();