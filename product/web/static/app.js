const $ = (selector) => document.querySelector(selector);

function card(node) {
  const el = document.createElement('article');
  el.className = 'node-card';
  const name = document.createElement('strong');
  name.textContent = node.name || node.hostname || node.node_id || node.id || 'Узел';
  const meta = document.createElement('small');
  const role = node.role || node.state || 'managed';
  const address = node.address || node.management_address || 'адрес определяется при подключении';
  meta.textContent = `${role} · ${address}`;
  el.append(name, meta);
  return el;
}

function renderNodes(nodes) {
  const root = $('#nodes');
  root.replaceChildren();
  if (!Array.isArray(nodes) || nodes.length === 0) {
    root.textContent = 'Узлы ещё не обнаружены или не подключены.';
    return;
  }
  nodes.forEach((node) => root.append(card(node)));
}

function renderCapabilities(values) {
  const root = $('#capabilities');
  root.textContent = Array.isArray(values) && values.length ? values.join(' · ') : 'Данные появятся после discovery/enrollment.';
}

async function loadState() {
  try {
    const response = await fetch('/api/v1/infrastructure', {headers: {'Accept': 'application/json'}});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    renderNodes(data.nodes || []);
    renderCapabilities(data.capabilities || []);
    if (data.version) $('#version').textContent = data.version;
  } catch (_) {
    renderNodes([]);
    renderCapabilities([]);
  }
}

loadState();
