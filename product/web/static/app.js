const $ = (selector) => document.querySelector(selector);
const views = ["#loading-view", "#login-view", "#password-view", "#dashboard-view"];

function showView(selector) {
  for (const view of views) $(view).hidden = view !== selector;
  $("#logout-button").hidden = selector !== "#dashboard-view" && selector !== "#password-view";
}

function setServiceState(text, kind = "neutral") {
  const badge = $("#service-state");
  badge.textContent = text;
  badge.className = `status-badge ${kind}`;
}

function setVersion(value) {
  $("#version").textContent = value ? `версия ${value}` : "Home Center";
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(path, {...options, headers, credentials: "same-origin"});
  let data = null;
  const type = response.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    try { data = await response.json(); } catch (_) { data = null; }
  }
  return {response, data};
}

function errorMessage(data, fallback) {
  return data?.error?.message || fallback;
}

async function loadProviders() {
  try {
    const {response, data} = await request("/api/v1/auth/providers");
    if (!response.ok || !Array.isArray(data?.providers)) return;
    const select = $("#provider");
    const labels = {local: "Локальный администратор", ad: "Доменная учётная запись"};
    const enabled = data.providers.filter((item) => item && item.enabled === true && labels[item.id]);
    if (!enabled.length) return;
    select.replaceChildren(...enabled.map((item) => {
      const option = document.createElement("option");
      option.value = item.id;
      option.textContent = labels[item.id];
      return option;
    }));
  } catch (_) {
    // The local provider remains available as the safe default.
  }
}

function formatBytes(value) {
  if (!Number.isFinite(value) || value < 0) return "—";
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"];
  let number = value;
  let index = 0;
  while (number >= 1024 && index < units.length - 1) {
    number /= 1024;
    index += 1;
  }
  const digits = index > 1 && number < 100 ? 1 : 0;
  return `${number.toFixed(digits)} ${units[index]}`;
}

function stateLabel(value) {
  return ({healthy: "Норма", degraded: "Требует внимания", empty: "Нет данных"})[value] || value || "—";
}

function nodeCard(node) {
  const card = document.createElement("article");
  card.className = "node-card";

  const head = document.createElement("div");
  head.className = "node-card-head";
  const name = document.createElement("div");
  name.className = "node-name";
  const title = document.createElement("strong");
  title.textContent = node.name || node.id || "Узел";
  const subtitle = document.createElement("small");
  subtitle.textContent = `${node.role || "managed"} · ${node.management_address || "адрес не указан"}`;
  name.append(title, subtitle);
  const status = document.createElement("span");
  const normalizedStatus = node.status === "ready" ? "ready" : "unreachable";
  status.className = `node-status ${normalizedStatus}`;
  status.textContent = normalizedStatus === "ready" ? "Готов" : "Недоступен";
  head.append(name, status);

  const meta = document.createElement("div");
  meta.className = "node-meta";
  const metrics = [
    ["Процессоры", Number.isFinite(node.hardware?.cpu_count) ? String(node.hardware.cpu_count) : "—"],
    ["Память", formatBytes(node.hardware?.memory_bytes)],
    ["Диск свободно", formatBytes(node.storage?.root?.free_bytes)],
    ["Система", [node.operating_system?.id, node.operating_system?.version].filter(Boolean).join(" ") || "—"],
  ];
  for (const [label, value] of metrics) {
    const metric = document.createElement("div");
    metric.className = "metric";
    const caption = document.createElement("span");
    caption.textContent = label;
    const strong = document.createElement("strong");
    strong.textContent = value;
    metric.append(caption, strong);
    meta.append(metric);
  }

  const footer = document.createElement("div");
  footer.className = "node-footer";
  const serviceCount = Array.isArray(node.services) ? node.services.length : 0;
  const capabilityCount = Array.isArray(node.capabilities) ? node.capabilities.length : 0;
  for (const text of [`Сервисов: ${serviceCount}`, `Возможностей: ${capabilityCount}`]) {
    const pill = document.createElement("span");
    pill.className = "tiny-pill";
    pill.textContent = text;
    footer.append(pill);
  }

  card.append(head, meta, footer);
  return card;
}

function renderInfrastructure(data) {
  setVersion(data.version);
  const summary = data.summary || {};
  $("#total-nodes").textContent = summary.total_nodes ?? "—";
  $("#ready-nodes").textContent = summary.ready_nodes ?? "—";
  $("#unreachable-nodes").textContent = summary.unreachable_nodes ?? "—";
  $("#cluster-state").textContent = stateLabel(data.state);

  const nodes = $("#nodes");
  nodes.replaceChildren();
  if (!Array.isArray(data.nodes) || data.nodes.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Узлы пока не обнаружены. После подключения серверов они появятся здесь автоматически.";
    nodes.append(empty);
  } else {
    data.nodes.forEach((node) => nodes.append(nodeCard(node)));
  }

  const capabilities = $("#capabilities");
  capabilities.replaceChildren();
  if (!Array.isArray(data.capabilities) || data.capabilities.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Список возможностей пока пуст.";
    capabilities.append(empty);
  } else {
    for (const value of data.capabilities) {
      const pill = document.createElement("span");
      pill.className = "capability";
      pill.textContent = value;
      capabilities.append(pill);
    }
  }

  if (data.state === "healthy") setServiceState("Система в норме", "good");
  else if (data.state === "degraded") setServiceState("Требует внимания", "warn");
  else setServiceState("Сервис доступен", "neutral");
}

async function loadInfrastructure() {
  const message = $("#dashboard-message");
  message.textContent = "";
  try {
    const {response, data} = await request("/api/v1/infrastructure");
    if (response.status === 401) {
      showView("#login-view");
      setServiceState("Нужен вход", "warn");
      return;
    }
    if (response.status === 403 && data?.error?.code === "password_change_required") {
      showView("#password-view");
      setServiceState("Смените пароль", "warn");
      return;
    }
    if (!response.ok || !data) throw new Error(errorMessage(data, `HTTP ${response.status}`));
    renderInfrastructure(data);
  } catch (error) {
    setServiceState("Ошибка данных", "bad");
    message.textContent = `Не удалось получить состояние инфраструктуры: ${error.message || "неизвестная ошибка"}`;
  }
}

async function handleSession(data) {
  if (data?.password_change_required) {
    showView("#password-view");
    setServiceState("Смените пароль", "warn");
    $("#current-password").focus();
    return;
  }
  showView("#dashboard-view");
  setServiceState("Сервис доступен", "good");
  await loadInfrastructure();
}

async function checkSession() {
  try {
    const {response, data} = await request("/api/v1/session");
    if (response.ok && data?.authenticated) {
      await handleSession(data);
      return;
    }
    if (response.status !== 401) setServiceState("Сервис доступен", "neutral");
  } catch (_) {
    setServiceState("Нет связи", "bad");
  }
  showView("#login-view");
  $("#password").focus();
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter;
  const message = $("#login-message");
  message.textContent = "";
  button.disabled = true;
  try {
    const payload = {
      provider: $("#provider").value,
      username: $("#username").value.trim(),
      password: $("#password").value,
    };
    const {response, data} = await request("/api/v1/session", {method: "POST", body: JSON.stringify(payload)});
    if (!response.ok || !data?.authenticated) {
      message.textContent = errorMessage(data, "Не удалось выполнить вход.");
      setServiceState("Вход отклонён", "warn");
      return;
    }
    $("#password").value = "";
    await handleSession(data);
  } catch (_) {
    message.textContent = "Home Center сейчас недоступен. Проверьте соединение и повторите попытку.";
    setServiceState("Нет связи", "bad");
  } finally {
    button.disabled = false;
  }
});

$("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter;
  const message = $("#password-message");
  const currentPassword = $("#current-password").value;
  const newPassword = $("#new-password").value;
  const confirmPassword = $("#confirm-password").value;
  message.textContent = "";
  if (newPassword !== confirmPassword) {
    message.textContent = "Новые пароли не совпадают.";
    return;
  }
  button.disabled = true;
  try {
    const {response, data} = await request("/api/v1/auth/local-admin/password/change", {
      method: "POST",
      body: JSON.stringify({
        schema: "home-center.local-admin-password-change.v1",
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });
    if (!response.ok) {
      message.textContent = errorMessage(data, "Не удалось сменить пароль.");
      return;
    }
    $("#current-password").value = "";
    $("#new-password").value = "";
    $("#confirm-password").value = "";
    await checkSession();
  } catch (_) {
    message.textContent = "Не удалось связаться с Home Center.";
  } finally {
    button.disabled = false;
  }
});

$("#logout-button").addEventListener("click", async () => {
  try { await request("/api/v1/session/logout", {method: "POST"}); } catch (_) {}
  setVersion(null);
  setServiceState("Нужен вход", "neutral");
  showView("#login-view");
  $("#password").value = "";
  $("#password").focus();
});

$("#refresh-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try { await loadInfrastructure(); } finally { button.disabled = false; }
});

Promise.allSettled([loadProviders(), checkSession()]);
