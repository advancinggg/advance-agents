const API_VERSION = "2026-06-30";
const WS_PROTOCOL = "advance.client.2026-06-30";
const state = { token: "", csrf: "", socket: null, eventCursor: null, reconnectTimer: null };
const cf = /[\u00ad\u0600-\u0605\u061c\u06dd\u070f\u0890-\u0891\u08e2\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb]/gu;

function safeText(value) {
  const source = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const text = source.replace(cf, "");
  return { text, changed: text !== source };
}

function render(container, value, actions = []) {
  const fragment = document.querySelector("#record-template").content.cloneNode(true);
  const safe = safeText(value);
  const article = fragment.querySelector("article");
  const pre = fragment.querySelector("pre");
  pre.textContent = safe.text;
  pre.dir = "auto";
  fragment.querySelector(".warning").hidden = !safe.changed;
  const actionBar = fragment.querySelector(".actions");
  for (const action of actions) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = action.label;
    button.addEventListener("click", action.run, { once: true });
    actionBar.append(button);
  }
  container.append(article);
}

async function request(path, { method = "GET", body, mutation = false } = {}) {
  if (!path.startsWith("/client/")) throw new Error("public Client API path required");
  const headers = { "x-advance-api-version": API_VERSION };
  if (state.token) headers.authorization = `Bearer ${state.token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  if (mutation) {
    headers["x-csrf-token"] = state.csrf;
    headers["idempotency-key"] = crypto.randomUUID();
  }
  const response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const envelope = await response.json();
  if (!response.ok || envelope.error) throw new Error(envelope.error?.message || `HTTP ${response.status}`);
  return envelope.data;
}

document.querySelector("#login-form").addEventListener("submit", async event => {
  event.preventDefault();
  const code = document.querySelector("#bootstrap-code").value;
  const data = await request("/client/session/login", {
    method: "POST",
    body: { bootstrap_code: code, platform: "web" },
  });
  state.token = data.token;
  state.csrf = data.csrf_token || "";
  document.querySelector("#connection").textContent = "connected";
  await refreshGrants();
  connectDashboard();
});

document.querySelector("#history-form").addEventListener("submit", async event => {
  event.preventDefault();
  const kind = document.querySelector("#history-kind").value;
  const id = encodeURIComponent(document.querySelector("#history-id").value);
  const data = await request(`/client/${kind}/${id}/history`);
  const target = document.querySelector("#history");
  target.replaceChildren();
  for (const item of data.entries || []) render(target, item);
});

async function decide(grant, action) {
  const encoded = encodeURIComponent(grant.request_id);
  const body = { decision_revision: grant.decision_revision };
  if (action === "deny") {
    const reason = window.prompt("Reason for denial");
    if (!reason) return;
    body.reason = reason;
  }
  await request(`/client/grants/pending/${encoded}:${action}`, { method: "POST", body, mutation: true });
  await refreshGrants();
}

async function refreshGrants() {
  const target = document.querySelector("#grants");
  target.replaceChildren();
  const data = await request("/client/grants/pending");
  for (const grant of data.requests || []) {
    render(target, grant, [
      { label: "Approve", run: () => decide(grant, "approve") },
      { label: "Deny", run: () => decide(grant, "deny") },
    ]);
  }
}
document.querySelector("#refresh-grants").addEventListener("click", refreshGrants);

function connectDashboard() {
  if (state.socket) state.socket.close();
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  state.socket = new WebSocket(
    `${protocol}//${location.host}/client/events/stream`,
    [WS_PROTOCOL, `advance.bearer.${state.token}`],
  );
  state.socket.addEventListener("open", () => {
    if (state.eventCursor) state.socket.send(JSON.stringify(state.eventCursor));
  });
  state.socket.addEventListener("message", event => {
    const envelope = JSON.parse(event.data);
    if (envelope.error) throw new Error(envelope.error.message);
    if (envelope.data?.cursor) {
      state.eventCursor = {
        stream_id: envelope.data.cursor.stream_id,
        last_event_id: envelope.data.cursor.last_event_id,
      };
    }
    for (const item of envelope.data?.events || []) render(document.querySelector("#events"), item);
  });
  state.socket.addEventListener("close", () => {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = setTimeout(connectDashboard, 2000);
  });
}
