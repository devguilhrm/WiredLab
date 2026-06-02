const HOST_RE = /IP:\s+([0-9a-fA-F:.]+)\s+MAC:\s+([0-9a-fA-F:-]{17})(?:\s+Hostname:\s+([^\s]+))?(?:\s+Vendor:\s+(.+))?/;
const DNS_RE = /^(?=.{1,253}$)([A-Za-z0-9_-]+\.)+[A-Za-z]{2,}\.?$/;
const DNS_QUERY_RE = /DNSQuery\s+SrcIP:\s+(\S+)\s+SrcMAC:\s+([0-9a-fA-F:-]{17})\s+Transport:\s+(\S+)\s+Domain:\s+(.+)/;

const state = {
  tools: {},
  currentTool: "",
  hosts: new Set(),
  dns: new Set(),
  runs: 0,
  alerts: 0,
};

const el = {
  interface: document.getElementById("interface"),
  tool: document.getElementById("tool"),
  mac: document.getElementById("mac"),
  gateway: document.getElementById("gateway"),
  host: document.getElementById("host"),
  fieldMac: document.getElementById("fieldMac"),
  fieldGateway: document.getElementById("fieldGateway"),
  fieldHost: document.getElementById("fieldHost"),
  authorized: document.getElementById("authorized"),
  runBtn: document.getElementById("runBtn"),
  stopBtn: document.getElementById("stopBtn"),
  killBtn: document.getElementById("killBtn"),
  refreshInterfaces: document.getElementById("refreshInterfaces"),
  clearDashboard: document.getElementById("clearDashboard"),
  clearConsole: document.getElementById("clearConsole"),
  deviceFilter: document.getElementById("deviceFilter"),
  runState: document.getElementById("runState"),
  hostsMetric: document.getElementById("hostsMetric"),
  dnsMetric: document.getElementById("dnsMetric"),
  runsMetric: document.getElementById("runsMetric"),
  alertsMetric: document.getElementById("alertsMetric"),
  eventsBody: document.getElementById("eventsBody"),
  console: document.getElementById("console"),
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: {"Content-Type": "application/json"},
    ...options,
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

async function loadTools() {
  state.tools = await api("/api/tools");
  el.tool.innerHTML = "";

  for (const [name, spec] of Object.entries(state.tools)) {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = spec.label || name;
    el.tool.appendChild(option);
  }

  updateFields();
}

async function loadInterfaces() {
  const data = await api("/api/interfaces");
  el.interface.innerHTML = "";

  for (const name of data.interfaces || []) {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    el.interface.appendChild(option);
  }
}

function updateFields() {
  const spec = state.tools[el.tool.value] || {};
  const fields = new Set(spec.fields || []);
  el.fieldMac.classList.toggle("hidden", !fields.has("mac"));
  el.fieldGateway.classList.toggle("hidden", !fields.has("gateway"));
  el.fieldHost.classList.toggle("hidden", !fields.has("host"));
}

async function runTool() {
  const tool = el.tool.value;
  const spec = state.tools[tool] || {};

  if (spec.dangerous && !el.authorized.checked) {
    alert("Confirme uso em rede autorizada antes de executar esta ferramenta.");
    return;
  }

  const payload = {
    tool,
    interface: el.interface.value,
    mac: el.mac.value.trim(),
    gateway: el.gateway.value.trim(),
    host: el.host.value.trim(),
  };

  try {
    await api("/api/run", {method: "POST", body: JSON.stringify(payload)});
  } catch (error) {
    appendConsole(`[error] ${error.message}\n`);
  }
}

async function stopTool() {
  await api("/api/stop", {method: "POST", body: "{}"});
}

async function killTool() {
  await api("/api/kill", {method: "POST", body: "{}"});
}

function connectEvents() {
  const source = new EventSource("/api/events");
  source.onmessage = (message) => {
    const event = JSON.parse(message.data);
    handleEvent(event);
  };
}

function handleEvent(event) {
  if (event.type === "start") {
    state.currentTool = event.tool;
    state.runs += 1;
    if ((state.tools[event.tool] || {}).dangerous) {
      state.alerts += 1;
    }
    setRunning(true, event.tool);
    updateMetrics();
  }

  if (event.text) {
    appendConsole(event.text);
    parseOutput(event.text, event.tool || state.currentTool);
  }

  if (event.type === "exit") {
    setRunning(false, "Idle");
    state.currentTool = "";
  }
}

function setRunning(running, label) {
  el.runState.textContent = running ? `Running: ${label}` : "Idle";
  el.runState.classList.toggle("running", running);
}

function appendConsole(text) {
  el.console.textContent += text;
  el.console.scrollTop = el.console.scrollHeight;
}

function parseOutput(text, tool) {
  for (const raw of text.replace(/\r/g, "\n").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("$ ") || line.startsWith("[exit code")) {
      continue;
    }

    const host = HOST_RE.exec(line);
    if (host) {
      recordHost(host[1], host[2], host[3] || "", host[4] || "", tool);
      continue;
    }

    const dnsQuery = DNS_QUERY_RE.exec(line);
    if (dnsQuery) {
      recordDnsQuery(dnsQuery[1], dnsQuery[2], dnsQuery[3], dnsQuery[4], tool);
      continue;
    }

    if (tool === "dns_scan" && DNS_RE.test(line)) {
      recordDns(line.replace(/\.$/, "").toLowerCase(), tool);
    }
  }
}

function recordHost(ip, mac, hostname, vendor, tool) {
  const key = `${ip}|${mac.toLowerCase()}`;
  if (state.hosts.has(key)) {
    return;
  }

  state.hosts.add(key);
  const info = [hostname, vendor].filter(Boolean).join(" | ");
  addEvent("Host", ip, mac, info, tool);
  updateMetrics();
}

function recordDns(domain, tool) {
  if (state.dns.has(domain)) {
    return;
  }

  state.dns.add(domain);
  addEvent("DNS", domain, "", "query", tool);
  updateMetrics();
}

function recordDnsQuery(srcIp, srcMac, transport, domain, tool) {
  const normalized = domain.replace(/\.$/, "").toLowerCase();
  const key = `${srcIp}|${srcMac.toLowerCase()}|${normalized}`;
  if (state.dns.has(key)) {
    return;
  }

  state.dns.add(key);
  addEvent("DNS", normalized, srcMac, `${srcIp} | ${transport}`, tool);
  updateMetrics();
}

function addEvent(kind, target, mac, info, source) {
  const tr = document.createElement("tr");
  const values = [kind, target, mac, info, source || "", new Date().toLocaleTimeString()];

  for (const value of values) {
    const td = document.createElement("td");
    td.textContent = value;
    tr.appendChild(td);
  }

  el.eventsBody.prepend(tr);
  applyDeviceFilter();
}

function updateMetrics() {
  el.hostsMetric.textContent = state.hosts.size;
  el.dnsMetric.textContent = state.dns.size;
  el.runsMetric.textContent = state.runs;
  el.alertsMetric.textContent = state.alerts;
}

function clearDashboard() {
  state.hosts.clear();
  state.dns.clear();
  state.runs = 0;
  state.alerts = 0;
  el.eventsBody.innerHTML = "";
  updateMetrics();
}

function clearConsole() {
  el.console.textContent = "";
}

function applyDeviceFilter() {
  const needle = el.deviceFilter.value.trim().toLowerCase();

  for (const row of el.eventsBody.querySelectorAll("tr")) {
    const text = row.textContent.toLowerCase();
    row.hidden = Boolean(needle) && !text.includes(needle);
  }
}

el.tool.addEventListener("change", updateFields);
el.runBtn.addEventListener("click", runTool);
el.stopBtn.addEventListener("click", stopTool);
el.killBtn.addEventListener("click", killTool);
el.refreshInterfaces.addEventListener("click", loadInterfaces);
el.clearDashboard.addEventListener("click", clearDashboard);
el.clearConsole.addEventListener("click", clearConsole);
el.deviceFilter.addEventListener("input", applyDeviceFilter);

loadTools();
loadInterfaces();
connectEvents();
