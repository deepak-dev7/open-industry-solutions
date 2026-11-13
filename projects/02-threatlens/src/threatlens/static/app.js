"use strict";

const VIEW_TITLES = {
  dashboard: ["Security Operations Center", "Real-time authentication telemetry & MITRE ATT&CK correlation"],
  ingest: ["Ingest Security Logs", "Upload syslog/auth.log, Windows JSON, CloudTrail, or launch attack scenarios"],
  incidents: ["Security Incident Queue", "Correlated attack campaigns, threat scores, and triage queue"],
  "incident-detail": ["Forensic Incident Analysis", "Attack progression timeline, raw event evidence, and response actions"],
  events: ["Security Event Explorer", "Search and filter normalized authentication and identity events"],
  ioc: ["Threat Intelligence IOC Feeds", "Active Tor exit nodes, botnet subnets, and malicious scanner indicators"],
  settings: ["Detection Rules & Policies", "Configurable behavioral thresholds, burst windows, and working hours"],
  help: ["MITRE ATT&CK & Architecture", "Enterprise attack technique taxonomy and ThreatLens defense principles"],
};

let currentIncidentId = null;

function dom(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}

function clearNode(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function showAlert(msg) {
  const box = document.getElementById("soc-alert");
  box.textContent = msg;
  box.classList.remove("hidden");
}

function hideAlert() {
  document.getElementById("soc-alert").classList.add("hidden");
}

function showToast(msg) {
  const box = document.getElementById("soc-toast");
  box.textContent = msg;
  box.classList.remove("hidden");
  setTimeout(() => box.classList.add("hidden"), 3500);
}

async function fetchJson(url, options = {}) {
  const resp = await fetch(url, options);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.detail || data.error || `HTTP error ${resp.status}`);
  }
  return data;
}

function switchView(viewName) {
  hideAlert();
  document.querySelectorAll(".soc-view").forEach((v) => v.classList.add("hidden"));
  const target = document.getElementById(`view-${viewName}`);
  if (target) target.classList.remove("hidden");

  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === viewName);
  });

  const [t, s] = VIEW_TITLES[viewName] || ["ThreatLens", ""];
  document.getElementById("view-header-title").textContent = t;
  document.getElementById("view-header-subtitle").textContent = s;
  document.getElementById("soc-sidebar").classList.remove("open");

  if (viewName === "dashboard") loadDashboard();
  if (viewName === "ingest") loadScenarios();
  if (viewName === "incidents") loadIncidents();
  if (viewName === "events") loadEvents();
  if (viewName === "ioc") loadIOCs();
  if (viewName === "settings") {
    loadSettings();
    loadAuditLogs();
  }
}

async function checkHealth() {
  try {
    const data = await fetchJson("/api/health");
    const dot = document.getElementById("system-status-dot");
    dot.style.backgroundColor = "var(--color-success)";
    dot.style.boxShadow = "0 0 8px var(--color-success)";
    document.getElementById("system-status-title").textContent = "SOC Engine Active";
    document.getElementById("system-status-sub").textContent = `ThreatLens v${data.version} · ${data.ioc_count} IOCs`;
  } catch (err) {
    const dot = document.getElementById("system-status-dot");
    dot.style.backgroundColor = "var(--color-critical)";
    dot.style.boxShadow = "0 0 8px var(--color-critical)";
    document.getElementById("system-status-title").textContent = "API Disconnected";
  }
}

async function loadDashboard() {
  try {
    const data = await fetchJson("/api/dashboard");
    document.getElementById("kpi-total-events").textContent = (data.total_events || 0).toLocaleString();
    document.getElementById("kpi-active-incidents").textContent = (data.active_incidents || 0).toLocaleString();
    document.getElementById("nav-active-count").textContent = (data.active_incidents || 0).toString();
    document.getElementById("kpi-critical-sub").textContent = `${data.severity_breakdown.critical || 0} Critical Alerts`;
    document.getElementById("kpi-failed-logins").textContent = (data.failed_logins || 0).toLocaleString();
    document.getElementById("kpi-unique-ips").textContent = `From ${data.unique_ips || 0} unique IPs`;
    document.getElementById("kpi-unique-users").textContent = (data.unique_users || 0).toLocaleString();

    // Severity bars
    const sev = data.severity_breakdown || {};
    const maxVal = Math.max(1, sev.critical || 0, sev.high || 0, sev.medium || 0, sev.low || 0);
    document.getElementById("bar-crit").style.width = `${Math.round(((sev.critical || 0) / maxVal) * 100)}%`;
    document.getElementById("count-crit").textContent = (sev.critical || 0).toString();
    document.getElementById("bar-high").style.width = `${Math.round(((sev.high || 0) / maxVal) * 100)}%`;
    document.getElementById("count-high").textContent = (sev.high || 0).toString();
    document.getElementById("bar-med").style.width = `${Math.round(((sev.medium || 0) / maxVal) * 100)}%`;
    document.getElementById("count-med").textContent = (sev.medium || 0).toString();
    document.getElementById("bar-low").style.width = `${Math.round(((sev.low || 0) / maxVal) * 100)}%`;
    document.getElementById("count-low").textContent = (sev.low || 0).toString();

    // Top Attacker IPs
    const ipWrap = document.getElementById("top-attackers-list");
    clearNode(ipWrap);
    if (!data.top_attacker_ips || data.top_attacker_ips.length === 0) {
      ipWrap.appendChild(dom("div", "empty-state-muted", "No threat origin IPs recorded yet."));
    } else {
      for (const ip of data.top_attacker_ips) {
        const item = dom("div", "timeline-item");
        const left = dom("div", "timeline-time");
        left.appendChild(dom("strong", "mono", ip.source_ip));
        const right = dom("div");
        right.appendChild(dom("div", null, `${ip.geo_city || "Unknown"}, ${ip.geo_country || "Unknown"}`));
        right.appendChild(dom("div", "text-dim", `${ip.count} failed login attempts`));
        item.appendChild(left);
        item.appendChild(right);
        ipWrap.appendChild(item);
      }
    }

    // Recent Incidents
    renderIncidentsTable(document.getElementById("recent-incidents-table"), data.recent_incidents || []);
  } catch (err) {
    showAlert(err.message);
  }
}

function renderIncidentsTable(container, incidents) {
  clearNode(container);
  if (!incidents || incidents.length === 0) {
    container.appendChild(dom("div", "empty-state-muted", "No incidents detected."));
    return;
  }

  const table = dom("table");
  const thead = dom("thead");
  const hrow = dom("tr");
  for (const h of ["ID", "Severity", "Risk", "MITRE", "Title", "Adversary IP", "Target", "Status", "Action"]) {
    hrow.appendChild(dom("th", null, h));
  }
  thead.appendChild(hrow);
  table.appendChild(thead);

  const tbody = dom("tbody");
  for (const inc of incidents) {
    const tr = dom("tr");
    tr.appendChild(dom("td", "mono", inc.id));
    
    const sevTd = dom("td");
    sevTd.appendChild(dom("span", `badge badge-${inc.severity}`, inc.severity.toUpperCase()));
    tr.appendChild(sevTd);

    tr.appendChild(dom("td", "mono", `${inc.risk_score}/100`));
    tr.appendChild(dom("td", "mono", inc.mitre_id));
    tr.appendChild(dom("td", null, inc.title));
    tr.appendChild(dom("td", "mono", inc.primary_ip));
    tr.appendChild(dom("td", "mono", inc.primary_user));

    const statusTd = dom("td");
    statusTd.appendChild(dom("span", `status-badge status-${inc.status}`, inc.status.toUpperCase()));
    tr.appendChild(statusTd);

    const actTd = dom("td");
    const openBtn = dom("button", "btn btn-outline btn-sm", "Investigate");
    openBtn.type = "button";
    openBtn.addEventListener("click", () => openIncidentDetail(inc.id));
    actTd.appendChild(openBtn);
    tr.appendChild(actTd);

    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

async function loadScenarios() {
  try {
    const data = await fetchJson("/api/scenarios");
    const grid = document.getElementById("scenarios-grid");
    clearNode(grid);

    for (const sc of data.scenarios) {
      const card = dom("div", "scenario-card");
      const top = dom("div");
      top.appendChild(dom("div", "scenario-title", sc.title));
      top.appendChild(dom("div", "scenario-desc", sc.description));
      card.appendChild(top);

      const foot = dom("div", "dashboard-split-row");
      const runBtn = dom("button", "btn btn-primary btn-sm", "Simulate & Analyze");
      runBtn.type = "button";
      runBtn.addEventListener("click", () => triggerScenario(sc.key));
      foot.appendChild(runBtn);
      card.appendChild(foot);

      grid.appendChild(card);
    }
  } catch (err) {
    showAlert(err.message);
  }
}

async function triggerScenario(key) {
  hideAlert();
  try {
    const res = await fetchJson("/api/ingest/scenario", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario_key: key }),
    });
    showToast(`Simulation ingested: ${res.events_count} events, ${res.incidents_count} incidents.`);
    showIngestResults(res);
  } catch (err) {
    showAlert(err.message);
  }
}

function showIngestResults(res) {
  const p = document.getElementById("ingest-results-panel");
  p.classList.remove("hidden");

  const strip = document.getElementById("ingest-stats-strip");
  clearNode(strip);
  strip.appendChild(dom("span", "tag-meta", `Source: ${res.filename}`));
  strip.appendChild(dom("span", "tag-meta", `Format: ${res.detected_format.toUpperCase()}`));
  strip.appendChild(dom("span", "tag-meta", `Events: ${res.events_count}`));
  strip.appendChild(dom("span", "tag-meta", `Incidents: ${res.incidents_count}`));
  strip.appendChild(dom("span", "tag-meta", `Processing Time: ${res.duration_ms} ms`));

  renderIncidentsTable(document.getElementById("ingest-incidents-table"), res.incidents || []);
  loadDashboard();
}

async function loadIncidents() {
  const sev = document.getElementById("incident-severity-select").value;
  const status = document.getElementById("incident-status-select").value;
  const q = document.getElementById("incident-search-input").value.trim();

  const params = new URLSearchParams();
  if (sev) params.set("severity", sev);
  if (status) params.set("status", status);
  if (q) params.set("search", q);

  try {
    const data = await fetchJson(`/api/incidents?${params.toString()}`);
    renderIncidentsTable(document.getElementById("incidents-full-table"), data.incidents || []);
  } catch (err) {
    showAlert(err.message);
  }
}

async function openIncidentDetail(incidentId) {
  currentIncidentId = incidentId;
  switchView("incident-detail");
  hideAlert();

  try {
    const inc = await fetchJson(`/api/incidents/${encodeURIComponent(incidentId)}`);
    document.getElementById("detail-id").textContent = inc.id;
    document.getElementById("detail-title").textContent = inc.title;
    document.getElementById("detail-mitre").textContent = `${inc.mitre_id} (${inc.mitre_name})`;
    document.getElementById("detail-risk").textContent = `${inc.risk_score} / 100`;
    document.getElementById("detail-ip").textContent = inc.primary_ip;
    document.getElementById("detail-user").textContent = inc.primary_user;
    document.getElementById("detail-count").textContent = String(inc.event_count);

    const badge = document.getElementById("detail-sev-badge");
    badge.className = `badge badge-${inc.severity}`;
    badge.textContent = inc.severity.toUpperCase();

    document.getElementById("detail-status-select").value = inc.status;
    document.getElementById("detail-notes-input").value = inc.analyst_notes || "";

    // Render Timeline
    const tl = document.getElementById("detail-timeline");
    clearNode(tl);
    const events = inc.events || [];
    document.getElementById("timeline-event-count").textContent = `${events.length} Correlated Events`;

    for (const ev of events) {
      const item = dom("div", "timeline-item");
      const left = dom("div", "timeline-time");
      left.appendChild(dom("div", null, ev.timestamp.slice(11, 19) + " UTC"));
      left.appendChild(dom("div", "text-dim", ev.timestamp.slice(0, 10)));
      item.appendChild(left);

      const right = dom("div");
      const top = dom("div");
      top.appendChild(dom("strong", "mono", ev.event_type));
      top.appendChild(dom("span", "text-dim", ` · User: ${ev.username} · IP: ${ev.source_ip} (${ev.geo_city}, ${ev.geo_country})`));
      right.appendChild(top);
      right.appendChild(dom("div", "text-dim", ev.raw_message));
      item.appendChild(right);

      tl.appendChild(item);
    }

    // Render Evidence Table
    const et = document.getElementById("detail-evidence-table");
    clearNode(et);
    const table = dom("table");
    const thead = dom("thead");
    const hr = dom("tr");
    for (const h of ["ID", "Time (UTC)", "Type", "Status", "User", "Source IP", "Location", "Raw Log Snippet"]) {
      hr.appendChild(dom("th", null, h));
    }
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = dom("tbody");
    for (const ev of events) {
      const row = dom("tr");
      row.appendChild(dom("td", "mono", ev.id));
      row.appendChild(dom("td", "mono", ev.timestamp));
      row.appendChild(dom("td", "mono", ev.event_type));
      row.appendChild(dom("td", null, ev.status.toUpperCase()));
      row.appendChild(dom("td", "mono", ev.username));
      row.appendChild(dom("td", "mono", ev.source_ip));
      row.appendChild(dom("td", null, `${ev.geo_city}, ${ev.geo_country}`));
      row.appendChild(dom("td", "text-dim mono", ev.raw_message));
      tbody.appendChild(row);
    }
    table.appendChild(tbody);
    et.appendChild(table);

  } catch (err) {
    showAlert(err.message);
  }
}

async function loadEvents() {
  const q = document.getElementById("event-search-input").value.trim();
  const u = document.getElementById("event-user-filter").value.trim();
  const ip = document.getElementById("event-ip-filter").value.trim();
  const st = document.getElementById("event-status-filter").value;

  const params = new URLSearchParams();
  if (q) params.set("search", q);
  if (u) params.set("username", u);
  if (ip) params.set("ip", ip);
  if (st) params.set("status", st);

  try {
    const data = await fetchJson(`/api/events?${params.toString()}`);
    const wrap = document.getElementById("events-full-table");
    clearNode(wrap);

    const events = data.events || [];
    if (events.length === 0) {
      wrap.appendChild(dom("div", "empty-state-muted", "No security events match the filters."));
      return;
    }

    const table = dom("table");
    const thead = dom("thead");
    const hr = dom("tr");
    for (const h of ["ID", "Timestamp (UTC)", "Event Type", "Status", "User", "IP Address", "Geo Location", "Target Host"]) {
      hr.appendChild(dom("th", null, h));
    }
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = dom("tbody");
    for (const ev of events) {
      const tr = dom("tr");
      tr.appendChild(dom("td", "mono", ev.id));
      tr.appendChild(dom("td", "mono", ev.timestamp));
      tr.appendChild(dom("td", "mono", ev.event_type));
      tr.appendChild(dom("td", null, ev.status.toUpperCase()));
      tr.appendChild(dom("td", "mono", ev.username));
      tr.appendChild(dom("td", "mono", ev.source_ip));
      tr.appendChild(dom("td", null, `${ev.geo_city}, ${ev.geo_country}`));
      tr.appendChild(dom("td", "text-dim", ev.target_host));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
  } catch (err) {
    showAlert(err.message);
  }
}

async function loadIOCs() {
  try {
    const data = await fetchJson("/api/ioc");
    const wrap = document.getElementById("ioc-list-table");
    clearNode(wrap);

    const iocs = data.iocs || [];
    if (iocs.length === 0) {
      wrap.appendChild(dom("div", "empty-state-muted", "No active threat intelligence IOCs configured."));
      return;
    }

    const table = dom("table");
    const thead = dom("thead");
    const hr = dom("tr");
    for (const h of ["Type", "Indicator", "Threat Category", "Severity", "Description", "Action"]) {
      hr.appendChild(dom("th", null, h));
    }
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = dom("tbody");
    for (const ioc of iocs) {
      const tr = dom("tr");
      tr.appendChild(dom("td", "mono", ioc.ioc_type.toUpperCase()));
      tr.appendChild(dom("td", "mono", ioc.indicator));
      tr.appendChild(dom("td", null, ioc.threat_type));
      
      const sevTd = dom("td");
      sevTd.appendChild(dom("span", `badge badge-${ioc.severity}`, ioc.severity.toUpperCase()));
      tr.appendChild(sevTd);

      tr.appendChild(dom("td", "text-dim", ioc.description));

      const actTd = dom("td");
      const delBtn = dom("button", "btn btn-danger btn-sm", "Remove");
      delBtn.type = "button";
      delBtn.addEventListener("click", async () => {
        try {
          await fetchJson(`/api/ioc/${ioc.id}`, { method: "DELETE" });
          showToast(`Removed IOC ${ioc.indicator}`);
          loadIOCs();
          checkHealth();
        } catch (e) {
          showAlert(e.message);
        }
      });
      actTd.appendChild(delBtn);
      tr.appendChild(actTd);
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
  } catch (err) {
    showAlert(err.message);
  }
}

async function loadSettings() {
  try {
    const s = await fetchJson("/api/settings");
    document.getElementById("set-bf-threshold").value = s.brute_force_threshold || 5;
    document.getElementById("set-bf-window").value = s.brute_force_window_sec || 300;
    document.getElementById("set-spray-threshold").value = s.spray_user_threshold || 4;
    document.getElementById("set-spray-window").value = s.spray_window_sec || 600;
    document.getElementById("set-travel-speed").value = s.impossible_travel_max_kmh || 850.0;
    document.getElementById("set-work-start").value = s.work_hours_start !== undefined ? s.work_hours_start : 8;
    document.getElementById("set-work-end").value = s.work_hours_end !== undefined ? s.work_hours_end : 19;
    document.getElementById("set-priv-users").value = (s.privileged_accounts || []).join(", ");
  } catch (err) {
    showAlert(err.message);
  }
}

async function loadAuditLogs() {
  try {
    const data = await fetchJson("/api/audit-logs");
    const wrap = document.getElementById("audit-trail-list");
    clearNode(wrap);

    const logs = data.logs || [];
    if (logs.length === 0) {
      wrap.appendChild(dom("div", "empty-state-muted", "No audit actions logged yet."));
      return;
    }

    for (const log of logs) {
      const item = dom("div", "audit-entry");
      const head = dom("div");
      head.appendChild(dom("strong", "mono", log.action));
      head.appendChild(dom("span", "text-dim", ` · ${log.timestamp}`));
      item.appendChild(head);
      item.appendChild(dom("div", "text-dim mono", `Target: ${log.target} | ${log.details}`));
      wrap.appendChild(item);
    }
  } catch (err) {
    showAlert(err.message);
  }
}

// EVENT LISTENERS INITIALIZATION
document.addEventListener("DOMContentLoaded", () => {
  checkHealth();
  loadDashboard();

  // Navigation
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchView(btn.dataset.view));
  });

  document.getElementById("mobile-toggle").addEventListener("click", () => {
    document.getElementById("soc-sidebar").classList.toggle("open");
  });

  document.getElementById("quick-scenario-btn").addEventListener("click", () => switchView("ingest"));
  document.getElementById("quick-ingest-btn").addEventListener("click", () => switchView("ingest"));
  document.getElementById("dash-view-all-btn").addEventListener("click", () => switchView("incidents"));
  document.getElementById("back-to-incidents-btn").addEventListener("click", () => switchView("incidents"));

  // Drop zone file selection
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("log-file-input");
  const browseBtn = document.getElementById("browse-file-btn");

  browseBtn.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      document.getElementById("selected-filename").textContent = fileInput.files[0].name;
      document.getElementById("file-info-bar").classList.remove("hidden");
    }
  });

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      document.getElementById("selected-filename").textContent = fileInput.files[0].name;
      document.getElementById("file-info-bar").classList.remove("hidden");
    }
  });

  // File Upload Form
  document.getElementById("upload-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!fileInput.files || fileInput.files.length === 0) {
      showAlert("Please select a log file to upload.");
      return;
    }
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    hideAlert();
    try {
      const res = await fetchJson("/api/ingest/upload", {
        method: "POST",
        body: formData,
      });
      showToast(`Uploaded ${res.filename}: ${res.events_count} events parsed.`);
      showIngestResults(res);
    } catch (err) {
      showAlert(err.message);
    }
  });

  // Raw Text Paste Form
  document.getElementById("paste-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = document.getElementById("paste-text-area").value.trim();
    if (!text) {
      showAlert("Please enter log content to ingest.");
      return;
    }
    const fmt = document.getElementById("paste-format-hint").value;

    hideAlert();
    try {
      const res = await fetchJson("/api/ingest/text", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, format_hint: fmt }),
      });
      showToast(`Ingested raw text: ${res.events_count} events parsed.`);
      showIngestResults(res);
    } catch (err) {
      showAlert(err.message);
    }
  });

  // Detail Triage Form
  document.getElementById("detail-triage-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!currentIncidentId) return;
    const st = document.getElementById("detail-status-select").value;
    const notes = document.getElementById("detail-notes-input").value.trim();

    try {
      await fetchJson(`/api/incidents/${encodeURIComponent(currentIncidentId)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: st, analyst_notes: notes }),
      });
      showToast("Incident triage status updated.");
      loadDashboard();
    } catch (err) {
      showAlert(err.message);
    }
  });

  // Detail Export Handlers
  document.getElementById("export-inc-json-btn").addEventListener("click", () => {
    if (currentIncidentId) window.location.href = `/api/incidents/${encodeURIComponent(currentIncidentId)}/export?format=json`;
  });
  document.getElementById("export-inc-csv-btn").addEventListener("click", () => {
    if (currentIncidentId) window.location.href = `/api/incidents/${encodeURIComponent(currentIncidentId)}/export?format=csv`;
  });
  document.getElementById("export-inc-md-btn").addEventListener("click", () => {
    if (currentIncidentId) window.location.href = `/api/incidents/${encodeURIComponent(currentIncidentId)}/export?format=markdown`;
  });

  // Incident Filters
  document.getElementById("incident-search-input").addEventListener("input", loadIncidents);
  document.getElementById("incident-severity-select").addEventListener("change", loadIncidents);
  document.getElementById("incident-status-select").addEventListener("change", loadIncidents);
  document.getElementById("refresh-incidents-btn").addEventListener("click", loadIncidents);

  // Event Explorer Filters
  document.getElementById("event-search-input").addEventListener("input", loadEvents);
  document.getElementById("event-user-filter").addEventListener("input", loadEvents);
  document.getElementById("event-ip-filter").addEventListener("input", loadEvents);
  document.getElementById("event-status-filter").addEventListener("change", loadEvents);
  document.getElementById("refresh-events-btn").addEventListener("click", loadEvents);

  // Add IOC Form
  document.getElementById("add-ioc-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    hideAlert();
    const type = document.getElementById("ioc-type-select").value;
    const indicator = document.getElementById("ioc-indicator-input").value.trim();
    const threat_type = document.getElementById("ioc-threat-type-input").value;
    const severity = document.getElementById("ioc-severity-select").value;
    const description = document.getElementById("ioc-desc-input").value.trim();

    try {
      await fetchJson("/api/ioc", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc_type: type, indicator, threat_type, severity, description }),
      });
      showToast(`Added threat indicator ${indicator}`);
      document.getElementById("ioc-indicator-input").value = "";
      document.getElementById("ioc-desc-input").value = "";
      loadIOCs();
      checkHealth();
    } catch (err) {
      showAlert(err.message);
    }
  });

  // Settings Form
  document.getElementById("settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    hideAlert();
    const users = document.getElementById("set-priv-users").value.split(",").map((u) => u.trim()).filter(Boolean);
    const body = {
      brute_force_threshold: Number(document.getElementById("set-bf-threshold").value),
      brute_force_window_sec: Number(document.getElementById("set-bf-window").value),
      spray_user_threshold: Number(document.getElementById("set-spray-threshold").value),
      spray_window_sec: Number(document.getElementById("set-spray-window").value),
      impossible_travel_max_kmh: Number(document.getElementById("set-travel-speed").value),
      work_hours_start: Number(document.getElementById("set-work-start").value),
      work_hours_end: Number(document.getElementById("set-work-end").value),
      privileged_accounts: users,
    };

    try {
      await fetchJson("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      showToast("Detection policy thresholds updated.");
      loadAuditLogs();
    } catch (err) {
      showAlert(err.message);
    }
  });

  document.getElementById("refresh-audit-btn").addEventListener("click", loadAuditLogs);
});
