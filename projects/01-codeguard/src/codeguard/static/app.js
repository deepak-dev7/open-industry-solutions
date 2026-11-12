"use strict";

const VIEW_META = {
  dashboard: ["Security & Quality Dashboard", "Real-time posture across persisted local scans"],
  scanner: ["CodeGuard Scanner", "Browse local folders, enter approved paths, or upload a directory"],
  history: ["Scan History & Reports", "Inspect persisted scans, triage findings, and export reports"],
  rules: ["Rules Catalog", "Search built-in CWE-mapped static analysis and secret detection rules"],
  settings: ["Settings & Audit Log", "Manage fail-on policies, approved scan roots, and audit records"],
  help: ["Help & Documentation", "CLI commands, CI integration, inline suppressions, and security model"],
};

const IGNORED_UPLOAD_DIRS = new Set([".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"]);
const MAX_UPLOAD_BYTES = 1024 * 1024;

let activeScan = null;
let allRulesCache = [];
let browserState = { current_path: "", parent_path: null };

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function showError(msg) {
  const box = document.getElementById("global-error");
  box.textContent = msg;
  box.classList.remove("hidden");
}

function showToast(msg) {
  const box = document.getElementById("global-toast");
  box.textContent = msg;
  box.classList.remove("hidden");
  setTimeout(() => box.classList.add("hidden"), 3500);
}

function clearAlerts() {
  document.getElementById("global-error").classList.add("hidden");
}

async function apiJson(url, options = {}) {
  const resp = await fetch(url, options);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.detail || data.error || `Request failed (${resp.status})`);
  }
  return data;
}

function switchView(viewName) {
  clearAlerts();
  document.querySelectorAll(".view").forEach((sec) => sec.classList.add("hidden"));
  document.getElementById(`view-${viewName}`).classList.remove("hidden");
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === viewName);
  });
  const [title, sub] = VIEW_META[viewName] || ["CodeGuard", ""];
  document.getElementById("page-title").textContent = title;
  document.getElementById("page-subtitle").textContent = sub;
  document.getElementById("sidebar").classList.remove("open");

  if (viewName === "dashboard") loadDashboard();
  if (viewName === "history") loadHistory();
  if (viewName === "rules") loadRules();
  if (viewName === "settings") {
    loadSettings();
    loadAuditLogs();
  }
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("codeguard_theme", theme);
  document.getElementById("theme-toggle-btn").textContent = theme === "dark" ? "Light Mode" : "Dark Mode";
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  applyTheme(current === "dark" ? "light" : "dark");
}

async function loadHealth() {
  const dot = document.getElementById("api-status-dot");
  const text = document.getElementById("api-status-text");
  try {
    const data = await apiJson("/api/health");
    dot.style.background = "var(--pass)";
    text.textContent = `API OK · v${data.version}`;
    document.getElementById("sidebar-version").textContent = `OIS · v${data.version} · ${data.rules_count} rules`;
  } catch (err) {
    dot.style.background = "var(--crit)";
    text.textContent = "API Offline";
  }
}

async function loadDashboard() {
  try {
    const data = await apiJson("/api/dashboard");
    const kpiWrap = document.getElementById("dashboard-kpis");
    clear(kpiWrap);
    const kpis = [
      ["Total Scans", data.total_scans],
      ["Files Scanned", data.total_files_scanned],
      ["Open Findings", data.open_findings],
      ["Failed Quality Gates", data.failed_scans],
    ];
    for (const [label, value] of kpis) {
      const card = el("div", "kpi-card");
      card.appendChild(el("div", "kpi-label", label));
      card.appendChild(el("div", "kpi-value", value));
      kpiWrap.appendChild(card);
    }

    const barsWrap = document.getElementById("severity-bars");
    clear(barsWrap);
    const sev = data.severity_breakdown || {};
    const maxCount = Math.max(1, sev.critical || 0, sev.high || 0, sev.medium || 0, sev.low || 0);
    for (const level of ["critical", "high", "medium", "low"]) {
      const count = sev[level] || 0;
      const row = el("div", "bar-row");
      row.appendChild(el("span", null, level.toUpperCase()));
      const track = el("div", "bar-track");
      const fill = el("div", `bar-fill fill-${level}`);
      fill.style.width = `${Math.round((count / maxCount) * 100)}%`;
      track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(el("strong", null, count));
      barsWrap.appendChild(row);
    }

    const topWrap = document.getElementById("top-rules-list");
    clear(topWrap);
    if (!data.top_rules || data.top_rules.length === 0) {
      topWrap.appendChild(el("p", "muted small", "No findings recorded yet. Run your first scan to populate rule telemetry."));
    } else {
      for (const r of data.top_rules) {
        const row = el("div", "audit-item");
        const head = el("div", "finding-top");
        const left = el("div", "finding-meta");
        left.appendChild(el("span", `badge ${r.severity}`, r.severity));
        left.appendChild(el("strong", "mono", r.rule_id));
        left.appendChild(el("span", null, r.rule_name));
        head.appendChild(left);
        head.appendChild(el("strong", null, `${r.count} hits`));
        row.appendChild(head);
        topWrap.appendChild(row);
      }
    }

    renderScanTable(document.getElementById("recent-scans-table"), data.recent_scans || [], false);
  } catch (err) {
    showError(err.message);
  }
}

function renderScanTable(container, scans, allowDelete) {
  clear(container);
  if (scans.length === 0) {
    container.appendChild(el("p", "muted small", "No scans found."));
    return;
  }
  const table = el("table");
  const thead = el("thead");
  const headRow = el("tr");
  for (const h of ["Target", "Type", "Files", "Findings", "Gate", "Time", "Actions"]) {
    headRow.appendChild(el("th", null, h));
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el("tbody");
  for (const s of scans) {
    const tr = el("tr");
    const targetTd = el("td", "mono", s.target_label);
    tr.appendChild(targetTd);
    tr.appendChild(el("td", null, s.source_type));
    tr.appendChild(el("td", null, s.files_scanned));
    tr.appendChild(el("td", null, s.findings_count));
    const gateTd = el("td");
    gateTd.appendChild(el("span", `badge ${s.failed ? "fail" : "pass"}`, s.failed ? "FAIL" : "PASS"));
    tr.appendChild(gateTd);
    tr.appendChild(el("td", "small muted", s.created_at));

    const actTd = el("td");
    const grp = el("div", "btn-group");
    const openBtn = el("button", "btn secondary small", "Open");
    openBtn.type = "button";
    openBtn.addEventListener("click", () => openScanInScanner(s.id));
    grp.appendChild(openBtn);
    if (allowDelete) {
      const delBtn = el("button", "btn danger small", "Delete");
      delBtn.type = "button";
      delBtn.addEventListener("click", () => deleteScanRecord(s.id));
      grp.appendChild(delBtn);
    }
    actTd.appendChild(grp);
    tr.appendChild(actTd);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

async function openScanInScanner(scanId) {
  switchView("scanner");
  await refreshActiveScan(scanId);
}

async function refreshActiveScan(scanId) {
  const sev = document.getElementById("finding-severity-filter").value;
  const status = document.getElementById("finding-status-filter").value;
  const search = document.getElementById("finding-search-input").value.trim();
  const params = new URLSearchParams();
  if (sev) params.set("severity", sev);
  if (status) params.set("status", status);
  if (search) params.set("search", search);

  try {
    activeScan = await apiJson(`/api/scans/${encodeURIComponent(scanId)}?${params.toString()}`);
    renderActiveScan();
  } catch (err) {
    showError(err.message);
  }
}

function renderActiveScan() {
  if (!activeScan) return;
  const card = document.getElementById("active-scan-card");
  card.classList.remove("hidden");

  document.getElementById("active-scan-title").textContent = `Scan: ${activeScan.target_label}`;
  document.getElementById("active-scan-meta").textContent =
    `ID ${activeScan.id.slice(0, 8)} · ${activeScan.created_at} · ${activeScan.duration_ms} ms · Fail threshold: ${activeScan.fail_on}`;

  const stats = document.getElementById("active-scan-stats");
  clear(stats);
  const chips = [
    ["Gate", activeScan.failed ? "FAIL" : "PASS"],
    ["Files Scanned", activeScan.files_scanned],
    ["Skipped", activeScan.files_skipped],
    ["Suppressed", activeScan.suppressed_count],
    ["Total Findings", activeScan.findings_count],
    ["Critical", activeScan.critical_count],
    ["High", activeScan.high_count],
    ["Medium", activeScan.medium_count],
    ["Low", activeScan.low_count],
  ];
  for (const [label, val] of chips) {
    const chip = el("div", "stat-chip");
    chip.appendChild(el("span", "muted", `${label}: `));
    chip.appendChild(el("strong", null, val));
    stats.appendChild(chip);
  }

  const list = document.getElementById("active-findings-list");
  clear(list);
  const findings = activeScan.findings || [];
  if (findings.length === 0) {
    list.appendChild(el("p", "muted", "No findings match the current filters."));
    return;
  }

  for (const f of findings) {
    const fc = el("div", `finding-card sev-${f.severity}`);
    const top = el("div", "finding-top");
    const meta = el("div", "finding-meta");
    meta.appendChild(el("span", `badge ${f.severity}`, f.severity));
    meta.appendChild(el("strong", "mono", f.rule_id));
    meta.appendChild(el("span", "muted small", f.cwe));
    meta.appendChild(el("code", "small", `${f.file_path}:${f.line}:${f.column}`));
    top.appendChild(meta);

    const triageSel = el("select");
    triageSel.style.width = "160px";
    triageSel.setAttribute("aria-label", `Triage status for finding ${f.id}`);
    for (const [val, label] of [["open", "Open"], ["acknowledged", "Acknowledged"], ["false_positive", "False Positive"]]) {
      const opt = el("option", null, label);
      opt.value = val;
      if (f.status === val) opt.selected = true;
      triageSel.appendChild(opt);
    }
    triageSel.addEventListener("change", async () => {
      try {
        await apiJson(`/api/findings/${f.id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: triageSel.value }),
        });
        showToast(`Updated finding #${f.id} to ${triageSel.value}`);
      } catch (err) {
        showError(err.message);
      }
    });
    top.appendChild(triageSel);
    fc.appendChild(top);

    fc.appendChild(el("div", null, f.message));
    if (f.snippet) {
      fc.appendChild(el("pre", "snippet", f.snippet));
    }
    fc.appendChild(el("div", "muted small", `Remediation: ${f.remediation}`));
    list.appendChild(fc);
  }
}

async function runPathScan() {
  clearAlerts();
  const targetPath = document.getElementById("scan-path-input").value.trim();
  if (!targetPath) {
    showError("Please enter or browse to a local folder or file path.");
    return;
  }
  const failOn = document.getElementById("scan-fail-on").value;
  await executeScanRequest("/api/scans/path", { path: targetPath, fail_on: failOn });
}

async function runUploadScan() {
  clearAlerts();
  const input = document.getElementById("folder-upload-input");
  const selected = Array.from(input.files || []);
  if (selected.length === 0) {
    showError("Please select a folder to upload first.");
    return;
  }

  document.getElementById("scan-loading").classList.remove("hidden");
  try {
    const filesPayload = [];
    let skippedClient = 0;
    const firstRel = (selected[0].webkitRelativePath || selected[0].name).replace(/\\/g, "/");
    const folderName = firstRel.split("/")[0] || "uploaded-folder";

    for (const file of selected) {
      const rel = (file.webkitRelativePath || file.name).replace(/\\/g, "/");
      const parts = rel.split("/");
      const ignored = parts.slice(0, -1).some((p) => IGNORED_UPLOAD_DIRS.has(p)) || rel.endsWith(".lock") || rel.endsWith(".min.js");
      if (ignored || file.size > MAX_UPLOAD_BYTES) {
        skippedClient += 1;
        continue;
      }
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let isBin = false;
      for (let i = 0; i < Math.min(bytes.length, 4096); i += 1) {
        if (bytes[i] === 0) {
          isBin = true;
          break;
        }
      }
      if (isBin) {
        skippedClient += 1;
        continue;
      }
      filesPayload.push({ path: rel, content: new TextDecoder("utf-8").decode(bytes) });
    }

    await executeScanRequest("/api/scans/upload", {
      folder_name: folderName,
      fail_on: document.getElementById("scan-fail-on").value,
      client_skipped: skippedClient,
      files: filesPayload,
    });
  } catch (err) {
    document.getElementById("scan-loading").classList.add("hidden");
    showError(err.message);
  }
}

async function executeScanRequest(url, payload) {
  const loader = document.getElementById("scan-loading");
  loader.classList.remove("hidden");
  try {
    activeScan = await apiJson(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    renderActiveScan();
    showToast(`Scan complete: ${activeScan.findings_count} findings across ${activeScan.files_scanned} files.`);
  } catch (err) {
    showError(err.message);
  } finally {
    loader.classList.add("hidden");
  }
}

async function loadHistory() {
  const search = document.getElementById("history-search-input").value.trim();
  const status = document.getElementById("history-status-filter").value;
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (status) params.set("status", status);
  try {
    const data = await apiJson(`/api/scans?${params.toString()}`);
    renderScanTable(document.getElementById("history-table-wrap"), data.scans || [], true);
  } catch (err) {
    showError(err.message);
  }
}

async function deleteScanRecord(scanId) {
  try {
    await apiJson(`/api/scans/${encodeURIComponent(scanId)}`, { method: "DELETE" });
    if (activeScan && activeScan.id === scanId) {
      activeScan = null;
      document.getElementById("active-scan-card").classList.add("hidden");
    }
    showToast("Scan record deleted.");
    loadHistory();
  } catch (err) {
    showError(err.message);
  }
}

async function loadRules() {
  try {
    if (allRulesCache.length === 0) {
      const data = await apiJson("/api/rules");
      allRulesCache = data.rules || [];
    }
    renderRulesCatalog();
  } catch (err) {
    showError(err.message);
  }
}

function renderRulesCatalog() {
  const q = document.getElementById("rules-search-input").value.trim().toLowerCase();
  const sev = document.getElementById("rules-severity-filter").value;
  const wrap = document.getElementById("rules-catalog-list");
  clear(wrap);

  const filtered = allRulesCache.filter((r) => {
    if (sev && r.severity !== sev) return false;
    if (q && !`${r.rule_id} ${r.name} ${r.cwe} ${r.description}`.toLowerCase().includes(q)) return false;
    return true;
  });

  if (filtered.length === 0) {
    wrap.appendChild(el("p", "muted small", "No rules match your filter."));
    return;
  }

  for (const r of filtered) {
    const card = el("div", "rule-card");
    const head = el("div", "finding-meta");
    head.appendChild(el("span", `badge ${r.severity}`, r.severity));
    head.appendChild(el("strong", "mono", r.rule_id));
    head.appendChild(el("span", "muted small", `${r.cwe} · ${r.category}`));
    card.appendChild(head);
    card.appendChild(el("h3", null, r.name));
    card.appendChild(el("p", "small", r.description));
    card.appendChild(el("p", "muted small", `Remediation: ${r.remediation}`));
    wrap.appendChild(card);
  }
}

async function loadSettings() {
  try {
    const s = await apiJson("/api/settings");
    document.getElementById("set-fail-on").value = s.fail_on || "high";
    document.getElementById("set-max-size").value = s.max_file_size_kb || 1024;
    document.getElementById("set-entropy").value = s.entropy_threshold || 4.2;
    document.getElementById("set-allowed-roots").value = (s.allowed_roots || []).join("\n");
    document.getElementById("set-disabled-rules").value = (s.disabled_rules || []).join(", ");
    document.getElementById("set-ignore-paths").value = (s.ignore_paths || []).join("\n");
    document.getElementById("set-allowlist").value = (s.allowlist_patterns || []).join("\n");
  } catch (err) {
    showError(err.message);
  }
}

async function saveSettings(event) {
  event.preventDefault();
  clearAlerts();
  const splitLines = (id) =>
    document.getElementById(id).value.split(/\r?\n/).map((v) => v.trim()).filter(Boolean);
  const splitCsv = (id) =>
    document.getElementById(id).value.split(",").map((v) => v.trim()).filter(Boolean);

  try {
    await apiJson("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fail_on: document.getElementById("set-fail-on").value,
        max_file_size_kb: Number(document.getElementById("set-max-size").value),
        entropy_threshold: Number(document.getElementById("set-entropy").value),
        allowed_roots: splitLines("set-allowed-roots"),
        disabled_rules: splitCsv("set-disabled-rules"),
        ignore_paths: splitLines("set-ignore-paths"),
        allowlist_patterns: splitLines("set-allowlist"),
      }),
    });
    showToast("Settings saved to SQLite.");
    loadAuditLogs();
  } catch (err) {
    showError(err.message);
  }
}

async function loadAuditLogs() {
  try {
    const data = await apiJson("/api/audit-logs?limit=40");
    const wrap = document.getElementById("audit-log-list");
    clear(wrap);
    if (!data.logs || data.logs.length === 0) {
      wrap.appendChild(el("p", "muted small", "No audit events recorded yet."));
      return;
    }
    for (const log of data.logs) {
      const item = el("div", "audit-item");
      const top = el("div", "finding-top");
      const left = el("div", "finding-meta");
      left.appendChild(el("strong", "mono", log.action));
      left.appendChild(el("span", `badge ${log.outcome === "success" ? "pass" : "fail"}`, log.outcome));
      top.appendChild(left);
      top.appendChild(el("span", "muted small", log.created_at));
      item.appendChild(top);
      item.appendChild(el("div", "mono small", log.target));
      if (log.details) item.appendChild(el("div", "muted small", log.details));
      wrap.appendChild(item);
    }
  } catch (err) {
    showError(err.message);
  }
}

async function openFolderBrowser(startPath = "") {
  const modal = document.getElementById("folder-modal");
  modal.classList.remove("hidden");
  await browseTo(startPath || document.getElementById("scan-path-input").value.trim());
}

async function browseTo(targetPath) {
  try {
    const params = targetPath ? `?path=${encodeURIComponent(targetPath)}` : "";
    browserState = await apiJson(`/api/browse${params}`);
    document.getElementById("browser-current-path").textContent = browserState.current_path;
    document.getElementById("browser-up-btn").disabled = !browserState.parent_path;
    document.getElementById("browser-git-badge").classList.toggle("hidden", !browserState.is_git_repo);

    const list = document.getElementById("browser-dir-list");
    clear(list);
    if (!browserState.directories || browserState.directories.length === 0) {
      list.appendChild(el("div", "muted small", "No subdirectories here."));
    } else {
      for (const dir of browserState.directories) {
        const btn = el("button", "browser-entry", `📁 ${dir.name}`);
        btn.type = "button";
        btn.addEventListener("click", () => browseTo(dir.path));
        list.appendChild(btn);
      }
    }
  } catch (err) {
    showError(err.message);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  applyTheme(localStorage.getItem("codeguard_theme") || "dark");
  loadHealth();
  loadDashboard();

  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => switchView(btn.dataset.view));
  });
  document.getElementById("mobile-menu-btn").addEventListener("click", () => {
    document.getElementById("sidebar").classList.toggle("open");
  });
  document.getElementById("theme-toggle-btn").addEventListener("click", toggleTheme);
  document.getElementById("quick-scan-nav-btn").addEventListener("click", () => switchView("scanner"));
  document.getElementById("view-all-history-btn").addEventListener("click", () => switchView("history"));

  document.getElementById("run-path-scan-btn").addEventListener("click", runPathScan);
  document.getElementById("run-upload-scan-btn").addEventListener("click", runUploadScan);
  document.getElementById("folder-upload-input").addEventListener("change", (ev) => {
    const files = Array.from(ev.target.files || []);
    if (files.length === 0) {
      document.getElementById("upload-selection-label").textContent = "No folder selected";
      return;
    }
    const root = (files[0].webkitRelativePath || files[0].name).split("/")[0];
    document.getElementById("upload-selection-label").textContent = `${root} (${files.length} files)`;
  });

  ["finding-search-input", "finding-severity-filter", "finding-status-filter"].forEach((id) => {
    document.getElementById(id).addEventListener("input", () => {
      if (activeScan) refreshActiveScan(activeScan.id);
    });
  });

  document.getElementById("export-json-btn").addEventListener("click", () => {
    if (activeScan) window.location.href = `/api/scans/${encodeURIComponent(activeScan.id)}/export?format=json`;
  });
  document.getElementById("export-sarif-btn").addEventListener("click", () => {
    if (activeScan) window.location.href = `/api/scans/${encodeURIComponent(activeScan.id)}/export?format=sarif`;
  });
  document.getElementById("export-html-btn").addEventListener("click", () => {
    if (activeScan) window.location.href = `/api/scans/${encodeURIComponent(activeScan.id)}/export?format=html`;
  });

  document.getElementById("history-search-input").addEventListener("input", loadHistory);
  document.getElementById("history-status-filter").addEventListener("change", loadHistory);
  document.getElementById("refresh-history-btn").addEventListener("click", loadHistory);

  document.getElementById("rules-search-input").addEventListener("input", renderRulesCatalog);
  document.getElementById("rules-severity-filter").addEventListener("change", renderRulesCatalog);

  document.getElementById("settings-form").addEventListener("submit", saveSettings);
  document.getElementById("refresh-audit-btn").addEventListener("click", loadAuditLogs);

  document.getElementById("open-browser-btn").addEventListener("click", () => openFolderBrowser());
  document.getElementById("close-browser-btn").addEventListener("click", () => {
    document.getElementById("folder-modal").classList.add("hidden");
  });
  document.getElementById("browser-up-btn").addEventListener("click", () => {
    if (browserState.parent_path) browseTo(browserState.parent_path);
  });
  document.getElementById("select-current-folder-btn").addEventListener("click", () => {
    if (browserState.current_path) {
      document.getElementById("scan-path-input").value = browserState.current_path;
    }
    document.getElementById("folder-modal").classList.add("hidden");
  });
});

