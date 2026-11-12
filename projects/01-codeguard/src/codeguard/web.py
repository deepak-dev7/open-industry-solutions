"""Local web UI and HTTP API for CodeGuard (stdlib-only, localhost-bound)."""

from __future__ import annotations

import json
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any

from codeguard import __version__
from codeguard.config import load_config
from codeguard.formatters import format_sarif
from codeguard.models import CodeGuardConfig, ScanResult, Severity
from codeguard.rules import ALL_RULES
from codeguard.scanner import scan_paths

MAX_REQUEST_BYTES = 16 * 1024 * 1024  # 16 MB max JSON upload payload
MAX_UPLOAD_FILES = 2000

_INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CodeGuard — Static Security & Quality Scanner</title>
  <style>
    :root {
      --bg: #0b1020;
      --panel: #131a2e;
      --panel-2: #19233d;
      --border: #273459;
      --text: #e6ecff;
      --muted: #98a6cc;
      --accent: #4f8cff;
      --accent-hover: #3b78eb;
      --ok: #22c55e;
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #38bdf8;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    .container {
      max-width: 1120px;
      margin: 0 auto;
      padding: 28px 20px 56px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 24px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
    }
    h1 { margin: 0; font-size: 1.5rem; letter-spacing: -0.02em; }
    .subtitle { color: var(--muted); font-size: 0.92rem; margin-top: 4px; }
    .badge {
      background: var(--panel-2);
      border: 1px solid var(--border);
      color: var(--muted);
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 0.8rem;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
    }
    .card h2 {
      margin: 0 0 8px;
      font-size: 1.05rem;
    }
    .card p.desc {
      margin: 0 0 14px;
      color: var(--muted);
      font-size: 0.88rem;
    }
    label {
      display: block;
      font-size: 0.84rem;
      color: var(--muted);
      margin-bottom: 6px;
    }
    input[type="text"], select {
      width: 100%;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text);
      font-size: 0.92rem;
      margin-bottom: 12px;
    }
    input[type="file"] {
      width: 100%;
      padding: 10px;
      border-radius: 8px;
      border: 1px dashed var(--border);
      background: var(--bg);
      color: var(--muted);
      margin-bottom: 12px;
      cursor: pointer;
    }
    .row {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }
    button {
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 10px 16px;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover { background: var(--accent-hover); }
    button:disabled { opacity: 0.55; cursor: not-allowed; }
    button.secondary {
      background: var(--panel-2);
      border: 1px solid var(--border);
      color: var(--text);
    }
    button.secondary:hover { background: #223052; }
    .summary-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }
    .stats {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .stat {
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 12px;
      font-size: 0.86rem;
    }
    .stat strong { color: var(--text); }
    .status-pass { color: var(--ok); font-weight: 700; }
    .status-fail { color: var(--crit); font-weight: 700; }
    .finding {
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-left-width: 4px;
      border-radius: 10px;
      padding: 14px 16px;
      margin-bottom: 12px;
    }
    .sev-critical { border-left-color: var(--crit); }
    .sev-high { border-left-color: var(--high); }
    .sev-medium { border-left-color: var(--med); }
    .sev-low { border-left-color: var(--low); }
    .finding-head {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      margin-bottom: 6px;
      font-size: 0.9rem;
    }
    .pill {
      font-size: 0.75rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 999px;
      text-transform: uppercase;
      background: var(--bg);
      border: 1px solid var(--border);
    }
    .pill-critical { color: var(--crit); border-color: var(--crit); }
    .pill-high { color: var(--high); border-color: var(--high); }
    .pill-medium { color: var(--med); border-color: var(--med); }
    .pill-low { color: var(--low); border-color: var(--low); }
    .loc { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--accent); font-size: 0.85rem; }
    .snippet {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.82rem;
      overflow-x: auto;
      margin: 8px 0;
      white-space: pre;
    }
    .remediation { color: var(--muted); font-size: 0.85rem; }
    .error-box {
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid var(--crit);
      color: #fecaca;
      border-radius: 8px;
      padding: 12px 14px;
      margin-bottom: 16px;
      display: none;
    }
    .hidden { display: none; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>CodeGuard</h1>
        <div class="subtitle">Local-first static security, secret detection, and code quality scanner</div>
      </div>
      <div class="badge" id="version-badge">OIS · Project 01</div>
    </header>

    <div class="card" style="margin-bottom: 16px;">
      <div class="row" style="justify-content: space-between;">
        <div>
          <label for="fail-on">Fail-on severity threshold</label>
          <select id="fail-on" style="width: 220px; margin-bottom: 0;">
            <option value="low">Low (show &amp; fail on all)</option>
            <option value="medium">Medium</option>
            <option value="high" selected>High (default)</option>
            <option value="critical">Critical only</option>
          </select>
        </div>
        <div class="subtitle" id="rules-count">Loading rules...</div>
      </div>
    </div>

    <div class="grid">
      <section class="card">
        <h2>1. Scan Local Folder Path</h2>
        <p class="desc">Enter an absolute directory or file path on this machine (e.g. <code>C:\xampp\htdocs\cinema</code>).</p>
        <label for="folder-path">Folder or File Path</label>
        <input type="text" id="folder-path" placeholder="C:\path\to\project" />
        <button id="scan-path-btn" type="button">Scan Path</button>
      </section>

      <section class="card">
        <h2>2. Upload Folder to Scan</h2>
        <p class="desc">Select any folder from your computer. Heavy build folders (<code>.git</code>, <code>node_modules</code>, <code>.venv</code>) and binaries are automatically skipped.</p>
        <label for="folder-upload">Choose Folder</label>
        <input type="file" id="folder-upload" webkitdirectory directory multiple />
        <div class="row">
          <button id="scan-upload-btn" type="button">Upload &amp; Scan Folder</button>
          <span class="subtitle" id="upload-info">No folder selected</span>
        </div>
      </section>
    </div>

    <div class="error-box" id="error-box"></div>

    <section class="card hidden" id="results-section">
      <div class="summary-bar">
        <div class="stats" id="summary-stats"></div>
        <div class="row">
          <button class="secondary" id="download-json-btn" type="button">Download JSON</button>
          <button class="secondary" id="download-sarif-btn" type="button">Download SARIF</button>
        </div>
      </div>
      <div id="findings-list"></div>
    </section>
  </div>

  <script>
    let lastReport = null;

    const failOnEl = document.getElementById("fail-on");
    const pathInputEl = document.getElementById("folder-path");
    const uploadInputEl = document.getElementById("folder-upload");
    const uploadInfoEl = document.getElementById("upload-info");
    const scanPathBtn = document.getElementById("scan-path-btn");
    const scanUploadBtn = document.getElementById("scan-upload-btn");
    const errorBoxEl = document.getElementById("error-box");
    const resultsSectionEl = document.getElementById("results-section");
    const summaryStatsEl = document.getElementById("summary-stats");
    const findingsListEl = document.getElementById("findings-list");

    const IGNORED_DIRS = new Set([".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"]);
    const MAX_FILE_BYTES = 1024 * 1024;

    function clearElement(el) {
      while (el.firstChild) {
        el.removeChild(el.firstChild);
      }
    }

    function showError(msg) {
      errorBoxEl.textContent = msg;
      errorBoxEl.style.display = "block";
    }

    function hideError() {
      errorBoxEl.textContent = "";
      errorBoxEl.style.display = "none";
    }

    function setBusy(busy) {
      scanPathBtn.disabled = busy;
      scanUploadBtn.disabled = busy;
    }

    function isIgnoredRelPath(relPath) {
      const parts = relPath.split("/");
      for (let i = 0; i < parts.length - 1; i += 1) {
        if (IGNORED_DIRS.has(parts[i])) return true;
      }
      return relPath.endsWith(".lock") || relPath.endsWith(".min.js");
    }

    uploadInputEl.addEventListener("change", () => {
      const files = Array.from(uploadInputEl.files || []);
      if (files.length === 0) {
        uploadInfoEl.textContent = "No folder selected";
        return;
      }
      const firstRel = files[0].webkitRelativePath || files[0].name;
      const rootName = firstRel.split("/")[0] || "folder";
      uploadInfoEl.textContent = rootName + " (" + files.length + " files selected)";
    });

    function addStatChip(label, value, extraClass) {
      const chip = document.createElement("div");
      chip.className = "stat";
      const strong = document.createElement("strong");
      strong.textContent = String(value);
      if (extraClass) strong.className = extraClass;
      chip.appendChild(document.createTextNode(label + ": "));
      chip.appendChild(strong);
      summaryStatsEl.appendChild(chip);
    }

    function renderResults(data) {
      lastReport = data;
      resultsSectionEl.classList.remove("hidden");
      clearElement(summaryStatsEl);
      clearElement(findingsListEl);

      const s = data.summary;
      const passed = !data.failed;
      addStatChip("Status", passed ? "PASS" : "FAIL", passed ? "status-pass" : "status-fail");
      addStatChip("Files scanned", s.files_scanned);
      addStatChip("Skipped", s.files_skipped);
      addStatChip("Suppressed", s.suppressed_count);
      addStatChip("Findings", s.findings_count);

      if (data.findings.length === 0) {
        const okMsg = document.createElement("p");
        okMsg.className = "status-pass";
        okMsg.textContent = "No security or policy findings detected.";
        findingsListEl.appendChild(okMsg);
        return;
      }

      for (const f of data.findings) {
        const card = document.createElement("div");
        card.className = "finding sev-" + f.severity;

        const head = document.createElement("div");
        head.className = "finding-head";

        const sevPill = document.createElement("span");
        sevPill.className = "pill pill-" + f.severity;
        sevPill.textContent = f.severity;
        head.appendChild(sevPill);

        const ruleStrong = document.createElement("strong");
        ruleStrong.textContent = f.rule_id + " (" + f.cwe + ")";
        head.appendChild(ruleStrong);

        const loc = document.createElement("span");
        loc.className = "loc";
        loc.textContent = f.file_path + ":" + f.line + ":" + f.column;
        head.appendChild(loc);
        card.appendChild(head);

        const msg = document.createElement("div");
        msg.textContent = f.message;
        card.appendChild(msg);

        if (f.snippet) {
          const pre = document.createElement("div");
          pre.className = "snippet";
          pre.textContent = f.snippet;
          card.appendChild(pre);
        }

        const rem = document.createElement("div");
        rem.className = "remediation";
        rem.textContent = "Remediation: " + f.remediation;
        card.appendChild(rem);

        findingsListEl.appendChild(card);
      }
    }

    async function postJson(url, payload) {
      hideError();
      setBusy(true);
      try {
        const resp = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!resp.ok) {
          showError(data.error || "Scan failed.");
          return;
        }
        renderResults(data);
      } catch (err) {
        showError("Request error: " + String(err));
      } finally {
        setBusy(false);
      }
    }

    scanPathBtn.addEventListener("click", async () => {
      const targetPath = pathInputEl.value.trim();
      if (!targetPath) {
        showError("Please enter a local folder or file path.");
        return;
      }
      await postJson("/api/scan-path", {
        path: targetPath,
        fail_on: failOnEl.value,
      });
    });

    scanUploadBtn.addEventListener("click", async () => {
      const selected = Array.from(uploadInputEl.files || []);
      if (selected.length === 0) {
        showError("Please choose a folder to upload first.");
        return;
      }
      hideError();
      setBusy(true);
      try {
        const filesPayload = [];
        let skippedClient = 0;
        for (const file of selected) {
          const rel = (file.webkitRelativePath || file.name).replace(/\\/g, "/");
          if (isIgnoredRelPath(rel) || file.size > MAX_FILE_BYTES) {
            skippedClient += 1;
            continue;
          }
          const buf = await file.arrayBuffer();
          const bytes = new Uint8Array(buf);
          let isBinary = false;
          const probeLen = Math.min(bytes.length, 4096);
          for (let i = 0; i < probeLen; i += 1) {
            if (bytes[i] === 0) {
              isBinary = true;
              break;
            }
          }
          if (isBinary) {
            skippedClient += 1;
            continue;
          }
          const text = new TextDecoder("utf-8").decode(bytes);
          filesPayload.push({ path: rel, content: text });
        }
        await postJson("/api/scan-upload", {
          fail_on: failOnEl.value,
          client_skipped: skippedClient,
          files: filesPayload,
        });
      } catch (err) {
        showError("Upload preparation failed: " + String(err));
        setBusy(false);
      }
    });

    function triggerDownload(filename, content) {
      const blob = new Blob([content], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    document.getElementById("download-json-btn").addEventListener("click", () => {
      if (!lastReport) return;
      triggerDownload("codeguard-report.json", JSON.stringify(lastReport, null, 2));
    });

    document.getElementById("download-sarif-btn").addEventListener("click", () => {
      if (!lastReport || !lastReport.sarif) return;
      triggerDownload("codeguard-report.sarif", lastReport.sarif);
    });

    fetch("/api/rules")
      .then((r) => r.json())
      .then((data) => {
        document.getElementById("version-badge").textContent = "CodeGuard v" + data.version;
        document.getElementById("rules-count").textContent = data.rules.length + " built-in rules active";
      })
      .catch(() => {
        document.getElementById("rules-count").textContent = "Ready";
      });
  </script>
</body>
</html>
"""


def _safe_relative_path(raw_path: str) -> Path:
    """Validate and sanitize an uploaded relative POSIX path against traversal."""
    normalized = raw_path.replace("\\", "/").lstrip("/")
    pure = PurePosixPath(normalized)
    if not normalized or pure.is_absolute():
        raise ValueError(f"Invalid uploaded path: '{raw_path}'")
    parts = [part for part in pure.parts if part not in ("", ".")]
    if not parts or any(part == ".." or ":" in part for part in parts):
        raise ValueError(f"Unsafe path traversal component in '{raw_path}'")
    return Path(*parts)


def _build_api_response(result: ScanResult, fail_on: Severity) -> dict[str, Any]:
    """Build JSON response payload including summary, findings, and SARIF text."""
    return {
        "tool": "codeguard",
        "version": __version__,
        "root": result.root,
        "fail_on": fail_on.label,
        "failed": result.should_fail(fail_on),
        "summary": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "suppressed_count": result.suppressed_count,
            "findings_count": len(result.findings),
        },
        "findings": [finding.to_dict() for finding in result.findings],
        "errors": result.errors,
        "sarif": format_sarif(result),
    }


def scan_local_path_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate a local-path scan payload and return formatted scan results."""
    raw_path = str(payload.get("path", "")).strip()
    if not raw_path:
        raise ValueError("Missing 'path' field.")
    target = Path(raw_path).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")

    root = target if target.is_dir() else target.parent
    config = load_config(config_path=None, root=root)
    fail_on = Severity.from_str(str(payload["fail_on"])) if payload.get("fail_on") else config.fail_on
    result = scan_paths(root=root, targets=[target], config=config)
    return _build_api_response(result, fail_on)


def scan_uploaded_files_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Materialize uploaded files in an isolated temp directory, scan, and clean up."""
    files = payload.get("files")
    if not isinstance(files, list):
        raise ValueError("'files' must be a list of {path, content} objects.")
    if len(files) > MAX_UPLOAD_FILES:
        raise ValueError(f"Too many uploaded files (max {MAX_UPLOAD_FILES}).")

    fail_on_raw = str(payload.get("fail_on", "high"))
    fail_on = Severity.from_str(fail_on_raw)
    client_skipped = int(payload.get("client_skipped", 0) or 0)

    with tempfile.TemporaryDirectory(prefix="codeguard_upload_") as tmp:
        root = Path(tmp).resolve()
        for entry in files:
            if not isinstance(entry, dict):
                raise ValueError("Each uploaded file entry must be an object.")
            rel_raw = str(entry.get("path", ""))
            content = entry.get("content")
            if not isinstance(content, str):
                raise ValueError(f"File '{rel_raw}' content must be a UTF-8 string.")
            safe_rel = _safe_relative_path(rel_raw)
            dest = (root / safe_rel).resolve()
            dest.relative_to(root)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

        config = load_config(config_path=None, root=root)
        result = scan_paths(root=root, targets=[root], config=config)
        result.files_skipped += max(0, client_skipped)
        result.root = "uploaded-folder"
        return _build_api_response(result, fail_on)


class CodeGuardRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler serving the CodeGuard UI and local JSON scan endpoints."""

    server_version = f"CodeGuard/{__version__}"

    def log_message(self, format: str, *args: object) -> None:
        return  # Keep terminal output quiet unless explicit errors occur

    def _send_json(self, status: HTTPStatus, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any]:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            raise ValueError("Missing Content-Length header.")
        length = int(raw_len)
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ValueError(f"Request body must be between 1 and {MAX_REQUEST_BYTES} bytes.")
        raw = self.rfile.read(length)
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON request body must be an object.")
        return parsed

    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/?"):
            self._send_html(_INDEX_HTML)
            return
        if self.path == "/api/rules":
            self._send_json(
                HTTPStatus.OK,
                {
                    "version": __version__,
                    "rules": [
                        {
                            "rule_id": r.rule_id,
                            "name": r.name,
                            "severity": r.severity.label,
                            "category": r.category,
                            "cwe": r.cwe,
                        }
                        for r in ALL_RULES
                    ],
                },
            )
            return
        if self.path == "/api/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "version": __version__})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:
        try:
            payload = self._read_json_body()
            if self.path == "/api/scan-path":
                self._send_json(HTTPStatus.OK, scan_local_path_payload(payload))
                return
            if self.path == "/api/scan-upload":
                self._send_json(HTTPStatus.OK, scan_uploaded_files_payload(payload))
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Unknown endpoint"})
        except FileNotFoundError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})


def create_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Create a configured ThreadingHTTPServer bound to host:port."""
    return ThreadingHTTPServer((host, port), CodeGuardRequestHandler)


def serve_ui(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Run the local CodeGuard web UI server until interrupted."""
    server = create_server(host=host, port=port)
    actual_host, actual_port = server.server_address[:2]
    print(f"CodeGuard Web UI running at http://{actual_host}:{actual_port} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
