"""FastAPI backend application for CodeGuard local-first web workbench."""

from __future__ import annotations

import re
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath
from threading import Lock
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from codeguard import __version__
from codeguard.config import load_config
from codeguard.formatters import format_html_report, format_sarif
from codeguard.models import CodeGuardConfig, Severity
from codeguard.rules import ALL_RULES
from codeguard.scanner import scan_paths
from codeguard.storage import CodeGuardStore

MAX_UPLOAD_FILES = 2000
MAX_UPLOAD_TOTAL_BYTES = 16 * 1024 * 1024
SCAN_RATE_LIMIT_COUNT = 60
SCAN_RATE_LIMIT_WINDOW_SEC = 60.0

STATIC_DIR = Path(__file__).resolve().parent / "static"


class ScanPathRequest(BaseModel):
    path: str = Field(..., min_length=1, max_length=1024)
    fail_on: str | None = Field(default=None)

    @field_validator("fail_on")
    @classmethod
    def validate_fail_on(cls, value: str | None) -> str | None:
        if value is not None:
            Severity.from_str(value)
        return value


class UploadedFileItem(BaseModel):
    path: str = Field(..., min_length=1, max_length=512)
    content: str


class ScanUploadRequest(BaseModel):
    folder_name: str = Field(default="uploaded-folder", max_length=128)
    fail_on: str | None = Field(default=None)
    client_skipped: int = Field(default=0, ge=0, le=100000)
    files: list[UploadedFileItem] = Field(..., max_length=MAX_UPLOAD_FILES)

    @field_validator("fail_on")
    @classmethod
    def validate_fail_on(cls, value: str | None) -> str | None:
        if value is not None:
            Severity.from_str(value)
        return value


class FindingTriageRequest(BaseModel):
    status: str = Field(..., pattern="^(open|acknowledged|false_positive)$")


class SettingsUpdateRequest(BaseModel):
    fail_on: str = Field(...)
    max_file_size_kb: int = Field(..., ge=1, le=20480)
    entropy_threshold: float = Field(..., gt=0.5, le=8.0)
    disabled_rules: list[str] = Field(default_factory=list, max_length=200)
    ignore_paths: list[str] = Field(default_factory=list, max_length=200)
    allowlist_patterns: list[str] = Field(default_factory=list, max_length=200)
    allowed_roots: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("fail_on")
    @classmethod
    def validate_fail_on(cls, value: str) -> str:
        Severity.from_str(value)
        return value.strip().lower()

    @field_validator("allowlist_patterns")
    @classmethod
    def validate_regexes(cls, patterns: list[str]) -> list[str]:
        for pat in patterns:
            try:
                re.compile(pat)
            except re.error as exc:
                raise ValueError(f"Invalid allowlist regex '{pat}': {exc}") from exc
        return patterns


class _SlidingWindowRateLimiter:
    """In-memory sliding-window rate limiter protecting scan endpoints."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True


def _safe_relative_path(raw_path: str) -> Path:
    """Validate uploaded relative paths against traversal and absolute escapes."""
    normalized = raw_path.replace("\\", "/").lstrip("/")
    pure = PurePosixPath(normalized)
    if not normalized or pure.is_absolute():
        raise ValueError(f"Invalid uploaded path: '{raw_path}'")
    parts = [part for part in pure.parts if part not in ("", ".")]
    if not parts or any(part == ".." or ":" in part for part in parts):
        raise ValueError(f"Unsafe path traversal component in '{raw_path}'")
    return Path(*parts)


def _check_approved_root(target: Path, allowed_roots: list[str]) -> None:
    """Enforce optional approved root boundaries when configured in settings."""
    roots = [Path(r).expanduser().resolve() for r in allowed_roots if r.strip()]
    if not roots:
        return
    if not any(target == root or target.is_relative_to(root) for root in roots):
        raise PermissionError(f"Path '{target}' is outside configured approved scan roots.")


def _merge_config(store: CodeGuardStore, project_root: Path) -> CodeGuardConfig:
    """Combine persisted app settings with optional project-level .codeguard.toml."""
    base = store.to_runtime_config()
    if (project_root / ".codeguard.toml").is_file():
        local_cfg = load_config(config_path=None, root=project_root)
        return CodeGuardConfig(
            ignore_paths=tuple(dict.fromkeys(base.ignore_paths + local_cfg.ignore_paths)),
            disabled_rules=tuple(dict.fromkeys(base.disabled_rules + local_cfg.disabled_rules)),
            allowlist_patterns=tuple(dict.fromkeys(base.allowlist_patterns + local_cfg.allowlist_patterns)),
            fail_on=local_cfg.fail_on,
            max_file_size_kb=min(base.max_file_size_kb, local_cfg.max_file_size_kb),
            entropy_threshold=local_cfg.entropy_threshold,
        )
    return base


def _sanitize_filename_stem(raw: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-")
    return stem or "codeguard-report"


def create_app(db_path: Path | None = None) -> FastAPI:
    """Build and configure the FastAPI application."""
    store = CodeGuardStore(db_path=db_path)
    limiter = _SlidingWindowRateLimiter(SCAN_RATE_LIMIT_COUNT, SCAN_RATE_LIMIT_WINDOW_SEC)

    app = FastAPI(
        title="CodeGuard API",
        version=__version__,
        description="Local-first static security and quality scanning workbench.",
    )
    app.state.store = store

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        if not request.url.path.startswith(("/docs", "/redoc")):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self';"
            )
        return response

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_index() -> FileResponse:
        index_path = STATIC_DIR / "index.html"
        if not index_path.is_file():
            raise HTTPException(status_code=404, detail="Frontend assets not found.")
        return FileResponse(index_path)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "database": "ok" if store.check_health() else "error",
            "rules_count": len(ALL_RULES),
        }

    @app.get("/api/dashboard")
    def dashboard() -> dict[str, Any]:
        return store.get_dashboard_stats()

    @app.get("/api/browse")
    def browse_directories(path: str = Query(default="")) -> dict[str, Any]:
        settings = store.get_settings()
        allowed_roots = [str(r) for r in settings.get("allowed_roots", [])]

        if path.strip():
            current = Path(path).expanduser().resolve()
        elif allowed_roots:
            current = Path(allowed_roots[0]).expanduser().resolve()
        else:
            current = Path.cwd().resolve()

        try:
            _check_approved_root(current, allowed_roots)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

        if not current.exists() or not current.is_dir():
            raise HTTPException(status_code=400, detail=f"Directory not found: {current}")

        parent = str(current.parent) if current.parent != current else None
        if parent and allowed_roots:
            try:
                _check_approved_root(Path(parent), allowed_roots)
            except PermissionError:
                parent = None

        dirs: list[dict[str, str]] = []
        try:
            for entry in sorted(current.iterdir(), key=lambda p: p.name.lower()):
                if entry.is_symlink() or not entry.is_dir():
                    continue
                if entry.name in {".git", "node_modules", "__pycache__", ".venv"}:
                    continue
                dirs.append({"name": entry.name, "path": str(entry)})
                if len(dirs) >= 200:
                    break
        except OSError as exc:
            raise HTTPException(status_code=403, detail=f"Cannot read directory: {exc}") from exc

        return {
            "current_path": str(current),
            "parent_path": parent,
            "is_git_repo": (current / ".git").exists(),
            "directories": dirs,
            "approved_roots": allowed_roots,
        }

    @app.post("/api/scans/path")
    def scan_local_path(req: ScanPathRequest, request: Request) -> dict[str, Any]:
        client_host = request.client.host if request.client else "local"
        if not limiter.allow(client_host):
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again shortly.")

        target = Path(req.path).expanduser().resolve()
        settings = store.get_settings()
        allowed_roots = [str(r) for r in settings.get("allowed_roots", [])]
        try:
            _check_approved_root(target, allowed_roots)
        except PermissionError as exc:
            store.log_audit("scan_path", str(target), "rejected", str(exc))
            raise HTTPException(status_code=403, detail=str(exc)) from exc

        if not target.exists():
            store.log_audit("scan_path", str(target), "rejected", "Target path does not exist.")
            raise HTTPException(status_code=400, detail=f"Path does not exist: {target}")

        root = target if target.is_dir() else target.parent
        config = _merge_config(store, root)
        fail_on = Severity.from_str(req.fail_on) if req.fail_on else config.fail_on

        started = time.perf_counter()
        result = scan_paths(root=root, targets=[target], config=config)
        duration_ms = max(1, int((time.perf_counter() - started) * 1000))
        sarif_json = format_sarif(result)

        record = store.save_scan(
            source_type="path",
            target_label=str(target),
            result=result,
            fail_on=fail_on,
            duration_ms=duration_ms,
            sarif_json=sarif_json,
        )
        store.log_audit(
            "scan_path",
            str(target),
            "failed_gate" if record["failed"] else "success",
            f"files={record['files_scanned']} findings={record['findings_count']}",
        )
        return record

    @app.post("/api/scans/upload")
    def scan_uploaded_folder(req: ScanUploadRequest, request: Request) -> dict[str, Any]:
        client_host = request.client.host if request.client else "local"
        if not limiter.allow(client_host):
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again shortly.")

        total_bytes = sum(len(item.content.encode("utf-8")) for item in req.files)
        if total_bytes > MAX_UPLOAD_TOTAL_BYTES:
            raise HTTPException(status_code=400, detail="Uploaded payload exceeds 16 MB limit.")

        label = _sanitize_filename_stem(req.folder_name)
        config = store.to_runtime_config()
        fail_on = Severity.from_str(req.fail_on) if req.fail_on else config.fail_on

        started = time.perf_counter()
        try:
            with tempfile.TemporaryDirectory(prefix="codeguard_upload_") as tmp:
                root = Path(tmp).resolve()
                for item in req.files:
                    safe_rel = _safe_relative_path(item.path)
                    dest = (root / safe_rel).resolve()
                    dest.relative_to(root)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(item.content, encoding="utf-8")

                result = scan_paths(root=root, targets=[root], config=config)
                result.files_skipped += req.client_skipped
                result.root = label
        except ValueError as exc:
            store.log_audit("scan_upload", label, "rejected", str(exc))
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        duration_ms = max(1, int((time.perf_counter() - started) * 1000))
        sarif_json = format_sarif(result)
        record = store.save_scan(
            source_type="upload",
            target_label=label,
            result=result,
            fail_on=fail_on,
            duration_ms=duration_ms,
            sarif_json=sarif_json,
        )
        store.log_audit(
            "scan_upload",
            label,
            "failed_gate" if record["failed"] else "success",
            f"files={record['files_scanned']} findings={record['findings_count']}",
        )
        return record

    @app.get("/api/scans")
    def list_scans(
        search: str = Query(default=""),
        status: str = Query(default=""),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        return {"scans": store.list_scans(search=search, status=status, limit=limit)}

    @app.get("/api/scans/{scan_id}")
    def get_scan(
        scan_id: str,
        severity: str = Query(default=""),
        rule_id: str = Query(default=""),
        status: str = Query(default=""),
        search: str = Query(default=""),
    ) -> dict[str, Any]:
        record = store.get_scan(
            scan_id,
            severity=severity,
            rule_id=rule_id,
            status=status,
            search=search,
        )
        if record is None:
            raise HTTPException(status_code=404, detail="Scan record not found.")
        return record

    @app.delete("/api/scans/{scan_id}")
    def delete_scan(scan_id: str) -> dict[str, bool]:
        deleted = store.delete_scan(scan_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Scan record not found.")
        store.log_audit("scan_delete", scan_id, "success", "Deleted scan history record.")
        return {"deleted": True}

    @app.get("/api/scans/{scan_id}/export")
    def export_scan(
        scan_id: str,
        format: str = Query(default="json", pattern="^(json|sarif|html)$"),
    ) -> Response:
        record = store.get_scan(scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Scan record not found.")

        stem = _sanitize_filename_stem(f"codeguard-{record['id'][:8]}")
        if format == "sarif":
            return Response(
                content=record["sarif_json"],
                media_type="application/sarif+json",
                headers={"Content-Disposition": f'attachment; filename="{stem}.sarif"'},
            )
        if format == "html":
            return Response(
                content=format_html_report(record),
                media_type="text/html; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{stem}.html"'},
            )
        export_copy = {k: v for k, v in record.items() if k != "sarif_json"}
        return JSONResponse(
            content=export_copy,
            headers={"Content-Disposition": f'attachment; filename="{stem}.json"'},
        )

    @app.patch("/api/findings/{finding_id}")
    def triage_finding(finding_id: int, req: FindingTriageRequest) -> dict[str, Any]:
        updated = store.update_finding_status(finding_id, req.status)
        if updated is None:
            raise HTTPException(status_code=404, detail="Finding not found.")
        store.log_audit(
            "finding_triage",
            f"finding:{finding_id}",
            "success",
            f"status={req.status} rule={updated['rule_id']}",
        )
        return updated

    @app.get("/api/rules")
    def list_rules(
        search: str = Query(default=""),
        severity: str = Query(default=""),
        category: str = Query(default=""),
    ) -> dict[str, Any]:
        q = search.strip().lower()
        sev = severity.strip().lower()
        cat = category.strip().lower()
        filtered = []
        for rule in ALL_RULES:
            if sev and rule.severity.label != sev:
                continue
            if cat and rule.category.lower() != cat:
                continue
            if q and q not in f"{rule.rule_id} {rule.name} {rule.cwe} {rule.description}".lower():
                continue
            filtered.append(
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "severity": rule.severity.label,
                    "category": rule.category,
                    "cwe": rule.cwe,
                    "description": rule.description,
                    "remediation": rule.remediation,
                }
            )
        return {"version": __version__, "rules": filtered}

    @app.get("/api/settings")
    def get_settings() -> dict[str, Any]:
        return store.get_settings()

    @app.put("/api/settings")
    def put_settings(req: SettingsUpdateRequest) -> dict[str, Any]:
        updated = store.update_settings(req.model_dump())
        store.log_audit(
            "settings_update",
            "app_settings",
            "success",
            f"fail_on={updated['fail_on']} roots={len(updated['allowed_roots'])}",
        )
        return updated

    @app.get("/api/audit-logs")
    def get_audit_logs(limit: int = Query(default=50, ge=1, le=200)) -> dict[str, Any]:
        return {"logs": store.list_audit_logs(limit=limit)}

    return app
