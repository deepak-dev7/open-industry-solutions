"""FastAPI application for ThreatLens SOC Workbench and Security Event API."""

from __future__ import annotations

import csv
import io
import json
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from threatlens import __version__
from threatlens.detector import ThreatDetector
from threatlens.ioc import IOCMatcher, IOCRecord
from threatlens.models import IncidentSeverity, IncidentStatus, ThreatLensConfig
from threatlens.parsers import auto_detect_and_parse
from threatlens.scenarios import SCENARIOS
from threatlens.storage import ThreatLensStore

STATIC_DIR = Path(__file__).resolve().parent / "static"


class IngestTextRequest(BaseModel):
    text: str = Field(..., min_length=1)
    format_hint: str = Field(default="auto", pattern="^(auto|syslog|windows_event|json|csv)$")
    filename: str = Field(default="pasted_log.txt", max_length=128)


class IngestScenarioRequest(BaseModel):
    scenario_key: str = Field(..., pattern="^(brute_force|password_spray|impossible_travel|after_hours_admin|clean_baseline)$")


class IncidentTriageRequest(BaseModel):
    status: str = Field(..., pattern="^(new|investigating|contained|resolved|false_positive)$")
    analyst_notes: str | None = Field(default=None, max_length=2000)


class AddIOCRequest(BaseModel):
    ioc_type: str = Field(default="ip", pattern="^(ip|cidr)$")
    indicator: str = Field(..., min_length=3, max_length=64)
    threat_type: str = Field(..., min_length=2, max_length=64)
    severity: str = Field(default="high", pattern="^(critical|high|medium|low)$")
    description: str = Field(default="", max_length=256)


class UpdateSettingsRequest(BaseModel):
    brute_force_threshold: int = Field(..., ge=2, le=100)
    brute_force_window_sec: int = Field(..., ge=10, le=3600)
    spray_user_threshold: int = Field(..., ge=2, le=50)
    spray_window_sec: int = Field(..., ge=10, le=7200)
    impossible_travel_max_kmh: float = Field(..., ge=100.0, le=10000.0)
    work_hours_start: int = Field(..., ge=0, le=23)
    work_hours_end: int = Field(..., ge=0, le=24)
    privileged_accounts: list[str] = Field(default_factory=list, max_length=50)


def create_app(db_path: Path | None = None) -> FastAPI:
    store = ThreatLensStore(db_path=db_path)

    app = FastAPI(
        title="ThreatLens SOC API",
        version=__version__,
        description="Security event analysis, suspicious login correlation, and MITRE ATT&CK incident workbench.",
    )
    app.state.store = store

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
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
        index_file = STATIC_DIR / "index.html"
        if not index_file.is_file():
            raise HTTPException(status_code=404, detail="ThreatLens UI assets not found.")
        return FileResponse(index_file)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "ThreatLens",
            "version": __version__,
            "database": "ok" if store.check_health() else "error",
            "ioc_count": len(store.list_iocs()),
        }

    @app.get("/api/dashboard")
    def dashboard() -> dict[str, Any]:
        return store.get_dashboard_metrics()

    def _execute_analysis(text: str, filename: str, format_hint: str) -> dict[str, Any]:
        started = time.perf_counter()
        events, detected_fmt = auto_detect_and_parse(text, format_hint=format_hint)
        if not events:
            raise HTTPException(status_code=400, detail="No valid authentication events could be parsed from log data.")

        # Load persisted settings and IOCs
        s = store.get_settings()
        cfg = ThreatLensConfig(
            brute_force_threshold=int(s["brute_force_threshold"]),
            brute_force_window_sec=int(s["brute_force_window_sec"]),
            spray_user_threshold=int(s["spray_user_threshold"]),
            spray_window_sec=int(s["spray_window_sec"]),
            impossible_travel_max_kmh=float(s["impossible_travel_max_kmh"]),
            work_hours_start=int(s["work_hours_start"]),
            work_hours_end=int(s["work_hours_end"]),
            privileged_accounts=tuple(s.get("privileged_accounts", ["root", "admin"])),
        )

        iocs_data = store.list_iocs()
        ioc_records = [
            IOCRecord(
                id=r["id"],
                ioc_type=r["ioc_type"],
                indicator=r["indicator"],
                threat_type=r["threat_type"],
                severity=IncidentSeverity.from_str(r["severity"]),
                description=r["description"],
                added_at=r["added_at"],
            )
            for r in iocs_data
        ]
        matcher = IOCMatcher(ioc_records)

        detector = ThreatDetector(config=cfg, ioc_matcher=matcher)
        incidents = detector.analyze(events)
        duration_ms = max(1, int((time.perf_counter() - started) * 1000))

        batch_id = store.save_ingest_batch(filename, detected_fmt, events, incidents, duration_ms)
        store.log_audit("ingest_logs", filename, "success", f"events={len(events)} incidents={len(incidents)}")

        return {
            "batch_id": batch_id,
            "filename": filename,
            "detected_format": detected_fmt,
            "events_count": len(events),
            "incidents_count": len(incidents),
            "duration_ms": duration_ms,
            "incidents": [inc.to_dict() for inc in incidents],
        }

    @app.post("/api/ingest/text")
    def ingest_raw_text(req: IngestTextRequest) -> dict[str, Any]:
        return _execute_analysis(req.text, req.filename, req.format_hint)

    @app.post("/api/ingest/upload")
    def ingest_upload(file: UploadFile = File(...)) -> dict[str, Any]:
        content_bytes = file.file.read()
        if len(content_bytes) > 32 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File exceeds 32 MB limit.")
        try:
            text = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = content_bytes.decode("latin-1", errors="replace")

        filename = file.filename or "uploaded_log.txt"
        return _execute_analysis(text, filename, "auto")

    @app.post("/api/ingest/scenario")
    def ingest_scenario(req: IngestScenarioRequest) -> dict[str, Any]:
        scenario = SCENARIOS.get(req.scenario_key)
        if not scenario:
            raise HTTPException(status_code=404, detail="Scenario not found.")
        return _execute_analysis(scenario["content"], f"Scenario: {scenario['title']}", scenario["format"])

    @app.get("/api/scenarios")
    def list_scenarios() -> dict[str, Any]:
        return {
            "scenarios": [
                {
                    "key": k,
                    "title": v["title"],
                    "description": v["description"],
                    "format": v["format"],
                }
                for k, v in SCENARIOS.items()
            ]
        }

    @app.get("/api/incidents")
    def list_incidents(
        severity: str = Query(default=""),
        status: str = Query(default=""),
        search: str = Query(default=""),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        incidents = store.list_incidents(severity=severity, status=status, search=search, limit=limit)
        return {"incidents": incidents}

    @app.get("/api/incidents/{incident_id}")
    def get_incident(incident_id: str) -> dict[str, Any]:
        inc = store.get_incident(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found.")
        return inc

    @app.patch("/api/incidents/{incident_id}")
    def triage_incident(incident_id: str, req: IncidentTriageRequest) -> dict[str, Any]:
        updated = store.update_incident(incident_id, req.status, req.analyst_notes)
        if not updated:
            raise HTTPException(status_code=404, detail="Incident not found.")
        store.log_audit("triage_incident", incident_id, "success", f"status={req.status}")
        return updated

    @app.delete("/api/incidents/{incident_id}")
    def delete_incident(incident_id: str) -> dict[str, bool]:
        ok = store.delete_incident(incident_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Incident not found.")
        store.log_audit("delete_incident", incident_id, "success", "Deleted incident record")
        return {"deleted": True}

    @app.get("/api/incidents/{incident_id}/export")
    def export_incident(
        incident_id: str,
        format: str = Query(default="json", pattern="^(json|csv|markdown)$"),
    ) -> Response:
        inc = store.get_incident(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found.")

        if format == "json":
            return Response(
                content=json.dumps(inc, indent=2),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{incident_id}.json"'},
            )

        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["EventID", "Timestamp", "EventType", "Status", "User", "SourceIP", "Country", "City", "RawMessage"])
            for ev in inc.get("events", []):
                writer.writerow([
                    ev.get("id"), ev.get("timestamp"), ev.get("event_type"), ev.get("status"),
                    ev.get("username"), ev.get("source_ip"), ev.get("geo_country"), ev.get("geo_city"),
                    ev.get("raw_message"),
                ])
            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="{incident_id}-events.csv"'},
            )

        # Markdown format
        md_text = f"""# Security Incident Forensic Report: {inc['id']}

- **Title:** {inc['title']}
- **Severity:** {inc['severity'].upper()}
- **Risk Score:** {inc['risk_score']} / 100
- **Status:** {inc['status'].upper()}
- **MITRE ATT&CK:** {inc['mitre_id']} ({inc['mitre_name']})
- **Primary Adversary IP:** `{inc['primary_ip']}`
- **Targeted Entity:** `{inc['primary_user']}`
- **Timeline:** {inc['first_seen']} to {inc['last_seen']} ({inc['event_count']} correlated events)

## Forensic Narrative & Analyst Notes
{inc.get('analyst_notes') or 'No notes recorded.'}

## Correlated Events ({len(inc.get('events', []))})
| Time (UTC) | Type | User | Source IP | Geo | Details |
| --- | --- | --- | --- | --- | --- |
"""
        for ev in inc.get("events", []):
            md_text += f"| {ev.get('timestamp')} | `{ev.get('event_type')}` | `{ev.get('username')}` | `{ev.get('source_ip')}` | {ev.get('geo_city')}, {ev.get('geo_country')} | {ev.get('raw_message')} |\n"

        return PlainTextResponse(
            content=md_text,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{incident_id}.md"'},
        )

    @app.get("/api/events")
    def search_events(
        username: str = Query(default=""),
        ip: str = Query(default=""),
        status: str = Query(default=""),
        event_type: str = Query(default=""),
        search: str = Query(default=""),
        limit: int = Query(default=100, ge=1, le=300),
    ) -> dict[str, Any]:
        events = store.search_events(
            username=username, ip=ip, status=status, event_type=event_type, search=search, limit=limit
        )
        return {"events": events}

    @app.get("/api/ioc")
    def list_iocs() -> dict[str, Any]:
        return {"iocs": store.list_iocs()}

    @app.post("/api/ioc")
    def add_ioc(req: AddIOCRequest) -> dict[str, Any]:
        rec = store.add_ioc(
            ioc_type=req.ioc_type,
            indicator=req.indicator,
            threat_type=req.threat_type,
            severity=req.severity,
            description=req.description,
        )
        store.log_audit("add_ioc", req.indicator, "success", f"type={req.threat_type} sev={req.severity}")
        return rec

    @app.delete("/api/ioc/{ioc_id}")
    def delete_ioc(ioc_id: int) -> dict[str, bool]:
        ok = store.delete_ioc(ioc_id)
        if not ok:
            raise HTTPException(status_code=404, detail="IOC record not found.")
        store.log_audit("delete_ioc", f"id={ioc_id}", "success", "Deleted IOC record")
        return {"deleted": True}

    @app.get("/api/settings")
    def get_settings() -> dict[str, Any]:
        return store.get_settings()

    @app.put("/api/settings")
    def update_settings(req: UpdateSettingsRequest) -> dict[str, Any]:
        updated = store.update_settings(req.model_dump())
        store.log_audit("update_settings", "detection_thresholds", "success", f"brute_force={req.brute_force_threshold}")
        return updated

    @app.get("/api/audit-logs")
    def get_audit_logs(limit: int = Query(default=40, ge=1, le=200)) -> dict[str, Any]:
        return {"logs": store.list_audit_logs(limit=limit)}

    return app


def get_app() -> FastAPI:
    """Factory for ASGI servers (e.g. uvicorn --factory threatlens.api:get_app)."""
    return create_app()
