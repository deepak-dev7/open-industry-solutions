"""Command-line interface for ThreatLens SOC log analysis and workbench server."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

import uvicorn

from threatlens import __version__
from threatlens.detector import ThreatDetector
from threatlens.ioc import IOCMatcher
from threatlens.parsers import auto_detect_and_parse
from threatlens.scenarios import SCENARIOS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="Security event analysis, suspicious login detection, and MITRE ATT&CK correlation.",
    )
    parser.add_argument("--version", action="version", version=f"threatlens {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. serve command
    serve_parser = subparsers.add_parser("serve", help="Launch the ThreatLens SOC web workbench.")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host address (default: 127.0.0.1).")
    serve_parser.add_argument("--port", type=int, default=8766, help="Bind port (default: 8766).")
    serve_parser.add_argument("--db", default=None, help="Custom SQLite database path.")

    # 2. analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze an authentication log file from terminal.")
    analyze_parser.add_argument("logfile", help="Path to log file (syslog, windows JSON, okta/cloudtrail, or CSV).")
    analyze_parser.add_argument(
        "--format",
        choices=("auto", "syslog", "windows_event", "json", "csv"),
        default="auto",
        help="Log format hint (default: auto).",
    )
    analyze_parser.add_argument(
        "--output",
        choices=("text", "json"),
        default="text",
        help="Report output format (default: text).",
    )

    # 3. scenarios command
    subparsers.add_parser("scenarios", help="List built-in synthetic attack scenarios.")

    return parser


def handle_serve(args: argparse.Namespace) -> int:
    from threatlens.api import create_app
    db_path = Path(args.db).resolve() if args.db else None
    app = create_app(db_path=db_path)
    print(f"ThreatLens SOC Workbench running at http://{args.host}:{args.port} (Ctrl+C to stop)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def handle_analyze(args: argparse.Namespace) -> int:
    log_path = Path(args.logfile).resolve()
    if not log_path.is_file():
        print(f"Error: Log file not found: {log_path}", file=sys.stderr)
        return 2

    try:
        text = log_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = log_path.read_text(encoding="latin-1", errors="replace")

    events, detected_fmt = auto_detect_and_parse(text, format_hint=args.format)
    if not events:
        print(f"Error: Could not parse any authentication events from {log_path.name}", file=sys.stderr)
        return 1

    detector = ThreatDetector()
    incidents = detector.analyze(events)

    if args.output == "json":
        data = {
            "logfile": str(log_path),
            "format": detected_fmt,
            "events_scanned": len(events),
            "incidents_count": len(incidents),
            "incidents": [inc.to_dict() for inc in incidents],
        }
        print(json.dumps(data, indent=2))
        return 1 if incidents else 0

    print(f"=== ThreatLens SOC Analysis Report: {log_path.name} ===")
    print(f"Format: {detected_fmt.upper()} | Events Parsed: {len(events)} | Correlated Incidents: {len(incidents)}")
    print("-" * 75)

    if not incidents:
        print("Status: CLEAN (No suspicious login anomalies or attacks detected).")
        return 0

    for idx, inc in enumerate(incidents, start=1):
        print(f"[{idx}] {inc.severity.value.upper():<8} {inc.mitre_id} ({inc.risk_score}/100) — {inc.title}")
        print(f"    Target:  User '{inc.primary_user}' | Attacker IP: {inc.primary_ip}")
        print(f"    Events:  {inc.event_count} | First Seen: {inc.first_seen} | Last Seen: {inc.last_seen}")
        print(f"    Details: {inc.analyst_notes}")
        print()

    return 1


def handle_scenarios(args: argparse.Namespace) -> int:
    print(f"{'Key':<20} {'Format':<10} {'Title'}")
    print("-" * 75)
    for k, v in SCENARIOS.items():
        print(f"{k:<20} {v['format']:<10} {v['title']}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        return handle_serve(args)
    if args.command == "analyze":
        return handle_analyze(args)
    if args.command == "scenarios":
        return handle_scenarios(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
