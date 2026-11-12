"""Command-line interface for CodeGuard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from codeguard import __version__
from codeguard.config import DEFAULT_CONFIG_FILENAME, STARTER_CONFIG_TOML, load_config
from codeguard.formatters import format_json, format_sarif, format_text
from codeguard.models import Severity
from codeguard.rules import ALL_RULES
from codeguard.scanner import get_git_changed_files, scan_paths


def build_parser() -> argparse.ArgumentParser:
    """Build the CodeGuard CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="codeguard",
        description="Fast, local-first static security and quality guardrail with SARIF v2.1.0 output.",
    )
    parser.add_argument("--version", action="version", version=f"codeguard {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan files, directories, or Git diffs.")
    scan_parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Target files or directories to scan (default: current directory).",
    )
    scan_parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan only Git staged files (ideal for pre-commit hooks).",
    )
    scan_parser.add_argument(
        "--diff",
        metavar="REF",
        default=None,
        help="Scan only files changed against a Git ref (for example origin/main).",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Report output format (default: text).",
    )
    scan_parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write formatted report to FILE instead of stdout.",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        default=None,
        help="Minimum severity that causes a non-zero exit code (overrides config).",
    )
    scan_parser.add_argument(
        "--config",
        metavar="FILE",
        default=None,
        help=f"Path to TOML configuration file (default: {DEFAULT_CONFIG_FILENAME}).",
    )

    rules_parser = subparsers.add_parser("rules", help="List built-in CodeGuard rules.")
    rules_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )

    init_parser = subparsers.add_parser("init", help=f"Create a starter {DEFAULT_CONFIG_FILENAME} file.")
    init_parser.add_argument(
        "--path",
        default=DEFAULT_CONFIG_FILENAME,
        help=f"Destination config path (default: {DEFAULT_CONFIG_FILENAME}).",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing configuration file.",
    )

    ui_parser = subparsers.add_parser("ui", help="Launch the local CodeGuard web UI.")
    ui_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host address (default: 127.0.0.1).",
    )
    ui_parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Bind port (default: 8765).",
    )

    return parser


def _handle_scan(args: argparse.Namespace) -> int:
    if args.staged and args.diff is not None:
        print("Error: --staged and --diff cannot be used together.", file=sys.stderr)
        return 2

    root = Path.cwd().resolve()
    config_path = Path(args.config).resolve() if args.config else None
    try:
        config = load_config(config_path=config_path, root=root)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    fail_on = Severity.from_str(args.fail_on) if args.fail_on else config.fail_on

    preselected: list[Path] | None = None
    if args.staged or args.diff is not None:
        try:
            preselected = get_git_changed_files(root=root, staged=args.staged, diff_ref=args.diff)
        except (ValueError, RuntimeError) as exc:
            print(f"Git error: {exc}", file=sys.stderr)
            return 2

    targets = [Path(p) for p in args.paths]
    if preselected is None:
        missing = [str(t) for t in targets if not t.exists()]
        if missing:
            print(f"Target path not found: {', '.join(missing)}", file=sys.stderr)
            return 2

    result = scan_paths(root=root, targets=targets, config=config, preselected_files=preselected)

    if args.format == "json":
        rendered = format_json(result)
    elif args.format == "sarif":
        rendered = format_sarif(result)
    else:
        rendered = format_text(result, fail_on=fail_on)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)

    return 1 if result.should_fail(fail_on) else 0


def _handle_rules(args: argparse.Namespace) -> int:
    if args.format == "json":
        payload = [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "severity": r.severity.label,
                "category": r.category,
                "cwe": r.cwe,
                "description": r.description,
                "remediation": r.remediation,
            }
            for r in ALL_RULES
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    for rule in ALL_RULES:
        sys.stdout.write(
            f"{rule.rule_id:<12} [{rule.severity.name:<8}] ({rule.cwe}) {rule.name}\n"
            f"  {rule.description}\n"
        )
    return 0


def _handle_init(args: argparse.Namespace) -> int:
    dest = Path(args.path)
    if dest.exists() and not args.force:
        print(f"Error: {dest} already exists. Use --force to overwrite.", file=sys.stderr)
        return 2
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(STARTER_CONFIG_TOML, encoding="utf-8")
    print(f"Created CodeGuard configuration at {dest}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint returning process exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _handle_scan(args)
    if args.command == "rules":
        return _handle_rules(args)
    if args.command == "init":
        return _handle_init(args)
    if args.command == "ui":
        from codeguard.web import serve_ui

        serve_ui(host=args.host, port=args.port)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
