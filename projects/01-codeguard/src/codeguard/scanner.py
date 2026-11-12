"""File discovery, Git diff integration, suppression filtering, and scan orchestration."""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from pathlib import Path

from codeguard.models import CodeGuardConfig, Finding, ScanResult
from codeguard.rules.general import scan_general_rules
from codeguard.rules.python_ast import scan_python_ast
from codeguard.rules.secrets import scan_secrets

_SUPPRESSION_RE = re.compile(r"codeguard:\s*ignore(?:\[([A-Za-z0-9_,\s-]+)\])?", re.IGNORECASE)


def _matches_ignore(rel_posix: str, patterns: tuple[str, ...]) -> bool:
    """Return True if a relative POSIX path matches any configured ignore glob."""
    parts = rel_posix.split("/")
    for pattern in patterns:
        norm_pat = pattern.replace("\\", "/").strip("/")
        if not norm_pat:
            continue
        if fnmatch.fnmatch(rel_posix, norm_pat):
            return True
        if norm_pat.endswith("/**"):
            prefix = norm_pat[:-3]
            if rel_posix == prefix or rel_posix.startswith(f"{prefix}/"):
                return True
        if "/" not in norm_pat and any(fnmatch.fnmatch(part, norm_pat) for part in parts):
            return True
    return False


def _is_binary_bytes(sample: bytes) -> bool:
    """Detect binary files via null-byte inspection."""
    return b"\x00" in sample


def _read_text_safe(path: Path, max_bytes: int) -> tuple[str | None, str | None]:
    """Read a UTF-8 text file safely; return (content, skip_reason)."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"stat failed: {exc}"

    if size > max_bytes:
        return None, "exceeds max_file_size_kb"

    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, f"read failed: {exc}"

    if _is_binary_bytes(raw[:8192]):
        return None, "binary file"

    return raw.decode("utf-8", errors="replace"), None


def _parse_suppressions(lines: list[str]) -> dict[int, set[str] | None]:
    """Map 1-based line numbers to suppressed rule IDs (None means all rules suppressed)."""
    suppressed: dict[int, set[str] | None] = {}
    for idx, line in enumerate(lines, start=1):
        match = _SUPPRESSION_RE.search(line)
        if not match:
            continue
        raw_rules = match.group(1)
        rules: set[str] | None = (
            {item.strip().upper() for item in raw_rules.split(",") if item.strip()}
            if raw_rules
            else None
        )
        for target_line in (idx, idx + 1):
            if target_line not in suppressed:
                suppressed[target_line] = None if rules is None else set(rules)
            elif suppressed[target_line] is not None:
                if rules is None:
                    suppressed[target_line] = None
                else:
                    suppressed[target_line].update(rules)
    return suppressed


def _is_suppressed(finding: Finding, suppressed: dict[int, set[str] | None]) -> bool:
    """Return True if a finding's line has a matching inline suppression."""
    if finding.line not in suppressed:
        return False
    rule_set = suppressed[finding.line]
    return rule_set is None or finding.rule_id.upper() in rule_set


def get_git_changed_files(root: Path, staged: bool = False, diff_ref: str | None = None) -> list[Path]:
    """Return existing changed file paths from Git without invoking a shell."""
    if diff_ref is not None and diff_ref.startswith("-"):
        raise ValueError(f"Invalid git diff ref '{diff_ref}': refs cannot start with '-'.")

    cmd = ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR"]
    if staged:
        cmd.append("--cached")
    elif diff_ref is not None:
        cmd.append(diff_ref)
    else:
        raise ValueError("Either staged=True or diff_ref must be specified.")

    completed = subprocess.run(cmd, capture_output=True, text=True, shell=False, check=False)
    if completed.returncode != 0:
        err = completed.stderr.strip() or "git diff failed"
        raise RuntimeError(f"Git diff error: {err}")

    paths: list[Path] = []
    for line in completed.stdout.splitlines():
        rel = line.strip()
        if not rel:
            continue
        candidate = (root / rel).resolve()
        if candidate.is_file():
            paths.append(candidate)
    return paths


def _collect_target_files(
    root: Path,
    targets: list[Path],
    ignore_paths: tuple[str, ...],
) -> tuple[list[Path], int]:
    """Collect non-ignored, non-symlink files under target paths."""
    collected: list[Path] = []
    skipped = 0
    seen: set[Path] = set()

    for target in targets:
        resolved = target.resolve()
        if resolved.is_symlink():
            skipped += 1
            continue
        if resolved.is_file():
            try:
                rel = resolved.relative_to(root).as_posix()
            except ValueError:
                rel = resolved.name
            if _matches_ignore(rel, ignore_paths):
                skipped += 1
            elif resolved not in seen:
                seen.add(resolved)
                collected.append(resolved)
            continue
        if not resolved.is_dir():
            continue

        for dirpath, dirnames, filenames in os.walk(resolved, followlinks=False):
            current_dir = Path(dirpath)
            kept_dirs: list[str] = []
            for dname in sorted(dirnames):
                full_dir = current_dir / dname
                if full_dir.is_symlink():
                    skipped += 1
                    continue
                try:
                    rel_dir = full_dir.relative_to(root).as_posix()
                except ValueError:
                    rel_dir = dname
                if _matches_ignore(rel_dir, ignore_paths):
                    continue
                kept_dirs.append(dname)
            dirnames[:] = kept_dirs

            for fname in sorted(filenames):
                full_file = current_dir / fname
                if full_file.is_symlink():
                    skipped += 1
                    continue
                try:
                    rel_file = full_file.relative_to(root).as_posix()
                except ValueError:
                    rel_file = fname
                if _matches_ignore(rel_file, ignore_paths):
                    skipped += 1
                    continue
                if full_file not in seen:
                    seen.add(full_file)
                    collected.append(full_file)

    return collected, skipped


def scan_paths(
    root: Path,
    targets: list[Path],
    config: CodeGuardConfig,
    preselected_files: list[Path] | None = None,
) -> ScanResult:
    """Scan specified targets (or preselected git-diff files) and return ScanResult."""
    resolved_root = root.resolve()
    disabled = {rule_id.upper() for rule_id in config.disabled_rules}
    allowlist_res = [re.compile(pattern) for pattern in config.allowlist_patterns]
    max_bytes = config.max_file_size_kb * 1024

    if preselected_files is not None:
        files: list[Path] = []
        skipped = 0
        for file_path in preselected_files:
            resolved = file_path.resolve()
            try:
                rel = resolved.relative_to(resolved_root).as_posix()
            except ValueError:
                rel = resolved.name
            if resolved.is_symlink() or _matches_ignore(rel, config.ignore_paths):
                skipped += 1
            else:
                files.append(resolved)
    else:
        files, skipped = _collect_target_files(resolved_root, targets, config.ignore_paths)

    result = ScanResult(root=str(resolved_root), files_scanned=0, files_skipped=skipped)

    for file_path in files:
        content, skip_reason = _read_text_safe(file_path, max_bytes=max_bytes)
        if content is None:
            result.files_skipped += 1
            if skip_reason and skip_reason not in {"binary file", "exceeds max_file_size_kb"}:
                result.errors.append(f"{file_path}: {skip_reason}")
            continue

        result.files_scanned += 1
        try:
            rel_path = file_path.relative_to(resolved_root).as_posix()
        except ValueError:
            rel_path = file_path.as_posix()

        lines = content.splitlines()
        suppressed = _parse_suppressions(lines)
        raw_findings: list[Finding] = []

        raw_findings.extend(scan_secrets(rel_path, content, config))
        raw_findings.extend(scan_general_rules(rel_path, content))

        if file_path.suffix.lower() == ".py":
            py_findings, py_err = scan_python_ast(rel_path, content)
            raw_findings.extend(py_findings)
            if py_err:
                result.errors.append(py_err)

        for finding in raw_findings:
            if finding.rule_id.upper() in disabled:
                continue
            if _is_suppressed(finding, suppressed):
                result.suppressed_count += 1
                continue
            line_text = lines[finding.line - 1] if 0 < finding.line <= len(lines) else ""
            if any(rx.search(line_text) for rx in allowlist_res):
                result.suppressed_count += 1
                continue
            result.findings.append(finding)

    result.findings.sort(key=lambda f: (f.file_path, f.line, f.column, f.rule_id))
    return result
