"""
rust_scan.py
------------
Python wrapper for Rust static-analysis / security tools:
  • cargo-audit  – advisory-database vulnerability scanner
  • cargo-geiger – unsafe Rust usage counter
  • cargo clippy – lint & code-quality analyser

Each runner captures stdout, stderr, the return-code, and any parse
errors, then returns everything in a unified dictionary so callers
never have to deal with raw subprocess mechanics.

The top-level ``scan()`` function also converts every finding into the
project-wide ``Finding`` dataclass (models.py) so results can flow
straight into the shared reporting pipeline.

Usage
-----
    from rust_scan import scan, run_audit, run_geiger, run_clippy

    # Run all three tools against a Cargo project
    results = scan("/path/to/rust/project")

    # Raw structured output
    print(results["audit"]["parsed"])
    print(results["geiger"]["stdout"])
    print(results["clippy"]["findings"])   # list[Finding]

Requirements
------------
    cargo, cargo-audit, cargo-geiger must be installed and on PATH.
    Install extras with:
        cargo install cargo-audit cargo-geiger
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Re-export the shared Finding schema (models.py lives in the same package).
# If models.py is not available we define a local fallback so this module
# can be used stand-alone during development/testing.
# ---------------------------------------------------------------------------
try:
    from models import Finding
except ImportError:  # pragma: no cover – fallback for isolated usage
    @dataclass
    class Finding:  # type: ignore[no-redef]
        tool: str
        type: str
        severity: str
        message: str
        file: str
        line: int


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, str] = {
    # cargo-audit advisory levels
    "error":    "HIGH",
    "warning":  "MEDIUM",
    "note":     "LOW",
    # clippy levels
    "ice":      "HIGH",
    "help":     "INFO",
    # geiger – we assign severity by unsafe-count band (see _geiger_findings)
}


def _run(
    cmd: list[str],
    cwd: str | Path,
    timeout: int = 300,
) -> dict[str, Any]:
    """
    Run *cmd* in *cwd* and return a normalised result dict:

        {
            "cmd":        list[str],          # the command that was executed
            "returncode": int,
            "stdout":     str,
            "stderr":     str,
            "timed_out":  bool,
            "error":      str | None,         # Python-level exception message
        }
    """
    result: dict[str, Any] = {
        "cmd": cmd,
        "returncode": -1,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "error": None,
    }

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result["returncode"] = proc.returncode
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr

    except subprocess.TimeoutExpired as exc:
        result["timed_out"] = True
        result["error"] = f"Timed out after {timeout}s: {exc}"
        logger.warning("Command timed out: %s", " ".join(cmd))

    except FileNotFoundError as exc:
        result["error"] = f"Executable not found – is it installed? {exc}"
        logger.error("Executable not found for command: %s", " ".join(cmd))

    except OSError as exc:
        result["error"] = str(exc)
        logger.error("OSError running %s: %s", " ".join(cmd), exc)

    return result


def _check_tool(name: str) -> bool:
    """Return True if *name* is available on PATH."""
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# cargo-audit
# ---------------------------------------------------------------------------

def run_audit(project_path: str | Path, timeout: int = 120) -> dict[str, Any]:
    """
    Run ``cargo audit --json`` and return:

        {
            "cmd":        list[str],
            "returncode": int,
            "stdout":     str,
            "stderr":     str,
            "timed_out":  bool,
            "error":      str | None,
            "parse_error": str | None,
            "parsed":     dict | None,   # decoded JSON from cargo-audit
        }

    cargo-audit exits with a non-zero code when vulnerabilities are found,
    which is *expected* behaviour – callers should rely on ``parsed``
    rather than ``returncode`` to determine whether issues exist.
    """
    available = _check_tool("cargo-audit") or _check_tool("cargo")
    if not available:
        return {
            "cmd": [],
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "error": "cargo / cargo-audit not found on PATH",
            "parse_error": None,
            "parsed": None,
        }

    cmd = ["cargo", "audit", "--json"]
    raw = _run(cmd, project_path, timeout=timeout)

    result = {**raw, "parse_error": None, "parsed": None}

    if raw["error"] or raw["timed_out"]:
        return result

    try:
        result["parsed"] = json.loads(raw["stdout"])
    except json.JSONDecodeError as exc:
        result["parse_error"] = f"JSON decode error: {exc}"
        logger.warning("cargo-audit JSON parse error: %s", exc)

    return result


def _audit_findings(audit_result: dict[str, Any]) -> list[Finding]:
    """Convert a parsed cargo-audit result into ``Finding`` objects."""
    findings: list[Finding] = []
    parsed = audit_result.get("parsed") or {}

    vulnerabilities = parsed.get("vulnerabilities", {})
    for vuln in vulnerabilities.get("list", []):
        advisory = vuln.get("advisory", {})
        package  = vuln.get("package", {})

        advisory_id = advisory.get("id", "UNKNOWN")
        advisory_url = advisory.get("url", "")
        cvss        = advisory.get("cvss") or ""
        severity    = _cvss_to_severity(cvss) if cvss else "HIGH"

        findings.append(Finding(
            tool     = "cargo-audit",
            type     = advisory.get("categories", ["vulnerability"])[0]
                        if advisory.get("categories") else "vulnerability",
            severity = severity,
            message  = (
                f"[{advisory_id}] {advisory.get('title', 'No title')} "
                f"in {package.get('name', '?')} {package.get('version', '?')}. "
                f"{advisory_url}"
            ),
            file     = "Cargo.lock",
            line     = 0,
        ))

    # Unmaintained / yanked warnings
    for warning in parsed.get("warnings", {}).get("unmaintained", []):
        advisory = warning.get("advisory", {})
        package  = warning.get("package", {})
        findings.append(Finding(
            tool     = "cargo-audit",
            type     = "unmaintained",
            severity = "MEDIUM",
            message  = (
                f"[{advisory.get('id', 'UNKNOWN')}] Unmaintained crate: "
                f"{package.get('name', '?')} {package.get('version', '?')}. "
                f"{advisory.get('url', '')}"
            ),
            file     = "Cargo.lock",
            line     = 0,
        ))

    return findings


def _cvss_to_severity(cvss: str) -> str:
    """Map a CVSS v3 score string (e.g. 'CVSS:3.1/AV:N/.../8.8') to a label."""
    match = re.search(r"/(\d+(?:\.\d+)?)$", cvss)
    if not match:
        return "MEDIUM"
    score = float(match.group(1))
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# cargo-geiger
# ---------------------------------------------------------------------------

def run_geiger(project_path: str | Path, timeout: int = 180) -> dict[str, Any]:
    """
    Run ``cargo geiger --output-format Json`` and return:

        {
            "cmd":        list[str],
            "returncode": int,
            "stdout":     str,
            "stderr":     str,
            "timed_out":  bool,
            "error":      str | None,
            "parse_error": str | None,
            "parsed":     dict | None,
        }

    Note: cargo-geiger must be installed separately::

        cargo install cargo-geiger
    """
    if not _check_tool("cargo-geiger") and not _check_tool("cargo"):
        return {
            "cmd": [],
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "error": "cargo-geiger not found on PATH. Install: cargo install cargo-geiger",
            "parse_error": None,
            "parsed": None,
        }

    cmd = ["cargo", "geiger", "--output-format", "Json", "--quiet"]
    raw = _run(cmd, project_path, timeout=timeout)

    result = {**raw, "parse_error": None, "parsed": None}

    if raw["error"] or raw["timed_out"]:
        return result

    # cargo-geiger may prefix output with non-JSON lines; strip them
    stdout = raw["stdout"].strip()
    json_start = stdout.find("{")
    if json_start == -1:
        result["parse_error"] = "No JSON object found in cargo-geiger output"
        return result

    try:
        result["parsed"] = json.loads(stdout[json_start:])
    except json.JSONDecodeError as exc:
        result["parse_error"] = f"JSON decode error: {exc}"
        logger.warning("cargo-geiger JSON parse error: %s", exc)

    return result


def _geiger_findings(geiger_result: dict[str, Any]) -> list[Finding]:
    """Convert cargo-geiger JSON output into ``Finding`` objects."""
    findings: list[Finding] = []
    parsed = geiger_result.get("parsed") or {}

    for package_info in parsed.get("packages", []):
        pkg   = package_info.get("package", {})
        name  = pkg.get("name", "unknown")
        ver   = pkg.get("version", "?")
        unsaf = package_info.get("unsafety", {})

        used = unsaf.get("used", {})
        total_unsafe = sum([
            used.get("functions", {}).get("unsafe", 0),
            used.get("exprs", {}).get("unsafe", 0),
            used.get("item_impls", {}).get("unsafe", 0),
            used.get("item_traits", {}).get("unsafe", 0),
            used.get("methods", {}).get("unsafe", 0),
        ])

        if total_unsafe == 0:
            continue  # No unsafe code – not a finding

        severity = "HIGH" if total_unsafe > 50 else "MEDIUM" if total_unsafe > 10 else "LOW"

        findings.append(Finding(
            tool     = "cargo-geiger",
            type     = "unsafe_code",
            severity = severity,
            message  = (
                f"{name} v{ver} contains {total_unsafe} unsafe code "
                f"construct(s) (functions, expressions, traits, impls, methods)."
            ),
            file     = f"{name}/src",
            line     = 0,
        ))

    return findings


# ---------------------------------------------------------------------------
# cargo clippy
# ---------------------------------------------------------------------------

def run_clippy(
    project_path: str | Path,
    extra_args: list[str] | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """
    Run ``cargo clippy --message-format=json`` and return:

        {
            "cmd":        list[str],
            "returncode": int,
            "stdout":     str,
            "stderr":     str,
            "timed_out":  bool,
            "error":      str | None,
            "parse_error": str | None,
            "messages":   list[dict],   # decoded compiler-message objects
        }

    ``extra_args`` are appended after ``--``, e.g.
    ``["-W", "clippy::all"]``.
    """
    cmd = [
        "cargo", "clippy",
        "--message-format=json",
        "--all-targets",
        "--all-features",
    ]
    if extra_args:
        cmd += ["--"] + extra_args

    raw = _run(cmd, project_path, timeout=timeout)
    result = {**raw, "parse_error": None, "messages": []}

    if raw["error"] or raw["timed_out"]:
        return result

    # clippy emits one JSON object per line (JSON Lines format)
    messages: list[dict] = []
    parse_errors: list[str] = []
    for lineno, line in enumerate(raw["stdout"].splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            messages.append(json.loads(line))
        except json.JSONDecodeError as exc:
            parse_errors.append(f"Line {lineno}: {exc}")

    result["messages"] = messages
    if parse_errors:
        result["parse_error"] = "; ".join(parse_errors[:5])  # first 5 only
        logger.warning("clippy JSON parse errors: %s", result["parse_error"])

    return result


def _clippy_findings(clippy_result: dict[str, Any]) -> list[Finding]:
    """Convert clippy JSON-lines messages into ``Finding`` objects."""
    findings: list[Finding] = []

    for msg in clippy_result.get("messages", []):
        if msg.get("reason") != "compiler-message":
            continue

        diag = msg.get("message", {})
        level: str = diag.get("level", "note")

        # Only surfaces warnings and errors (skip "note", "help", etc.)
        if level not in ("warning", "error"):
            continue

        severity = _SEVERITY_MAP.get(level, "MEDIUM")
        code_obj = diag.get("code") or {}
        lint_code = code_obj.get("code", "unknown")

        # Prefer the first span that has a file_name
        spans: list[dict] = diag.get("spans", [])
        primary = next(
            (s for s in spans if s.get("is_primary")),
            spans[0] if spans else {},
        )

        file_name = primary.get("file_name", "unknown")
        line_start = primary.get("line_start", 0)

        findings.append(Finding(
            tool     = "clippy",
            type     = lint_code,
            severity = severity,
            message  = diag.get("message", "No message"),
            file     = file_name,
            line     = line_start,
        ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(
    project_path: str | Path,
    *,
    run_audit_: bool = True,
    run_geiger_: bool = True,
    run_clippy_: bool = True,
    audit_timeout: int = 120,
    geiger_timeout: int = 180,
    clippy_timeout: int = 300,
    clippy_extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run all enabled Rust analysis tools against *project_path* and return:

    .. code-block:: python

        {
            "audit": {
                "cmd": [...],
                "returncode": int,
                "stdout": str,
                "stderr": str,
                "timed_out": bool,
                "error": str | None,
                "parse_error": str | None,
                "parsed": dict | None,
                "findings": list[Finding],
            },
            "geiger": {
                "cmd": [...],
                "returncode": int,
                "stdout": str,
                "stderr": str,
                "timed_out": bool,
                "error": str | None,
                "parse_error": str | None,
                "parsed": dict | None,
                "findings": list[Finding],
            },
            "clippy": {
                "cmd": [...],
                "returncode": int,
                "stdout": str,
                "stderr": str,
                "timed_out": bool,
                "error": str | None,
                "parse_error": str | None,
                "messages": list[dict],
                "findings": list[Finding],
            },
            "all_findings": list[Finding],   # union across all tools
            "project_path": str,
        }

    Parameters
    ----------
    project_path:
        Root directory that contains ``Cargo.toml``.
    run_audit_, run_geiger_, run_clippy_:
        Toggle individual tools off (useful in CI to skip slow steps).
    *_timeout:
        Per-tool subprocess timeout in seconds.
    clippy_extra_args:
        Extra flags passed after ``--`` to clippy, e.g. ``["-W", "clippy::pedantic"]``.
    """
    project_path = Path(project_path).resolve()
    logger.info("Starting Rust scan on: %s", project_path)

    audit_result:  dict[str, Any] = {}
    geiger_result: dict[str, Any] = {}
    clippy_result: dict[str, Any] = {}

    if run_audit_:
        logger.info("Running cargo-audit…")
        audit_result = run_audit(project_path, timeout=audit_timeout)
        audit_result["findings"] = _audit_findings(audit_result)
        logger.info("cargo-audit: %d finding(s)", len(audit_result["findings"]))

    if run_geiger_:
        logger.info("Running cargo-geiger…")
        geiger_result = run_geiger(project_path, timeout=geiger_timeout)
        geiger_result["findings"] = _geiger_findings(geiger_result)
        logger.info("cargo-geiger: %d finding(s)", len(geiger_result["findings"]))

    if run_clippy_:
        logger.info("Running cargo clippy…")
        clippy_result = run_clippy(
            project_path,
            extra_args=clippy_extra_args,
            timeout=clippy_timeout,
        )
        clippy_result["findings"] = _clippy_findings(clippy_result)
        logger.info("clippy: %d finding(s)", len(clippy_result["findings"]))

    all_findings: list[Finding] = (
        audit_result.get("findings", [])
        + geiger_result.get("findings", [])
        + clippy_result.get("findings", [])
    )

    return {
        "audit":        audit_result,
        "geiger":       geiger_result,
        "clippy":       clippy_result,
        "all_findings": all_findings,
        "project_path": str(project_path),
    }


# ---------------------------------------------------------------------------
# CLI entry-point (python rust_scan.py /path/to/project)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Run cargo-audit, cargo-geiger, and clippy on a Rust project."
    )
    parser.add_argument("project", help="Path to the Rust project (contains Cargo.toml)")
    parser.add_argument("--no-audit",  action="store_true", help="Skip cargo-audit")
    parser.add_argument("--no-geiger", action="store_true", help="Skip cargo-geiger")
    parser.add_argument("--no-clippy", action="store_true", help="Skip clippy")
    parser.add_argument(
        "--output",
        choices=["summary", "json", "findings"],
        default="summary",
        help="Output format (default: summary)",
    )
    args = parser.parse_args()

    results = scan(
        args.project,
        run_audit_=not args.no_audit,
        run_geiger_=not args.no_geiger,
        run_clippy_=not args.no_clippy,
    )

    if args.output == "json":
        # Serialise findings as plain dicts for JSON output
        import dataclasses
        serialisable = {
            k: {
                **{sk: sv for sk, sv in v.items() if sk != "findings"},
                "findings": [dataclasses.asdict(f) for f in v.get("findings", [])],
            }
            for k, v in results.items()
            if isinstance(v, dict)
        }
        serialisable["project_path"] = results["project_path"]
        print(json.dumps(serialisable, indent=2))

    elif args.output == "findings":
        for f in results["all_findings"]:
            print(f"[{f.severity}] {f.tool} | {f.type} | {f.file}:{f.line} | {f.message}")

    else:  # summary
        for tool in ("audit", "geiger", "clippy"):
            r = results[tool]
            if not r:
                continue
            n = len(r.get("findings", []))
            err = r.get("error") or ""
            print(f"  {tool:15s} → {n:3d} finding(s)  rc={r.get('returncode', '–')}  {err}")
        print(f"\nTotal: {len(results['all_findings'])} finding(s)")

    sys.exit(0 if not results["all_findings"] else 1)
