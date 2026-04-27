#!/usr/bin/env python3
"""
rust_parser.py

Unified parser for Rust tool outputs:
- cargo-audit
- cargo-geiger
- cargo clippy

This module parses raw tool outputs and converts them into a unified format.

Expected usage:
    python3 rust_parser.py \
      --audit ripgrep:outputs/ripgrep_audit.json \
      --audit tokio:outputs/tokio_audit.json \
      --geiger ripgrep:outputs/ripgrep_geiger.txt \
      --geiger tokio:outputs/tokio_geiger.txt \
      --clippy ripgrep:outputs/ripgrep_clippy.jsonl \
      --clippy tokio:outputs/tokio_clippy.jsonl \
      --output parsed_findings.json

Output format:
[
  {
    "repo": "tokio",
    "tool": "cargo-audit",
    "category": "vulnerability",
    "target": "some-crate",
    "file": "Cargo.lock",
    "line": 0,
    "rule_id": "RUSTSEC-....",
    "message": "...",
    "raw_level": "vulnerability",
    "normalized_priority": "HIGH",
    "metadata": {...}
  }
]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Unified model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Unified finding model for Rust tool outputs."""
    repo: str
    tool: str
    category: str              # vulnerability | unsafe_usage | lint | warning | advisory
    target: str                # crate/package/target name when known
    file: str
    line: int
    rule_id: str
    message: str
    raw_level: str
    normalized_priority: str   # INFO | LOW | MEDIUM | HIGH | CRITICAL
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Priority normalization
# ---------------------------------------------------------------------------

class PriorityNormalizer:
    """Maps tool-specific classifications to a common priority scale."""

    PRIORITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    @staticmethod
    def normalize_audit(kind: str, advisory: Optional[Dict[str, Any]] = None) -> str:
        kind_lower = (kind or "").lower()

        if kind_lower in {"vulnerability", "unmaintained", "unsound"}:
            return "HIGH"
        if kind_lower in {"warning"}:
            return "MEDIUM"
        if kind_lower in {"notice", "info", "informational"}:
            return "LOW"

        # Try to refine with CVSS / severity hints if available
        if advisory:
            cvss = advisory.get("cvss")
            if isinstance(cvss, (int, float)):
                if cvss >= 9.0:
                    return "CRITICAL"
                if cvss >= 7.0:
                    return "HIGH"
                if cvss >= 4.0:
                    return "MEDIUM"
                return "LOW"

            severity = str(advisory.get("severity", "")).lower()
            if severity in {"critical"}:
                return "CRITICAL"
            if severity in {"high"}:
                return "HIGH"
            if severity in {"medium", "moderate"}:
                return "MEDIUM"
            if severity in {"low"}:
                return "LOW"

        return "MEDIUM"

    @staticmethod
    def normalize_geiger(unsafe_count: int) -> str:
        # cargo-geiger does not report vulnerabilities; only "unsafe usage".
        # This is a prioritization hint, not a vulnerability severity.
        if unsafe_count >= 50:
            return "MEDIUM"
        if unsafe_count > 0:
            return "LOW"
        return "INFO"

    @staticmethod
    def normalize_clippy(level: str, code: Optional[str] = None) -> str:
        level_lower = (level or "").lower()

        if level_lower == "error":
            return "MEDIUM"
        if level_lower == "warning":
            return "LOW"
        if level_lower in {"note", "help", "failure-note"}:
            return "INFO"

        # A few lints may be more important, but keep it conservative.
        if code and "unsafe" in code.lower():
            return "LOW"

        return "INFO"


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_repo_file_arg(value: str) -> Tuple[str, Path]:
    """
    Parse CLI arguments in the form:
        repo_name:/path/to/file
    """
    if ":" not in value:
        raise ValueError(
            f"Invalid value '{value}'. Expected format repo_name:/path/to/file"
        )

    repo, file_path = value.split(":", 1)
    repo = repo.strip()
    path = Path(file_path.strip())

    if not repo:
        raise ValueError(f"Missing repository name in '{value}'")

    return repo, path


def safe_read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def safe_json_load(path: Path) -> Any:
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def compact_message(*parts: Optional[str], max_len: int = 3000) -> str:
    msg = " | ".join(p.strip() for p in parts if p and str(p).strip())
    if len(msg) > max_len:
        return msg[:max_len].rstrip() + " ..."
    return msg


# ---------------------------------------------------------------------------
# cargo-audit parser
# ---------------------------------------------------------------------------

def parse_audit(repo: str, path: Path) -> List[Finding]:
    """
    Parse cargo-audit JSON output into unified findings.

    Supports typical cargo-audit JSON structures, with some defensive handling
    because the schema can vary slightly between versions.
    """
    findings: List[Finding] = []

    try:
        data = safe_json_load(path)
    except Exception as e:
        raise ValueError(f"Failed to read cargo-audit JSON from {path}: {e}") from e

    if not isinstance(data, dict):
        return findings

    # ---------------------------
    # Vulnerabilities
    # ---------------------------
    vulnerabilities: List[Dict[str, Any]] = []

    vulns_obj = data.get("vulnerabilities")
    if isinstance(vulns_obj, dict):
        if isinstance(vulns_obj.get("list"), list):
            vulnerabilities.extend(vulns_obj["list"])
    elif isinstance(vulns_obj, list):
        vulnerabilities.extend(vulns_obj)

    for vuln in vulnerabilities:
        advisory = vuln.get("advisory", {}) if isinstance(vuln, dict) else {}
        package = vuln.get("package", {}) if isinstance(vuln, dict) else {}

        package_name = str(package.get("name", "unknown-package"))
        package_version = str(package.get("version", "unknown-version"))
        advisory_id = str(advisory.get("id", "unknown-advisory"))

        title = advisory.get("title")
        description = advisory.get("description")
        url = advisory.get("url")
        severity = advisory.get("severity")
        cvss = advisory.get("cvss")

        findings.append(
            Finding(
                repo=repo,
                tool="cargo-audit",
                category="vulnerability",
                target=package_name,
                file="Cargo.lock",
                line=0,
                rule_id=advisory_id,
                message=compact_message(
                    f"Package: {package_name} {package_version}",
                    f"Title: {title}" if title else None,
                    f"Description: {description}" if description else None,
                    f"URL: {url}" if url else None,
                ),
                raw_level="vulnerability",
                normalized_priority=PriorityNormalizer.normalize_audit(
                    "vulnerability", advisory=advisory
                ),
                metadata={
                    "package_version": package_version,
                    "advisory_title": title,
                    "advisory_url": url,
                    "advisory_severity": severity,
                    "advisory_cvss": cvss,
                    "raw_advisory": advisory,
                    "raw_package": package,
                },
            )
        )

    # ---------------------------
    # Warnings
    # ---------------------------
    warnings_obj = data.get("warnings")
    if isinstance(warnings_obj, dict):
        flat_warnings = []
        for key, warn_list in warnings_obj.items():
            if isinstance(warn_list, list):
                flat_warnings.extend(warn_list)
        warnings_obj = flat_warnings

    if isinstance(warnings_obj, list):
        for idx, warning in enumerate(warnings_obj, start=1):
            if isinstance(warning, dict):
                kind = str(warning.get("kind", "warning"))
                package = warning.get("package", {})
                package_name = str(package.get("name", "unknown-package"))
                package_version = str(package.get("version", "unknown-version"))

                msg = compact_message(
                    f"Kind: {kind}",
                    f"Package: {package_name} {package_version}",
                    warning.get("message", ""),
                    warning.get("advisory", {}).get("title", ""),
                )
                rule_id = str(warning.get("advisory", {}).get("id", f"audit-warning-{idx}"))
            else:
                kind = "warning"
                package_name = "unknown-package"
                package_version = "unknown-version"
                msg = str(warning)
                rule_id = f"audit-warning-{idx}"

            findings.append(
                Finding(
                    repo=repo,
                    tool="cargo-audit",
                    category="warning",
                    target=package_name,
                    file="Cargo.lock",
                    line=0,
                    rule_id=rule_id,
                    message=msg,
                    raw_level=kind,
                    normalized_priority=PriorityNormalizer.normalize_audit(kind),
                    metadata={
                        "package_version": package_version,
                        "raw_warning": warning,
                    },
                )
            )

    return findings


# ---------------------------------------------------------------------------
# cargo-geiger parser
# ---------------------------------------------------------------------------

_GEIGER_NUM_RE = re.compile(r"\b\d+\b")

def _extract_unsafe_count(line: str) -> int:
    nums = [int(x) for x in _GEIGER_NUM_RE.findall(line)]
    if not nums:
        return 1
    return max(nums)

def parse_geiger(repo: str, path: Path) -> List[Finding]:
    """
    Parse cargo-geiger text output into unified findings.
    """
    findings: List[Finding] = []

    try:
        content = safe_read_text(path)
    except Exception as e:
        raise ValueError(f"Failed to read cargo-geiger output from {path}: {e}") from e

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        # Ignorar delimitadores de tabelas
        if set(line) <= {"-", "=", "+", "|", " "}:
            continue

        # Ficar APENAS com as linhas que têm o aviso de uso unsafe (" ! ") 
        # e ignorar as linhas que têm a legenda (" = ")
        if " ! " not in line or " = " in line:
            continue

        # Separar a parte das métricas (esq) da parte do pacote (dir)
        parts = line.split(" ! ")
        if len(parts) < 2:
            continue

        metrics_part = parts[0]
        target_part = parts[1].strip()

        # Limpar os caracteres estranhos da árvore "Ôö£ÔöÇÔöÇ " usando regex
        target_clean = re.sub(r'^[^a-zA-Z0-9]+', '', target_part)
        target = target_clean.split()[0] if target_clean else "unknown-target"
        
        unsafe_count = _extract_unsafe_count(metrics_part)

        findings.append(
            Finding(
                repo=repo,
                tool="cargo-geiger",
                category="unsafe_usage",
                target=target,
                file="Cargo.toml",
                line=0,
                rule_id="unsafe-usage",
                message=f"Unsafe code used in dependency: {target_clean}",
                raw_level=str(unsafe_count),
                normalized_priority=PriorityNormalizer.normalize_geiger(unsafe_count),
                metadata={
                    "source_line": line_no,
                    "unsafe_count_hint": unsafe_count,
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# cargo-clippy parser
# ---------------------------------------------------------------------------

def parse_clippy(repo: str, path: Path) -> List[Finding]:
    """
    Parse cargo clippy JSON lines output into unified findings.

    Expected input:
        cargo clippy ... --message-format=json

    Cargo emits one JSON object per line. We keep only compiler-message entries.
    """
    findings: List[Finding] = []

    try:
        with open(path, "r", encoding="utf-8-sig") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line:
                        continue 

                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if obj.get("reason") != "compiler-message":
                        continue

                    message_obj = obj.get("message", {})
                    if not isinstance(message_obj, dict):
                        continue

                    level = str(message_obj.get("level", "note"))
                    code_obj = message_obj.get("code") or {}
                    lint_code = code_obj.get("code") if isinstance(code_obj, dict) else None
                    lint_code = lint_code or "clippy-or-rustc"

                    rendered = message_obj.get("rendered")
                    plain_message = message_obj.get("message")
                    msg = rendered.strip() if isinstance(rendered, str) and rendered.strip() else str(plain_message or "")

                    spans = message_obj.get("spans") or []
                    file_name = "unknown"
                    line_start = 0

                    if isinstance(spans, list) and spans:
                        primary = next(
                            (s for s in spans if isinstance(s, dict) and s.get("is_primary")),
                            spans[0] if isinstance(spans[0], dict) else {},
                        )
                        if isinstance(primary, dict):
                            file_name = str(primary.get("file_name", "unknown"))
                            try:
                                line_start = int(primary.get("line_start", 0))
                            except (TypeError, ValueError):
                                line_start = 0

                    target = "unknown-target"
                    target_obj = obj.get("target")
                    if isinstance(target_obj, dict):
                        target = str(target_obj.get("name", "unknown-target"))
                    elif "package_id" in obj:
                        target = str(obj["package_id"])

                    category = "lint"
                    if level == "error":
                        category = "lint"
                    elif level == "warning":
                        category = "lint"
                    elif level in {"note", "help"}:
                        category = "lint"

                    findings.append(
                        Finding(
                            repo=repo,
                            tool="cargo-clippy",
                            category=category,
                            target=target,
                            file=file_name,
                            line=line_start,
                            rule_id=str(lint_code),
                            message=msg,
                            raw_level=level,
                            normalized_priority=PriorityNormalizer.normalize_clippy(
                                level, code=str(lint_code)
                            ),
                            metadata={
                                "package_id": obj.get("package_id"),
                                "manifest_path": obj.get("manifest_path"),
                                "raw_reason": obj.get("reason"),
                            },
                        )
                    )

    except Exception as e:
        raise ValueError(f"Failed to read cargo-clippy JSON lines from {path}: {e}") from e

    return findings


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def findings_to_json(findings: List[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False)


def summarize_findings(findings: List[Finding]) -> str:
    by_repo: Dict[str, int] = {}
    by_tool: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_priority: Dict[str, int] = {}

    for finding in findings:
        by_repo[finding.repo] = by_repo.get(finding.repo, 0) + 1
        by_tool[finding.tool] = by_tool.get(finding.tool, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
        by_priority[finding.normalized_priority] = by_priority.get(finding.normalized_priority, 0) + 1

    lines: List[str] = []
    lines.append("=" * 70)
    lines.append("RUST PARSER SUMMARY")
    lines.append("=" * 70)
    lines.append(f"Total findings: {len(findings)}")
    lines.append("")

    lines.append("By repository:")
    for repo, count in sorted(by_repo.items()):
        lines.append(f"  {repo:12s}: {count}")
    lines.append("")

    lines.append("By tool:")
    for tool, count in sorted(by_tool.items()):
        lines.append(f"  {tool:12s}: {count}")
    lines.append("")

    lines.append("By category:")
    for category, count in sorted(by_category.items()):
        lines.append(f"  {category:12s}: {count}")
    lines.append("")

    lines.append("By normalized priority:")
    for priority in PriorityNormalizer.PRIORITY_ORDER[::-1]:
        lines.append(f"  {priority:12s}: {by_priority.get(priority, 0)}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unified parser for cargo-audit, cargo-geiger and cargo clippy outputs"
    )
    parser.add_argument(
        "--audit",
        action="append",
        default=[],
        help="cargo-audit JSON file in format repo:/path/to/file",
    )
    parser.add_argument(
        "--geiger",
        action="append",
        default=[],
        help="cargo-geiger text file in format repo:/path/to/file",
    )
    parser.add_argument(
        "--clippy",
        action="append",
        default=[],
        help="cargo-clippy JSON lines file in format repo:/path/to/file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional output JSON file for unified findings",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a summary after parsing",
    )

    args = parser.parse_args()

    all_findings: List[Finding] = []

    # cargo-audit
    for item in args.audit:
        try:
            repo, path = parse_repo_file_arg(item)
            if not path.exists():
                print(f"[warn] File not found: {path}", file=sys.stderr)
                continue

            parsed = parse_audit(repo, path)
            all_findings.extend(parsed)
            print(f"[ok] Parsed cargo-audit for {repo}: {len(parsed)} findings", file=sys.stderr)
        except Exception as e:
            print(f"[error] Failed to parse --audit {item}: {e}", file=sys.stderr)

    # cargo-geiger
    for item in args.geiger:
        try:
            repo, path = parse_repo_file_arg(item)
            if not path.exists():
                print(f"[warn] File not found: {path}", file=sys.stderr)
                continue

            parsed = parse_geiger(repo, path)
            all_findings.extend(parsed)
            print(f"[ok] Parsed cargo-geiger for {repo}: {len(parsed)} findings", file=sys.stderr)
        except Exception as e:
            print(f"[error] Failed to parse --geiger {item}: {e}", file=sys.stderr)

    # cargo-clippy
    for item in args.clippy:
        try:
            repo, path = parse_repo_file_arg(item)
            if not path.exists():
                print(f"[warn] File not found: {path}", file=sys.stderr)
                continue

            parsed = parse_clippy(repo, path)
            all_findings.extend(parsed)
            print(f"[ok] Parsed cargo-clippy for {repo}: {len(parsed)} findings", file=sys.stderr)
        except Exception as e:
            print(f"[error] Failed to parse --clippy {item}: {e}", file=sys.stderr)

    if args.output:
        args.output.write_text(findings_to_json(all_findings), encoding="utf-8")
        print(f"[ok] Wrote unified findings to {args.output}", file=sys.stderr)
    else:
        print(findings_to_json(all_findings))

    if args.summary:
        print("", file=sys.stderr)
        print(summarize_findings(all_findings), file=sys.stderr)


if __name__ == "__main__":
    main()