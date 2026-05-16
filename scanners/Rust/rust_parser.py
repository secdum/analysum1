from __future__ import annotations

import re
from typing import Any
from secdojo.models import Finding

def _cvss_to_level(cvss: str) -> str:
    """
    Converts a CVSS v3 vector string to a SARIF-style level.
 
    CVSS score ranges:
        >= 9.0  → error    (Critical)
        >= 7.0  → error    (High)
        >= 4.0  → warning  (Medium)
        <  4.0  → note     (Low)
    """
    match = re.search(r"/(\d+(?:\.\d+)?)$", cvss)
    if not match:
        # No score available, default to warning so it doesn't get lost
        return "warning"
    score = float(match.group(1))
    if score >= 7.0:
        return "error"
    if score >= 4.0:
        return "warning"
    return "note"
 
def parse_audit(audit_result: dict[str, Any]) -> list[Finding]:
    """
    Converts the raw cargo-audit dictionary into a list of Finding objects.
 
    Handles two categories:
      - vulnerabilities: active CVEs / RustSec advisories with a CVSS score
      - warnings.unmaintained: crates that are no longer maintained
    """
    findings: list[Finding] = []
    parsed = audit_result.get("parsed") or {}
 
    # --- Active vulnerabilities ---
    vulnerabilities = parsed.get("vulnerabilities", {})
    for vuln in vulnerabilities.get("list", []):
        advisory = vuln.get("advisory", {})
        package  = vuln.get("package", {})
 
        advisory_id = advisory.get("id", "UNKNOWN")
        cvss        = advisory.get("cvss") or ""
 
        # Use CVSS score if present; fall back to "error" for unscored advisories
        level = _cvss_to_level(cvss) if cvss else "error"
 
        # Pull the first category tag (e.g. "memory-corruption", "denial-of-service")
        categories = advisory.get("categories") or []
        vuln_type  = categories[0] if categories else "vulnerability"
 
        findings.append(Finding(
            tool="cargo-audit",
            type=vuln_type,
            severity=level,
            message=(
                f"[{advisory_id}] {advisory.get('title', 'No title')} "
                f"in {package.get('name', '?')} {package.get('version', '?')}. "
                f"{advisory.get('url', '')}"
            ),
            file="Cargo.lock",
            line=0,
        ))
 
    # --- Unmaintained crate warnings ---
    for warning in parsed.get("warnings", {}).get("unmaintained", []):
        advisory = warning.get("advisory", {})
        package  = warning.get("package", {})
 
        findings.append(Finding(
            tool="cargo-audit",
            type="unmaintained",
            severity="warning",   # unmaintained is a risk, not an active exploit → warning
            message=(
                f"[{advisory.get('id', 'UNKNOWN')}] "
                f"Unmaintained crate: {package.get('name', '?')} {package.get('version', '?')}. "
                f"{advisory.get('url', '')}"
            ),
            file="Cargo.lock",
            line=0,
        ))
 
    return findings

def parse_geiger(geiger_result: dict[str, Any]) -> list[Finding]:
    """
    Converts the raw cargo-geiger dictionary into a list of Finding objects.
 
    cargo-geiger reports how many unsafe constructs each crate uses.
    We sum all unsafe counters and map the total to a SARIF-style level:
        > 50 unsafe constructs → error
        > 10                   → warning
        <= 10                  → note
    Crates with zero unsafe constructs are skipped.
    """
    
    findings: list[Finding] = []
    parsed = geiger_result.get("parsed") or {}

    for package_info in parsed.get("packages", []):
        pkg = package_info.get("package", {})
        name = pkg.get("name", "unknown")
        ver = pkg.get("version", "?")
        unsaf = package_info.get("unsafety", {})

        used = unsaf.get("used", {})
        # Sum every category of unsafe construct reported by geiger
        total_unsafe = sum([
            used.get("functions", {}).get("unsafe", 0),
            used.get("exprs", {}).get("unsafe", 0),
            used.get("item_impls", {}).get("unsafe", 0),
            used.get("item_traits", {}).get("unsafe", 0),
            used.get("methods", {}).get("unsafe", 0),
        ])

        if total_unsafe == 0:
            continue

        severity = "HIGH" if total_unsafe > 50 else "MEDIUM" if total_unsafe > 10 else "LOW"

        findings.append(Finding(
            tool="cargo-geiger",
            type="unsafe_code",
            severity=level,
            message=(
                f"{name} v{ver} contains {total_unsafe} unsafe code "
                f"construct(s) (functions, expressions, traits, impls, methods)."
            ),
            file=f"{name}/src",
            line=0,
        ))
 
    return findings

def parse_clippy(clippy_result: dict[str, Any]) -> list[Finding]:
    """
    Converts raw Clippy JSON messages into a list of Finding objects.
 
    Only 'warning' and 'error' level compiler messages are included;
    informational messages are skipped to reduce noise.
    Each message is mapped to a SARIF-style level:
        error   → error
        warning → warning
    """
    findings: list[Finding] = []
    # Clippy outputs one JSON object per line; each has a "reason" field
    for msg in clippy_result.get("messages", []):
        if msg.get("reason") != "compiler-message":
            continue

        diag = msg.get("message", {})
        level = diag.get("level", "note")
        # Skip anything that is not a warning or error
        if level not in ("warning", "error"):
            continue

        severity = _SEVERITY_MAP.get(level, "MEDIUM")
        lint_code = diag.get("code", {}).get("code", "unknown")

        spans = diag.get("spans", [])
        primary = next((s for s in spans if s.get("is_primary")), spans[0] if spans else {})

        findings.append(Finding(
            tool="clippy",
            type=lint_code,
            severity=severity,
            message=diag.get("message", "No message"),
            file=primary.get("file_name", "unknown"),
            line=primary.get("line_start", 0)
        ))

    return findings

def parse_all_rust(raw_results: dict[str, Any]) -> list[Finding]:
    """
    Entry point for the Rust parsing stage.
 
    Accepts the raw results dict produced by rust_scan.scan_raw() and
    dispatches each tool's output to the appropriate parser.
    Returns a unified list of Finding objects ready for display or export.
    """
    all_findings = []
    
    if "audit" in raw_results:
        all_findings.extend(parse_audit(raw_results["audit"]))
        
    if "geiger" in raw_results:
        all_findings.extend(parse_geiger(raw_results["geiger"]))
        
    if "clippy" in raw_results:
        all_findings.extend(parse_clippy(raw_results["clippy"]))
        
    return all_findings