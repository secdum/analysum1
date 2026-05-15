from __future__ import annotations

import re
from typing import Any
from secdojo.models import Finding

_SEVERITY_MAP: dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "ice": "HIGH",
    "help": "INFO",
}

def _cvss_to_severity(cvss: str) -> str:
    """Mapeia uma string de score CVSS v3 para uma label de gravidade."""
    match = re.search(r"/(\d+(?:\.\d+)?)$", cvss)
    if not match:
        return "MEDIUM"
    score = float(match.group(1))
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"

def parse_audit(audit_result: dict[str, Any]) -> list[Finding]:
    """Converte o dicionário bruto do cargo-audit para Findings."""
    findings: list[Finding] = []
    parsed = audit_result.get("parsed") or {}

    # Vulnerabilidades
    vulnerabilities = parsed.get("vulnerabilities", {})
    for vuln in vulnerabilities.get("list", []):
        advisory = vuln.get("advisory", {})
        package  = vuln.get("package", {})

        advisory_id = advisory.get("id", "UNKNOWN")
        cvss = advisory.get("cvss") or ""
        severity = _cvss_to_severity(cvss) if cvss else "HIGH"

        findings.append(Finding(
            tool="cargo-audit",
            type=advisory.get("categories", ["vulnerability"])[0] if advisory.get("categories") else "vulnerability",
            severity=severity,
            message=f"[{advisory_id}] {advisory.get('title', 'No title')} in {package.get('name', '?')} {package.get('version', '?')}. {advisory.get('url', '')}",
            file="Cargo.lock",
            line=0
        ))

    # Avisos Unmaintained
    for warning in parsed.get("warnings", {}).get("unmaintained", []):
        advisory = warning.get("advisory", {})
        package  = warning.get("package", {})
        findings.append(Finding(
            tool="cargo-audit",
            type="unmaintained",
            severity="MEDIUM",
            message=f"[{advisory.get('id', 'UNKNOWN')}] Unmaintained crate: {package.get('name', '?')} {package.get('version', '?')}. {advisory.get('url', '')}",
            file="Cargo.lock",
            line=0
        ))

    return findings

def parse_geiger(geiger_result: dict[str, Any]) -> list[Finding]:
    """Converte o dicionário bruto do cargo-geiger para Findings."""
    findings: list[Finding] = []
    parsed = geiger_result.get("parsed") or {}

    for package_info in parsed.get("packages", []):
        pkg = package_info.get("package", {})
        name = pkg.get("name", "unknown")
        ver = pkg.get("version", "?")
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
            continue

        severity = "HIGH" if total_unsafe > 50 else "MEDIUM" if total_unsafe > 10 else "LOW"

        findings.append(Finding(
            tool="cargo-geiger",
            type="unsafe_code",
            severity=severity,
            message=f"{name} v{ver} contains {total_unsafe} unsafe code construct(s) (functions, expressions, traits, impls, methods).",
            file=f"{name}/src",
            line=0
        ))

    return findings

def parse_clippy(clippy_result: dict[str, Any]) -> list[Finding]:
    """Converte as linhas JSON do clippy para Findings."""
    findings: list[Finding] = []

    for msg in clippy_result.get("messages", []):
        if msg.get("reason") != "compiler-message":
            continue

        diag = msg.get("message", {})
        level = diag.get("level", "note")

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
    """Processa todos os dicionários raw e devolve a lista unificada de Findings."""
    all_findings = []
    
    if "audit" in raw_results:
        all_findings.extend(parse_audit(raw_results["audit"]))
        
    if "geiger" in raw_results:
        all_findings.extend(parse_geiger(raw_results["geiger"]))
        
    if "clippy" in raw_results:
        all_findings.extend(parse_clippy(raw_results["clippy"]))
        
    return all_findings