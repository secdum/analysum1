#!/usr/bin/env python3

import json
from pathlib import Path
from collections import defaultdict, Counter

INPUT_FILES = {
    "ripgrep": Path("outputs/ripgrep/unified_findings.json"),
    "tokio": Path("outputs/tokio/tokio_unified_findings.json"),
    "rustls": Path("outputs/rustls/rustls_unified_findings.json"),
}

OUTPUT_DIR = Path("reports")
OUTPUT_DIR.mkdir(exist_ok=True)

PRIORITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

GEIGER_LEGEND_PREFIXES = [
    "x = unsafe code used by the build",
    "y = total unsafe code found in the crate",
    ":) = No `unsafe` usage found, declares #![forbid(unsafe_code)]",
    "?  = No `unsafe` usage found, missing #![forbid(unsafe_code)]",
    "!  = `unsafe` usage found",
]


def load_findings(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def is_geiger_legend_finding(finding: dict) -> bool:
    if finding.get("tool") != "cargo-geiger":
        return False

    message = str(finding.get("message", "")).strip()
    return any(message.startswith(prefix) for prefix in GEIGER_LEGEND_PREFIXES)


def filter_findings(findings: list[dict]) -> list[dict]:
    return [f for f in findings if not is_geiger_legend_finding(f)]


def summarize(findings: list[dict]):
    by_tool = defaultdict(int)
    by_category = defaultdict(int)
    by_priority = defaultdict(int)
    by_file = defaultdict(int)
    by_rule = defaultdict(int)

    for f in findings:
        by_tool[f.get("tool", "unknown")] += 1
        by_category[f.get("category", "unknown")] += 1
        by_priority[f.get("normalized_priority", "INFO")] += 1

        file_name = str(f.get("file", "unknown"))
        if file_name and file_name != "N/A":
            by_file[file_name] += 1

        rule_id = str(f.get("rule_id", "unknown"))
        by_rule[rule_id] += 1

    return by_tool, by_category, by_priority, by_file, by_rule


def priority_rank(value: str) -> int:
    try:
        return PRIORITY_ORDER.index(value)
    except ValueError:
        return len(PRIORITY_ORDER)


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (
            priority_rank(f.get("normalized_priority", "INFO")),
            f.get("tool", ""),
            f.get("rule_id", ""),
            f.get("file", ""),
            f.get("line", 0),
        ),
    )


def top_findings(findings: list[dict], n: int = 5) -> list[dict]:
    sorted_findings = sort_findings(findings)
    return sorted_findings[:n]


def top_rules(by_rule: dict[str, int], n: int = 10):
    return sorted(by_rule.items(), key=lambda x: (-x[1], x[0]))[:n]


def top_files(by_file: dict[str, int], n: int = 10):
    return sorted(by_file.items(), key=lambda x: (-x[1], x[0]))[:n]


def generate_observations(findings: list[dict], by_tool, by_category) -> list[str]:
    observations = []

    audit_count = by_tool.get("cargo-audit", 0)
    geiger_count = by_tool.get("cargo-geiger", 0)
    clippy_count = by_tool.get("cargo-clippy", 0)

    if audit_count == 0:
        observations.append("- No cargo-audit vulnerabilities were reported.")
    else:
        observations.append(f"- cargo-audit reported {audit_count} dependency advisory/warning findings.")

    if geiger_count == 0:
        observations.append("- No parseable unsafe-usage findings were extracted from cargo-geiger output.")
    else:
        observations.append(f"- cargo-geiger reported {geiger_count} unsafe-usage findings.")

    if clippy_count == 0:
        observations.append("- No parseable cargo-clippy findings were extracted from the analyzed output.")
    else:
        observations.append(f"- cargo-clippy reported {clippy_count} lint findings.")

    if clippy_count > geiger_count and clippy_count > audit_count:
        observations.append("- Most findings come from cargo-clippy, indicating that code-quality issues dominate the output.")

    if by_category.get("unsafe_usage", 0) > 0:
        observations.append("- Unsafe usage findings should be interpreted as risk indicators, not confirmed vulnerabilities.")

    return observations


def generate_report(repo: str, findings: list[dict]) -> str:
    findings = filter_findings(findings)

    by_tool, by_category, by_priority, by_file, by_rule = summarize(findings)
    top = top_findings(findings, n=5)
    most_common_rules = top_rules(by_rule, n=10)
    most_common_files = top_files(by_file, n=10)
    observations = generate_observations(findings, by_tool, by_category)

    lines = []
    lines.append("=" * 70)
    lines.append(f"RUST SECURITY ANALYSIS SUMMARY - {repo.upper()}")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Total Findings: {len(findings)}")
    lines.append("")

    lines.append("Distribution by Unified Severity:")
    for p in PRIORITY_ORDER:
        lines.append(f"  {p:12s}: {by_priority.get(p, 0):4d}")
    lines.append("")

    lines.append("Distribution by Tool:")
    if by_tool:
        for tool, count in sorted(by_tool.items()):
            lines.append(f"  {tool:16s}: {count:4d}")
    else:
        lines.append("  No tool findings")
    lines.append("")

    lines.append("Distribution by Category:")
    if by_category:
        for category, count in sorted(by_category.items()):
            lines.append(f"  {category:16s}: {count:4d}")
    else:
        lines.append("  No category findings")
    lines.append("")

    lines.append("Top 10 Rules:")
    if most_common_rules:
        for idx, (rule_id, count) in enumerate(most_common_rules, start=1):
            lines.append(f"  {idx:2d}. {rule_id:35s}: {count:4d}")
    else:
        lines.append("  No rules")
    lines.append("")

    lines.append("Top 10 Files:")
    if most_common_files:
        for idx, (file_name, count) in enumerate(most_common_files, start=1):
            lines.append(f"  {idx:2d}. {file_name:35s}: {count:4d}")
    else:
        lines.append("  No files")
    lines.append("")

    lines.append("Top 5 Findings:")
    if top:
        for idx, f in enumerate(top, start=1):
            lines.append(f"  {idx}. [{f.get('tool', 'unknown')}] {f.get('rule_id', 'unknown')}")
            lines.append(f"     File: {f.get('file', 'unknown')}:{f.get('line', 0)}")
            msg = str(f.get("message", "")).replace("\n", " ").strip()
            if len(msg) > 120:
                msg = msg[:120].rstrip() + "..."
            lines.append(f"     {msg}")
            lines.append("")
    else:
        lines.append("  No findings")
        lines.append("")

    lines.append("Observations:")
    if observations:
        lines.extend(observations)
    else:
        lines.append("- No relevant observations.")
    lines.append("")
    lines.append("=" * 70)

    return "\n".join(lines)


def main():
    for repo, input_path in INPUT_FILES.items():
        if not input_path.exists():
            print(f"[warn] Missing {input_path}")
            continue

        findings = load_findings(input_path)
        report = generate_report(repo, findings)

        output_file = OUTPUT_DIR / f"{repo}_summary.txt"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)

        print(f"[ok] Generated {output_file}")


if __name__ == "__main__":
    main()