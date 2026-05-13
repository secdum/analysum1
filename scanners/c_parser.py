import xml.etree.ElementTree as ET
import csv
import io
import sys

def _severity_to_sarif_level(severity: str) -> str:
    s = severity.lower().strip()
    if s in ("critical", "high", "error"):
        return "error"
    if s in ("medium", "warning", "moderate"):
        return "warning"
    return "note"

def parse_cppcheck(xml_output: str) -> list[dict]:
    results = []
    if not xml_output.strip():
        return results
    try:
        root = ET.fromstring(xml_output)  # nosec B314
    except ET.ParseError as exc:
        print(f"[WARN] Invalid cppcheck XML: {exc}", file=sys.stderr)
        return results

    for error in root.iter("error"):
        severity_raw = error.attrib.get("severity", "information")
        rule_id = error.attrib.get("id", "unknown")
        message = error.attrib.get("msg", "")
        cwe = error.attrib.get("cwe", "")
        rule_id_final = f"CWE-{cwe}" if cwe else rule_id

        locations = error.findall("location")
        if locations:
            for loc in locations:
                results.append({
                    "ruleId": rule_id_final,
                    "level": _severity_to_sarif_level(severity_raw),
                    "message": message,
                    "uri": loc.attrib.get("file", "unknown"),
                    "startLine": int(loc.attrib.get("line", 1)),
                })
        else:
            results.append({
                "ruleId": rule_id_final,
                "level": _severity_to_sarif_level(severity_raw),
                "message": message,
                "uri": "unknown",
                "startLine": 1,
            })
    return results

def parse_flawfinder(csv_output: str) -> list[dict]:
    results = []
    if not csv_output.strip():
        return results
    reader = csv.DictReader(io.StringIO(csv_output))
    for row in reader:
        try:
            level_int = int(row.get("Level", 0))
        except ValueError:
            level_int = 0
        
        sev_text = "high" if level_int >= 4 else ("medium" if level_int == 3 else "low")
        cwe_raw = row.get("CWEs", "").strip()
        rule_id = cwe_raw.split(",")[0].strip() if cwe_raw else f"flawfinder/{row.get('Name', 'unknown')}"

        results.append({
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(sev_text),
            "message": row.get("Warning", row.get("Name", "")),
            "uri": row.get("File", "unknown"),
            "startLine": int(row.get("Line", 1) or 1),
        })
    return results

def parse_semgrep(json_output: str) -> list[dict]:
    import json
    results = []
    if not json_output.strip():
        return results
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as exc:
        print(f"[WARN] Invalid semgrep JSON: {exc}", file=sys.stderr)
        return results

    for finding in data.get("results", []):
        extra = finding.get("extra", {})
        results.append({
            "ruleId": finding.get("check_id", "unknown"),
            "level": _severity_to_sarif_level(extra.get("severity", "INFO")),
            "message": extra.get("message", ""),
            "uri": finding.get("path", "unknown"),
            "startLine": finding.get("start", {}).get("line", 1),
        })
    return results