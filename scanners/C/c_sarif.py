_LEVEL_ORDER = {"error": 0, "warning": 1, "note": 2}

def _dedup(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for f in findings:
        key = (f["uri"], f["startLine"], f["ruleId"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique

def aggregate(cpp_f: list[dict], flaw_f: list[dict], sem_f: list[dict]) -> list[dict]:
    all_findings = cpp_f + flaw_f + sem_f
    all_findings = _dedup(all_findings)
    all_findings.sort(key=lambda f: _LEVEL_ORDER.get(f["level"], 99))
    return all_findings

def _build_sarif_run(tool_name: str, findings: list[dict]) -> dict:
    results = []
    for f in findings:
        results.append({
            "ruleId": f["ruleId"],
            "level": f["level"],
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["uri"]},
                    "region": {"startLine": f["startLine"]},
                }
            }],
        })
    return {
        "tool": {
            "driver": {
                "name": tool_name,
                "informationUri": "https://github.com/secdum/secdojo-scan",
                "rules": [],
            }
        },
        "results": results,
    }

def build_sarif(cpp_f: list[dict], flaw_f: list[dict], sem_f: list[dict]) -> dict:
    aggregated = aggregate(cpp_f, flaw_f, sem_f)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            _build_sarif_run("Cppcheck", cpp_f),
            _build_sarif_run("Flawfinder", flaw_f),
            _build_sarif_run("Semgrep", sem_f),
            _build_sarif_run("secdojo-scan-c-aggregated", aggregated),
        ],
    }