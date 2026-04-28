import subprocess
import json
import xml.etree.ElementTree as ET
import csv
import io
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Mapeamento de severidade -> SARIF level
# ---------------------------------------------------------------------------

def _severity_to_sarif_level(severity: str) -> str:
    """
    Mapeia a severidade original de cada ferramenta para o campo
    SARIF 'level' conforme a especificação do projecto:
        critical / high  -> error
        medium           -> warning
        low / info / *   -> note
    """
    s = severity.lower().strip()
    if s in ("critical", "high", "error"):
        return "error"
    if s in ("medium", "warning", "moderate"):
        return "warning"
    return "note"


# ---------------------------------------------------------------------------
# Runners - correm cada ferramenta via subprocess
# ---------------------------------------------------------------------------

def _run(cmd: list[str], cwd: str | None = None) -> tuple[str, str, int]:
    """
    Executa um comando e devolve (stdout, stderr, returncode)
    Não levanta exceção se o processo falhar - as ferramentas
    devolvem returncode != 0 quando encontram issues
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        tool = cmd[0]
        print(f"[WARN] Tool not found: {tool}", file=sys.stderr)
        return "", f"{tool}: command not found", 127


def run_cppcheck(target: str) -> str:
    """Corre cppcheck com output XML v2 e devolve o XML em string"""
    stdout, stderr, _ = _run([
        "cppcheck",
        "--xml",
        "--xml-version=2",
        "--enable=all",
        "--inconclusive",
        target,
    ])
    # cppcheck escreve o XML no stderr
    return stderr if stderr.strip().startswith("<") else stdout


def run_flawfinder(target: str) -> str:
    """Corre flawfinder com output CSV e devolve o CSV em string"""
    stdout, _, _ = _run([
        "flawfinder",
        "--csv",
        "--quiet",
        target,
    ])
    return stdout


def run_semgrep(target: str) -> str:
    """Corre semgrep com ruleset C/C++ e devolve JSON em string"""
    stdout, _, _ = _run([
        "semgrep",
        "--config", "p/c",
        "--json",
        "--quiet",
        target,
    ])
    return stdout


# ---------------------------------------------------------------------------
# Parsers — transformam o output raw em lista de dicts internos
# ---------------------------------------------------------------------------
# Formato interno (SARIF):
# {
#     "ruleId"   : str,   # identificador da regra / CWE
#     "level"    : str,   # "error" | "warning" | "note"
#     "message"  : str,   # descrição da issue
#     "uri"      : str,   # caminho do ficheiro
#     "startLine": int,   # linha (1-based)
# }
# ---------------------------------------------------------------------------

def parse_cppcheck(xml_output: str) -> list[dict]:
    """Parseia o XML do cppcheck e devolve lista de findings"""
    results = []
    if not xml_output.strip():
        return results

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        print(f"[WARN] Invalid cppcheck XML: {exc}", file=sys.stderr)
        return results

    for error in root.iter("error"):
        severity_raw = error.attrib.get("severity", "information")
        rule_id      = error.attrib.get("id", "unknown")
        message      = error.attrib.get("msg", "")
        cwe          = error.attrib.get("cwe", "")

        # Preferir o CWE como ruleId quando disponível
        rule_id_final = f"CWE-{cwe}" if cwe else rule_id

        # A localização pode estar em vários <location> filhos
        locations = error.findall("location")
        if locations:
            for loc in locations:
                file_path = loc.attrib.get("file", "unknown")
                line      = int(loc.attrib.get("line", 1))
                results.append({
                    "ruleId"   : rule_id_final,
                    "level"    : _severity_to_sarif_level(severity_raw),
                    "message"  : message,
                    "uri"      : file_path,
                    "startLine": line,
                })
        else:
            results.append({
                "ruleId"   : rule_id_final,
                "level"    : _severity_to_sarif_level(severity_raw),
                "message"  : message,
                "uri"      : "unknown",
                "startLine": 1,
            })

    return results


def parse_flawfinder(csv_output: str) -> list[dict]:
    """
    Parseia o CSV do flawfinder.
    Colunas esperadas (--csv):
        File, Line, Column, Level, Category, Name, Warning, Suggestion,
        Note, CWEs, Context
    """
    results = []
    if not csv_output.strip():
        return results

    reader = csv.DictReader(io.StringIO(csv_output))
    for row in reader:
        # Flawfinder usa Level 0-5 (inteiro)
        try:
            level_int = int(row.get("Level", 0))
        except ValueError:
            level_int = 0

        # Converter nível numérico para categoria textual
        if level_int >= 4:
            sev_text = "high"
        elif level_int == 3:
            sev_text = "medium"
        else:
            sev_text = "low"

        cwe_raw  = row.get("CWEs", "").strip()
        # CWEs pode conter múltiplos valores separados por vírgula
        rule_id  = cwe_raw.split(",")[0].strip() if cwe_raw else f"flawfinder/{row.get('Name', 'unknown')}"

        try:
            line = int(row.get("Line", 1))
        except ValueError:
            line = 1

        results.append({
            "ruleId"   : rule_id,
            "level"    : _severity_to_sarif_level(sev_text),
            "message"  : row.get("Warning", row.get("Name", "")),
            "uri"      : row.get("File", "unknown"),
            "startLine": line,
        })

    return results


def parse_semgrep(json_output: str) -> list[dict]:
    """Parseia o JSON do semgrep e devolve lista de findings"""
    results = []
    if not json_output.strip():
        return results

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as exc:
        print(f"[WARN] Invalid semgrep JSON: {exc}", file=sys.stderr)
        return results

    for finding in data.get("results", []):
        severity_raw = finding.get("extra", {}).get("severity", "INFO")
        rule_id      = finding.get("check_id", "unknown")
        message      = finding.get("extra", {}).get("message", "")
        file_path    = finding.get("path", "unknown")
        start_line   = finding.get("start", {}).get("line", 1)

        results.append({
            "ruleId"   : rule_id,
            "level"    : _severity_to_sarif_level(severity_raw),
            "message"  : message,
            "uri"      : file_path,
            "startLine": start_line,
        })

    return results


# ---------------------------------------------------------------------------
# Agregação - remove duplicados e ordena por severidade
# ---------------------------------------------------------------------------

_LEVEL_ORDER = {"error": 0, "warning": 1, "note": 2}


def _dedup(findings: list[dict]) -> list[dict]:
    """Remove duplicados com base em (uri, startLine, ruleId)"""
    seen    = set()
    unique  = []
    for f in findings:
        key = (f["uri"], f["startLine"], f["ruleId"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def aggregate(
    cppcheck_findings : list[dict],
    flawfinder_findings: list[dict],
    semgrep_findings  : list[dict],
) -> list[dict]:
    """
    Junta os 3 parsers, remove duplicados e ordena por severidade 
    (error > warning > note)
    Os ruleId são diferentes para cada ferramenta, eles podem nao ser removidos na agregação
    """
    all_findings = cppcheck_findings + flawfinder_findings + semgrep_findings
    all_findings = _dedup(all_findings)
    all_findings.sort(key=lambda f: _LEVEL_ORDER.get(f["level"], 99))
    return all_findings


# ---------------------------------------------------------------------------
# Builder SARIF 2.1.0
# ---------------------------------------------------------------------------

def _build_sarif_run(tool_name: str, findings: list[dict]) -> dict:
    """Constrói um único 'run' SARIF para uma ferramenta"""
    results = []
    for f in findings:
        results.append({
            "ruleId" : f["ruleId"],
            "level"  : f["level"],
            "message": {"text": f["message"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["uri"]},
                        "region"          : {"startLine": f["startLine"]},
                    }
                }
            ],
        })

    return {
        "tool": {
            "driver": {
                "name"           : tool_name,
                "informationUri" : "https://github.com/secdum/secdojo-scan",
                "rules"          : [],
            }
        },
        "results": results,
    }


def build_sarif(
    cppcheck_findings : list[dict],
    flawfinder_findings: list[dict],
    semgrep_findings  : list[dict],
) -> dict:
    """
    Monta o objecto SARIF 2.1.0 completo com um 'run' por ferramenta,
    mais um 'run' agregado com todos os resultados juntos
    """
    aggregated = aggregate(cppcheck_findings, flawfinder_findings, semgrep_findings)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            _build_sarif_run("Cppcheck",    cppcheck_findings),
            _build_sarif_run("Flawfinder",  flawfinder_findings),
            _build_sarif_run("Semgrep",     semgrep_findings),
            _build_sarif_run("secdojo-scan-c-aggregated", aggregated),
        ],
    }


# ---------------------------------------------------------------------------
# Entrypoint público
# ---------------------------------------------------------------------------

def scan_c(target: str) -> dict:
    """
    Função principal:
      1. Corre as 3 ferramentas sobre `target`
      2. Parseia cada output
      3. Devolve o objecto SARIF 2.1.0 completo
    """
    target_path = str(Path(target).resolve())
    print(f"[INFO] Running Cppcheck on: {target_path}", file=sys.stderr)
    cppcheck_raw    = run_cppcheck(target_path)

    print(f"[INFO] Running Flawfinder on: {target_path}", file=sys.stderr)
    flawfinder_raw  = run_flawfinder(target_path)

    print(f"[INFO] Running Semgrep on: {target_path}", file=sys.stderr)
    semgrep_raw     = run_semgrep(target_path)

    cppcheck_findings    = parse_cppcheck(cppcheck_raw)
    flawfinder_findings  = parse_flawfinder(flawfinder_raw)
    semgrep_findings     = parse_semgrep(semgrep_raw)

    print(
        f"[INFO] Findings — Cppcheck: {len(cppcheck_findings)} | "
        f"Flawfinder: {len(flawfinder_findings)} | "
        f"Semgrep: {len(semgrep_findings)}",
        file=sys.stderr,
    )

    return build_sarif(cppcheck_findings, flawfinder_findings, semgrep_findings)


# ---------------------------------------------------------------------------
# CLI para testar o scanner manualmente 
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_c.py <path_to_c_code>", file=sys.stderr)
        sys.exit(1)

    sarif_output = scan_c(sys.argv[1])
    print(json.dumps(sarif_output, indent=2))
