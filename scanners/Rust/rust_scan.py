from __future__ import annotations

import json
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

def _run(cmd: list[str], cwd: str | Path, timeout: int = 300) -> dict[str, Any]:
    
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
        result["error"] = f"Executable not found: {exc}"
        logger.error("Executable not found for command: %s", " ".join(cmd))
    except OSError as exc:
        result["error"] = str(exc)
        logger.error("OSError running %s: %s", " ".join(cmd), exc)

    return result

def _check_tool(name: str) -> bool:
    """Verifica se a ferramenta está instalada no sistema."""
    return shutil.which(name) is not None

def run_audit(project_path: str | Path, timeout: int = 120) -> dict[str, Any]:
    """Executa o cargo-audit e extrai o JSON bruto."""
    if not _check_tool("cargo") or not _check_tool("cargo-audit"):
        return {"error": "cargo-audit not found", "parsed": None}

    cmd = ["cargo", "audit", "--json"]
    raw = _run(cmd, project_path, timeout=timeout)
    result = {**raw, "parse_error": None, "parsed": None}

    if raw["error"] or raw["timed_out"]:
        return result

    try:
        result["parsed"] = json.loads(raw["stdout"])
    except json.JSONDecodeError as exc:
        result["parse_error"] = f"JSON decode error: {exc}"

    return result

def run_geiger(project_path: str | Path, timeout: int = 180) -> dict[str, Any]:
    """Executa o cargo-geiger e extrai o JSON bruto."""
    if not _check_tool("cargo-geiger") and not _check_tool("cargo"):
        return {"error": "cargo-geiger not found", "parsed": None}

    cmd = ["cargo", "geiger", "--output-format", "Json", "--quiet"]
    raw = _run(cmd, project_path, timeout=timeout)
    result = {**raw, "parse_error": None, "parsed": None}

    if raw["error"] or raw["timed_out"]:
        return result

    stdout = raw["stdout"].strip()
    json_start = stdout.find("{")
    if json_start == -1:
        result["parse_error"] = "No JSON object found"
        return result

    try:
        result["parsed"] = json.loads(stdout[json_start:])
    except json.JSONDecodeError as exc:
        result["parse_error"] = f"JSON decode error: {exc}"

    return result

def run_clippy(project_path: str | Path, timeout: int = 300) -> dict[str, Any]:
    """Executa o cargo clippy e extrai as linhas JSON brutas."""
    cmd = ["cargo", "clippy", "--message-format=json", "--all-targets", "--all-features"]
    raw = _run(cmd, project_path, timeout=timeout)
    result = {**raw, "parse_error": None, "messages": []}

    if raw["error"] or raw["timed_out"]:
        return result

    messages = []
    parse_errors = []
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
        result["parse_error"] = "; ".join(parse_errors[:5])

    return result

def scan_raw(project_path: str | Path) -> dict[str, Any]:
    """Função principal do scanner: Retorna dicionários em bruto para todas as ferramentas de Rust."""
    project_path = Path(project_path).resolve()
    logger.info(f"A extrair dados raw de Rust no diretório: {project_path}")
    
    return {
        "project_path": str(project_path),
        "audit": run_audit(project_path),
        "geiger": run_geiger(project_path),
        "clippy": run_clippy(project_path),
    }