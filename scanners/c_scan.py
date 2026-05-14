import subprocess
import json
import sys
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanners.c_parser import parse_cppcheck, parse_flawfinder, parse_semgrep
from scanners.c_sarif import build_sarif

MAX_FILES_PER_DIR = 200

def _run(cmd: list[str], cwd: str | None = None, timeout: int | None = None) -> tuple[str, str, int]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 124
    except FileNotFoundError:
        return "", f"{cmd[0]}: command not found", 127

def run_cppcheck_on_dir(directory: str, timeout: int = 300) -> str:
    stdout, stderr, _ = _run([
        "cppcheck", "--xml", "--xml-version=2",
        "--enable=warning,style,performance,portability",
        "--force", "--suppress=missingIncludeSystem", "--max-ctu-depth=0", directory
    ], timeout=timeout)
    xml_content = stderr.strip().lstrip("\ufeff")
    return xml_content if ("<" in xml_content[:10]) else stdout

def _count_c_files(path: Path) -> int:
    return sum(1 for _ in path.rglob("*.[ch]"))

def _collect_scan_targets(target_path: Path, ignore_dirs: set) -> list[str]:
    targets = []
    for p in sorted(target_path.iterdir()):
        if not p.is_dir() or p.name in ignore_dirs:
            continue
        if _count_c_files(p) > MAX_FILES_PER_DIR:
            sub_subdirs = [str(s) for s in sorted(p.iterdir()) if s.is_dir() and s.name not in ignore_dirs]
            targets.extend(sub_subdirs) if sub_subdirs else targets.append(str(p))
        else:
            targets.append(str(p))
    return targets

def run_cppcheck(target: str, max_workers: int = 4, timeout_per_dir: int = 600) -> str:
    target_path = Path(target)
    if target_path.is_file():
        return run_cppcheck_on_dir(target, timeout=timeout_per_dir)

    IGNORE_DIRS = {".git", "LICENSES", "Documentation", "tools", "scripts", "include"}
    subdirs = _collect_scan_targets(target_path, IGNORE_DIRS)
    
    if not subdirs:
        return run_cppcheck_on_dir(target, timeout=timeout_per_dir)

    effective_workers = min(len(subdirs), os.cpu_count() or max_workers)
    all_errors = []

    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        futures = {executor.submit(run_cppcheck_on_dir, d, timeout_per_dir): d for d in subdirs}
        for future in as_completed(futures):
            try:
                xml_chunk = future.result()
                if xml_chunk.strip():
                    root = ET.fromstring(xml_chunk)  # nosec B314
                    for error in root.iter("error"):
                        all_errors.append(ET.tostring(error, encoding="unicode"))
            except Exception as exc:
                print(f"[WARN] Falha: {exc}", file=sys.stderr)

    if not all_errors: return ""
    return f"<results version=\"2\">\n<errors>\n" + "\n".join(all_errors) + "\n</errors>\n</results>"

def run_flawfinder(target: str) -> str:
    stdout, _, _ = _run(["flawfinder", "--csv", "--quiet", target])
    return stdout

def run_semgrep(target: str) -> str:
    stdout, _, _ = _run(["semgrep", "--config", "auto", "--json", "--quiet", target], timeout=600)
    return stdout

def scan_c(target: str, timeout_per_dir: int = 600, max_workers: int = 4) -> dict:
    target_path = str(Path(target).resolve())
    
    print(f"[INFO] Scanning: {target_path}", file=sys.stderr)
    
    cpp_raw = run_cppcheck(target_path, max_workers, timeout_per_dir)
    flaw_raw = run_flawfinder(target_path)
    sem_raw = run_semgrep(target_path)

    return build_sarif(
        parse_cppcheck(cpp_raw),
        parse_flawfinder(flaw_raw),
        parse_semgrep(sem_raw)
    )

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    
    result = scan_c(args.target, args.timeout, args.workers)
    print(json.dumps(result, indent=2))
