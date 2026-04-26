#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path


def run_command(cmd: list[str], cwd: Path | str | None = None) -> dict:
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            shell=False,
        )

        return {
            "command": cmd,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    except Exception as e:
        return {
            "command": cmd,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
        }


def run_rust_scan(repo_path: str | Path) -> dict:
    repo_path = Path(repo_path)

    return {
        "audit": run_command(["cargo", "audit", "--json"], cwd=repo_path),
        "geiger": run_command(["cargo", "geiger"], cwd=repo_path),
        "clippy": run_command(
            ["cargo", "clippy", "--all-targets", "--all-features", "--message-format=json"],
            cwd=repo_path,
        ),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: py rust_scan.py <repo_path>")
        sys.exit(1)

    repo = sys.argv[1]
    output = run_rust_scan(repo)

    print(json.dumps(output, indent=2, ensure_ascii=False))