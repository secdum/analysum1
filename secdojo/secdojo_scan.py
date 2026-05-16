import argparse
import sys
import os
import time
import json
from collections import defaultdict
import re

# Add parent directory to sys.path to allow importing from 'scanners'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanners.Rust.rust_scan import scan_raw
from scanners.Rust.rust_parser import parse_all_rust
from scanners.Rust.rust_sarif import export_to_sarif
from scanners.C.c_scan import scan_c
from secdojo.models import Finding

# ANSI Color Codes for CLI output
CYAN   = '\033[96m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
RED    = '\033[91m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

# Maps SARIF-style levels to display colors.
# Both the Rust parser (rust_parser.py) and the C scanner already produce
# error / warning / note in f.severity, so no extra mapping is needed here.
LEVEL_COLOR = {
    "error":   RED,
    "warning": YELLOW,
    "note":    CYAN,
}


def typewriter_print(text, delay=0.015):
    """Prints text with a typewriter effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def spinner_animation(text, duration=2.0):
    """Displays a spinning animation for a given duration, then prints [OK]."""
    chars = ['|', '/', '-', '\\']
    start_time = time.time()
    i = 0
    while time.time() - start_time < duration:
        sys.stdout.write(f"\r{CYAN}[{chars[i % len(chars)]}]{RESET} {text}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write(f"\r{GREEN}[OK]{RESET} {text}{' ' * 10}\n")
    sys.stdout.flush()


def print_banner():
    """Prints the SecDojo ASCII banner at startup."""
    banner = f"""
{CYAN}{BOLD}================================================={RESET}
{CYAN}{BOLD}       SecDojo Scanner - Security Analysis       {RESET}
{CYAN}{BOLD}================================================={RESET}
"""
    for line in banner.splitlines():
        print(line)
        time.sleep(0.05)


def wizard():
    """
    Interactive wizard that prompts the user to select a language and a repo path.
    Returns a (lang, path) tuple.
    """
    print()
    typewriter_print(f"{YELLOW}Welcome to the SecDojo Scanner Interactive Wizard!{RESET}")
    time.sleep(0.2)

    print(f"\n{BOLD}Which language/ecosystem would you like to analyze?{RESET}")
    time.sleep(0.1)
    print(f"  {CYAN}1){RESET} Rust")
    time.sleep(0.1)
    print(f"  {CYAN}2){RESET} C")
    time.sleep(0.1)
    print(f"  {CYAN}3){RESET} All (Both Rust and C)")

    lang_choice = ""
    while lang_choice not in ['1', '2', '3']:
        lang_choice = input(f"\n{GREEN}Select an option (1/2/3): {RESET}").strip()

    lang_map = {'1': 'rust', '2': 'c', '3': 'all'}
    lang = lang_map[lang_choice]

    print()
    typewriter_print(f"{BOLD}Enter the path to the repository you want to scan:{RESET}")
    path = input(f"{GREEN}Path (e.g. ./my_repo): {RESET}").strip()

    if not path:
        print(f"\n{RED}Error: Path cannot be empty.{RESET}")
        sys.exit(2)

    return lang, path


def sarif_to_findings(sarif_data):
    """
    Converts a SARIF report produced by the C scanner into Finding objects.
    Uses the last run in the report (secdojo-scan-c-aggregated).
    """
    findings = []
    run = sarif_data["runs"][-1]
    tool_name = run["tool"]["driver"]["name"]

    for res in run.get("results", []):
        loc = res["locations"][0]["physicalLocation"]
        findings.append(Finding(
            tool=tool_name,
            type=res.get("ruleId", "N/A"),
            message=res["message"]["text"],
            file=loc["artifactLocation"]["uri"],
            line=loc["region"]["startLine"],
            severity=res.get("level", "warning"),  
        ))
    return findings


def print_results(all_findings, had_errors):
    """
    Prints the scan results section:
      - Summary table with counts per level
      - Findings grouped by tool
    """
    print(f"\n{CYAN}{BOLD}================================================={RESET}")
    print(f"{CYAN}{BOLD}                  SCAN RESULTS                   {RESET}")
    print(f"{CYAN}{BOLD}================================================={RESET}")

    if not all_findings:
        if had_errors:
            print(f"\n{YELLOW}{BOLD}[!] Scan finished with errors. Results may be incomplete.{RESET}\n")
        else:
            print(f"\n{GREEN}{BOLD}[+] Excellent! No vulnerabilities or issues found.{RESET}\n")
        return

    # --- Summary: count findings per SARIF level ---
    counts = {"error": 0, "warning": 0, "note": 0}
    for f in all_findings:
        level = f.severity if f.severity in counts else "warning"
        counts[level] += 1

    print(f"\n{BOLD}  Summary{RESET}")
    print(f"  {RED}  Errors   : {counts['error']}{RESET}")
    print(f"  {YELLOW}  Warnings : {counts['warning']}{RESET}")
    print(f"  {CYAN}  Notes    : {counts['note']}{RESET}")
    print(f"  {BOLD}  Total    : {len(all_findings)}{RESET}\n")

    # --- Findings grouped by tool ---
    grouped = defaultdict(list)
    for f in all_findings:
        grouped[f.tool].append(f)

    for tool, tool_findings in grouped.items():
        print(f"{CYAN}{BOLD}[ {tool} — {len(tool_findings)} finding(s) ]{RESET}")
        print("=" * 50)
        for f in tool_findings:
            color = LEVEL_COLOR.get(f.severity, YELLOW)
            print(f"[{color}{BOLD}{f.severity}{RESET}] {f.tool} ({f.type})")
            print(f"    {f.message}")
            print(f"    {CYAN}Location:{RESET} {f.file}:{f.line}")
            print("-" * 50)
        print()

def save_results(filepath, all_findings, lang, path):
    """
    Saves scan results to a file.
    - .json  → structured JSON
    - .txt   → plain text (colors stripped)
    """
    if filepath.endswith(".json"):
        results = []
        for f in all_findings:
            results.append({
                "tool": f.tool,
                "type": f.type,
                "severity": f.severity,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "cwe": getattr(f, 'cwe', None)
            })
        report = {
            "scan": {
                "language": lang,
                "target": path,
                "total_findings": len(all_findings),
            },
            "findings": results
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
    else:
        # .txt or any other extension → plain text
        lines = []
        lines.append("=" * 50)
        lines.append("  SecDojo Scanner - Results")
        lines.append(f"  Language: {lang.capitalize()}")
        lines.append(f"  Target:   {path}")
        lines.append("=" * 50)
        lines.append("")

        counts = {"error": 0, "warning": 0, "note": 0}
        for f in all_findings:
            level = f.severity if f.severity in counts else "warning"
            counts[level] += 1

        lines.append("  Summary")
        if counts["error"]:
            lines.append(f"    Errors   : {counts['error']}")
        if counts["warning"]:
            lines.append(f"    Warnings : {counts['warning']}")
        if counts["note"]:
            lines.append(f"    Notes    : {counts['note']}")
        lines.append(f"    Total    : {len(all_findings)}")
        lines.append("")

        grouped = defaultdict(list)
        for f in all_findings:
            grouped[f.tool].append(f)

        for tool, tool_findings in grouped.items():
            lines.append(f"[ {tool} — {len(tool_findings)} finding(s) ]")
            lines.append("=" * 50)
            for f in tool_findings:
                lines.append(f"[{f.severity}] {f.tool} ({f.type})")
                lines.append(f"    {f.message}")
                lines.append(f"    Location: {f.file}:{f.line}")
                lines.append("-" * 50)
            lines.append("")

        with open(filepath, "w") as f:
            f.write("\n".join(lines))

    print(f"{GREEN}[OK] Results saved to: {os.path.abspath(filepath)}{RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="SecDojo Scanner CLI - A security analysis tool for C and Rust codebases.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--lang", choices=["rust", "c", "all"], help="Language to analyze: 'rust', 'c', or 'all'")
    parser.add_argument("--path", type=str, help="Path to the repository to scan")
    parser.add_argument("--output", type=str, help="Save results to file (strips colors). Supports .txt, .json, .sarif")

    # If no arguments are passed, start the interactive wizard
    if len(sys.argv) == 1:
        print_banner()
        lang, path = wizard()
        output_file = None
    else:
        args = parser.parse_args()
        lang = args.lang
        path = args.path
        output_file = getattr(args, 'output', None)

        if not lang or not path:
            print(f"{RED}Error: When using CLI arguments, both --lang and --path are required.{RESET}")
            parser.print_help()
            sys.exit(2)

    while True:
        print("\n")
        spinner_animation("Validating configuration...", duration=1.2)

        print(f"\n{CYAN}{BOLD}[*] Configuration Accepted!{RESET}")
        typewriter_print(f"  {BOLD}Language:{RESET} {lang.capitalize()}")
        typewriter_print(f"  {BOLD}Target Path:{RESET} {os.path.abspath(path)}")

        print()
        spinner_animation("Initializing scan engines...", duration=1.8)

        path = os.path.abspath(path)
        if not os.path.exists(path):
            print(f"{RED}[ERROR] The path '{path}' does not exist.{RESET}")
            sys.exit(2)

        all_findings = []
        had_errors = False

        if lang in ['rust', 'all']:
            print(f"\n{CYAN}[*] Starting Rust Analysis...{RESET}")
            try:
                raw_results = scan_raw(path)
                
                audit_error = raw_results.get("audit", {}).get("error")
                geiger_error = raw_results.get("geiger", {}).get("error")
                clippy_error = raw_results.get("clippy", {}).get("error")
                if audit_error:
                    print(f"[ERROR] cargo-audit error: {audit_error}{RESET}")
                if geiger_error:
                    print(f"[ERROR] cargo-geiger error: {geiger_error}{RESET}") 
                if clippy_error:
                    print(f"[ERROR] cargo-clippy error: {clippy_error}{RESET}")

                rust_findings = parse_all_rust(raw_results)
                all_findings.extend(rust_findings)

                rust_report = "secdojo_rust_report.sarif"
                export_to_sarif(rust_findings, rust_report)
                print(f"{GREEN}[OK] Rust SARIF report saved to: {os.path.abspath(rust_report)}{RESET}")

                print(f"{GREEN}[OK] Rust analysis completed!{RESET}")
            except Exception as e:
                print(f"{RED}[ERROR] Rust scan failed: {e}{RESET}")
                had_errors = True

        if lang in ['c', 'all']:
            print(f"\n{CYAN}[*] Starting C Analysis...{RESET}")
            try:
                spinner_animation("Running C analysis engines...", duration=2.0)
                sarif_results = scan_c(path)

                # Save the SARIF report to disk
                report_name = "secdojo_report.sarif"
                with open(report_name, "w") as f_out:
                    json.dump(sarif_results, f_out, indent=2)
                print(f"{GREEN}[OK] SARIF report saved to: {os.path.abspath(report_name)}{RESET}")

                c_findings = sarif_to_findings(sarif_results)
                all_findings.extend(c_findings)
                print(f"{GREEN}[OK] C analysis completed!{RESET}")
            except Exception as e:
                print(f"{RED}[ERROR] C scan failed: {e}{RESET}")
                had_errors = True

        # Print summary + grouped findings
        print_results(all_findings, had_errors)
        if output_file:
            save_results(output_file, all_findings, lang, path)

        # Post-scan prompt (skipped in CI/CD non-interactive mode)
        if sys.stdin.isatty():
            print(f"\n{BOLD}What do you want to do next?{RESET}")
            print(f"  {CYAN}1){RESET} Run another scan")
            print(f"  {CYAN}2){RESET} Close CLI")

            choice = ""
            while choice not in ['1', '2']:
                choice = input(f"\n{GREEN}Select an option (1/2): {RESET}").strip()

            if choice == '2':
                print(f"\n{CYAN}Goodbye!{RESET}\n")
                sys.exit(0)

            lang, path = wizard()
            output_file = None
        else:
            # Non-interactive mode (CI/CD) — exit with meaningful code
            if had_errors:
                sys.exit(2)
            elif all_findings:
                sys.exit(1)
            sys.exit(0)
            break


if __name__ == "__main__":
    main()