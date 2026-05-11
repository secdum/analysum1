import argparse
import sys
import os
import time
from scanners.rust_scan import scan_raw
from scanners.rust_parser import parse_all_rust

# ANSI Color Codes for beautiful CLI output
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BOLD = '\033[1m'
RESET = '\033[0m'

def typewriter_print(text, delay=0.015):
    """Prints text with a typewriter effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def spinner_animation(text, duration=2.0):
    """Displays a spinning animation for a given duration."""
    chars = ['|', '/', '-', '\\']
    start_time = time.time()
    i = 0
    while time.time() - start_time < duration:
        sys.stdout.write(f"\r{CYAN}[{chars[i % len(chars)]}]{RESET} {text}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    # Clear line and print final state
    sys.stdout.write(f"\r{GREEN}[OK]{RESET} {text}{' ' * 10}\n")
    sys.stdout.flush()

def print_banner():
    banner = f"""
{CYAN}{BOLD}================================================={RESET}
{CYAN}{BOLD}       SecDojo Scanner - Security Analysis       {RESET}
{CYAN}{BOLD}================================================={RESET}
"""
    # Print banner with a slight delay per line
    for line in banner.splitlines():
        print(line)
        time.sleep(0.05)

def wizard():
    print()
    typewriter_print(f"{YELLOW}Welcome to the SecDojo Scanner Interactive Wizard!{RESET}")
    time.sleep(0.2)
    
    # Prompt for language selection
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
    
    # Prompt for repository path
    print()
    typewriter_print(f"{BOLD}Enter the path to the repository you want to scan:{RESET}")
    path = input(f"{GREEN}Path (e.g. ./my_repo): {RESET}").strip()
    
    if not path:
        print(f"\n{RED}Error: Path cannot be empty.{RESET}")
        sys.exit(1)
        
    return lang, path

def main():
    parser = argparse.ArgumentParser(
        description="SecDojo Scanner CLI - A security analysis tool for C and Rust codebases.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("--lang", choices=["rust", "c", "all"], help="Language to analyze: 'rust', 'c', or 'all'")
    parser.add_argument("--path", type=str, help="Path to the repository to scan")
    
    # If no arguments are passed, start the interactive wizard
    if len(sys.argv) == 1:
        print_banner()
        lang, path = wizard()
    else:
        args = parser.parse_args()
        lang = args.lang
        path = args.path
        
        if not lang or not path:
            print(f"{RED}Error: When using CLI arguments, both --lang and --path are required.{RESET}")
            parser.print_help()
            sys.exit(1)
            
    print("\n")
    spinner_animation("Validating configuration...", duration=1.2)
    
    print(f"\n{CYAN}{BOLD}[*] Configuration Accepted!{RESET}")
    typewriter_print(f"  {BOLD}Language:{RESET} {lang.capitalize()}")
    typewriter_print(f"  {BOLD}Target Path:{RESET} {os.path.abspath(path)}")
    
    print()
    spinner_animation("Initializing scan engines...", duration=1.8)
    
    all_findings = []

    if lang in ['rust', 'all']:
        print(f"\n{CYAN}[*] Starting Rust Analysis...{RESET}")
        try:
            # Correr as ferramentas 
            raw_results = scan_raw(path)
            print(f"\n[DEBUG] Erro Audit: {raw_results['audit'].get('error')}")
            print(f"[DEBUG] Erro Geiger: {raw_results['geiger'].get('error')}\n")
            #Fazer o parse dos resultados
            rust_findings = parse_all_rust(raw_results)
            all_findings.extend(rust_findings)
            
            print(f"{GREEN}[OK] Rust analysis completed!{RESET}")
        except Exception as e:
            print(f"{RED}[ERROR] Rust scan failed: {e}{RESET}")

    if lang in ['c', 'all']:
        print(f"\n{YELLOW}[!] C analysis is not yet implemented.{RESET}")
        

  
    print(f"\n{CYAN}{BOLD}================================================={RESET}")
    print(f"{CYAN}{BOLD}                  SCAN RESULTS                   {RESET}")
    print(f"{CYAN}{BOLD}================================================={RESET}")

    if not all_findings:
        print(f"\n{GREEN} Excellent! No vulnerabilities or issues found.{RESET}\n")
    else:
        print(f"\n{RED} Found {len(all_findings)} issue(s):{RESET}\n")
        for f in all_findings:
            color = RED if f.severity in ["CRITICAL", "HIGH"] else YELLOW
            
            print(f"[{color}{BOLD}{f.severity}{RESET}] {f.tool} ({f.type})")
            print(f"    {f.message}")
            print(f"    {CYAN}Location:{RESET} {f.file}:{f.line}")
            print("-" * 50)

if __name__ == "__main__":
    main()
