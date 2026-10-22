"""
CLI Multipurpose Security Assessment Tool — Main Entry Point.
Supports both rich interactive prompt menu and command-line execution:
  python main.py
  python main.py scan --target https://example.com --profile standard
  python main.py scan --target https://example.com --profile active --scope scope.json
  python main.py list
  python main.py doctor
  python main.py history list
  python main.py history compare <scan-id-1> <scan-id-2>
"""

import argparse
import os
import sys

from core.doctor import run_doctor
from core.history import history_store
from core.orchestrator import ScanOrchestrator
from core.registry import registry
from core.scope import ScopePolicy
from reports.report_generator import generate_json_report
from utils import formatter

# Individual module runners for interactive menu compatibility
from modules import (
    http_headers,
    dns_scanner,
    whois,
    subdomain_enum,
    port_scanner,
    sql_detector,
    web_dir_scan,
    tls_checker,
    tech_fingerprint,
    cookie_auditor,
    cors_auditor,
    redirect_auditor,
    secret_scanner,
)


def interactive_menu():
    """Interactive prompt-driven menu with graceful cancellation and comprehensive choices."""
    formatter.banner("CLI Multipurpose Security Assessment Tool")

    while True:
        print("\nSelect a security module or workflow:")
        print("  1.  HTTP Security Headers & Cookies")
        print("  2.  DNS Record Scanner (DoH / dig)")
        print("  3.  WHOIS & RDAP Domain Information")
        print("  4.  Subdomain Enumeration (Passive CT logs)")
        print("  5.  TCP Port Scanner (nmap / socket)")
        print("  6.  SQL Injections (Active / Opt-in)")
        print("  7.  Web Directory Scanner (Active / Opt-in)")
        print("  8.  TLS / SSL Certificate & Protocol Checker")
        print("  9.  Technology & Framework Fingerprinting")
        print("  10. Cookie Security Auditor (HttpOnly, Secure, SameSite)")
        print("  11. CORS Configuration Auditor")
        print("  12. Redirect & HTTPS Upgrade Auditor")
        print("  13. Secret & Credential Scanner (Local repository)")
        print("  14. Run Full Profile Scan (Passive / Standard / Active)")
        print("  15. System Diagnostics & Tool Check (Doctor)")
        print("  16. View Scan History & Diff")
        print("  0.  Exit (or 'exit' / 'quit')")

        try:
            choice = input("\nEnter your choice: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break

        if choice in ["0", "exit", "quit", "q"]:
            print("Exiting CLI Multipurpose...")
            break
        elif choice == "1":
            http_headers.run()
        elif choice == "2":
            dns_scanner.run()
        elif choice == "3":
            whois.run()
        elif choice == "4":
            subdomain_enum.run()
        elif choice == "5":
            port_scanner.run()
        elif choice == "6":
            sql_detector.run()
        elif choice == "7":
            web_dir_scan.run()
        elif choice == "8":
            # For backward compatibility, if user typed 8 intending Exit or TLS
            tls_checker.run()
        elif choice == "9":
            tech_fingerprint.run()
        elif choice == "10":
            cookie_auditor.run()
        elif choice == "11":
            cors_auditor.run()
        elif choice == "12":
            redirect_auditor.run()
        elif choice == "13":
            secret_scanner.run()
        elif choice == "14":
            run_interactive_profile_scan()
        elif choice == "15":
            run_doctor()
        elif choice == "16":
            run_interactive_history()
        else:
            formatter.error(f"Invalid choice '{choice}'! Please select an option between 0 and 16.")


def run_interactive_profile_scan():
    """Guides user through an orchestrated multi-scanner assessment."""
    target = input("\nEnter target domain or URL: ").strip()
    if not target:
        formatter.error("Target cannot be empty.")
        return

    print("Select Scan Profile:")
    print("  1. Passive (Zero intrusive traffic, safe reconnaissance)")
    print("  2. Standard (Low impact port & web inspection)")
    print("  3. Active (Includes directory discovery & SQL injection tests)")
    p_choice = input("Enter profile [1-3, default 1]: ").strip()

    profile_map = {"1": "passive", "2": "standard", "3": "active"}
    profile = profile_map.get(p_choice, "passive")

    active_allowed = (profile == "active")
    if active_allowed:
        confirm = input(f"{formatter.RED}[!] Confirm active checks on '{target}'? (yes/no): {formatter.RESET}").strip().lower()
        if confirm not in ["yes", "y"]:
            formatter.info("Switching to standard profile.")
            profile = "standard"
            active_allowed = False

    scope = ScopePolicy.create_single_target_scope(target, active_checks=active_allowed)
    orchestrator = ScanOrchestrator()
    report = orchestrator.run_scan(target, scope, profile=profile)

    # Save to history
    history_store.save_scan(report)

    # Generate reports
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    json_path = f"reports/scan_{safe_target}_{report.scan_id}.json"
    generate_json_report(report, json_path)

    formatter.success(f"Assessment complete! Total findings: {len(report.all_findings)}")
    formatter.info(f"JSON Report: {os.path.abspath(json_path)}")


def run_interactive_history():
    """Lists recent scans and allows delta comparison."""
    scans = history_store.list_scans(limit=10)
    if not scans:
        formatter.info("No scan history found. Run a scan first!")
        return

    print(f"\n{formatter.BOLD}[*] Recent Assessment History:{formatter.RESET}")
    for idx, s in enumerate(scans, start=1):
        print(f"  {idx}. ID: {s['scan_id']} | Target: {s['target']} | Profile: {s['profile']} | Findings: {s['total_findings']} | Date: {s['start_time'][:19]}")

    compare = input("\nCompare two scans? (yes/no) [default: no]: ").strip().lower()
    if compare in ["yes", "y"]:
        id1 = input("Enter first Scan ID (older): ").strip()
        id2 = input("Enter second Scan ID (newer): ").strip()
        try:
            diff = history_store.compare_scans(id1, id2)
            print(f"\n{formatter.BOLD}[*] Scan Comparison Delta:{formatter.RESET}")
            formatter.info(f"Introduced (New) Findings: {diff['introduced_count']}")
            formatter.success(f"Resolved (Fixed) Findings: {diff['resolved_count']}")
            formatter.info(f"Persisting Findings: {diff['persisting_count']}")
            if diff["introduced_findings"]:
                print("\nNew Findings:")
                for f in diff["introduced_findings"]:
                    formatter.error(f"  + [{f['severity'].upper()}] {f['title']}")
            if diff["resolved_findings"]:
                print("\nResolved Findings:")
                for f in diff["resolved_findings"]:
                    formatter.success(f"  - [{f['severity'].upper()}] {f['title']}")
        except Exception as e:
            formatter.error(f"Comparison error: {e}")


def build_arg_parser() -> argparse.ArgumentParser:
    """Builds CLI argument parser for non-interactive / scriptable usage."""
    parser = argparse.ArgumentParser(
        prog="cli-multipurpose",
        description="CLI Multipurpose Security Assessment & Recon Framework"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Execute an orchestrated security assessment")
    scan_parser.add_argument("--target", "-t", required=True, help="Target URL, domain, or IP address")
    scan_parser.add_argument("--profile", "-p", choices=["passive", "standard", "active", "local"], default="standard", help="Scan profile preset")
    scan_parser.add_argument("--modules", "-m", help="Comma-separated list of specific module IDs to run")
    scan_parser.add_argument("--scope", "-s", help="Path to JSON scope configuration file")
    scan_parser.add_argument("--dry-run", action="store_true", help="Preview planned scanner executions without sending requests")
    scan_parser.add_argument("--output", "-o", help="Base path for report output (without extension)")
    scan_parser.add_argument("--format", choices=["json"], default="json", help="Output report format")

    # Command: list
    subparsers.add_parser("list", help="List all available scanner modules and profiles")

    # Command: doctor
    subparsers.add_parser("doctor", help="Run system diagnostics and verify tool dependencies")

    # Command: init-scope
    init_scope_parser = subparsers.add_parser("init-scope", help="Generate an example scope policy file")
    init_scope_parser.add_argument("--output", "-o", default="scope.json", help="Destination file path")

    # Command: history
    hist_parser = subparsers.add_parser("history", help="Inspect historical assessments")
    hist_sub = hist_parser.add_subparsers(dest="hist_action")
    hist_sub.add_parser("list", help="List recent scans")
    comp_parser = hist_sub.add_parser("compare", help="Compare two scans for delta changes")
    comp_parser.add_argument("scan_a", help="First Scan ID (older)")
    comp_parser.add_argument("scan_b", help="Second Scan ID (newer)")

    return parser


def cli_main():
    """Main CLI entrypoint routing between argparse commands and interactive menu."""
    if len(sys.argv) == 1:
        # No arguments passed: enter interactive menu
        interactive_menu()
        return

    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "list":
        print(f"\n{formatter.BOLD}[*] Available Security Assessment Modules:{formatter.RESET}\n")
        for s in registry.list_all():
            mode = f"{formatter.RED}[ACTIVE]{formatter.RESET}" if s.is_active else f"{formatter.GREEN}[PASSIVE]{formatter.RESET}"
            print(f"  * {s.scanner_id:<18} {mode} [{s.category.upper()}] - {s.name}")
            print(f"    {s.description}")
        print(f"\n{formatter.BOLD}[*] Execution Profiles:{formatter.RESET}")
        for p_name, mods in registry.profiles.items():
            print(f"  * {p_name:<10}: {', '.join(mods)}")
        print()

    elif args.command == "doctor":
        run_doctor()

    elif args.command == "init-scope":
        scope = ScopePolicy.create_local_lab_scope()
        scope.save_to_file(args.output)
        formatter.success(f"Generated default scope policy at '{args.output}'.")

    elif args.command == "history":
        if args.hist_action == "list" or not args.hist_action:
            scans = history_store.list_scans()
            if not scans:
                formatter.info("No scan history recorded.")
                return
            print(f"\n{formatter.BOLD}[*] Assessment History:{formatter.RESET}")
            for s in scans:
                print(f"  Scan ID: {s['scan_id']} | Target: {s['target']} | Profile: {s['profile']} | Findings: {s['total_findings']} | {s['start_time'][:19]}")
            print()
        elif args.hist_action == "compare":
            diff = history_store.compare_scans(args.scan_a, args.scan_b)
            print(f"\n{formatter.BOLD}[*] Diff: {args.scan_a} -> {args.scan_b}{formatter.RESET}")
            formatter.info(f"Introduced Findings: {diff['introduced_count']}")
            formatter.success(f"Resolved Findings:   {diff['resolved_count']}")
            formatter.info(f"Persisting Findings: {diff['persisting_count']}")

    elif args.command == "scan":
        # Load or generate scope
        if args.scope:
            scope = ScopePolicy.from_file(args.scope)
        else:
            active_flag = (args.profile == "active")
            scope = ScopePolicy.create_single_target_scope(args.target, active_checks=active_flag)

        modules = [m.strip() for m in args.modules.split(",")] if args.modules else None
        orchestrator = ScanOrchestrator()
        report = orchestrator.run_scan(
            target=args.target,
            scope=scope,
            profile=args.profile,
            selected_modules=modules,
            dry_run=args.dry_run
        )

        if not args.dry_run:
            history_store.save_scan(report)
            target_slug = args.target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
            base_out = args.output or f"reports/scan_{target_slug}_{report.scan_id}"

            jpath = generate_json_report(report, f"{base_out}.json")
            formatter.info(f"Exported JSON: {jpath}")

            formatter.success(f"Scan finished. Total unique findings: {len(report.all_findings)}")


if __name__ == "__main__":
    cli_main()