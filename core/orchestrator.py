"""
Scan Orchestrator for CLI Multipurpose Security Assessment.
Coordinates pre-flight scope validation, scanner dispatch, error isolation,
finding aggregation, and result normalization.
"""

from datetime import datetime, timezone
import uuid
from typing import List, Optional, Dict, Any

from core.base_scanner import BaseScanner
from core.models import (
    ScanResult,
    ScanStatus,
    AggregatedScanReport,
    Finding,
)
from core.registry import registry
from core.scope import ScopePolicy
from utils import formatter


class ScanOrchestrator:
    """Dispatches and manages security assessment runs across multiple modules."""

    def __init__(self, scanner_registry=None):
        self.registry = scanner_registry or registry

    def plan_modules(self, profile: str = "standard", selected_modules: Optional[List[str]] = None) -> List[BaseScanner]:
        """Resolves the list of scanners to execute based on profile or module filter."""
        if selected_modules:
            scanners = []
            for mod_name in selected_modules:
                clean_name = mod_name.strip()
                s = self.registry.get(clean_name)
                if not s:
                    raise ValueError(f"Module '{clean_name}' not found in registry.")
                scanners.append(s)
            return scanners

        return self.registry.get_by_profile(profile)

    def run_scan(
        self,
        target: str,
        scope: ScopePolicy,
        profile: str = "standard",
        selected_modules: Optional[List[str]] = None,
        dry_run: bool = False,
        config: Optional[Dict[str, Any]] = None
    ) -> AggregatedScanReport:
        """
        Executes an orchestrated scan workflow:
        1. Pre-flight scope and target validation
        2. Module selection and active-check safety gating
        3. Dry-run preview if requested
        4. Isolated scanner execution
        5. Aggregation and fingerprint deduplication
        """
        scan_id = str(uuid.uuid4())[:8]
        report = AggregatedScanReport(
            scan_id=scan_id,
            target=target,
            profile=profile,
            scope_name=scope.name
        )

        # 1. Pre-flight Scope Check
        in_scope, scope_reason = scope.is_target_in_scope(target)
        if not in_scope:
            formatter.error(f"Pre-flight scope validation failed: {scope_reason}")
            empty_result = ScanResult(
                scanner_id="orchestrator",
                scanner_version="1.0.0",
                target=target,
                status=ScanStatus.FAILED
            )
            empty_result.add_error(f"Target '{target}' is out of authorized scope: {scope_reason}")
            empty_result.finish()
            report.results.append(empty_result)
            report.finish()
            return report

        # 2. Plan Scanners
        try:
            scanners = self.plan_modules(profile, selected_modules)
        except ValueError as e:
            formatter.error(str(e))
            empty_result = ScanResult(
                scanner_id="orchestrator",
                scanner_version="1.0.0",
                target=target,
                status=ScanStatus.FAILED
            )
            empty_result.add_error(str(e))
            empty_result.finish()
            report.results.append(empty_result)
            report.finish()
            return report

        # 3. Dry-Run Mode
        if dry_run:
            print(f"\n{formatter.BOLD}{formatter.CYAN}--- DRY RUN PREVIEW (No Network Requests) ---{formatter.RESET}")
            formatter.info(f"Target: {target}")
            formatter.info(f"Scope: {scope.name} (Active Checks: {scope.active_checks})")
            formatter.info(f"Planned Scanners ({len(scanners)} total):")
            for s in scanners:
                active_label = f"{formatter.RED}[ACTIVE]{formatter.RESET}" if s.is_active else f"{formatter.GREEN}[PASSIVE]{formatter.RESET}"
                print(f"  * {active_label} {s.scanner_id} - {s.name}")
            report.finish()
            return report

        # 4. Execute Scanners Sequentially with Error Isolation
        print(f"\n{formatter.BOLD}[*] Starting Orchestrated Scan [{profile.upper()}] on {target}{formatter.RESET}")
        print(f"    Scope Policy: {scope.name} | Active Checks Allowed: {scope.active_checks}\n")

        for scanner in scanners:
            # Check active checks permission
            can_run, reason = scanner.can_run(scope)
            if not can_run:
                skip_res = ScanResult(
                    scanner_id=scanner.scanner_id,
                    scanner_version=scanner.version,
                    target=target,
                    status=ScanStatus.SKIPPED
                )
                skip_res.add_warning(f"Skipped: {reason}")
                skip_res.finish()
                report.results.append(skip_res)
                formatter.info(f"[-] Skipped '{scanner.name}': Active checks not authorized in scope.")
                continue

            formatter.info(f"[>] Running: {scanner.name}...")
            try:
                mod_result = scanner.run(target, scope, config=config)
                report.results.append(mod_result)
                if mod_result.status == ScanStatus.SUCCESS:
                    findings_cnt = len(mod_result.findings)
                    formatter.success(f"{scanner.name} completed ({findings_cnt} findings)")
                elif mod_result.status == ScanStatus.PARTIAL:
                    formatter.info(f"[~] {scanner.name} completed with warnings")
                elif mod_result.status == ScanStatus.SKIPPED:
                    formatter.info(f"[-] {scanner.name} skipped")
                else:
                    formatter.error(f"[!] {scanner.name} failed: {', '.join(mod_result.errors)}")
            except Exception as e:
                # Isolate exception so other scanners continue running
                err_res = ScanResult(
                    scanner_id=scanner.scanner_id,
                    scanner_version=scanner.version,
                    target=target,
                    status=ScanStatus.FAILED
                )
                err_res.add_error(f"Unhandled exception during module execution: {e}")
                err_res.finish()
                report.results.append(err_res)
                formatter.error(f"[!] Exception running {scanner.name}: {e}")

        report.finish()
        return report
