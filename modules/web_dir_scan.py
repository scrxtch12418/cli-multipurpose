"""
Web Directory & Sensitive File Discovery Scanner.
Performs scoped discovery of common web paths and sensitive configuration files (.git, .env).
Handles status codes distinctly (2xx, 3xx, 401/403, 429 backoff), respects budgets.
Implements WebDirScanner(BaseScanner) and interactive run().
"""

import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List, Tuple

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from modules.wordlists import COMMON_DIRS
from utils import validation, runner, formatter


# Curated sensitive files that constitute real security risks if exposed
SENSITIVE_TARGETS = {
    ".git": ("Exposed Git Repository (.git)", Severity.HIGH, "Block public access to .git directory in web server configuration."),
    ".git/config": ("Exposed Git Config File", Severity.HIGH, "Block access to .git directory and configuration files."),
    ".env": ("Exposed Environment (.env) File", Severity.HIGH, "Never host .env files in public webroot; block access immediately."),
    "wp-config.php.bak": ("Exposed WordPress Backup File", Severity.HIGH, "Delete backup files containing database credentials from webroot."),
    "robots.txt": ("Robots.txt Disclosed", Severity.INFO, "Review robots.txt disallow rules for sensitive hidden paths."),
    "phpinfo.php": ("Exposed phpinfo() File", Severity.MEDIUM, "Remove phpinfo.php from public webroot to avoid information disclosure."),
    "server-status": ("Apache Server-Status Exposed", Severity.LOW, "Restrict /server-status to internal loopback / administrator IPs."),
}


def probe_path(base_url: str, path: str, timeout: int = 5) -> Tuple[str, Optional[int], Optional[str]]:
    """Probes a single path and returns (path, status_code, redirect_location)."""
    clean_base = base_url.rstrip("/")
    clean_path = path.lstrip("/")
    url = f"{clean_base}/{clean_path}"

    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "CLI-Multipurpose-Security/2.0")

    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            # Don't follow redirects automatically so we see 301/302 distinctly
            return None

    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return path, resp.status, resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location") if hasattr(e, "headers") else None
        return path, e.code, loc
    except Exception:
        return path, None, None


class WebDirScanner(BaseScanner):
    scanner_id = "web_dir_scan"
    name = "Web Directory & Content Discovery Scanner"
    description = "Probes web targets for accessible directories, admin panels, and exposed backup/config files."
    category = "web"
    is_active = True  # Content discovery sends multiple active requests

    def run(self, target: str, scope: ScopePolicy, config: Optional[Dict[str, Any]] = None) -> ScanResult:
        result = ScanResult(
            scanner_id=self.scanner_id,
            scanner_version=self.version,
            target=target
        )

        can_run, reason = self.can_run(scope)
        if not can_run:
            result.add_error(reason)
            result.finish(ScanStatus.SKIPPED)
            return result

        in_scope, scope_reason = scope.is_target_in_scope(target)
        if not in_scope:
            result.add_error(f"Target '{target}' is out of scope: {scope_reason}")
            result.finish(ScanStatus.SKIPPED)
            return result

        info = validation.parse_target(target)
        if not info:
            result.add_error(f"Failed to parse target: {target}")
            result.finish(ScanStatus.FAILED)
            return result

        base_url = info.normalized_url.rstrip("/")
        max_requests = min(scope.max_requests_per_target, 50)
        wordlist = COMMON_DIRS[:max_requests]

        discovered_paths: List[Dict[str, Any]] = []
        requests_sent = 0
        backoff_delay = 0.0

        for path in wordlist:
            if requests_sent >= max_requests:
                result.add_warning(f"Hit request budget limit ({max_requests}) for directory scanning.")
                break

            if backoff_delay > 0:
                time.sleep(backoff_delay)

            subpath, status, loc = probe_path(base_url, path, timeout=scope.timeout_seconds)
            requests_sent += 1

            if status == 429:
                result.add_warning("Target returned HTTP 429 (Too Many Requests). Applying backoff.")
                backoff_delay = min(backoff_delay + 2.0, 10.0)
                continue
            else:
                backoff_delay = max(0.0, backoff_delay - 0.5)

            if status in [200, 204, 301, 302, 401, 403]:
                discovered_paths.append({
                    "path": subpath,
                    "status": status,
                    "location": loc
                })

                # Check if this is an explicitly sensitive file
                if subpath in SENSITIVE_TARGETS and status == 200:
                    title, sev, rem = SENSITIVE_TARGETS[subpath]
                    result.add_finding(Finding(
                        check_id=f"dirscan.sensitive_{subpath.replace('/', '_').replace('.', '_')}",
                        title=f"{title} Discovered at /{subpath}",
                        description=f"Direct access to sensitive resource '/{subpath}' returned HTTP {status} on {base_url}.",
                        severity=sev,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=f"{base_url}/{subpath}",
                        remediation=rem,
                        evidence=[Evidence(
                            source="web_dir_scan",
                            description=f"GET /{subpath} returned HTTP {status}",
                            sanitized_value=f"Status: {status}"
                        )]
                    ))
                elif status in [200, 301, 302]:
                    result.add_finding(Finding(
                        check_id=f"dirscan.path_{subpath.replace('/', '_').replace('.', '_')}",
                        title=f"Accessible Path Discovered: /{subpath} (HTTP {status})",
                        description=f"Path '/{subpath}' returned HTTP {status}" + (f" -> {loc}" if loc else ""),
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=f"{base_url}/{subpath}",
                        remediation="Verify whether this directory/endpoint should be publicly accessible.",
                        evidence=[Evidence(
                            source="web_dir_scan",
                            description=f"Path returned HTTP {status}",
                            sanitized_value=f"Status: {status}"
                        )]
                    ))

        result.metadata["requests_sent"] = requests_sent
        result.metadata["discovered_count"] = len(discovered_paths)
        result.metadata["discovered_paths"] = discovered_paths
        result.finish(ScanStatus.SUCCESS)
        return result


def run():
    """Interactive CLI entrypoint."""
    formatter.banner("Web Directory Scanner")
    print(f"{formatter.RED}{formatter.BOLD}[!] CAUTION: Active Security Test{formatter.RESET}")
    print("This module sends requests to discover files and endpoints on the target system.")
    print("Ensure you have explicit permission to test this target.\n")

    confirm = input("Do you have authorization to test this target? (yes/no): ").strip().lower()
    if confirm not in ["yes", "y"]:
        formatter.error("Aborted: Unauthorized testing is prohibited.")
        return

    target = input("Enter target domain or URL: ").strip()
    info = validation.parse_target(target)
    if not info:
        formatter.error("Invalid target!")
        return

    url = info.normalized_url
    formatter.info(f"Scanning directories on: {url}")
    scope = ScopePolicy.create_single_target_scope(url, active_checks=True)
    scanner = WebDirScanner()
    res = scanner.run(url, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    paths = res.metadata.get("discovered_paths", [])
    if paths:
        print(f"\n{formatter.BOLD}[*] Discovered Endpoints ({len(paths)} found):{formatter.RESET}")
        for p in paths:
            st = p["status"]
            path_str = p["path"]
            if st == 200:
                formatter.success(f"/{path_str} (HTTP {st})")
            elif st in [301, 302]:
                formatter.info(f"/{path_str} (HTTP {st} -> {p.get('location')})")
            else:
                formatter.info(f"/{path_str} (HTTP {st})")
    else:
        formatter.info("No common endpoints or sensitive files discovered.")
