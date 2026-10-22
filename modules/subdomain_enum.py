"""
Subdomain Discovery & Enumeration Scanner.
Uses passive Certificate Transparency logs (crt.sh, HackerTarget) and subfinder
with strict DNS-label boundary verification.
Implements SubdomainScanner(BaseScanner) and interactive run().
"""

import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, Set, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, runner, formatter


def fetch_crtsh_subdomains(domain: str, timeout: int = 12) -> Set[str]:
    """Queries Certificate Transparency logs on crt.sh passively."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "CLI-Multipurpose-Security/2.0"})
    subdomains = set()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode(errors="ignore"))
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    clean = sub.strip().lower()
                    if clean.startswith("*."):
                        clean = clean[2:]
                    if validation.matches_domain_boundary(clean, domain):
                        subdomains.add(clean)
    except Exception:
        pass
    return subdomains


def fetch_hackertarget_subdomains(domain: str, timeout: int = 10) -> Set[str]:
    """Fallback passive host search via HackerTarget API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    req = urllib.request.Request(url, headers={"User-Agent": "CLI-Multipurpose-Security/2.0"})
    subdomains = set()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            text = response.read().decode(errors="ignore")
            for line in text.splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if validation.matches_domain_boundary(sub, domain):
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains


class SubdomainScanner(BaseScanner):
    scanner_id = "subdomain_enum"
    name = "Subdomain Enumeration Scanner"
    description = "Discovers subdomains passively via Certificate Transparency logs and subfinder."
    category = "dns"
    is_active = False

    def run(self, target: str, scope: ScopePolicy, config: Optional[Dict[str, Any]] = None) -> ScanResult:
        result = ScanResult(
            scanner_id=self.scanner_id,
            scanner_version=self.version,
            target=target
        )

        in_scope, reason = scope.is_target_in_scope(target)
        if not in_scope:
            result.add_error(f"Target '{target}' is out of scope: {reason}")
            result.finish(ScanStatus.SKIPPED)
            return result

        info = validation.parse_target(target)
        domain = info.host if info else target
        if not validation.is_valid_domain(domain):
            result.add_error(f"Target '{domain}' is not a valid domain name for subdomain enumeration.")
            result.finish(ScanStatus.FAILED)
            return result

        discovered: Set[str] = set()
        sources_used = []

        # 1. External tool subfinder if installed
        if runner.tool_available("subfinder"):
            sources_used.append("subfinder")
            sub_res = runner.run_tool_result(["subfinder", "-d", domain, "-silent"], timeout=scope.timeout_seconds)
            if sub_res.succeeded and sub_res.stdout.strip():
                for line in sub_res.stdout.splitlines():
                    sub = line.strip().lower()
                    if validation.matches_domain_boundary(sub, domain):
                        discovered.add(sub)

        # 2. crt.sh passive CT logs
        sources_used.append("crt.sh")
        crt_subs = fetch_crtsh_subdomains(domain, timeout=scope.timeout_seconds)
        discovered.update(crt_subs)

        # 3. HackerTarget fallback
        if len(discovered) < 2:
            sources_used.append("hackertarget")
            ht_subs = fetch_hackertarget_subdomains(domain, timeout=scope.timeout_seconds)
            discovered.update(ht_subs)

        result.metadata["subdomains_count"] = len(discovered)
        result.metadata["sources_used"] = sources_used
        result.metadata["subdomains"] = sorted(list(discovered))

        if discovered:
            result.add_finding(Finding(
                check_id="subdomains.discovered",
                title=f"Discovered {len(discovered)} Subdomain(s) for {domain}",
                description=f"Passive intelligence uncovered {len(discovered)} public subdomain records under {domain}.",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                affected_asset=domain,
                remediation="Ensure uncovered staging, testing, or internal subdomains are not publicly exposed without authorization.",
                evidence=[Evidence(
                    source="subdomain_enum",
                    description=f"Discovered subdomains via {', '.join(sources_used)}",
                    sanitized_value=", ".join(sorted(list(discovered))[:20])
                )],
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage"]
            ))
            result.finish(ScanStatus.SUCCESS)
        else:
            result.add_warning("No subdomains discovered.")
            result.finish(ScanStatus.PARTIAL)

        return result


def run():
    """Interactive CLI entrypoint."""
    target = input("Enter target domain or URL: ").strip()
    info = validation.parse_target(target)
    domain = info.host if info else target

    if not validation.is_valid_domain(domain):
        formatter.error("Please enter a valid domain name (subdomain enumeration requires domains).")
        return

    formatter.info(f"Enumerating subdomains for: {domain}")
    scope = ScopePolicy.create_single_target_scope(domain)
    scanner = SubdomainScanner()
    res = scanner.run(domain, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    subs = res.metadata.get("subdomains", [])
    if subs:
        print(f"\n{formatter.BOLD}[*] Discovered Subdomains ({len(subs)} total):{formatter.RESET}")
        for s in subs:
            formatter.success(s)
    else:
        formatter.error("No subdomains found from available passive sources.")
