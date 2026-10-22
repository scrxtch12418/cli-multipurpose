"""
WHOIS & RDAP Domain Registration Information Scanner.
Retrieves registrar, registration/expiration dates, and status via RDAP (RFC 7480) or whois CLI.
Implements WhoisScanner(BaseScanner) and interactive run().
"""

import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, runner, formatter


def query_rdap(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """Queries RDAP protocol over HTTPS for domain registration data."""
    url = f"https://rdap.org/domain/{domain}"
    req = urllib.request.Request(url, headers={"User-Agent": "CLI-Multipurpose-Security/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode(errors="ignore"))


class WhoisScanner(BaseScanner):
    scanner_id = "whois"
    name = "WHOIS / RDAP Domain Scanner"
    description = "Queries domain registration details, registrar, creation, and expiration dates."
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
            result.add_error(f"Target '{domain}' is not a valid domain name for WHOIS lookup.")
            result.finish(ScanStatus.FAILED)
            return result

        data = {}
        # Try whois binary if available
        if runner.tool_available("whois"):
            whois_res = runner.run_tool_result(["whois", domain], timeout=scope.timeout_seconds)
            if whois_res.succeeded and whois_res.stdout.strip():
                data["raw_whois"] = whois_res.stdout[:2000]

        # RDAP fallback / enrichment
        try:
            rdap_data = query_rdap(domain, timeout=scope.timeout_seconds)
            data["rdap"] = rdap_data
        except Exception as e:
            result.add_warning(f"RDAP query failed: {e}")

        if not data:
            result.add_error("Could not obtain WHOIS or RDAP records.")
            result.finish(ScanStatus.FAILED)
            return result

        result.metadata = data
        rdap = data.get("rdap", {})
        registrar = "Unknown"
        events = rdap.get("events", [])
        created = "Unknown"
        expires = "Unknown"

        for entity in rdap.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for prop in vcard[1]:
                        if prop[0] == "fn":
                            registrar = prop[3]
                            break

        for ev in events:
            act = ev.get("eventAction")
            dt = ev.get("eventDate", "").replace("T", " ").replace("Z", "")
            if act == "registration":
                created = dt
            elif act == "expiration":
                expires = dt

        summary_val = f"Registrar: {registrar} | Created: {created} | Expires: {expires}"
        result.add_finding(Finding(
            check_id="whois.registration_info",
            title=f"Domain Registration Info for {domain}",
            description=f"Domain registered via {registrar}. Expires: {expires}.",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            affected_asset=domain,
            remediation="Ensure domain contact information is protected and auto-renewal is enabled.",
            evidence=[Evidence(
                source="whois",
                description="WHOIS/RDAP registration metadata",
                sanitized_value=summary_val
            )]
        ))

        result.finish(ScanStatus.SUCCESS)
        return result


def run():
    """Interactive CLI entrypoint."""
    target = input("Enter target domain: ").strip()
    info = validation.parse_target(target)
    domain = info.host if info else target

    if not validation.is_valid_domain(domain):
        formatter.error("Please enter a valid domain name.")
        return

    formatter.info(f"Looking up registration info for: {domain}")
    scope = ScopePolicy.create_single_target_scope(domain)
    scanner = WhoisScanner()
    res = scanner.run(domain, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    for f in res.findings:
        formatter.success(f.title)
        for ev in f.evidence:
            formatter.info(ev.sanitized_value)
