"""
DNS Enumeration & Record Inspection Scanner.
Queries DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) using native DoH or dig.
Implements DnsScanner(BaseScanner) and interactive run().
"""

import json
import socket
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, runner, formatter


RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


def query_doh(domain: str, record_type: str, timeout: int = 8) -> List[str]:
    """Queries Cloudflare DNS-over-HTTPS (DoH) JSON API."""
    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "CLI-Multipurpose-Security/2.0"})
    answers = []
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode())
            if "Answer" in data:
                for item in data["Answer"]:
                    answers.append(str(item.get("data", "")))
    except Exception:
        pass
    return answers


class DnsScanner(BaseScanner):
    scanner_id = "dns_scanner"
    name = "DNS Record Scanner"
    description = "Queries DNS records (A, AAAA, MX, NS, TXT, SOA) via native DoH or dig."
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
            result.add_error(f"Target '{domain}' is not a valid domain name for DNS inspection.")
            result.finish(ScanStatus.FAILED)
            return result

        all_records = {}
        # Try dig if available
        if runner.tool_available("dig"):
            dig_res = runner.run_tool_result(["dig", "+noall", "+answer", domain, "ANY"], timeout=scope.timeout_seconds)
            if dig_res.succeeded and dig_res.stdout.strip():
                for line in dig_res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 5:
                        rtype = parts[3].upper()
                        rval = " ".join(parts[4:])
                        all_records.setdefault(rtype, []).append(rval)

        # Fallback to DoH if no records from dig
        if not all_records:
            for rtype in RECORD_TYPES:
                records = query_doh(domain, rtype, timeout=scope.timeout_seconds)
                if records:
                    all_records[rtype] = records

        if not all_records:
            result.add_warning(f"No DNS records found for domain '{domain}'.")
            result.finish(ScanStatus.PARTIAL)
            return result

        result.metadata["records"] = all_records

        # Create findings for interesting DNS attributes
        # SPF missing or weak
        txt_records = all_records.get("TXT", [])
        spf_found = any("v=spf1" in r for r in txt_records)
        dmarc_found = False

        # Query DMARC record
        dmarc_recs = query_doh(f"_dmarc.{domain}", "TXT", timeout=scope.timeout_seconds)
        if any("v=DMARC1" in r for r in dmarc_recs):
            dmarc_found = True

        if not spf_found:
            result.add_finding(Finding(
                check_id="dns.spf_missing",
                title=f"Missing SPF Record on {domain}",
                description="The domain lacks an SPF TXT record, allowing attackers to spoof emails from this domain.",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                affected_asset=domain,
                remediation="Configure a valid TXT SPF record (e.g. 'v=spf1 -all' or authorized mail servers).",
                evidence=[Evidence(
                    source="dns_scanner",
                    description="TXT records evaluated for 'v=spf1'. None found.",
                    sanitized_value=f"TXT records: {txt_records}"
                )],
                references=["https://en.wikipedia.org/wiki/Sender_Policy_Framework"]
            ))

        if not dmarc_found:
            result.add_finding(Finding(
                check_id="dns.dmarc_missing",
                title=f"Missing DMARC Policy on {domain}",
                description="The domain lacks a DMARC policy (_dmarc record), reducing protection against email phishing/impersonation.",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                affected_asset=domain,
                remediation="Publish a DMARC record at _dmarc with appropriate policy (p=quarantine or p=reject).",
                evidence=[Evidence(
                    source="dns_scanner",
                    description=f"Queried _dmarc.{domain} for TXT records. None found.",
                    sanitized_value="No DMARC record"
                )],
                references=["https://dmarc.org/"]
            ))

        # Zone transfer check or general info
        for rtype, values in all_records.items():
            result.add_finding(Finding(
                check_id=f"dns.record_{rtype.lower()}",
                title=f"DNS {rtype} Records Disclosed ({len(values)} entries)",
                description=f"DNS {rtype} records published for {domain}.",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                affected_asset=domain,
                remediation="Review DNS records for unintended internal IP or subdomain disclosures.",
                evidence=[Evidence(
                    source="dns_scanner",
                    description=f"DNS {rtype} values",
                    sanitized_value=", ".join(values[:5])
                )]
            ))

        result.finish(ScanStatus.SUCCESS)
        return result


def run():
    """Interactive CLI entrypoint."""
    target = input("Enter target domain or URL: ").strip()
    info = validation.parse_target(target)
    domain = info.host if info else target

    if not validation.is_valid_domain(domain):
        formatter.error("Please enter a valid domain name (DNS lookups require domains).")
        return

    formatter.info(f"Scanning DNS for: {domain}")
    scope = ScopePolicy.create_single_target_scope(domain)
    scanner = DnsScanner()
    res = scanner.run(domain, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    records = res.metadata.get("records", {})
    if records:
        for rtype, vals in records.items():
            print(f"\n{formatter.BOLD}[*] {rtype} Records:{formatter.RESET}")
            for v in vals:
                formatter.success(f"{domain} -> {v}")
    else:
        formatter.info("No DNS records found.")
