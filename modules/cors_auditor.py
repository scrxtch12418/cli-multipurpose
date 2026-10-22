"""
CORS (Cross-Origin Resource Sharing) Configuration Auditor.
Tests for insecure origin reflections, wildcard policies, and credential combinations
using safe, benign test origins within authorized target scope.
Implements CorsAuditorScanner(BaseScanner) and interactive run().
"""

import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, formatter


class CorsAuditorScanner(BaseScanner):
    scanner_id = "cors_auditor"
    name = "CORS Configuration Auditor"
    description = "Evaluates Cross-Origin Resource Sharing policies for origin reflection and credential exposure."
    category = "web"
    is_active = False  # Sends benign probe headers

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
        if not info:
            result.add_error(f"Cannot parse target: {target}")
            result.finish(ScanStatus.FAILED)
            return result

        url = info.normalized_url

        # Test origins
        test_origins = [
            ("arbitrary_origin", "https://untrusted-security-test.example"),
            ("null_origin", "null"),
        ]

        for test_type, origin_val in test_origins:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "CLI-Multipurpose-Security/2.0")
            req.add_header("Origin", origin_val)

            headers = {}
            try:
                with urllib.request.urlopen(req, timeout=scope.timeout_seconds) as resp:
                    for k, v in resp.headers.items():
                        headers[k.lower()] = v
            except urllib.error.HTTPError as e:
                for k, v in e.headers.items():
                    headers[k.lower()] = v
            except Exception as e:
                result.add_warning(f"CORS test probe failed for origin {origin_val}: {e}")
                continue

            acao = headers.get("access-control-allow-origin")
            acac = headers.get("access-control-allow-credentials", "").lower() == "true"

            if not acao:
                continue

            # Case 1: Reflected arbitrary origin + Credentials = CRITICAL/HIGH
            if acao.strip() == origin_val and acac:
                result.add_finding(Finding(
                    check_id=f"cors.arbitrary_origin_with_credentials_{test_type}",
                    title=f"Critical CORS Vulnerability: Reflected Origin '{origin_val}' With Credentials",
                    description=f"The application dynamically reflects arbitrary Origin headers ('{origin_val}') AND permits credentials (cookies/tokens), allowing cross-origin data theft.",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=url,
                    remediation="Validate Origin against a strict server-side allowlist before setting Access-Control-Allow-Origin, or disallow credentials.",
                    evidence=[Evidence(
                        source="cors_auditor",
                        description="Probe sent Origin and received reflected ACAO with ACAC: true",
                        sanitized_value=f"Origin: {origin_val} -> ACAO: {acao}, ACAC: true"
                    )],
                    references=["https://portswigger.net/web-security/cors"]
                ))
            # Case 2: Reflected arbitrary origin without credentials = MEDIUM
            elif acao.strip() == origin_val and test_type == "arbitrary_origin":
                result.add_finding(Finding(
                    check_id="cors.arbitrary_origin_reflected",
                    title="CORS Arbitrary Origin Reflection",
                    description=f"The server reflects arbitrary Origin headers ('{origin_val}') in Access-Control-Allow-Origin without allowlist verification.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=url,
                    remediation="Validate incoming Origin headers against an explicit trusted allowlist.",
                    evidence=[Evidence(
                        source="cors_auditor",
                        description="Origin reflected in Access-Control-Allow-Origin",
                        sanitized_value=f"ACAO: {acao}"
                    )]
                ))
            # Case 3: Wildcard ACAO
            elif acao.strip() == "*":
                result.add_finding(Finding(
                    check_id="cors.wildcard_allowed",
                    title="Permissive CORS Policy: Wildcard Access-Control-Allow-Origin (*)",
                    description="The server allows any origin (*) to read cross-origin responses. May expose sensitive API endpoints.",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=url,
                    remediation="Restrict Access-Control-Allow-Origin to specific trusted domains if API contains sensitive data.",
                    evidence=[Evidence(
                        source="cors_auditor",
                        description="Access-Control-Allow-Origin is wildcard",
                        sanitized_value="Access-Control-Allow-Origin: *"
                    )]
                ))

        result.finish(ScanStatus.SUCCESS)
        return result


def run():
    """Interactive CLI entrypoint."""
    target = input("Enter target domain or URL: ").strip()
    info = validation.parse_target(target)
    if not info:
        formatter.error("Invalid target!")
        return

    url = info.normalized_url
    formatter.info(f"Auditing CORS policy for: {url}")
    scope = ScopePolicy.create_single_target_scope(url)
    scanner = CorsAuditorScanner()
    res = scanner.run(url, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    if res.findings:
        print(f"\n{formatter.BOLD}[*] CORS Policy Assessment:{formatter.RESET}")
        for f in res.findings:
            if f.severity in [Severity.HIGH, Severity.CRITICAL]:
                formatter.error(f"[{f.severity.value.upper()}] {f.title}")
            else:
                formatter.info(f"[{f.severity.value.upper()}] {f.title}")
            for ev in f.evidence:
                formatter.info(f"  {ev.sanitized_value}")
    else:
        formatter.success("No overly permissive or exploitable CORS policies identified.")
