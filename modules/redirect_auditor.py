"""
HTTP Redirect & Open-Redirect Parameter Auditor.
Evaluates HTTP-to-HTTPS upgrade enforcement, redirect chain hops, and potential
open-redirect patterns using benign controlled test values within authorized scope.
Implements RedirectAuditorScanner(BaseScanner) and interactive run().
"""

import urllib.request
import urllib.error
import urllib.parse
from typing import Optional, Dict, Any, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, formatter


REDIRECT_PARAM_NAMES = [
    "redirect", "url", "next", "return", "dest", "target", "goto", "redirect_uri", "return_url"
]


class RedirectAuditorScanner(BaseScanner):
    scanner_id = "redirect_auditor"
    name = "Redirect & Open-Redirect Auditor"
    description = "Checks HTTP-to-HTTPS upgrades and tests redirect parameters for open-redirect weaknesses."
    category = "web"
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
        if not info:
            result.add_error(f"Cannot parse target: {target}")
            result.finish(ScanStatus.FAILED)
            return result

        host = info.host

        # 1. Test HTTP to HTTPS automatic upgrade
        http_url = f"http://{host}/"
        req = urllib.request.Request(http_url, method="GET")
        req.add_header("User-Agent", "CLI-Multipurpose-Security/2.0")

        class DisallowRedirects(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(DisallowRedirects)
        try:
            with opener.open(req, timeout=scope.timeout_seconds) as resp:
                # If HTTP returned 200 without redirecting to HTTPS
                if resp.status == 200:
                    result.add_finding(Finding(
                        check_id="redirect.no_https_upgrade",
                        title=f"Unencrypted HTTP Serves Content Directly on {host}",
                        description="The server serves responses over unencrypted HTTP (200 OK) without upgrading to HTTPS (301/308).",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=http_url,
                        remediation="Configure a 301 Permanent Redirect from HTTP to HTTPS for all traffic.",
                        evidence=[Evidence(
                            source="redirect_auditor",
                            description="GET http:// returned HTTP 200 without redirect.",
                            sanitized_value="HTTP 200 OK over port 80"
                        )],
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"]
                    ))
        except urllib.error.HTTPError as e:
            if e.code in [301, 302, 307, 308]:
                location = e.headers.get("Location", "")
                if location.startswith("https://"):
                    result.add_finding(Finding(
                        check_id="redirect.https_upgrade_enforced",
                        title=f"HTTPS Upgrade Enforced on {host}",
                        description=f"HTTP connection automatically redirects to HTTPS: {location}",
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=http_url,
                        remediation="Ensure HSTS header is also enabled on HTTPS responses.",
                        evidence=[Evidence(
                            source="redirect_auditor",
                            description=f"HTTP {e.code} redirect to HTTPS",
                            sanitized_value=f"Location: {location}"
                        )]
                    ))
                else:
                    result.add_warning(f"HTTP redirects to non-HTTPS destination: {location}")
        except Exception as e:
            result.add_warning(f"Could not test HTTP port 80: {e}")

        # 2. Check for open-redirect parameters if URL has query string
        if "?" in target:
            parsed = urllib.parse.urlparse(target)
            qs = urllib.parse.parse_qs(parsed.query)

            for param in qs:
                if param.lower() in REDIRECT_PARAM_NAMES:
                    # Test probe with benign controlled external domain
                    test_domain = "https://example.com"
                    mod_qs = qs.copy()
                    mod_qs[param] = [test_domain]
                    new_query = urllib.parse.urlencode(mod_qs, doseq=True)
                    probe_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    probe_req = urllib.request.Request(probe_url)
                    probe_req.add_header("User-Agent", "CLI-Multipurpose-Security/2.0")

                    try:
                        opener.open(probe_req, timeout=scope.timeout_seconds)
                    except urllib.error.HTTPError as err:
                        if err.code in [301, 302, 303, 307, 308]:
                            loc = err.headers.get("Location", "")
                            if loc.startswith("https://example.com"):
                                result.add_finding(Finding(
                                    check_id=f"redirect.open_redirect_{param}",
                                    title=f"Potential Open Redirect on Parameter '{param}'",
                                    description=f"Server redirects user to arbitrary external destination specified in '{param}' ({loc}).",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.HIGH,
                                    affected_asset=f"{parsed.path}?{param}",
                                    remediation="Validate redirect destinations against a strict whitelist or use relative paths only.",
                                    evidence=[Evidence(
                                        source="redirect_auditor",
                                        description="Location header reflects injected external domain",
                                        sanitized_value=f"Location: {loc}"
                                    )],
                                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"]
                                ))
                    except Exception:
                        pass

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
    formatter.info(f"Auditing redirects for: {url}")
    scope = ScopePolicy.create_single_target_scope(url)
    scanner = RedirectAuditorScanner()
    res = scanner.run(url, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    if res.findings:
        print(f"\n{formatter.BOLD}[*] Redirect Assessment Findings:{formatter.RESET}")
        for f in res.findings:
            if f.severity in [Severity.HIGH, Severity.MEDIUM]:
                formatter.error(f"[{f.severity.value.upper()}] {f.title}")
            else:
                formatter.success(f"{f.title}")
            for ev in f.evidence:
                formatter.info(f"  {ev.sanitized_value}")
    else:
        formatter.info("No redirect anomalies discovered.")
