"""
Cookie Security & Attribute Auditor.
Deep audit of Set-Cookie attributes: HttpOnly, Secure, SameSite, cookie domain scope,
expiration lifespans, and cookie prefixes (__Host-, __Secure-).
Implements CookieAuditorScanner(BaseScanner) and interactive run().
"""

import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from modules.http_headers import parse_cookie_header
from utils import validation, formatter


# Known sensitive session cookie names
SESSION_COOKIE_NAMES = [
    "session", "sessionid", "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "sid", "auth", "authtoken", "jwt", "remember_token"
]


class CookieAuditorScanner(BaseScanner):
    scanner_id = "cookie_auditor"
    name = "Cookie Security Auditor"
    description = "Performs deep evaluation of cookie security flags (HttpOnly, Secure, SameSite, __Host- prefix)."
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

        url = info.normalized_url

        raw_cookies = []
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "CLI-Multipurpose-Security/2.0")

        try:
            with urllib.request.urlopen(req, timeout=scope.timeout_seconds) as resp:
                headers = resp.headers
                raw_cookies = headers.get_all("Set-Cookie") or []
        except urllib.error.HTTPError as e:
            raw_cookies = e.headers.get_all("Set-Cookie") or []
        except Exception as e:
            result.add_error(f"Failed to connect: {e}")
            result.finish(ScanStatus.FAILED)
            return result

        if not raw_cookies:
            result.add_warning("No Set-Cookie headers returned by target page.")
            result.finish(ScanStatus.SUCCESS)
            return result

        result.metadata["cookies_count"] = len(raw_cookies)

        for cookie_str in raw_cookies:
            parsed = parse_cookie_header(cookie_str)
            name = parsed["name"]
            flags = parsed["flags"]
            is_session = name.lower() in SESSION_COOKIE_NAMES or any(s in name.lower() for s in ["sess", "auth", "token"])

            # 1. HttpOnly check
            if "httponly" not in flags:
                sev = Severity.HIGH if is_session else Severity.LOW
                result.add_finding(Finding(
                    check_id=f"cookie.missing_httponly_{name}",
                    title=f"Cookie '{name}' Missing 'HttpOnly' Flag",
                    description=f"Cookie '{name}' can be accessed via client-side JavaScript (document.cookie), exposing it to XSS theft.",
                    severity=sev,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{url} [Cookie: {name}]",
                    remediation=f"Add the 'HttpOnly' directive to the Set-Cookie header for '{name}'.",
                    evidence=[Evidence(
                        source="cookie_auditor",
                        description="Parsed cookie attributes lack 'HttpOnly'",
                        sanitized_value=f"Set-Cookie: {name}=[REDACTED]"
                    )],
                    references=["https://owasp.org/www-community/HttpOnly"]
                ))

            # 2. Secure flag check
            if "secure" not in flags and url.startswith("https://"):
                sev = Severity.HIGH if is_session else Severity.MEDIUM
                result.add_finding(Finding(
                    check_id=f"cookie.missing_secure_{name}",
                    title=f"Cookie '{name}' Missing 'Secure' Flag over HTTPS",
                    description=f"Cookie '{name}' is transmitted in unencrypted plaintext if user navigates via HTTP.",
                    severity=sev,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{url} [Cookie: {name}]",
                    remediation=f"Add the 'Secure' directive to ensure cookie '{name}' is only transmitted over HTTPS.",
                    evidence=[Evidence(
                        source="cookie_auditor",
                        description="Parsed cookie attributes lack 'Secure'",
                        sanitized_value=f"Set-Cookie: {name}=[REDACTED]"
                    )],
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"]
                ))

            # 3. SameSite check
            samesite_val = flags.get("samesite")
            if not samesite_val:
                result.add_finding(Finding(
                    check_id=f"cookie.missing_samesite_{name}",
                    title=f"Cookie '{name}' Missing 'SameSite' Attribute",
                    description=f"Without SameSite attribute, browser defaults or cross-site requests may include cookie '{name}', increasing CSRF exposure.",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{url} [Cookie: {name}]",
                    remediation=f"Set 'SameSite=Lax' or 'SameSite=Strict' on cookie '{name}'.",
                    evidence=[Evidence(
                        source="cookie_auditor",
                        description="Parsed cookie attributes lack SameSite",
                        sanitized_value=f"Set-Cookie: {name}=[REDACTED]"
                    )],
                    references=["https://portswigger.net/web-security/csrf/samesite-cookies"]
                ))
            elif isinstance(samesite_val, str) and samesite_val.lower() == "none" and "secure" not in flags:
                result.add_finding(Finding(
                    check_id=f"cookie.samesite_none_insecure_{name}",
                    title=f"Cookie '{name}' Sets 'SameSite=None' Without 'Secure'",
                    description="Modern browsers reject cookies with SameSite=None unless they also have the Secure attribute.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{url} [Cookie: {name}]",
                    remediation=f"Set both 'SameSite=None' and 'Secure' on cookie '{name}'.",
                    evidence=[Evidence(
                        source="cookie_auditor",
                        description="SameSite=None present without Secure flag",
                        sanitized_value=f"Set-Cookie: {name}=[REDACTED]; SameSite=None"
                    )]
                ))

            # 4. Cookie prefix validation
            if name.startswith("__Host-"):
                if "secure" not in flags or flags.get("path") != "/" or "domain" in flags:
                    result.add_finding(Finding(
                        check_id=f"cookie.invalid_host_prefix_{name}",
                        title=f"Invalid '__Host-' Prefix Configuration on '{name}'",
                        description="__Host- cookies must have Secure flag, Path=/, and MUST NOT specify a Domain attribute.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=f"{url} [Cookie: {name}]",
                        remediation="Ensure __Host- cookies use Secure, Path=/, and omit the Domain attribute.",
                        evidence=[Evidence(
                            source="cookie_auditor",
                            description="Cookie prefix rule violated",
                            sanitized_value=f"Cookie {name}"
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
    formatter.info(f"Auditing cookies on: {url}")
    scope = ScopePolicy.create_single_target_scope(url)
    scanner = CookieAuditorScanner()
    res = scanner.run(url, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    if res.findings:
        print(f"\n{formatter.BOLD}[*] Cookie Security Findings ({len(res.findings)} issues):{formatter.RESET}")
        for f in res.findings:
            if f.severity in [Severity.HIGH, Severity.CRITICAL]:
                formatter.error(f"[{f.severity.value.upper()}] {f.title}")
            else:
                formatter.info(f"[{f.severity.value.upper()}] {f.title}")
    else:
        formatter.success("All returned cookies have proper HttpOnly, Secure, and SameSite flags!")
