"""
HTTP Security Headers & Server Information Scanner.
Analyzes response headers, security flags (HSTS, CSP, X-Frame-Options, etc.),
Cookie security attributes (HttpOnly, Secure, SameSite), and caching/proxy disclosure.
Supports both interactive CLI execution and structured BaseScanner orchestration.
"""

import http.client
import urllib.request
import urllib.parse
from typing import Optional, Dict, Any, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, runner, formatter


def parse_cookie_header(cookie_str: str) -> Dict[str, Any]:
    """Parses a Set-Cookie header value into its name, value, and security flags."""
    parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
    if not parts:
        return {"raw": cookie_str, "name": "unknown", "flags": {}}
    
    name_val = parts[0]
    name = name_val.split("=", 1)[0].strip() if "=" in name_val else name_val
    flags = {}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            flags[k.strip().lower()] = v.strip()
        else:
            flags[part.strip().lower()] = True
    return {"raw": cookie_str, "name": name, "flags": flags}


def assess_headers(headers_dict: Dict[str, Any], target_url: str) -> List[Finding]:
    """Generates structured findings from normalized lower-case headers dictionary."""
    findings = []

    # 1. Main Security Headers definitions
    security_headers = [
        ("strict-transport-security", "Strict-Transport-Security (HSTS) Missing",
         "The Strict-Transport-Security header enforces HTTPS connections, protecting against SSL stripping attacks.",
         Severity.MEDIUM, "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses."),
        ("content-security-policy", "Content-Security-Policy (CSP) Missing",
         "CSP prevents XSS and data injection attacks by restricting which sources can load scripts, styles, and other resources.",
         Severity.MEDIUM, "Implement a strong Content-Security-Policy tailored to your web application."),
        ("x-frame-options", "X-Frame-Options Missing (Clickjacking Protection)",
         "The X-Frame-Options header specifies whether a page can be rendered in a frame, preventing clickjacking attacks.",
         Severity.LOW, "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."),
        ("x-content-type-options", "X-Content-Type-Options Missing (MIME Sniffing)",
         "Prevents browsers from MIME-sniffing a response away from the declared Content-Type, mitigating script injection.",
         Severity.LOW, "Add 'X-Content-Type-Options: nosniff' header to all responses."),
        ("referrer-policy", "Referrer-Policy Header Missing",
         "Controls how much referrer information (like sensitive URLs/tokens in path) is included with requests.",
         Severity.LOW, "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."),
        ("permissions-policy", "Permissions-Policy Header Missing",
         "Allows sites to restrict browser features like geolocation, camera, and microphone.",
         Severity.INFO, "Configure 'Permissions-Policy' to disable unused sensitive browser APIs.")
    ]

    for header_name, title, desc, sev, remediation in security_headers:
        if header_name not in headers_dict:
            findings.append(Finding(
                check_id=f"headers.{header_name.replace('-', '_')}_missing",
                title=title,
                description=desc,
                severity=sev,
                confidence=Confidence.CONFIRMED,
                affected_asset=target_url,
                remediation=remediation,
                evidence=[Evidence(
                    source="http_headers",
                    description=f"Header '{header_name}' was not found in response.",
                    sanitized_value="Header missing"
                )],
                references=["https://owasp.org/www-project-secure-headers/"]
            ))

    # 2. Technology & Server Disclosures
    tech_headers = [
        ("server", "Web Server Header Disclosed", Severity.LOW),
        ("x-powered-by", "Application Framework Header Disclosed", Severity.LOW),
        ("x-aspnet-version", "ASP.NET Framework Version Disclosed", Severity.LOW),
    ]
    for h_name, title, sev in tech_headers:
        if h_name in headers_dict:
            val = str(headers_dict[h_name])
            findings.append(Finding(
                check_id=f"headers.{h_name.replace('-', '_')}_disclosed",
                title=title,
                description=f"The application leaks infrastructure details via the '{h_name}' header.",
                severity=sev,
                confidence=Confidence.CONFIRMED,
                affected_asset=target_url,
                remediation=f"Remove or mask the '{h_name}' header in production web server configuration.",
                evidence=[Evidence(
                    source="http_headers",
                    description=f"Server returned '{h_name}' header.",
                    sanitized_value=val
                )],
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Information_Leakage_Cheat_Sheet.html"]
            ))

    # 3. Cookie Flags
    raw_cookies = headers_dict.get("set-cookie")
    if raw_cookies:
        cookie_list = raw_cookies if isinstance(raw_cookies, list) else [raw_cookies]
        for c in cookie_list:
            parsed = parse_cookie_header(c)
            c_name = parsed["name"]
            flags = parsed["flags"]

            missing_flags = []
            if "httponly" not in flags:
                missing_flags.append("HttpOnly")
            if "secure" not in flags and target_url.startswith("https://"):
                missing_flags.append("Secure")
            if "samesite" not in flags:
                missing_flags.append("SameSite")

            if missing_flags:
                findings.append(Finding(
                    check_id=f"cookies.insecure_cookie_{c_name}",
                    title=f"Cookie '{c_name}' Missing Security Flags: {', '.join(missing_flags)}",
                    description=f"Cookie '{c_name}' lacks recommended protective attributes ({', '.join(missing_flags)}).",
                    severity=Severity.MEDIUM if "HttpOnly" in missing_flags else Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=target_url,
                    remediation=f"Set HttpOnly, Secure, and SameSite=Lax (or Strict) on cookie '{c_name}'.",
                    evidence=[Evidence(
                        source="http_headers",
                        description=f"Set-Cookie attribute missing: {', '.join(missing_flags)}",
                        sanitized_value=f"Cookie '{c_name}' missing {missing_flags}"
                    )],
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"]
                ))

    # 4. CORS Permissive Wildcard
    acao = headers_dict.get("access-control-allow-origin")
    if acao == "*":
        findings.append(Finding(
            check_id="headers.cors_wildcard",
            title="CORS Access-Control-Allow-Origin Wildcard (*)",
            description="The application sets Access-Control-Allow-Origin to '*', permitting any third-party origin to read responses.",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            affected_asset=target_url,
            remediation="Restricted trusted origins explicitly rather than using wildcard '*'.",
            evidence=[Evidence(
                source="http_headers",
                description="Access-Control-Allow-Origin is set to wildcard (*).",
                sanitized_value="Access-Control-Allow-Origin: *"
            )],
            references=["https://portswigger.net/web-security/cors"]
        ))

    return findings


def fetch_headers(url: str, timeout: int = 10) -> Dict[str, Any]:
    """Fetches headers using curl if available, otherwise urllib with scheme preservation."""
    headers_dict = {}

    if runner.tool_available("curl"):
        res = runner.run_tool_result(["curl", "-sIL", "--max-time", str(timeout), url])
        if res.succeeded and res.stdout:
            for line in res.stdout.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    k = key.strip().lower()
                    v = val.strip()
                    if k in headers_dict:
                        if isinstance(headers_dict[k], list):
                            headers_dict[k].append(v)
                        else:
                            headers_dict[k] = [headers_dict[k], v]
                    else:
                        headers_dict[k] = v
            return headers_dict

    # Native urllib fallback
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "CLI-Multipurpose-Security/2.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            for k, v in response.headers.items():
                key = k.lower()
                if key in headers_dict:
                    if isinstance(headers_dict[key], list):
                        headers_dict[key].append(v)
                    else:
                        headers_dict[key] = [headers_dict[key], v]
                else:
                    headers_dict[key] = v
    except urllib.error.HTTPError as e:
        # HTTP errors still contain headers!
        for k, v in e.headers.items():
            key = k.lower()
            if key in headers_dict:
                if isinstance(headers_dict[key], list):
                    headers_dict[key].append(v)
                else:
                    headers_dict[key] = [headers_dict[key], v]
            else:
                headers_dict[key] = v
    except Exception as e:
        raise RuntimeError(f"Failed to connect to {url}: {e}")

    return headers_dict


class HttpHeadersScanner(BaseScanner):
    scanner_id = "http_headers"
    name = "HTTP Security Headers Scanner"
    description = "Inspects HTTP response headers, security flags, cookie attributes, and information leakage."
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
            result.add_error(f"Cannot parse target URL: {target}")
            result.finish(ScanStatus.FAILED)
            return result

        url = info.normalized_url

        try:
            headers = fetch_headers(url, timeout=scope.timeout_seconds)
            if not headers:
                result.add_warning("No headers returned from target.")
                result.finish(ScanStatus.PARTIAL)
                return result

            result.metadata["headers_count"] = len(headers)
            findings = assess_headers(headers, url)
            for f in findings:
                result.add_finding(f)
            result.finish(ScanStatus.SUCCESS)
        except Exception as e:
            result.add_error(str(e))
            result.finish(ScanStatus.FAILED)

        return result


def analyze_headers(headers_dict: dict):
    """Legacy interactive helper for displaying header analysis."""
    print(f"\n{formatter.BOLD}{formatter.CYAN}--- HTTP Headers Security & Tech Analysis ---{formatter.RESET}\n")

    # 1. Tech headers
    tech_headers = {
        "server": "Server Software",
        "x-powered-by": "Application Framework",
        "x-aspnet-version": "ASP.NET Version",
    }
    found_tech = False
    for h, label in tech_headers.items():
        if h in headers_dict:
            if not found_tech:
                print(f"{formatter.BOLD}[*] Technology & Server Information:{formatter.RESET}")
                found_tech = True
            formatter.info(f"{label}: {headers_dict[h]}")
    if not found_tech:
        print(f"{formatter.BOLD}[*] Technology & Server Information:{formatter.RESET}")
        formatter.info("No server identification headers disclosed.")
    print()

    # 2. Main Security Headers
    security_headers = {
        "strict-transport-security": "Strict-Transport-Security (HSTS)",
        "content-security-policy": "Content-Security-Policy (CSP)",
        "x-frame-options": "X-Frame-Options (Clickjacking protection)",
        "x-content-type-options": "X-Content-Type-Options (MIME Sniffing)",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    print(f"{formatter.BOLD}[*] Security Headers Check:{formatter.RESET}")
    for h, label in security_headers.items():
        if h in headers_dict:
            formatter.success(f"{label}: {headers_dict[h]}")
        else:
            formatter.error(f"{label}: Missing!")
    print()

    # 3. Cookie Flags
    raw_cookies = headers_dict.get("set-cookie")
    if raw_cookies:
        print(f"{formatter.BOLD}[*] Cookie Security Check:{formatter.RESET}")
        cookie_list = raw_cookies if isinstance(raw_cookies, list) else [raw_cookies]
        for cookie in cookie_list:
            parsed = parse_cookie_header(cookie)
            missing = []
            if "httponly" not in parsed["flags"]:
                missing.append("HttpOnly")
            if "secure" not in parsed["flags"]:
                missing.append("Secure")
            if "samesite" not in parsed["flags"]:
                missing.append("SameSite")
            if missing:
                formatter.error(f"Cookie '{parsed['name']}' missing: {', '.join(missing)}")
            else:
                formatter.success(f"Cookie '{parsed['name']}' has HttpOnly, Secure, and SameSite!")
        print()


def run():
    """Interactive CLI entrypoint preserving legacy menu workflow."""
    target = input("Enter target domain or URL: ").strip()
    if not validation.is_valid_target(target):
        formatter.error("Invalid target!")
        return

    info = validation.parse_target(target)
    if not info:
        formatter.error("Failed to parse target URL.")
        return

    url = info.normalized_url
    formatter.info(f"Target URL: {url}")

    try:
        headers = fetch_headers(url)
        if headers:
            analyze_headers(headers)
        else:
            formatter.error("No headers collected to analyze.")
    except Exception as e:
        formatter.error(f"Failed to fetch headers: {e}")
