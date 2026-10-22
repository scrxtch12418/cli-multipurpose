"""
Web Technology & Framework Fingerprinting Scanner.
Analyzes response headers, meta generator tags, script signatures, and cookies
to infer web servers, programming languages, CMS platforms, and frontend frameworks.
Implements TechFingerprintScanner(BaseScanner) and interactive run().
"""

import re
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, formatter


# Technology signatures map: (Category, Name, MatchType, Pattern, Confidence)
TECH_SIGNATURES = [
    # Headers
    ("server", "Apache Web Server", "header", ("server", r"apache"), Confidence.HIGH),
    ("server", "Nginx Web Server", "header", ("server", r"nginx"), Confidence.HIGH),
    ("server", "Microsoft IIS", "header", ("server", r"microsoft-iis"), Confidence.HIGH),
    ("server", "Cloudflare CDN", "header", ("server", r"cloudflare"), Confidence.HIGH),
    ("framework", "ASP.NET", "header", ("x-powered-by", r"asp\.net"), Confidence.HIGH),
    ("language", "PHP", "header", ("x-powered-by", r"php"), Confidence.HIGH),
    ("framework", "Express.js", "header", ("x-powered-by", r"express"), Confidence.HIGH),
    ("proxy", "Varnish Cache", "header", ("via", r"varnish"), Confidence.HIGH),

    # HTML Meta Generator Tags
    ("cms", "WordPress", "html", r'<meta[^>]+name=[\'"]generator[\'"][^>]+content=[\'"]WordPress\s*([0-9\.]*)', Confidence.HIGH),
    ("cms", "Drupal", "html", r'<meta[^>]+name=[\'"]generator[\'"][^>]+content=[\'"]Drupal\s*([0-9\.]*)', Confidence.HIGH),
    ("cms", "Joomla", "html", r'<meta[^>]+name=[\'"]generator[\'"][^>]+content=[\'"]Joomla', Confidence.HIGH),

    # Script and Asset Signatures
    ("frontend", "React", "html", r'react(-dom)?(\.min)?\.js|_reactRootContainer|data-reactroot', Confidence.MEDIUM),
    ("frontend", "Vue.js", "html", r'vue(\.min)?\.js|data-v-[a-f0-9]+', Confidence.MEDIUM),
    ("frontend", "Next.js", "html", r'/_next/static/|__NEXT_DATA__', Confidence.HIGH),
    ("frontend", "Angular", "html", r'ng-version=|ng-app=|angular(\.min)?\.js', Confidence.MEDIUM),
    ("frontend", "jQuery", "html", r'jquery(-[0-9\.]+)?(\.min)?\.js', Confidence.MEDIUM),
    ("frontend", "Bootstrap", "html", r'bootstrap(\.min)?\.(css|js)', Confidence.MEDIUM),
]


class TechFingerprintScanner(BaseScanner):
    scanner_id = "tech_fingerprint"
    name = "Technology Fingerprinting Scanner"
    description = "Infers web servers, CMSs, and frontend/backend frameworks from headers and HTML markers."
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

        headers = {}
        body = ""

        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "CLI-Multipurpose-Security/2.0")

        try:
            with urllib.request.urlopen(req, timeout=scope.timeout_seconds) as resp:
                for k, v in resp.headers.items():
                    headers[k.lower()] = v
                # Read first 100KB of HTML response
                raw_bytes = resp.read(102400)
                body = raw_bytes.decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            for k, v in e.headers.items():
                headers[k.lower()] = v
            try:
                body = e.read(102400).decode("utf-8", errors="ignore")
            except Exception:
                pass
        except Exception as e:
            result.add_error(f"Failed to fetch content from {url}: {e}")
            result.finish(ScanStatus.FAILED)
            return result

        detected_tech = []

        # Evaluate signatures
        for category, name, match_type, pattern_spec, conf in TECH_SIGNATURES:
            if match_type == "header":
                header_name, regex_pattern = pattern_spec
                val = headers.get(header_name, "")
                if val and re.search(regex_pattern, val, re.IGNORECASE):
                    detected_tech.append((category, name, f"{header_name}: {val}", conf))
            elif match_type == "html" and body:
                match = re.search(pattern_spec, body, re.IGNORECASE)
                if match:
                    matched_snippet = match.group(0)[:80]
                    detected_tech.append((category, name, f"HTML signature: '{matched_snippet}'", conf))

        result.metadata["technologies_count"] = len(detected_tech)

        for cat, name, evidence_snippet, conf in detected_tech:
            result.add_finding(Finding(
                check_id=f"tech.{cat}_{name.lower().replace(' ', '_').replace('.', '_')}",
                title=f"Technology Fingerprint: {name} ({cat.capitalize()})",
                description=f"Identified {name} ({cat}) in use on the target system.",
                severity=Severity.INFO,
                confidence=conf,
                affected_asset=url,
                remediation="Ensure technology components and dependencies are actively patched and updated.",
                evidence=[Evidence(
                    source="tech_fingerprint",
                    description=f"Matched {cat} signature for {name}",
                    sanitized_value=evidence_snippet
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
    formatter.info(f"Fingerprinting technologies on: {url}")
    scope = ScopePolicy.create_single_target_scope(url)
    scanner = TechFingerprintScanner()
    res = scanner.run(url, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    if res.findings:
        print(f"\n{formatter.BOLD}[*] Identified Technologies ({len(res.findings)} found):{formatter.RESET}")
        for f in res.findings:
            formatter.success(f"{f.title} [Confidence: {f.confidence.value}]")
            for ev in f.evidence:
                formatter.info(f"  {ev.sanitized_value}")
    else:
        formatter.info("No specific framework or CMS technologies fingerprinted.")
