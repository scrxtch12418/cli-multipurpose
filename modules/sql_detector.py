"""
SQL Injection Detection Scanner.
Performs scoped, opt-in parameter testing for database error signatures
and differential responses. Never escalates to intrusive tools without authorization.
Implements SqlDetectorScanner(BaseScanner) and interactive run().
"""

import urllib.request
import urllib.error
import urllib.parse
from typing import Optional, Dict, Any, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, runner, formatter


# Curated SQL syntax error patterns mapped to database engine
SQL_ERROR_SIGNATURES = [
    ("MySQL", "you have an error in your sql syntax"),
    ("MySQL", "warning: mysql"),
    ("MySQL", "supplied argument is not a valid mysql"),
    ("PostgreSQL", "pg_query(): query failed"),
    ("PostgreSQL", "syntax error at or near"),
    ("SQLite", "sqlite3::query"),
    ("SQLite", "sqlite3::exec"),
    ("SQLite", "unrecognized token"),
    ("Oracle", "ora-00933"),
    ("Oracle", "ora-01756"),
    ("MSSQL", "unclosed quotation mark"),
    ("MSSQL", "microsoft ole db provider for sql server"),
    ("MSSQL", "odbc microsoft access driver"),
    ("Generic", "dynamic sql error"),
    ("Generic", "jdbc exception"),
]

# Benign boundary injection test probes
TEST_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]


class SqlDetectorScanner(BaseScanner):
    scanner_id = "sql_detector"
    name = "SQL Injection Detector"
    description = "Tests URL query parameters with benign quote probes for database error signatures. Active check."
    category = "web"
    is_active = True  # Active probe requiring explicit authorization

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
            result.add_error(f"Target '{target}' is out of scope: {reason}")
            result.finish(ScanStatus.SKIPPED)
            return result

        if "?" not in target or "=" not in target:
            result.add_warning("Target URL does not contain query parameters to test (e.g. ?id=1).")
            result.finish(ScanStatus.SKIPPED)
            return result

        parsed = urllib.parse.urlparse(target)
        params = urllib.parse.parse_qs(parsed.query)

        requests_sent = 0
        max_requests = min(scope.max_requests_per_target, 20)

        for param in params:
            for payload in TEST_PAYLOADS:
                if requests_sent >= max_requests:
                    result.add_warning(f"Hit request budget limit ({max_requests}) for SQL injection testing.")
                    break

                modified = params.copy()
                modified[param] = [payload]
                new_query = urllib.parse.urlencode(modified, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                req = urllib.request.Request(test_url)
                req.add_header("User-Agent", "CLI-Multipurpose-Security/2.0")

                requests_sent += 1
                try:
                    with urllib.request.urlopen(req, timeout=scope.timeout_seconds) as resp:
                        body = resp.read().decode("utf-8", errors="ignore").lower()
                        for dbms, signature in SQL_ERROR_SIGNATURES:
                            if signature in body:
                                result.add_finding(Finding(
                                    check_id=f"sqli.error_based_{param}",
                                    title=f"Potential SQL Injection Error on Parameter '{param}' ({dbms})",
                                    description=f"Server returned a {dbms} SQL syntax error when injected with payload: {payload}",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    affected_asset=f"{parsed.path}?{param}",
                                    remediation="Use parameterized queries / prepared statements (e.g. ORM or PDO) to prevent SQL injection.",
                                    evidence=[Evidence(
                                        source="sql_detector",
                                        description=f"Matched signature: '{signature}' for {dbms}",
                                        sanitized_value=f"Payload: {payload} | Matched: {signature}"
                                    )],
                                    references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                                ))
                                break
                except urllib.error.HTTPError as e:
                    # Check body of 500/400 for SQL error message
                    body = ""
                    try:
                        body = e.read().decode("utf-8", errors="ignore").lower()
                    except Exception:
                        pass

                    matched_sig = False
                    for dbms, signature in SQL_ERROR_SIGNATURES:
                        if signature in body:
                            matched_sig = True
                            result.add_finding(Finding(
                                check_id=f"sqli.error_based_{param}",
                                title=f"Confirmed SQL Error on Parameter '{param}' ({dbms})",
                                description=f"HTTP {e.code} response contained {dbms} SQL error message: {signature}",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                affected_asset=f"{parsed.path}?{param}",
                                remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                                evidence=[Evidence(
                                    source="sql_detector",
                                    description=f"HTTP {e.code} with database error signature: {signature}",
                                    sanitized_value=f"Payload: {payload} | Error: {signature}"
                                )],
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
                            ))
                            break

                    # An unhandled HTTP 500 without database error text is only an unhandled exception indicator
                    if not matched_sig and e.code == 500:
                        result.add_finding(Finding(
                            check_id=f"sqli.server_error_{param}",
                            title=f"Server HTTP 500 on Parameter '{param}' With Probe",
                            description="The server raised an internal error (500) when sent an unexpected quote character. May indicate poor input handling.",
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            affected_asset=f"{parsed.path}?{param}",
                            remediation="Implement robust error handling and validate that user input does not cause unhandled database exceptions.",
                            evidence=[Evidence(
                                source="sql_detector",
                                description="Server returned HTTP 500 Internal Server Error without disclosing SQL signature.",
                                sanitized_value=f"Payload: {payload} -> HTTP 500"
                            )]
                        ))
                except Exception as e:
                    result.add_warning(f"Probe failed for {param}={payload}: {e}")

        result.metadata["requests_sent"] = requests_sent
        result.finish(ScanStatus.SUCCESS if result.findings else ScanStatus.SUCCESS)
        return result


def run():
    """Interactive CLI entrypoint requiring explicit user authorization."""
    formatter.banner("SQL Injection Detector")
    print(f"{formatter.RED}{formatter.BOLD}[!] CAUTION: Active Security Test{formatter.RESET}")
    print("This module sends test payloads to query parameters on the target system.")
    print("You MUST have explicit written authorization before running this test.\n")

    confirm = input("Do you have authorization to test this target? (yes/no): ").strip().lower()
    if confirm not in ["yes", "y"]:
        formatter.error("Aborted: Unauthorized testing is prohibited.")
        return

    url = input("Enter full target URL with parameter (e.g. http://127.0.0.1:8000/page?id=1): ").strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    if "?" not in url or "=" not in url:
        formatter.error("URL must contain a query parameter (e.g. http://example.com/item?id=1).")
        return

    # Check if sqlmap should be invoked optionally
    if runner.tool_available("sqlmap"):
        use_sqlmap = input("External tool 'sqlmap' is installed. Do you want to invoke sqlmap? (yes/no) [default: no]: ").strip().lower()
        if use_sqlmap in ["yes", "y"]:
            formatter.info("Executing sqlmap in batch mode...")
            res = runner.run_tool_result(["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1"])
            if res.succeeded and res.stdout:
                print(res.stdout)
            else:
                formatter.error(f"sqlmap execution returned code {res.returncode}: {res.error or res.stderr}")
            return

    formatter.info(f"Running safe native SQL error signature detector on {url}...")
    scope = ScopePolicy.create_single_target_scope(url, active_checks=True)
    scanner = SqlDetectorScanner()
    res = scanner.run(url, scope)

    if res.findings:
        print(f"\n{formatter.BOLD}[*] Findings Detected:{formatter.RESET}")
        for f in res.findings:
            if f.severity in [Severity.HIGH, Severity.CRITICAL]:
                formatter.error(f"[{f.severity.value.upper()}] {f.title} (Confidence: {f.confidence.value})")
            else:
                formatter.info(f"[{f.severity.value.upper()}] {f.title} (Confidence: {f.confidence.value})")
            print(f"    Remediation: {f.remediation}")
    else:
        formatter.success("No SQL injection signatures detected with standard test probes.")
