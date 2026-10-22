"""
TLS/SSL Certificate & Configuration Scanner.
Inspects certificate validity, expiration, SAN hostname matches, protocol version,
and cipher suite negotiation using standard Python ssl library.
Implements TlsCheckerScanner(BaseScanner) and interactive run().
"""

from datetime import datetime, timezone
import socket
import ssl
from typing import Optional, Dict, Any, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, formatter


class TlsCheckerScanner(BaseScanner):
    scanner_id = "tls_checker"
    name = "TLS/SSL Certificate & Protocol Checker"
    description = "Inspects SSL/TLS certificates, expiry dates, hostname validity, and negotiated cipher suites."
    category = "tls"
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

        info = validation.parse_target(target, default_scheme="https")
        if not info:
            result.add_error(f"Cannot parse target: {target}")
            result.finish(ScanStatus.FAILED)
            return result

        host = info.host
        port = info.port or 443

        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=scope.timeout_seconds) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    proto = ssock.version()
        except ssl.SSLCertVerificationError as e:
            result.add_finding(Finding(
                check_id="tls.cert_untrusted",
                title=f"SSL Certificate Verification Failed on {host}",
                description=f"The SSL certificate could not be verified by standard trust store: {e.strerror}",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                affected_asset=f"{host}:{port}",
                remediation="Install a valid certificate issued by a trusted Certificate Authority (e.g. Let's Encrypt).",
                evidence=[Evidence(
                    source="tls_checker",
                    description="SSLCertVerificationError raised during TLS handshake.",
                    sanitized_value=str(e)
                )],
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"]
            ))
            result.finish(ScanStatus.SUCCESS)
            return result
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result.add_error(f"Could not connect to TLS service on {host}:{port}: {e}")
            result.finish(ScanStatus.FAILED)
            return result
        except Exception as e:
            result.add_error(f"TLS inspection error: {e}")
            result.finish(ScanStatus.FAILED)
            return result

        if not cert:
            result.add_warning("No peer certificate was returned by server.")
            result.finish(ScanStatus.PARTIAL)
            return result

        # Extract expiry
        not_after_str = cert.get("notAfter")
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        subject = dict(x[0] for x in cert.get("subject", ()))
        sans = [val for key, val in cert.get("subjectAltName", ()) if key == "DNS"]

        result.metadata["protocol"] = proto
        result.metadata["cipher"] = cipher
        result.metadata["issuer"] = issuer
        result.metadata["sans"] = sans

        # Check expiration date
        if not_after_str:
            try:
                # Format: 'May 20 12:00:00 2026 GMT'
                exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (exp_date - now).days
                result.metadata["days_until_expiry"] = days_left

                if days_left < 0:
                    result.add_finding(Finding(
                        check_id="tls.cert_expired",
                        title=f"SSL/TLS Certificate Expired on {host}",
                        description=f"Certificate expired {abs(days_left)} days ago (on {exp_date.isoformat()}).",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=f"{host}:{port}",
                        remediation="Renew and deploy an active TLS certificate immediately.",
                        evidence=[Evidence(
                            source="tls_checker",
                            description="Certificate expiration check",
                            sanitized_value=f"Expired on {exp_date.isoformat()} ({abs(days_left)} days ago)"
                        )]
                    ))
                elif days_left < 30:
                    result.add_finding(Finding(
                        check_id="tls.cert_expiring_soon",
                        title=f"SSL/TLS Certificate Expiring Soon ({days_left} days remaining)",
                        description=f"The SSL certificate for {host} will expire on {exp_date.isoformat()}.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=f"{host}:{port}",
                        remediation="Schedule certificate renewal before expiration to avoid outages.",
                        evidence=[Evidence(
                            source="tls_checker",
                            description="Certificate expiration check",
                            sanitized_value=f"{days_left} days remaining until {exp_date.isoformat()}"
                        )]
                    ))
                else:
                    result.add_finding(Finding(
                        check_id="tls.cert_valid",
                        title=f"Valid TLS Certificate ({days_left} days remaining)",
                        description=f"Certificate is valid until {exp_date.isoformat()} issued by {issuer.get('organizationName', 'Unknown')}.",
                        severity=Severity.INFO,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=f"{host}:{port}",
                        remediation="Maintain automated certificate renewal monitoring.",
                        evidence=[Evidence(
                            source="tls_checker",
                            description="TLS certificate validity check",
                            sanitized_value=f"Valid until: {exp_date.isoformat()}"
                        )]
                    ))
            except Exception as e:
                result.add_warning(f"Could not parse certificate expiry: {e}")

        # Check negotiated protocol
        if proto in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            result.add_finding(Finding(
                check_id="tls.deprecated_protocol",
                title=f"Deprecated TLS Protocol Version Negotiated: {proto}",
                description=f"The server negotiated {proto}, which is deprecated and contains known security weaknesses.",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                affected_asset=f"{host}:{port}",
                remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 in web server configuration; enforce TLS 1.2 or TLS 1.3.",
                evidence=[Evidence(
                    source="tls_checker",
                    description="Negotiated TLS protocol",
                    sanitized_value=proto
                )],
                references=["https://datatracker.ietf.org/doc/rfc8996/"]
            ))

        result.finish(ScanStatus.SUCCESS)
        return result


def run():
    """Interactive CLI entrypoint."""
    target = input("Enter target hostname or URL: ").strip()
    info = validation.parse_target(target, default_scheme="https")
    if not info:
        formatter.error("Invalid target!")
        return

    host = info.host
    formatter.info(f"Inspecting TLS certificate for: {host}")
    scope = ScopePolicy.create_single_target_scope(host)
    scanner = TlsCheckerScanner()
    res = scanner.run(host, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    print(f"\n{formatter.BOLD}[*] TLS Assessment Summary:{formatter.RESET}")
    formatter.info(f"Protocol: {res.metadata.get('protocol')}")
    cipher_info = res.metadata.get('cipher')
    if cipher_info:
        formatter.info(f"Cipher: {cipher_info[0]} ({cipher_info[2]} bits)")

    for f in res.findings:
        if f.severity in [Severity.CRITICAL, Severity.HIGH]:
            formatter.error(f"[{f.severity.value.upper()}] {f.title}")
        elif f.severity == Severity.MEDIUM:
            formatter.info(f"[{f.severity.value.upper()}] {f.title}")
        else:
            formatter.success(f.title)
