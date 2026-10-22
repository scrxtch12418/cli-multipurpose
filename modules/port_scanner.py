"""
TCP Port Scanner & Service Discovery.
Performs scoped TCP port scanning via nmap or native socket concurrency.
Implements PortScanner(BaseScanner) and interactive run().
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, Any, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, runner, formatter


DEFAULT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy/Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Probes a single TCP port using a stream socket."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


class PortScanner(BaseScanner):
    scanner_id = "port_scanner"
    name = "TCP Port Scanner"
    description = "Scans common network ports to inventory accessible services via nmap or native sockets."
    category = "network"
    is_active = False  # Standard network scan is low-impact

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
        host = info.host if info else target

        # Determine which ports to scan (respect scope.allowed_ports if set)
        ports_to_scan = list(DEFAULT_PORTS.keys())
        if scope.allowed_ports:
            ports_to_scan = [p for p in ports_to_scan if p in scope.allowed_ports]

        open_ports: List[int] = []

        # Try nmap first if installed
        if runner.tool_available("nmap"):
            ports_arg = ",".join(map(str, ports_to_scan))
            nmap_res = runner.run_tool_result(
                ["nmap", "-Pn", "-sT", "-p", ports_arg, "--open", host],
                timeout=scope.timeout_seconds * 2
            )
            if nmap_res.succeeded and nmap_res.stdout:
                for line in nmap_res.stdout.splitlines():
                    if "/tcp" in line and "open" in line:
                        try:
                            port_num = int(line.split("/")[0].strip())
                            open_ports.append(port_num)
                        except ValueError:
                            pass
            elif not nmap_res.succeeded:
                result.add_warning(f"nmap invocation failed: {nmap_res.error}. Falling back to native socket.")

        # Fallback to native sockets if nmap not used or had errors
        if not open_ports:
            max_workers = min(scope.max_concurrency * 2, 20)
            timeout = min(scope.timeout_seconds / 5.0, 1.5)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_port = {
                    executor.submit(check_port, host, port, timeout): port
                    for port in ports_to_scan
                }
                for future in as_completed(future_to_port):
                    p = future_to_port[future]
                    try:
                        if future.result():
                            open_ports.append(p)
                    except Exception:
                        pass

        open_ports.sort()
        result.metadata["open_ports"] = open_ports
        result.metadata["ports_checked"] = len(ports_to_scan)

        # Flag exposed sensitive services
        sensitive_services = {
            21: ("FTP Exposed (Cleartext Auth)", Severity.MEDIUM, "Disable FTP or migrate to SFTP/FTPS."),
            23: ("Telnet Service Open (Cleartext)", Severity.HIGH, "Disable Telnet immediately and use SSH."),
            445: ("SMB Port Exposed to Network", Severity.MEDIUM, "Restrict SMB access to internal management VLANs only."),
            3389: ("RDP Port Exposed", Severity.MEDIUM, "Do not expose RDP directly; require VPN or zero-trust proxy."),
            6379: ("Redis Port Open", Severity.MEDIUM, "Ensure Redis is bound to localhost and requires strong authentication."),
            27017: ("MongoDB Port Open", Severity.MEDIUM, "Restrict MongoDB port to application servers only."),
            9200: ("Elasticsearch Exposed", Severity.MEDIUM, "Ensure Elasticsearch is not exposed without authentication.")
        }

        for port in open_ports:
            svc_name = DEFAULT_PORTS.get(port, "Unknown Service")
            if port in sensitive_services:
                title, sev, rem = sensitive_services[port]
                result.add_finding(Finding(
                    check_id=f"port.{port}_open",
                    title=f"Port {port}/TCP ({svc_name}) Open - {title}",
                    description=f"Port {port} ({svc_name}) is accessible over the network on {host}.",
                    severity=sev,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{host}:{port}",
                    remediation=rem,
                    evidence=[Evidence(
                        source="port_scanner",
                        description=f"TCP connection established on port {port}",
                        sanitized_value=f"Port {port} OPEN"
                    )]
                ))
            else:
                result.add_finding(Finding(
                    check_id=f"port.{port}_open",
                    title=f"Port {port}/TCP ({svc_name}) Open",
                    description=f"Port {port} ({svc_name}) responded to connection requests on {host}.",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    affected_asset=f"{host}:{port}",
                    remediation="Ensure this service is intended to be accessible from this network.",
                    evidence=[Evidence(
                        source="port_scanner",
                        description=f"TCP connection established on port {port}",
                        sanitized_value=f"Port {port} OPEN"
                    )]
                ))

        result.finish(ScanStatus.SUCCESS)
        return result


def run():
    """Interactive CLI entrypoint."""
    target = input("Enter target domain or IP address: ").strip()
    if not validation.is_valid_target(target):
        formatter.error("Invalid target! Please enter a valid domain or IP address.")
        return

    info = validation.parse_target(target)
    host = info.host if info else target

    formatter.info(f"Scanning common ports on: {host}")
    scope = ScopePolicy.create_single_target_scope(host)
    scanner = PortScanner()
    res = scanner.run(host, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    open_ports = res.metadata.get("open_ports", [])
    if open_ports:
        print(f"\n{formatter.BOLD}[*] Open Ports Discovered:{formatter.RESET}")
        for p in open_ports:
            svc = DEFAULT_PORTS.get(p, "Unknown")
            formatter.success(f"Port {p}/TCP: {svc}")
    else:
        formatter.info("No common open ports discovered.")