"""
Input and Target Validation for CLI Multipurpose Security Tool.
Provides robust URL, hostname, IP, and port parsing using standard libraries
and strict DNS-label boundary checks.
"""

from dataclasses import dataclass
import ipaddress
import re
from typing import Optional, List, Tuple
import urllib.parse


# RFC 1035 / RFC 1123 compliant domain label regex:
# Labels 1-63 alphanumeric chars or hyphens, not starting or ending with hyphen.
_DOMAIN_LABEL_REGEX = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass
class TargetInfo:
    """Structured information parsed from a target string or URL."""
    raw: str
    scheme: Optional[str]
    host: str
    port: Optional[int]
    path: str
    is_ip: bool
    is_ipv6: bool

    @property
    def normalized_url(self) -> str:
        """Reconstruct normalized URL with appropriate scheme and host."""
        scheme = self.scheme or "http"
        port_str = f":{self.port}" if self.port and (
            (scheme == "http" and self.port != 80) or
            (scheme == "https" and self.port != 443)
        ) else ""
        host_repr = f"[{self.host}]" if self.is_ipv6 else self.host
        path = self.path if self.path.startswith("/") else f"/{self.path}"
        return f"{scheme}://{host_repr}{port_str}{path}"


def is_valid_ipv4(ip: str) -> bool:
    """Checks if string is a valid IPv4 address."""
    if not ip or not isinstance(ip, str):
        return False
    try:
        ipaddress.IPv4Address(ip.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Checks if string is a valid IPv6 address."""
    if not ip or not isinstance(ip, str):
        return False
    # Strip brackets if passed as [::1]
    clean_ip = ip.strip().strip("[]")
    try:
        ipaddress.IPv6Address(clean_ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ip(ip: str) -> bool:
    """Checks if string is valid IPv4 or IPv6."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_valid_domain(domain: str) -> bool:
    """
    Validates domain/hostname using standard DNS label rules.
    Disallows trailing dots in raw input, handles lengths up to 253 chars,
    and enforces RFC label boundaries.
    """
    if not domain or not isinstance(domain, str):
        return False
    
    clean = domain.strip().lower()
    if clean.endswith("."):
        clean = clean[:-1]

    if len(clean) > 253 or len(clean) < 1:
        return False

    labels = clean.split(".")
    # A single label like 'localhost' is acceptable as a hostname
    if len(labels) == 1:
        return bool(_DOMAIN_LABEL_REGEX.match(labels[0]))

    for label in labels:
        if not label or len(label) > 63:
            return False
        if not _DOMAIN_LABEL_REGEX.match(label):
            return False

    # TLD should be alphabetic or punycode
    tld = labels[-1]
    if tld.isdigit():
        return False

    return True


def matches_domain_boundary(candidate: str, parent_domain: str) -> bool:
    """
    Tests whether candidate hostname is within parent_domain on DNS label boundaries.
    Example:
      'sub.example.com' matches 'example.com' -> True
      'example.com' matches 'example.com' -> True
      'notexample.com' matches 'example.com' -> False
      'my-example.com' matches 'example.com' -> False
    """
    if not candidate or not parent_domain:
        return False
    
    cand = candidate.strip().lower().rstrip(".")
    parent = parent_domain.strip().lower().rstrip(".")

    if cand == parent:
        return True

    return cand.endswith("." + parent)


def validate_port(port: any) -> bool:
    """Validates that a port number is an integer between 1 and 65535."""
    try:
        val = int(port)
        return 1 <= val <= 65535
    except (ValueError, TypeError):
        return False


def parse_port_range(port_spec: str) -> List[int]:
    """
    Parses comma-separated port numbers and dash-separated ranges.
    Example: '80,443,8000-8002' -> [80, 443, 8000, 8001, 8002]
    """
    ports = set()
    parts = [p.strip() for p in port_spec.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            sub = part.split("-", 1)
            if len(sub) == 2 and validate_port(sub[0]) and validate_port(sub[1]):
                start, end = int(sub[0]), int(sub[1])
                if start <= end and (end - start) <= 10000:
                    for p in range(start, end + 1):
                        ports.add(p)
        elif validate_port(part):
            ports.add(int(part))
    return sorted(list(ports))


def parse_target(target: str, default_scheme: str = "http") -> Optional[TargetInfo]:
    """
    Parses a target string (which may be a domain, IP, or full URL) into TargetInfo.
    Handles schemes, IPv6 bracketed literals, custom ports, and URL paths.
    """
    if not target or not isinstance(target, str):
        return None

    raw = target.strip()
    
    # Check if a scheme is present
    has_scheme = "://" in raw
    if has_scheme:
        parse_str = raw
    else:
        parse_str = f"{default_scheme}://{raw}"

    try:
        parsed = urllib.parse.urlparse(parse_str)
    except Exception:
        return None

    scheme = parsed.scheme if has_scheme else None
    hostname = parsed.hostname
    port = parsed.port

    if not hostname:
        return None

    # Determine if host is IP
    is_v4 = is_valid_ipv4(hostname)
    is_v6 = is_valid_ipv6(hostname)
    is_ip_addr = is_v4 or is_v6

    # Validate host syntax if not IP
    if not is_ip_addr and not is_valid_domain(hostname):
        return None

    path = parsed.path or "/"

    return TargetInfo(
        raw=raw,
        scheme=scheme,
        host=hostname,
        port=port,
        path=path,
        is_ip=is_ip_addr,
        is_ipv6=is_v6
    )


def is_valid_target(target: str) -> bool:
    """
    Checks if target is syntactically a valid IPv4, IPv6, domain, or URL.
    Does NOT assert authorization; syntactic check only.
    """
    if not target or not isinstance(target, str):
        return False

    clean = target.strip()
    if is_valid_ipv4(clean) or is_valid_ipv6(clean) or is_valid_domain(clean):
        return True

    info = parse_target(clean)
    return info is not None
