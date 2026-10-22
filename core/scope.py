"""
Target Scope Enforcement & Safety Policy for CLI Multipurpose.
Ensures that all scanning actions are strictly authorized, validated against
allowed hostnames/domains/IPs/CIDRs, rate-limited, and gated against unauthorized
active checks or SSRF/DNS-rebinding attacks.
"""

from dataclasses import dataclass, field
import ipaddress
import json
import os
import socket
from typing import List, Optional, Tuple, Dict, Any
from urllib.parse import urlparse

from utils.validation import (
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_domain,
    matches_domain_boundary,
    parse_target,
    validate_port,
)


@dataclass
class ScopePolicy:
    """Defines operator-authorized boundary and execution rules for security assessments."""
    name: str = "default-scope"
    targets: List[str] = field(default_factory=list)
    excluded_targets: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=lambda: [80, 443, 8000, 8080, 8443])
    allowed_schemes: List[str] = field(default_factory=lambda: ["http", "https"])
    active_checks: bool = False
    max_requests_per_target: int = 100
    max_concurrency: int = 4
    timeout_seconds: int = 10
    follow_redirects: bool = False
    allow_private_ips: bool = False

    def is_target_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        Validates whether a candidate target (URL, IP, hostname) falls strictly inside
        the authorized scope and is not excluded.
        Returns (is_allowed, reason_or_error).
        """
        if not target or not target.strip():
            return False, "Target is empty."

        # Support local filesystem paths for local audit profile
        if os.path.exists(target):
            abs_target = os.path.abspath(target)
            if self.allow_private_ips or any(r in [target, abs_target, ".", "local"] for r in self.targets):
                return True, f"Local path '{target}' is authorized."

        info = parse_target(target)
        if not info:
            return False, f"Target '{target}' could not be parsed into a valid hostname, IP, or local path."

        # Check scheme if URL specified
        if info.scheme and info.scheme.lower() not in [s.lower() for s in self.allowed_schemes]:
            return False, f"Scheme '{info.scheme}' is not permitted by scope policy (allowed: {self.allowed_schemes})."

        # Check port if specified
        if info.port and self.allowed_ports:
            if info.port not in self.allowed_ports:
                return False, f"Port '{info.port}' is not permitted by scope policy (allowed: {self.allowed_ports})."

        host = info.host.lower().strip()

        # Check exclusions first
        for exc in self.excluded_targets:
            exc_clean = exc.lower().strip()
            if self._host_matches_rule(host, exc_clean):
                return False, f"Target '{host}' matches exclusion rule: '{exc}'."

        # Check target allowlist
        if not self.targets:
            return False, "Scope policy contains no allowed targets."

        matched = False
        matching_rule = ""
        for rule in self.targets:
            rule_clean = rule.lower().strip()
            if self._host_matches_rule(host, rule_clean):
                matched = True
                matching_rule = rule
                break

        if not matched:
            return False, f"Target '{host}' is outside defined authorized scope."

        # Check private IP policy
        if info.is_ip and not self.allow_private_ips:
            try:
                ip_obj = ipaddress.ip_address(host)
                if ip_obj.is_private or ip_obj.is_loopback:
                    if not any(self._host_matches_rule(host, r) for r in ["127.0.0.1", "localhost", "::1"]):
                        return False, f"Target IP '{host}' is a private/internal network address and allow_private_ips is False."
            except ValueError:
                pass

        return True, f"Target '{host}' is authorized by rule '{matching_rule}'."

    def _host_matches_rule(self, host: str, rule: str) -> bool:
        """Evaluates match against IP, CIDR, domain wildcard, or domain boundary."""
        # 1. Exact match
        if host == rule:
            return True

        # 2. CIDR network match
        if "/" in rule:
            try:
                net = ipaddress.ip_network(rule, strict=False)
                if is_valid_ipv4(host) or is_valid_ipv6(host):
                    ip_obj = ipaddress.ip_address(host)
                    return ip_obj in net
            except ValueError:
                pass

        # 3. Wildcard domain match (e.g. *.example.com)
        if rule.startswith("*."):
            parent = rule[2:]
            return matches_domain_boundary(host, parent)

        # 4. Standard domain suffix boundary match
        if is_valid_domain(rule) and is_valid_domain(host):
            return matches_domain_boundary(host, rule)

        return False

    def is_redirect_in_scope(self, original_url: str, redirect_url: str) -> Tuple[bool, str]:
        """
        Validates whether following an HTTP redirect is permitted under policy.
        """
        if not self.follow_redirects:
            return False, "Redirect following is disabled by scope policy."

        return self.is_target_in_scope(redirect_url)

    def validate_resolved_ip(self, hostname: str) -> Tuple[bool, str]:
        """
        Resolves hostname and verifies that resolved IP addresses do not resolve to
        disallowed internal/private ranges (preventing SSRF and DNS rebinding).
        """
        if is_valid_ipv4(hostname) or is_valid_ipv6(hostname):
            # Already an IP literal
            return True, "Target is an explicit IP literal."

        try:
            addr_info = socket.getaddrinfo(hostname, None)
            resolved_ips = set(item[4][0] for item in addr_info)
        except (socket.gaierror, socket.herror) as e:
            return False, f"DNS resolution failed for '{hostname}': {e}"

        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if (ip_obj.is_private or ip_obj.is_loopback) and not self.allow_private_ips:
                    # Allow only if target was explicitly localhost or local rule
                    if hostname not in ["localhost", "127.0.0.1", "::1"]:
                        return False, f"Hostname '{hostname}' resolves to private/internal IP {ip_str} which is prohibited."
            except ValueError:
                pass

        return True, f"Resolved {len(resolved_ips)} IP(s) successfully in-scope."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "targets": self.targets,
            "excluded_targets": self.excluded_targets,
            "allowed_ports": self.allowed_ports,
            "allowed_schemes": self.allowed_schemes,
            "active_checks": self.active_checks,
            "max_requests_per_target": self.max_requests_per_target,
            "max_concurrency": self.max_concurrency,
            "timeout_seconds": self.timeout_seconds,
            "follow_redirects": self.follow_redirects,
            "allow_private_ips": self.allow_private_ips,
        }

    def save_to_file(self, filepath: str):
        """Saves scope policy to JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScopePolicy":
        """Instantiates ScopePolicy with schema validation."""
        return cls(
            name=str(data.get("name", "custom-scope")),
            targets=list(data.get("targets", [])),
            excluded_targets=list(data.get("excluded_targets", [])),
            allowed_ports=[int(p) for p in data.get("allowed_ports", [80, 443]) if validate_port(p)],
            allowed_schemes=list(data.get("allowed_schemes", ["http", "https"])),
            active_checks=bool(data.get("active_checks", False)),
            max_requests_per_target=int(data.get("max_requests_per_target", 100)),
            max_concurrency=int(data.get("max_concurrency", 4)),
            timeout_seconds=int(data.get("timeout_seconds", 10)),
            follow_redirects=bool(data.get("follow_redirects", False)),
            allow_private_ips=bool(data.get("allow_private_ips", False)),
        )

    @classmethod
    def from_file(cls, filepath: str) -> "ScopePolicy":
        """Loads and parses scope configuration file."""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Scope configuration file not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def create_local_lab_scope(cls, active_checks: bool = False) -> "ScopePolicy":
        """Creates safe default policy for localhost testing."""
        return cls(
            name="local-lab-scope",
            targets=["127.0.0.1", "localhost", "::1"],
            allowed_ports=[80, 443, 3000, 5000, 8000, 8080, 8443, 9000],
            allowed_schemes=["http", "https"],
            active_checks=active_checks,
            max_requests_per_target=50,
            max_concurrency=2,
            timeout_seconds=5,
            follow_redirects=False,
            allow_private_ips=True,
        )

    @classmethod
    def create_single_target_scope(cls, target: str, active_checks: bool = False) -> "ScopePolicy":
        """Creates an on-the-fly scope for an explicitly operator-supplied target."""
        if os.path.exists(target):
            return cls(
                name=f"local-target-{os.path.basename(os.path.abspath(target)) or 'root'}",
                targets=[target, os.path.abspath(target), "."],
                allow_private_ips=True,
                active_checks=active_checks,
            )

        info = parse_target(target)
        host = info.host if info else target
        return cls(
            name=f"single-target-{host}",
            targets=[host],
            allowed_ports=[80, 443, 8000, 8080, 8443],
            allowed_schemes=["http", "https"],
            active_checks=active_checks,
            max_requests_per_target=100,
            max_concurrency=4,
            timeout_seconds=10,
            follow_redirects=False,
            allow_private_ips=False,
        )
