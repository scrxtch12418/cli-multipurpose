"""
Scanner Registry & Profile Management for CLI Multipurpose.
Provides centralized registration, lookup, and profiles (passive, standard, active, local).
"""

from typing import Dict, List, Optional
from core.base_scanner import BaseScanner

# Import all module scanners
from modules.http_headers import HttpHeadersScanner
from modules.dns_scanner import DnsScanner
from modules.whois import WhoisScanner
from modules.subdomain_enum import SubdomainScanner
from modules.port_scanner import PortScanner
from modules.sql_detector import SqlDetectorScanner
from modules.web_dir_scan import WebDirScanner
from modules.tls_checker import TlsCheckerScanner
from modules.tech_fingerprint import TechFingerprintScanner
from modules.cookie_auditor import CookieAuditorScanner
from modules.cors_auditor import CorsAuditorScanner
from modules.redirect_auditor import RedirectAuditorScanner
from modules.secret_scanner import SecretScanner


class ScannerRegistry:
    """Registry maintaining all available security scanners and execution profiles."""

    def __init__(self):
        self._scanners: Dict[str, BaseScanner] = {}
        self._profiles: Dict[str, List[str]] = {
            "passive": [
                "http_headers",
                "dns_scanner",
                "whois",
                "subdomain_enum",
                "tls_checker",
                "tech_fingerprint",
                "cookie_auditor",
                "redirect_auditor",
            ],
            "standard": [
                "http_headers",
                "dns_scanner",
                "whois",
                "subdomain_enum",
                "port_scanner",
                "tls_checker",
                "tech_fingerprint",
                "cookie_auditor",
                "cors_auditor",
                "redirect_auditor",
            ],
            "active": [
                "http_headers",
                "dns_scanner",
                "subdomain_enum",
                "port_scanner",
                "tls_checker",
                "tech_fingerprint",
                "cookie_auditor",
                "cors_auditor",
                "redirect_auditor",
                "web_dir_scan",
                "sql_detector",
            ],
            "local": [
                "secret_scanner",
            ]
        }
        self._register_default_scanners()

    def _register_default_scanners(self):
        default_scanners = [
            HttpHeadersScanner(),
            DnsScanner(),
            WhoisScanner(),
            SubdomainScanner(),
            PortScanner(),
            SqlDetectorScanner(),
            WebDirScanner(),
            TlsCheckerScanner(),
            TechFingerprintScanner(),
            CookieAuditorScanner(),
            CorsAuditorScanner(),
            RedirectAuditorScanner(),
            SecretScanner(),
        ]
        for s in default_scanners:
            self.register(s)

    def register(self, scanner: BaseScanner):
        self._scanners[scanner.scanner_id] = scanner

    def get(self, scanner_id: str) -> Optional[BaseScanner]:
        return self._scanners.get(scanner_id)

    def list_all(self) -> List[BaseScanner]:
        return list(self._scanners.values())

    def get_by_profile(self, profile: str) -> List[BaseScanner]:
        profile_key = profile.lower().strip()
        ids = self._profiles.get(profile_key)
        if not ids:
            raise ValueError(f"Unknown scan profile '{profile}'. Available: {list(self._profiles.keys())}")
        scanners = []
        for sid in ids:
            if sid in self._scanners:
                scanners.append(self._scanners[sid])
        return scanners

    @property
    def profiles(self) -> Dict[str, List[str]]:
        return self._profiles


# Global singleton registry instance
registry = ScannerRegistry()
