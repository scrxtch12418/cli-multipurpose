"""
Shared data models for CLI Multipurpose Security Assessment Framework.
Includes typed Enums, Finding, Evidence, and ScanResult models with stable
fingerprinting, JSON serialization, and automatic sensitive data redaction.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Optional, List, Dict, Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, val: str) -> "Severity":
        try:
            return cls(val.lower())
        except (ValueError, KeyError):
            return cls.UNKNOWN


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"

    @classmethod
    def from_str(cls, val: str) -> "Confidence":
        try:
            return cls(val.lower())
        except (ValueError, KeyError):
            return cls.LOW


class ScanStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


# Regex patterns for sensitive data redaction
_SECRET_PATTERNS = [
    (re.compile(r"(api[_-]?key|secret[_-]?key|access[_-]?token|bearer\s+[A-Za-z0-9_\-\.]+)[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?", re.IGNORECASE), r"\1: [REDACTED]"),
    (re.compile(r"(password|passwd|pwd)[:=]\s*['\"]?([^'\"\s,;]+)['\"]?", re.IGNORECASE), r"\1: [REDACTED]"),
    (re.compile(r"(sessionid|phpsessid|jsessionid|connect\.sid)[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?", re.IGNORECASE), r"\1: [REDACTED]"),
    (re.compile(r"(authorization:\s*)(bearer|basic|token)\s+([A-Za-z0-9_\-\.\+/=]+)", re.IGNORECASE), r"\1\2 [REDACTED]"),
]


def redact_sensitive_text(text: str) -> str:
    """Sanitizes tokens, credentials, session IDs, and secret values from strings."""
    if not text or not isinstance(text, str):
        return text
    sanitized = text
    for pattern, replacement in _SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


@dataclass
class Evidence:
    """Represents a discrete piece of evidence supporting a finding."""
    source: str
    description: str
    sanitized_value: str
    location: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "description": self.description,
            "sanitized_value": redact_sensitive_text(self.sanitized_value),
            "location": self.location,
            "timestamp": self.timestamp,
        }


@dataclass
class Finding:
    """Standardized security finding."""
    check_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    affected_asset: str
    remediation: str
    evidence: List[Evidence] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """
        Computes a deterministic SHA-256 fingerprint for deduplication across scans.
        Based on check_id, title, affected_asset, and severity.
        """
        raw = f"{self.check_id}|{self.title.lower().strip()}|{self.affected_asset.lower().strip()}|{self.severity.value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "confidence": self.confidence.value if isinstance(self.confidence, Confidence) else str(self.confidence),
            "affected_asset": self.affected_asset,
            "remediation": self.remediation,
            "evidence": [e.to_dict() if isinstance(e, Evidence) else e for e in self.evidence],
            "references": self.references,
        }


@dataclass
class ScanResult:
    """Standardized output container for a single scanner execution."""
    scanner_id: str
    scanner_version: str
    target: str
    status: ScanStatus = ScanStatus.SUCCESS
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None

    def finish(self, status: Optional[ScanStatus] = None):
        """Marks scan completion time and sets final status."""
        self.end_time = datetime.now(timezone.utc).isoformat()
        if status:
            self.status = status
        elif self.errors and not self.findings:
            self.status = ScanStatus.FAILED
        elif self.errors and self.findings:
            self.status = ScanStatus.PARTIAL

    def add_error(self, message: str):
        self.errors.append(redact_sensitive_text(message))

    def add_warning(self, message: str):
        self.warnings.append(redact_sensitive_text(message))

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "target": self.target,
            "status": self.status.value if isinstance(self.status, ScanStatus) else str(self.status),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() if isinstance(f, Finding) else f for f in self.findings],
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


@dataclass
class AggregatedScanReport:
    """Combines multiple scanner results into a unified scan assessment report."""
    scan_id: str
    target: str
    profile: str
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None
    results: List[ScanResult] = field(default_factory=list)
    scope_name: Optional[str] = None
    operator_notes: str = ""

    def finish(self):
        self.end_time = datetime.now(timezone.utc).isoformat()

    @property
    def all_findings(self) -> List[Finding]:
        """Deduplicated list of findings by fingerprint ID."""
        seen = set()
        deduped = []
        for r in self.results:
            for f in r.findings:
                if f.id not in seen:
                    seen.add(f.id)
                    deduped.append(f)
        return deduped

    @property
    def severity_summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "profile": self.profile,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "scope_name": self.scope_name,
            "severity_summary": self.severity_summary,
            "total_findings": len(self.all_findings),
            "modules_executed": len(self.results),
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
