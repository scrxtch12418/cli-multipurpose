"""
Local Secret & Credential Leak Scanner.
Scans source code repositories and configuration files for accidentally committed
API keys, tokens, private keys, database credentials, and secrets with full redaction.
Implements SecretScanner(BaseScanner) and interactive run().
"""

import os
import re
from typing import Optional, Dict, Any, List

from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence, redact_sensitive_text
from core.scope import ScopePolicy
from utils import formatter


# Secret detection rules: (Rule ID, Title, Severity, RegexPattern)
SECRET_RULES = [
    ("secret.aws_access_key", "AWS Access Key ID Leaked", Severity.HIGH,
     re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("secret.private_key", "Private Cryptographic Key Disclosed", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("secret.github_token", "GitHub Personal Access Token Leaked", Severity.CRITICAL,
     re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b")),
    ("secret.google_api_key", "Google Cloud / Firebase API Key Leaked", Severity.HIGH,
     re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("secret.slack_token", "Slack Bot / User Token Leaked", Severity.HIGH,
     re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,48})\b")),
    ("secret.db_connection_uri", "Database Connection String With Embedded Password", Severity.HIGH,
     re.compile(r"\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s]+:([^@\s]+)@[^\s\/]+")),
    ("secret.generic_api_key", "Generic Hardcoded Secret or API Key", Severity.MEDIUM,
     re.compile(r"(?i)\b(?:api_key|secret_key|private_token|auth_token|access_key)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,64})['\"]")),
]

# File extensions or directories to skip
IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".idea", ".vscode"}
IGNORE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll", ".so", ".pyc", ".db"}


def mask_secret(secret_str: str) -> str:
    """Masks secret keeping only the first 3 characters and replacing the rest with '*'."""
    if len(secret_str) <= 6:
        return "[REDACTED]"
    return secret_str[:3] + "*" * (len(secret_str) - 3)


class SecretScanner(BaseScanner):
    scanner_id = "secret_scanner"
    name = "Local Secret & Credential Leak Scanner"
    description = "Scans local repository files for hardcoded passwords, tokens, API keys, and private keys."
    category = "local"
    is_active = False

    def run(self, target: str, scope: ScopePolicy, config: Optional[Dict[str, Any]] = None) -> ScanResult:
        result = ScanResult(
            scanner_id=self.scanner_id,
            scanner_version=self.version,
            target=target
        )

        scan_path = os.path.abspath(target)
        if not os.path.exists(scan_path):
            result.add_error(f"Path does not exist: {scan_path}")
            result.finish(ScanStatus.FAILED)
            return result

        files_scanned = 0
        total_findings = 0

        # Gather target files
        target_files = []
        if os.path.isfile(scan_path):
            target_files.append(scan_path)
        else:
            for root, dirs, files in os.walk(scan_path):
                # Filter out ignored directories in-place
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext not in IGNORE_EXTS:
                        target_files.append(os.path.join(root, file))

        for fpath in target_files:
            # Skip files larger than 2MB
            try:
                if os.path.getsize(fpath) > 2 * 1024 * 1024:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            files_scanned += 1
            rel_path = os.path.relpath(fpath, scan_path) if os.path.isdir(scan_path) else os.path.basename(fpath)

            for line_no, line in enumerate(content.splitlines(), start=1):
                # Ignore lines marked as test or example
                if "test" in line.lower() and ("dummy" in line.lower() or "example" in line.lower() or "fake" in line.lower()):
                    continue

                for rule_id, title, sev, pattern in SECRET_RULES:
                    match = pattern.search(line)
                    if match:
                        total_findings += 1
                        matched_str = match.group(0)
                        masked_evidence = mask_secret(matched_str)

                        result.add_finding(Finding(
                            check_id=rule_id,
                            title=f"{title} in {rel_path}:{line_no}",
                            description=f"Hardcoded sensitive secret matching rule '{rule_id}' discovered in source file.",
                            severity=sev,
                            confidence=Confidence.HIGH,
                            affected_asset=f"{rel_path}:{line_no}",
                            remediation="Remove secret immediately, revoke and rotate the credential, and store in environment variables or a secret manager.",
                            evidence=[Evidence(
                                source="secret_scanner",
                                description=f"Pattern match at line {line_no}",
                                sanitized_value=masked_evidence,
                                location=f"{rel_path}:{line_no}"
                            )],
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"]
                        ))

        result.metadata["files_scanned"] = files_scanned
        result.metadata["secrets_found"] = total_findings
        result.finish(ScanStatus.SUCCESS)
        return result


def run():
    """Interactive CLI entrypoint."""
    target = input("Enter path to file or directory to scan for secrets [default: .]: ").strip()
    if not target:
        target = "."

    formatter.info(f"Scanning for hardcoded secrets in: {os.path.abspath(target)}")
    scope = ScopePolicy.create_local_lab_scope()
    scanner = SecretScanner()
    res = scanner.run(target, scope)

    if res.errors:
        for err in res.errors:
            formatter.error(err)
        return

    print(f"\n{formatter.BOLD}[*] Secret Scanner Summary: Scanned {res.metadata.get('files_scanned')} files.{formatter.RESET}")
    if res.findings:
        for f in res.findings:
            if f.severity == Severity.CRITICAL:
                formatter.error(f"[CRITICAL] {f.title}")
            elif f.severity == Severity.HIGH:
                formatter.error(f"[HIGH] {f.title}")
            else:
                formatter.info(f"[{f.severity.value.upper()}] {f.title}")
            for ev in f.evidence:
                print(f"    Location: {ev.location} | Masked Secret: {ev.sanitized_value}")
    else:
        formatter.success("No hardcoded secrets or exposed credentials detected.")
