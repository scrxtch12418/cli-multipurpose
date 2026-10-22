# CLI Multipurpose — Modular Security Assessment & Recon Framework

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Architecture](https://img.shields.io/badge/architecture-hybrid%20dual--backend-green.svg)](docs/architecture.md)
[![Safety](https://img.shields.io/badge/policy-scope%20enforced-orange.svg)](docs/safety-and-scope.md)

An interactive, extensible command-line security assessment and reconnaissance framework. Built on a **hybrid dual-backend architecture**, every security module provides an out-of-the-box pure Python implementation (zero external installations required) while optionally coordinating specialist command-line tools (`nmap`, `curl`, `dig`, `whois`, `subfinder`, `sqlmap`, `dirsearch`) whenever they are available on the host system.

---

## 🎯 Key Features

- **Dual-Mode Operation:**
  - **Interactive Menu Loop:** Simple prompt-driven menu with graceful cancellation (`Ctrl+C`, `0. Exit`).
  - **Scriptable CLI Commands:** `scan`, `list`, `doctor`, `init-scope`, and `history` subcommands for automated pipelines.
- **Scope Enforcement & Safety Gating:**
  - Strict DNS-label boundary verification (`notexample.com` never matches `example.com`).
  - SSRF & DNS-rebinding protection on resolved IP addresses.
  - Active intrusive checks (`sql_detector`, `web_dir_scan`) require explicit opt-in confirmation.
- **Normalized Findings & Risk Schema:**
  - Standardized `Finding` dataclass with stable SHA-256 fingerprints for deduplication.
  - Granular `Severity` (Critical, High, Medium, Low, Info) and `Confidence` (Low, Medium, High, Confirmed).
  - Built-in sensitive data redaction (API keys, tokens, session cookies, passwords).
- **Structured Reporting:**
  - Canonical, machine-readable JSON reports for CI/CD, audit pipelines, and tooling integration.
- **Scan History & Differential Analysis:**
  - Local SQLite history (`scan_history.db`) to track changes and resolve findings across scans.
- **Diagnostics (`doctor`):**
  - Instant runtime checks verifying Python version, standard library, and optional tool availability.

---

## 📊 Module Matrix

| Module ID | Category | Type | Native Python Engine | Specialist Tool Engine (Optional) |
| :--- | :--- | :--- | :--- | :--- |
| **`http_headers`** | Web | Passive | `urllib` HTTP response inspection & cookie flags | `curl -sIL` |
| **`dns_scanner`** | DNS | Passive | Cloudflare DNS-over-HTTPS (DoH) JSON API | `dig ANY` |
| **`whois`** | DNS | Passive | Native RDAP protocol (RFC 7480) query | `whois` CLI |
| **`subdomain_enum`** | DNS | Passive | Certificate Transparency logs (`crt.sh` & HackerTarget) | `subfinder -d` |
| **`port_scanner`** | Network | Passive | `socket` + `ThreadPoolExecutor` TCP scanner | `nmap -Pn -sT` |
| **`tls_checker`** | TLS | Passive | Python `ssl` SNI certificate & protocol auditor | — |
| **`tech_fingerprint`** | Web | Passive | Header, HTML meta tag & script fingerprinting | — |
| **`cookie_auditor`** | Web | Passive | HttpOnly, Secure, SameSite & `__Host-` prefix audit | — |
| **`cors_auditor`** | Web | Passive | Cross-origin policy & credential reflection auditor | — |
| **`redirect_auditor`** | Web | Passive | HTTP-to-HTTPS upgrade & open-redirect parameter check | — |
| **`secret_scanner`** | Local | Passive | Repository & file hardcoded secret leak scanner | — |
| **`web_dir_scan`** | Web | Active | Scoped HTTP directory probe with 429 backoff | `dirsearch` |
| **`sql_detector`** | Web | Active | Benign boundary error-signature detector | `sqlmap --batch` (opt-in) |

---

## 🚀 Getting Started

### Prerequisites

- Python `3.8` or higher (tested on 3.8, 3.9, 3.10, 3.11, 3.12, 3.13)
- Pure standard library — no mandatory third-party pip dependencies required.

### Quick Start

```bash
# 1. Interactive Menu Mode
python main.py

# 2. Check System Health & Dependencies
python main.py doctor

# 3. List All Modules & Profiles
python main.py list

# 4. Run a Passive Scan with Auto-Generated Reports
python main.py scan --target https://example.com --profile passive

# 5. Dry-Run Preview (No Network Requests)
python main.py scan --target https://example.com --profile standard --dry-run

# 6. Active Assessment with Custom Scope File
python main.py init-scope --output scope.json
python main.py scan --target https://staging.example.com --profile active --scope scope.json

# 7. Compare Two Scans for Changes
python main.py history list
python main.py history compare <scan-id-1> <scan-id-2>
```

---

## 🛡️ Scope Policy Schema

CLI Multipurpose requires active target authorization before sending invasive traffic. Generate a template scope configuration with:

```bash
python main.py init-scope --output my_scope.json
```

Example `my_scope.json`:
```json
{
  "name": "local-lab",
  "targets": ["127.0.0.1", "localhost", "test.example"],
  "excluded_targets": ["prod.example"],
  "allowed_ports": [80, 443, 8000, 8080],
  "allowed_schemes": ["http", "https"],
  "active_checks": false,
  "max_requests_per_target": 100,
  "max_concurrency": 4,
  "timeout_seconds": 10,
  "follow_redirects": false,
  "allow_private_ips": true
}
```

---

## 🧪 Running Tests

The test suite covers runner execution, target validation, DNS suffix boundaries, scope enforcement, model serialization, evidence redaction, and scanner modules:

```bash
python -m unittest discover tests
```

---

## 📖 Documentation

- [Architecture & Design](docs/architecture.md)
- [Safety & Scope Enforcement](docs/safety-and-scope.md)
- [Adding a New Scanner](docs/adding-a-scanner.md)

---

## ⚖️ Legal Disclaimer

This tool is strictly intended for authorized security audits, internal compliance, educational research, and defensive assessment. Testing target systems without prior explicit authorization from the asset owner is illegal and unethical.
