# Architecture & System Design — CLI Multipurpose

CLI Multipurpose is an extensible, modular security assessment framework built with a **dual-backend hybrid architecture**:

```
                       ┌───────────────────────────────┐
                       │     CLI Entrypoint (main.py)  │
                       │   Interactive Menu / Argparse │
                       └───────────────┬───────────────┘
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │   Scan Orchestrator           │
                       │   (core/orchestrator.py)      │
                       └───────┬───────────────┬───────┘
                               │               │
                     Pre-flight Scope     Module Registry
                     (core/scope.py)      (core/registry.py)
                               │               │
                               ▼               ▼
                 ┌──────────────────────────────────────────────┐
                 │          BaseScanner Modules                 │
                 │                                              │
                 │  • http_headers      • tls_checker           │
                 │  • dns_scanner       • tech_fingerprint      │
                 │  • whois             • cookie_auditor        │
                 │  • subdomain_enum    • cors_auditor          │
                 │  • port_scanner      • redirect_auditor      │
                 │  • sql_detector      • secret_scanner        │
                 │  • web_dir_scan      ...                     │
                 └──────────────────────┬───────────────────────┘
                                        │
                         Execution Backend Routing
                                        │
                 ┌──────────────────────┴───────────────────────┐
                 ▼                                              ▼
    ┌───────────────────────────┐                ┌───────────────────────────┐
    │  Native Python Backend    │                │  External Specialist Tool │
    │  • urllib / socket / ssl  │                │  (utils/runner.ToolResult)│
    │  • DNS over HTTPS (DoH)   │                │  • nmap, curl, whois      │
    │  • RDAP (RFC 7480)        │                │  • subfinder, dirsearch   │
    └────────────┬──────────────┘                └──────────────┬────────────┘
                 │                                              │
                 └──────────────────────┬───────────────────────┘
                                        │
                                        ▼
                 ┌──────────────────────────────────────────────┐
                 │       Normalized Output & Findings           │
                 │       (core/models.AggregatedReport)         │
                 └──────────────┬───────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
       ┌────────────────────────┐  ┌────────────────────────┐
       │   Multi-Format Reports │  │  SQLite Scan History   │
       │   • JSON (canonical)   │  │  (core/history.py)     │
       │   • Markdown / HTML    │  │  • Delta scan diffing  │
       └────────────────────────┘  └────────────────────────┘
```

## Core Components

1. **`core/models.py`**:
   - Typed data models: `Severity`, `Confidence`, `ScanStatus`, `Evidence`, `Finding`, `ScanResult`, `AggregatedScanReport`.
   - Stable SHA-256 fingerprinting for findings deduplication across repeated assessments.
   - Built-in sensitive data redaction (tokens, credentials, cookies, passwords).

2. **`core/scope.py`**:
   - Operator authorization contract.
   - Target boundary matching (RFC label boundary domain checks, CIDR matching, port allowlists).
   - SSRF and DNS-rebinding protection via resolved IP validation.
   - Gating mechanism preventing active or intrusive checks unless explicitly opt-in.

3. **`core/base_scanner.py` & `core/registry.py`**:
   - Uniform abstract contract for all security assessment modules.
   - Profiles: `passive`, `standard`, `active`, and `local`.

4. **`utils/runner.py`**:
   - Structured subprocess runner returning `ToolResult` with exit code, separate stdout/stderr, timeout handling, and `shell=False` safety.

5. **`reports/report_generator.py`**:
   - Canonical machine-readable JSON reports.

6. **`core/history.py`**:
   - SQLite-backed persistence (`scan_history.db`).
   - Scan delta diffing (introduced, resolved, and persisting findings).
