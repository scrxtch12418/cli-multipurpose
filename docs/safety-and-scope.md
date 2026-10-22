# Safety, Authorization & Scope Enforcement

CLI Multipurpose enforces strict safety rules to guarantee that security assessments are authorized, bounded, and low-impact by default.

## 1. Principles of Authorized Assessment

- **Authorized Target Testing Only:** Never test systems without explicit, documented permission from the asset owner.
- **Scope Verification Before Network Requests:** Every scanner checks `scope.is_target_in_scope()` before initiating network traffic or executing external tools.
- **Safe Defaults:** Profiles default to `passive` or `standard`. Intrusive modules (`web_dir_scan`, `sql_detector`) are classified as `is_active = True` and require `scope.active_checks = True`.

## 2. Scope Configuration Schema

An example scope file (`scope.json`):

```json
{
  "name": "staging-environment",
  "targets": [
    "staging.example.com",
    "127.0.0.1",
    "10.0.0.0/24"
  ],
  "excluded_targets": [
    "prod.example.com",
    "10.0.0.1"
  ],
  "allowed_ports": [80, 443, 8080],
  "allowed_schemes": ["http", "https"],
  "active_checks": false,
  "max_requests_per_target": 100,
  "max_concurrency": 4,
  "timeout_seconds": 10,
  "follow_redirects": false,
  "allow_private_ips": false
}
```

### Key Policy Controls

- **DNS Label Boundary Matching:** A target `notexample.com` will **never** match an authorized rule `example.com`. Only exact domain matches or valid subdomains (`sub.example.com`) are admitted.
- **SSRF & DNS Rebinding Protection:** The validator resolves hostnames and checks if the resulting IP addresses belong to private/internal networks (e.g. `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.169.254`). If `allow_private_ips` is False, scanning is blocked.
- **Request Budgets:** Scanners enforce request counts and apply backoff upon receiving HTTP `429 Too Many Requests`.
- **Credential Redaction:** Discovered secrets, authorization tokens, passwords, and sensitive cookies are automatically redacted before rendering or storing.
