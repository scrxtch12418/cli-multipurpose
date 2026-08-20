# cli-multipurpose — Security & Recon CLI Assistant

An interactive menu-driven command-line helper for security reconnaissance and ethical-hacking tasks. Designed with a **dual-backend hybrid architecture**, every security module provides a native Python fallback (zero external downloads required) while automatically executing real CLI utilities (`nmap`, `gobuster`, `sqlmap`, `curl`, `whois`, `dig`, `subfinder`) whenever they are available on the host system (e.g. Kali Linux or WSL).

---

## 🎯 Key Features

- **Interactive Menu Loop**: Simple prompt-driven menu — no need to memorize complex CLI flags.
- **Dual-Backend Fallback System**:
  - **Native Backend**: Pure Python execution utilizing `urllib`, `socket`, `concurrent.futures`, DoH (DNS over HTTPS), and RDAP. Works out-of-the-box on any standard system.
  - **Tool Backend**: Automatically invokes installed CLI tools (`nmap -sV`, `gobuster dir`, `sqlmap --batch`, `subfinder -d`, etc.) when available.
- **Input Validation & Security**: Target validation for IPs and domains with parameter list separation (avoids `shell=True` subprocess injection vulnerabilities).
- **Result Tagging**: Visual output tagging (`[native]` vs `[nmap]`) to indicate which engine generated the scan results.

---

## 📊 Module Matrix

| Module | Native Engine | Tool Engine (when available) |
|---|---|---|
| **`http_headers`** | `urllib` HTTP response header inspection | `curl -sIL` |
| **`dns_scanner`** | Cloudflare DNS-over-HTTPS (DoH) API | `dig` / `nslookup` |
| **`whois`** | RDAP protocol (RFC 7480) query | `whois` |
| **`subdomain_enum`** | `crt.sh` SSL certificate transparency logs | `subfinder -d` |
| **`port_scanner`** | `socket` + `concurrent.futures` multi-threaded TCP scanner | `nmap -sV` |
| **`web_dir_scan`** | HTTP requests wordlist brute-force scanner | `gobuster dir` |
| **`sql_detector`** | Basic error-based SQL payload detector | `sqlmap --batch` |

---

## 📁 File Layout

```
cli-multipurpose/
├── main.py                  # Interactive menu loop & module dispatcher
├── _make_plan_pdf.py        # PDF architecture plan generator
├── cli-multipurpose-plan.pdf # Complete architectural design document
├── modules/                 # Recon & security module implementations
│   ├── __init__.py          # Module registry dictionary
│   ├── http_headers.py      # HTTP headers analyzer
│   ├── dns_scanner.py       # DNS lookup module
│   ├── whois.py             # WHOIS / RDAP domain registration info
│   ├── subdomain_enum.py    # Subdomain discovery engine
│   ├── port_scanner.py      # TCP port scanner
│   ├── web_dir_scan.py      # Directory & file brute-forcer
│   └── sql_detector.py      # Basic SQL injection vulnerability checker
└── utils/                   # Shared utility framework
    ├── __init__.py
    ├── runner.py            # Subprocess wrapper & tool detection
    ├── validation.py        # IP/domain/port input validation
    └── formatter.py         # ANSI colors & terminal output table formatting
```

---

## 🚀 Getting Started

### Prerequisites

- Python `3.8` or higher
- Optional: `nmap`, `gobuster`, `sqlmap`, `subfinder`, `whois`, `curl` installed on system path for tool-backed execution.

### Installation & Execution

```bash
# Navigate to the project directory
cd cli-multipurpose

# Run the CLI tool
python main.py
```
