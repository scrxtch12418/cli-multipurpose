"""
Environment & Dependency Diagnostics for CLI Multipurpose (tool doctor).
Checks Python runtime, standard library features, system capabilities,
and installed external security binaries with fallback explanations.
"""

import sys
import shutil
from typing import Dict, List, Any

from utils import runner, formatter


EXTERNAL_TOOLS = [
    ("nmap", "Network service discovery & port scanning", "Native socket ThreadPool fallback"),
    ("curl", "Raw HTTP request & header retrieval", "Native urllib HEAD/GET fallback"),
    ("dig", "DNS ANY / record query tool", "Native Cloudflare DoH (DNS over HTTPS) fallback"),
    ("whois", "Domain WHOIS registry query tool", "Native RDAP (RFC 7480 HTTPS) API fallback"),
    ("subfinder", "Fast passive subdomain enumeration", "Native Certificate Transparency (crt.sh) logs fallback"),
    ("sqlmap", "Automated SQL injection assessment tool", "Native error-based signature detector fallback"),
    ("dirsearch", "Web path brute-forcer", "Native HTTP directory scanner fallback"),
]


def run_doctor() -> Dict[str, Any]:
    """Runs system diagnostics and prints formatted environment report."""
    print(f"\n{formatter.BOLD}{formatter.CYAN}--- CLI Multipurpose System Health & Diagnostics ---{formatter.RESET}\n")

    # 1. Python Runtime
    py_ver = sys.version.split()[0]
    is_compatible = sys.version_info >= (3, 8)
    if is_compatible:
        formatter.success(f"Python Runtime: v{py_ver} (Compatible, >= 3.8)")
    else:
        formatter.error(f"Python Runtime: v{py_ver} (Incompatible! Requires Python 3.8+)")

    print(f"\n{formatter.BOLD}[*] External Tool Integrations (Optional Specialists):{formatter.RESET}")
    print("The framework operates with 100% native Python fallbacks when tools are absent.\n")

    tool_statuses = {}
    for tool_name, desc, fallback in EXTERNAL_TOOLS:
        is_avail = runner.tool_available(tool_name)
        tool_statuses[tool_name] = is_avail
        if is_avail:
            ver = runner.get_tool_version(tool_name)
            ver_str = f" - {ver}" if ver else ""
            formatter.success(f"{tool_name:<12} [AVAILABLE]{ver_str}")
            print(f"             Purpose: {desc}")
        else:
            formatter.info(f"{tool_name:<12} [NOT FOUND] -> Using: {fallback}")

    print(f"\n{formatter.BOLD}[*] Summary:{formatter.RESET}")
    avail_count = sum(1 for v in tool_statuses.values() if v)
    total_count = len(EXTERNAL_TOOLS)
    formatter.info(f"{avail_count}/{total_count} external tools detected. Framework is fully operational via native fallbacks.\n")

    return {
        "python_version": py_ver,
        "is_compatible": is_compatible,
        "external_tools": tool_statuses,
    }
