"""
Report Generator for CLI Multipurpose Security Tool.
Exports AggregatedScanReport to Canonical JSON.
"""

import os
from core.models import AggregatedScanReport


def generate_json_report(report: AggregatedScanReport, output_path: str) -> str:
    """Exports report as canonical JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report.to_json(indent=2))
    return output_path
