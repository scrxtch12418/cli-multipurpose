# Adding a New Security Scanner

Adding a security assessment module to CLI Multipurpose requires subclassing `BaseScanner` and registering it in `core/registry.py`.

## Step 1: Create the Scanner Module

Create `modules/my_scanner.py`:

```python
from typing import Optional, Dict, Any
from core.base_scanner import BaseScanner
from core.models import ScanResult, ScanStatus, Finding, Evidence, Severity, Confidence
from core.scope import ScopePolicy
from utils import validation, formatter

class MyScanner(BaseScanner):
    scanner_id = "my_scanner"
    name = "My Custom Scanner"
    description = "Checks target for specific vulnerabilities."
    category = "web"
    is_active = False  # Set to True if this scanner sends invasive probes

    def run(self, target: str, scope: ScopePolicy, config: Optional[Dict[str, Any]] = None) -> ScanResult:
        result = ScanResult(
            scanner_id=self.scanner_id,
            scanner_version=self.version,
            target=target
        )

        # 1. Verify Scope
        in_scope, reason = scope.is_target_in_scope(target)
        if not in_scope:
            result.add_error(f"Target out of scope: {reason}")
            result.finish(ScanStatus.SKIPPED)
            return result

        # 2. Check Active Gate
        can_run, reason = self.can_run(scope)
        if not can_run:
            result.add_error(reason)
            result.finish(ScanStatus.SKIPPED)
            return result

        # 3. Perform Assessment
        try:
            # Inspection logic...
            result.add_finding(Finding(
                check_id="custom.check_id",
                title="Example Weakness Detected",
                description="Detailed technical description.",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                affected_asset=target,
                remediation="Recommended security remediation.",
                evidence=[Evidence(
                    source=self.scanner_id,
                    description="Observed behavior",
                    sanitized_value="Evidence data"
                )]
            ))
            result.finish(ScanStatus.SUCCESS)
        except Exception as e:
            result.add_error(f"Scan failed: {e}")
            result.finish(ScanStatus.FAILED)

        return result

def run():
    """Interactive CLI runner for menu selection."""
    target = input("Enter target: ").strip()
    scope = ScopePolicy.create_single_target_scope(target)
    scanner = MyScanner()
    res = scanner.run(target, scope)
    for f in res.findings:
        formatter.success(f.title)
```

## Step 2: Register in `core/registry.py`

Import `MyScanner` and add it to `_register_default_scanners()` and the desired profiles (`passive`, `standard`, or `active`).

## Step 3: Write Unit Tests

Add a unit test in `tests/unit/test_my_scanner.py` using mocks or controlled fixtures.
