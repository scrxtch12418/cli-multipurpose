"""
Structured Subprocess Runner for CLI Multipurpose Security Tool.
Provides safe, structured execution of external tools with timeout handling,
separate stdout/stderr, return codes, and binary availability detection.
"""

from dataclasses import dataclass
import os
import shutil
import subprocess
from typing import Optional, List


@dataclass
class ToolResult:
    """Structured result from running an external tool."""
    command: List[str]
    returncode: Optional[int]
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        """Returns True only if command returned exit code 0 without errors or timeouts."""
        return (
            self.returncode == 0
            and not self.timed_out
            and self.error is None
        )

    @property
    def output(self) -> str:
        """Combined output, favoring stdout, falling back to stderr or error."""
        if self.stdout.strip():
            return self.stdout
        if self.stderr.strip():
            return self.stderr
        if self.error:
            return f"[error] {self.error}"
        return ""


def tool_available(name: str) -> bool:
    """Returns True if a CLI tool is installed and reachable on the system PATH."""
    return shutil.which(name) is not None


def get_tool_path(name: str) -> Optional[str]:
    """Returns absolute path to tool executable if available."""
    return shutil.which(name)


def get_tool_version(name: str, version_flag: str = "--version", timeout: int = 5) -> Optional[str]:
    """Attempts to retrieve the version string of an installed tool."""
    if not tool_available(name):
        return None
    try:
        res = run_tool_result([name, version_flag], timeout=timeout)
        if res.succeeded and res.output.strip():
            # Return first line of version output
            return res.output.strip().splitlines()[0]
        return "Installed (version query returned non-zero)"
    except Exception:
        return "Installed"


def run_tool_result(args: List[str], timeout: int = 30, cwd: Optional[str] = None) -> ToolResult:
    """
    Run an external CLI tool safely (shell=False, argument list, explicit timeout).
    Never raises uncaught execution exceptions; returns a structured ToolResult.
    """
    if not args or not args[0]:
        return ToolResult(
            command=args,
            returncode=None,
            error="Empty command arguments provided."
        )

    # Check if executable exists
    executable = args[0]
    if not shutil.which(executable) and not os.path.isfile(executable):
        return ToolResult(
            command=args,
            returncode=None,
            error=f"Executable '{executable}' not found on system PATH."
        )

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            cwd=cwd
        )
        return ToolResult(
            command=args,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            timed_out=False,
            error=None if proc.returncode == 0 else f"Process exited with code {proc.returncode}"
        )
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout if isinstance(e.stdout, str) else (e.stdout.decode(errors="replace") if e.stdout else "")
        stderr = e.stderr if isinstance(e.stderr, str) else (e.stderr.decode(errors="replace") if e.stderr else "")
        return ToolResult(
            command=args,
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            error=f"Execution timed out after {timeout} seconds."
        )
    except OSError as e:
        return ToolResult(
            command=args,
            returncode=None,
            error=f"OS execution error: {e}"
        )
    except Exception as e:
        return ToolResult(
            command=args,
            returncode=None,
            error=f"Unexpected execution error: {e}"
        )


def run_tool(args: List[str], timeout: int = 30) -> str:
    """
    Backward-compatibility wrapper returning string output.
    Callers are encouraged to use run_tool_result() instead.
    """
    result = run_tool_result(args, timeout=timeout)
    if result.succeeded:
        return result.stdout or result.stderr
    if result.timed_out:
        return f"[error] Command timed out after {timeout}s: {' '.join(args)}"
    if result.error:
        return f"[error] {result.error}"
    return result.stderr or result.stdout