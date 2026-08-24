import shutil
import subprocess

def tool_available(name: str) -> bool:
    """Returns True if a CLI tool is on PATH."""
    return shutil.which(name) is not None

def run_tool(args: list[str], timeout: int = 30) -> str:
    """Run a CLI tool safely (no shell=True). Returns stdout string."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout or result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"[error] {e}"