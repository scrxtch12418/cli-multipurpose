from utils import validation, runner, formatter
from modules.wordlists import COMMON_DIRS
import urllib.request
import urllib.error


def check_dir(base_url: str, path: str) -> tuple[str, int | None]:
    url = f"{base_url}/{path}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0")

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return path, response.status
    except urllib.error.HTTPError as e:
        return path, e.code
    except (urllib.error.URLError, TimeoutError, Exception):
        return path, None


def run():
    target = input("Enter target domain or URL: ").strip()
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    if not validation.is_valid_target(clean_target):
        formatter.error("Invalid target! Please enter a valid domain or URL.")
        return

    base_url = f"http://{clean_target}" if not target.startswith(("http://", "https://")) else target

    if runner.tool_available("dirsearch"):
        formatter.info("Using dirsearch for directory scanning.")
        output = runner.run_tool(["dirsearch", "-u", base_url, "-e", "php,html,txt,xml,json", "--plain-text-report=dirsearch_results.txt"])
        if output.strip():
            print(output)
        else:
            formatter.error("dirsearch returned no results.")
    else:
        formatter.info("Using native Python for directory scanning.")
        found_dirs = []

        for path in COMMON_DIRS:
            dir_path, status_code = check_dir(base_url, path)
            if status_code == 200:
                found_dirs.append(dir_path)
                formatter.success(f"Found: {base_url}/{dir_path} (Status: {status_code})")
            elif status_code is not None:
                formatter.info(f"Checked: {base_url}/{dir_path} (Status: {status_code})")

        if found_dirs:
            print("\nSummary of found directories:")
            for dir_path in found_dirs:
                print(f"  {base_url}/{dir_path}")
        else:
            formatter.info("No common directories found.")
