from utils import validation, runner, formatter
import urllib.request
import urllib.error

def run():
    target = input("Enter the target domain or URL").strip()
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    if not validation.is_valid_target(clean_target):
        formatter.error("Invalid target! Please enter a valid domain or URL.")
        return

    if runner.tool_available("sqlmap"):
        formatter.info("Using SQLMap and scanning for SQL vulns")
        output = runner.run_tool(["sqlmap", "-u", f"http://{clean_target}", "--batch", "--level=5", "--risk=1"])
    else:
        
        