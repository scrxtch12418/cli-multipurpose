from inspect import cleandoc

from utils import validation, runner, formatter
import urllib.request
import urllib.error
import json

def run():
    target = input("Enter target domain or URL: ").strip()
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    if not validation.is_valid_domain(clean_target):
        formatter.error("Please enter a valid domain name (subdomain enumeration requires domains).")
        return

    if runner.tool_available("subfinder"):
        formatter.info("Using subfinder for subdomain enumeration.")
        output = runner.run_tool(["subfinder", "-d", clean_target])
        if output.strip():
            print(f"\n{formatter.BOLD}[*] Subdomains found by subfinder:{formatter.RESET}")
            print(output)
        else:
            formatter.error("subfinder returned no subdomains.")
    else:
        formatter.info("Using Certificate Transparency logs via crt.sh for subdomain enumeration.")
        url = f"https://crt.sh/?q=%25.{clean_target}&output=json"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                subdomains = set()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for subdomain in name_value.split("\n"):
                        if subdomain.endswith(clean_target):
                            subdomains.add(subdomain.strip())
                if subdomains:
                    print(f"\n{formatter.BOLD}[*] Subdomains found via crt.sh:{formatter.RESET}")
                    for sub in sorted(subdomains):
                        formatter.success(sub)
                else:
                    formatter.error("No subdomains found via crt.sh.")
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            formatter.error(f"Error fetching subdomains from crt.sh: {e}")