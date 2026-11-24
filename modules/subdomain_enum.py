from utils import validation, runner, formatter
import urllib.request
import urllib.error
import json

def fetch_hackertarget(domain: str) -> set:
    """Fallback subdomain finder using HackerTarget API when crt.sh is down or timing out."""
    formatter.info("Attempting secondary fallback via HackerTarget API...")
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0")

    subdomains = set()
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            text = response.read().decode()
            for line in text.splitlines():
                if "," in line:
                    subdomain = line.split(",")[0].strip()
                    if subdomain.endswith(domain):
                        subdomains.add(subdomain)
    except Exception as e:
        formatter.error(f"HackerTarget fallback failed: {e}")
    return subdomains


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
        formatter.info("Using Certificate Transparency logs via crt.sh (HTTPS fallback).")
        formatter.info("Querying crt.sh... (This may take a few seconds)")
        
        url = f"https://crt.sh/?q=%25.{clean_target}&output=json"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")
        
        subdomains = set()
        success = False

        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode())
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for subdomain in name_value.split("\n"):
                        if subdomain.endswith(clean_target):
                            subdomains.add(subdomain.strip())
                success = True
        except TimeoutError:
            formatter.error("crt.sh timed out (database is under heavy load).")
        except urllib.error.HTTPError as e:
            formatter.error(f"crt.sh returned HTTP {e.code} ({e.reason}).")
        except Exception as e:
            formatter.error(f"crt.sh query failed: {e}")

        # If crt.sh failed or returned no results, try HackerTarget fallback
        if not subdomains:
            subdomains = fetch_hackertarget(clean_target)

        if subdomains:
            print(f"\n{formatter.BOLD}[*] Discovered Subdomains ({len(subdomains)} total):{formatter.RESET}")
            for sub in sorted(subdomains):
                formatter.success(sub)
        else:
            formatter.error("No subdomains found from any CT log APIs.")
