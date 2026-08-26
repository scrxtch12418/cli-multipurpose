import urllib.request
import urllib.error
import json
from utils import validation, runner, formatter

def run():
    target = input("Enter target domain or URL: ").strip()
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    if not validation.is_valid_domain(clean_target):
        formatter.error("Please enter a valid domain name (WHOIS lookups require domains).")
        return

    if runner.tool_available("whois"):
        formatter.info("Using whois command-line tool.")
        output = runner.run_tool(["whois", clean_target])
        if output.strip():
            print(output)
        else:
            formatter.error("whois returned no information.")
    else:
        formatter.info("Using native RDAP API (HTTPS fallback).")
        url = f"https://rdap.org/domain/{clean_target}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")  # Avoid being blocked
        
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                
                # Print the domain name
                domain_name = data.get("ldhName", clean_target).upper()
                print(f"\n{formatter.BOLD}{formatter.CYAN}--- WHOIS/RDAP: {domain_name} ---{formatter.RESET}\n")
                
                # 1. Get Registrar
                registrar = "Unknown"
                entities = data.get("entities", [])
                for entity in entities:
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        # Find public name in vcardArray
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for prop in vcard[1]:
                                if prop[0] == "fn":
                                    registrar = prop[3]
                                    break
                formatter.success(f"Registrar: {registrar}")
                
                # 2. Get Dates (Creation, Expiry, Last Updated)
                events = data.get("events", [])
                for event in events:
                    action = event.get("eventAction", "")
                    date = event.get("eventDate", "").replace("T", " ").replace("Z", "")
                    
                    if action == "registration":
                        formatter.success(f"Created On: {date}")
                    elif action == "expiration":
                        formatter.success(f"Expires On: {date}")
                    elif action == "last update of rdap database":
                        formatter.info(f"Last Updated: {date}")
                        
                # 3. Get Status
                status = data.get("status", [])
                if status:
                    formatter.info(f"Domain Status: {', '.join(status)}")
                    
        except urllib.error.HTTPError as e:
            if e.code == 404:
                formatter.error("Domain registration not found (may be unregistered or unsupported TLD).")
            else:
                formatter.error(f"RDAP lookup failed with HTTP error: {e.code}")
        except Exception as e:
            formatter.error(f"RDAP lookup failed: {e}")
