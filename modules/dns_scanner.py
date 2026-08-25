from utils import validation, runner, formatter
import urllib.request
import json
import socket

def run():
    target = input("Enter target domain or URL: ").strip()
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    # DNS records can only be queried for domain names
    if not validation.is_valid_domain(clean_target):
        formatter.error("Please enter a valid domain name (DNS lookups require domains).")
        return

    if runner.tool_available("dig"):
        formatter.info("Using dig for DNS scan.")
        # Querying for ANY record type gets A, MX, NS, TXT etc.
        output = runner.run_tool(["dig", clean_target, "ANY"])
        if output.strip():
            print(output)
        else:
            formatter.error("dig returned no records.")
    else:
        # Fallback: Query Cloudflare's JSON API directly over HTTPS (no dependencies required)
        formatter.info("Using Cloudflare DNS-over-HTTPS API.")
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

        for record_type in record_types:
            url = f"https://cloudflare-dns.com/dns-query?name={clean_target}&type={record_type}"
            headers = {"Accept": "application/dns-json"}
            req = urllib.request.Request(url, headers=headers)

            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    if "Answer" in data:
                        print(f"\n{formatter.BOLD}[*] {record_type} Records:{formatter.RESET}")
                        for answer in data["Answer"]:
                            formatter.success(f"{answer['name']} -> {answer['data']}")
            except (urllib.error.URLError, socket.timeout) as e:
                formatter.error(f"Error fetching {record_type} records: {e}")
