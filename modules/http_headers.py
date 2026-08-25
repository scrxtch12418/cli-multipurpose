from utils import validation, runner, formatter
import urllib.request

def analyze_headers(headers_dict: dict):
    """Analyzes a case-insensitive dictionary of HTTP headers and prints a security assessment."""
    print(f"\n{formatter.BOLD}{formatter.CYAN}--- HTTP Headers Security & Tech Analysis ---{formatter.RESET}\n")

    # 1. Server & Technology Headers
    tech_headers = {
        "server": "Server Server Software",
        "x-powered-by": "Application Framework",
        "x-aspnet-version": "ASP.NET Version",
        "x-redirect-by": "Redirected By Tool"
    }
    
    found_tech = False
    for header, label in tech_headers.items():
        if header in headers_dict:
            if not found_tech:
                print(f"{formatter.BOLD}[*] Technology & Server Information:{formatter.RESET}")
                found_tech = True
            formatter.info(f"{label}: {headers_dict[header]}")
    if not found_tech:
        print(f"{formatter.BOLD}[*] Technology & Server Information:{formatter.RESET}")
        formatter.info("No server identification headers disclosed.")
    print()

    # 2. Main Security Headers
    security_headers = {
        "strict-transport-security": "Strict-Transport-Security (HSTS)",
        "content-security-policy": "Content-Security-Policy (CSP)",
        "x-frame-options": "X-Frame-Options (Clickjacking protection)",
        "x-content-type-options": "X-Content-Type-Options (MIME Sniffing protection)",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy (Browser feature controls)",
        "clear-site-data": "Clear-Site-Data"
    }

    print(f"{formatter.BOLD}[*] Security Headers Check:{formatter.RESET}")
    for header, label in security_headers.items():
        if header in headers_dict:
            formatter.success(f"{label}: {headers_dict[header]}")
        else:
            formatter.error(f"{label}: Missing!")
    print()

    # 3. Cookie Security Flags
    # Since headers can have multiple 'Set-Cookie' fields, we search for them
    cookies = headers_dict.get("set-cookie")
    if cookies:
        print(f"{formatter.BOLD}[*] Cookie Security Check:{formatter.RESET}")
        # convert single string or list of cookies into list for iteration
        cookie_list = cookies if isinstance(cookies, list) else [cookies]
        for cookie in cookie_list:
            cookie_clean = cookie.split(";")[0]
            cookie_lower = cookie.lower()
            
            missing_flags = []
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")
                
            if missing_flags:
                formatter.error(f"Cookie '{cookie_clean}' missing: {', '.join(missing_flags)}")
            else:
                formatter.success(f"Cookie '{cookie_clean}' is fully secured (HttpOnly, Secure, SameSite)!")
        print()

    # 4. Cross-Origin Policy (CORS / COEP / COOP)
    cors_headers = {
        "access-control-allow-origin": "Access-Control-Allow-Origin",
        "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy (COEP)",
        "cross-origin-opener-policy": "Cross-Origin-Opener-Policy (COOP)"
    }
    found_cors = False
    for header, label in cors_headers.items():
        if header in headers_dict:
            if not found_cors:
                print(f"{formatter.BOLD}[*] Cross-Origin Security Policies:{formatter.RESET}")
                found_cors = True
            val = headers_dict[header]
            if val == "*":
                formatter.error(f"{label}: '*' (Wildcard is highly permissive!)")
            else:
                formatter.success(f"{label}: {val}")
    if found_cors:
        print()

    # 5. CDN, Proxy & Cache Info
    cdn_headers = {
        "x-cache": "Cache Status",
        "x-cache-lookup": "Cache Lookup Status",
        "via": "Proxy Server Info (Via)",
        "cf-ray": "Cloudflare Ray ID"
    }
    found_cdn = False
    for header, label in cdn_headers.items():
        if header in headers_dict:
            if not found_cdn:
                print(f"{formatter.BOLD}[*] CDN, Proxy & Cache Routing:{formatter.RESET}")
                found_cdn = True
            formatter.info(f"{label}: {headers_dict[header]}")
    if found_cdn:
        print()


def run():
    target = input("Enter target domain or URL: ").strip()
    
    # Strip protocol prefix to get raw domain or IP for validation
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    if not validation.is_valid_target(clean_target):
        formatter.error("Invalid target!")
        return
 
    url = f"http://{clean_target}"
    headers_dict = {}

    if runner.tool_available("curl"):
        formatter.info("Using curl for HTTP headers.")
        output = runner.run_tool(["curl", "-sIL", url])
        
        # Parse curl's flat multiline output block into a case-insensitive dictionary
        for line in output.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower()
                val = val.strip()
                # Handle multiple headers with same name (like Set-Cookie)
                if key in headers_dict:
                    if isinstance(headers_dict[key], list):
                        headers_dict[key].append(val)
                    else:
                        headers_dict[key] = [headers_dict[key], val]
                else:
                    headers_dict[key] = val
    else:
        formatter.info("Using urllib for HTTP headers.")
        try:
            req = urllib.request.Request(url, method="HEAD")
            # Set user agent to avoid default urllib blocks
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            with urllib.request.urlopen(req, timeout=10) as response:
                # Convert response headers to a lowercase dictionary
                for k, v in response.headers.items():
                    key = k.lower()
                    if key in headers_dict:
                        if isinstance(headers_dict[key], list):
                            headers_dict[key].append(v)
                        else:
                            headers_dict[key] = [headers_dict[key], v]
                    else:
                        headers_dict[key] = v
        except Exception as e:
            formatter.error(f"Failed to fetch headers: {e}")
            return

    # Run the security analysis on our standardized headers dictionary
    if headers_dict:
        analyze_headers(headers_dict)
    else:
        formatter.error("No headers collected to analyze.")
