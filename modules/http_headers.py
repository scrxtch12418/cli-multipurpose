from utils import validation, runner, formatter

def run():
    target = input("Enter target domain or URL: ").strip()
    
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    if not validation.is_valid_target(clean_target):
        formatter.error("Invalid target!")
        return
 
    url = f"http://{clean_target}"

    if runner.tool_available("curl"):
        print(formatter.info("Using curl for HTTP headers."))
        output = runner.run_tool(["curl", "-sIL", url])
    else:
        print(formatter.info("Using urllib for HTTP headers."))
        import urllib.request
        try:
            with urllib.request.urlopen(url) as response:
                output = "\n".join(f"{k}: {v}" for k, v in response.getheaders())
        except Exception as e:
            output = f"[error] {e}"
    print(output)
