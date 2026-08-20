from fpdf import FPDF
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli-multipurpose-plan.pdf")

pdf = FPDF(format="A4")
pdf.set_auto_page_break(auto=True, margin=16)
pdf.set_margins(16, 16, 16)
pdf.add_font("App", "", r"C:\Windows\Fonts\arial.ttf")
pdf.add_font("App", "B", r"C:\Windows\Fonts\arialbd.ttf")
pdf.add_page()

ACCENT = (13, 71, 161)
DARK = (33, 33, 33)
GREY = (80, 80, 80)
LIGHT = (235, 239, 245)

def h1(text):
    pdf.set_font("App", "B", 17)
    pdf.set_text_color(*ACCENT)
    pdf.cell(0, 10, text, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

def h2(text):
    pdf.ln(3)
    pdf.set_font("App", "B", 12.5)
    pdf.set_text_color(*ACCENT)
    pdf.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

def body(text):
    pdf.set_font("App", "", 10)
    pdf.set_text_color(*DARK)
    pdf.multi_cell(0, 5.2, text)
    pdf.ln(1)

def bullet(text):
    pdf.set_font("App", "", 10)
    pdf.set_text_color(*DARK)
    pdf.multi_cell(0, 5.2, "  \u2022  " + text, new_x="LMARGIN")
    pdf.ln(0.5)

def table(headers, rows, widths):
    pdf.set_font("App", "B", 9.5)
    pdf.set_fill_color(*ACCENT)
    pdf.set_text_color(255, 255, 255)
    for i, h in enumerate(headers):
        pdf.cell(widths[i], 7, h, border=0, fill=True, new_x="RIGHT")
    pdf.ln()
    pdf.set_font("App", "", 9)
    pdf.set_text_color(*DARK)
    for r in rows:
        fill = False
        pdf.set_fill_color(*LIGHT)
        for i, c in enumerate(r):
            pdf.cell(widths[i], 6, c, border=0, fill=fill, new_x="RIGHT")
        pdf.ln()

# Title
pdf.set_font("App", "B", 22)
pdf.set_text_color(*ACCENT)
pdf.cell(0, 12, "cli-multipurpose - Development Plan", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("App", "", 10.5)
pdf.set_text_color(*GREY)
pdf.cell(0, 7, "Interactive ethical-hacking helper | Hybrid backends with automatic fallback", new_x="LMARGIN", new_y="NEXT")
pdf.ln(4)

h1("1. Goal")
body("A CLI tool that lets the user select a security/recon tool from an interactive menu, "
     "answer a few prompts, and get results - instead of typing long command lines by hand. "
     "Every module ships TWO backends behind one interface: a native Python implementation "
     "(zero external downloads, works today) and an optional wrapper around a real CLI tool "
     "(nmap, sqlmap, gobuster, ...) used automatically when that tool is installed, e.g. on WSL/Kali.")

h1("2. Architecture")
bullet("Each module exposes: MENU_LABEL (menu text), PROMPTS (list of questions to ask), and run(target, options).")
bullet("run() validates input, then dispatches: if the real tool is available, run_tool(); otherwise run_native().")
bullet("Results are tagged with the backend used: [native] or [nmap].")
bullet("The tool works zero-install today and silently upgrades to full power on systems with the real tools.")
bullet("main.py only knows the module interface - it never touches tool details. Adding a tool = adding one module.")

h1("3. Module Matrix")
table(
    ["Module", "Native backend", "Tool backend (when present)"],
    [
        ["http_headers", "urllib HTTP request", "curl -sIL"],
        ["dns_scanner", "Cloudflare DoH API", "dig / nslookup"],
        ["whois", "RDAP (RFC 7480)", "whois"],
        ["subdomain_enum", "crt.sh certificate log", "subfinder -d"],
        ["port_scanner", "socket + concurrent.futures threaded TCP scan", "nmap -sV"],
        ["web_dir_scan", "requests wordlist brute-force", "gobuster dir"],
        ["sql_detector", "basic error-based payload check", "sqlmap --batch"],
    ],
    [38, 72, 65],
)

h1("4. File Layout")
table(
    ["Path", "Purpose"],
    [
        ["main.py", "Interactive menu loop, registry-driven"],
        ["modules/__init__.py", "REGISTRY dict: name -> module"],
        ["modules/http_headers.py", "HTTP response headers"],
        ["modules/dns_scanner.py", "DNS record lookup"],
        ["modules/whois.py", "Domain registration info"],
        ["modules/subdomain_enum.py", "Subdomain discovery"],
        ["modules/port_scanner.py", "TCP port scanning"],
        ["modules/web_dir_scan.py", "Directory/file brute-force"],
        ["modules/sql_detector.py", "Basic SQLi detection"],
        ["utils/runner.py", "tool_exists / run / first_available (subprocess)"],
        ["utils/validation.py", "validate_target / validate_ports"],
        ["utils/formatter.py", "section / ok / warn / err / table + ANSI colors"],
        ["utils/net.py", "Shared HTTP / DoH / RDAP / crt.sh helpers"],
    ],
    [52, 123],
)

h1("5. Build Order")
steps = [
    "Skeleton - __init__.py files; 'python -c \"import modules, utils\"' passes.",
    "utils/runner.py - tool_exists (shutil.which + cache), run(cmd_list) with arg-list only and NO shell=True, utf-8 decode, exit-code + timeout handling. Test: run(['python','--version']).",
    "utils/validation.py - validate_target (ipaddress, else domain regex), validate_ports (1-65535). Test good + malicious inputs.",
    "utils/formatter.py - section, ok/warn/err/info, table; ANSI codes (needs Windows Terminal).",
    "utils/net.py - urllib helpers: get_json(url) with timeout + error wrapping.",
    "modules/http_headers.py - full dual-backend module; testable NOW (urllib always works, curl exists here). Template for all later modules.",
    "modules/dns_scanner.py - DoH native (testable now), dig/nslookup fallback.",
    "modules/whois.py - RDAP native (testable now), whois fallback.",
    "modules/subdomain_enum.py - crt.sh native (testable now), subfinder fallback.",
    "main.py - registry-driven menu: availability pass, generic PROMPTS rendering, target-confirmation gate, global try/except, 'q' to quit. 4 working modules by now.",
    "port_scanner.py - socket threaded TCP scan native, nmap -sV backend.",
    "web_dir_scan.py - requests brute-force native, gobuster dir backend.",
    "sql_detector.py - error-based detector native, sqlmap backend.",
    "Polish - result tagging, optional --dry-run, README + tool install checklist.",
]
for i, s in enumerate(steps, 1):
    pdf.set_font("App", "B", 10)
    pdf.set_text_color(*ACCENT)
    pdf.cell(7, 5.4, f"{i}.")
    pdf.set_font("App", "", 10)
    pdf.set_text_color(*DARK)
    try:
        pdf.multi_cell(0, 5.4, s, new_x="LMARGIN")
    except Exception as e:
        print("FAIL at step", i, repr(s))
        raise

h1("6. Key Design Decisions")
bullet("One module interface (MENU_LABEL / PROMPTS / run) is what makes the menu trivial and additions trivial.")
bullet("PROMPTS metadata drives the menu generically - adding an option later is editing a list, not menu code.")
bullet("Arg-list subprocess, never shell=True - the injection defense, and cross-platform for free.")
bullet("Respect free APIs (crt.sh / DoH): keep requests modest, always set timeouts.")
bullet("Port scanner is the deliberate weak spot - socket scan reports open/closed only; nmap -sV appears whenever nmap exists.")

h1("7. Verification Strategy")
bullet("Modules http_headers / dns_scanner / whois / subdomain_enum are fully testable on a stock Windows box today.")
bullet("port_scanner / web_dir_scan / sql_detector test the native path locally; the tool path is verified on WSL/Kali.")
bullet("Missing-tool path is a valid test by itself: graceful '[missing: nmap]' messages, never a crash.")
bullet("Only dependency for the zero-install core: pip install requests (and even that is optional - urllib covers everything).")

pdf.output(OUT)
print("Wrote:", OUT)
