import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from tokenize import tabsize
from utils import validation, formatter, runner

ports = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS"
}

def check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def run():
    tardomain = input("Enter target domain or IP address: ").strip()
    clean_target = tardomain.replace("http://", "").replace("https://", "").split("/")[0]

    if not validation.is_valid_target(clean_target):
        formatter.error("Invalid target! Please enter a valid domain or IP address.")
        return

    if runner.tool_available("nmap"):
        formatter.info("Using nmap for port scanning.")
        output = runner.run_tool(["nmap", "-Pn", "-p", ",".join(map(str, ports.keys())), clean_target])
        if output.strip():
            print(output)
        else:
            formatter.error("nmap returned no results.")
    else:
        formatter.info("Using native python socket for port scanning.")
        open_ports = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(check_port, clean_target, port): port for port in ports.keys()}

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    formatter.error(f"Error checking port {port}: {e}")

        if open_ports:
            print("Open ports found:")
            for port in open_ports:
                print(f"  {port}: {ports[port]}")
        else:
            formatter.info("No open ports found.")