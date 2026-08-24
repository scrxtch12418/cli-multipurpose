RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"
CYAN = "\033[96m"
ASCII_ART = f"""{CYAN}
███████╗██╗   ██╗███████╗██████╗ ██╗   ██╗████████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
██╔════╝██║   ██║██╔════╝██╔══██╗╚██╗ ██╔╝╚══██╔══╝██║  ██║██║████╗  ██║██╔════╝ 
█████╗  ██║   ██║█████╗  ██████╔╝ ╚████╔╝    ██║   ███████║██║██╔██╗ ██║██║  ███╗
██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗  ╚██╔╝     ██║   ██╔══██║██║██║╚██╗██║██║   ██║
███████╗ ╚████╔╝ ███████╗██║  ██║   ██║      ██║   ██║  ██║██║██║ ╚████║╚██████╔╝
╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
                                                                                 """

BOLD = "\033[1m"
                                                                                
def tag(msg, tag_type):
    if tag_type == "error":
        return f"{RED}[-]{RESET} {msg}"
    elif tag_type == "success":
        return f"{GREEN}[+]{RESET} {msg}"
    elif tag_type == "info":
        return f"{CYAN}[i]{RESET} {msg}"
    else:
        return msg

def error(msg):
    print(tag(msg, "error"))

def success(msg):
    print(tag(msg, "success"))

def info(msg):
    print(tag(msg, "info"))


def banner(title):
    print(ASCII_ART)    
    print(f"\n{BOLD}{CYAN}{'='*50}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*50}{RESET}\n")

