class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log_info(msg): print(f"{Colors.OKCYAN}[*] {msg}{Colors.ENDC}")
def log_success(msg): print(f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}")
def log_warn(msg): print(f"{Colors.WARNING}[!] {msg}{Colors.ENDC}")
def log_error(msg): print(f"{Colors.FAIL}[-] {msg}{Colors.ENDC}")
