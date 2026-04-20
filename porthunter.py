import socket
import threading
import signal
import time
import json
import ipaddress
import os
from queue import Queue, Empty
import argparse

try:
    from pyfiglet import figlet_format
    has_figlet = True
except ImportError:
    has_figlet = False


# colors
RED     = '\033[31m'
GREEN   = '\033[32m'
YELLOW  = '\033[33m'
CYAN    = '\033[36m'
BOLD    = '\033[1m'
RESET   = '\033[0m'

SPINNER = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

# common ports we care about
SERVICES = {
    21:   ("ftp",        "Remote Access"),
    22:   ("ssh",        "Remote Access"),
    23:   ("telnet",     "Remote Access"),
    25:   ("smtp",       "Mail"),
    53:   ("dns",        "Infrastructure"),
    80:   ("http",       "Web"),
    110:  ("pop3",       "Mail"),
    139:  ("netbios",    "Windows"),
    143:  ("imap",       "Mail"),
    443:  ("https",      "Web"),
    445:  ("smb",        "Windows"),
    3306: ("mysql",      "Database"),
    3389: ("rdp",        "Remote Access"),
    5432: ("postgresql", "Database"),
    8080: ("http-alt",   "Web"),
}

TOP_PORTS = list(SERVICES.keys())

# (timeout, retries) — go slower if you don't wanna get caught
TIMING = {
    1: (2.0, 1),
    2: (1.5, 1),
    3: (1.0, 2),
    4: (0.6, 2),
    5: (0.4, 3),
}

stop_scan = False
lock = threading.Lock()
results = {}
q = Queue()


def handle_exit(sig, frame):
    global stop_scan
    stop_scan = True
    print(RED + "\n[!] stopped by user" + RESET)
    exit(0)

signal.signal(signal.SIGINT, handle_exit)


def scan_port(host, port, timeout, retries, grab_banner):
    for _ in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                banner_data = ""
                if grab_banner:
                    try:
                        s.sendall(b"\r\n")
                        banner_data = s.recv(1024).decode(errors="ignore").strip()
                    except:
                        pass
                return True, banner_data
        except:
            pass
    return False, ""


def worker(timeout, retries, grab_banner):
    while not stop_scan:
        try:
            host, port = q.get(timeout=1)
        except Empty:
            return

        is_open, banner_data = scan_port(host, port, timeout, retries, grab_banner)

        if is_open:
            service, category = SERVICES.get(port, ("unknown", "Unknown"))
            if service in ["http", "https"]:
                risk = "LOW"
            elif service in ["ssh", "ftp", "rdp", "smb"]:
                risk = "MEDIUM"
            else:
                risk = "INFO"

            with lock:
                results[host]["open_ports"].append({
                    "port":     port,
                    "service":  service,
                    "category": category,
                    "banner":   banner_data[:60],
                    "risk":     risk,
                })

        q.task_done()


def resolve_targets(target):
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        return [socket.gethostbyname(target)]
    except socket.gaierror:
        print(RED + "[!] can't resolve host" + RESET)
        exit(1)
    except ValueError:
        print(RED + "[!] bad CIDR" + RESET)
        exit(1)


def parse_ports(port_arg, use_top):
    if use_top:
        return TOP_PORTS
    start, end = map(int, port_arg.split("-"))
    return list(range(start, end + 1))


def show_banner():
    os.system("clear")
    if has_figlet:
        print(RED + BOLD + figlet_format("PORTHUNTER", font="slant"))
    else:
        print(RED + BOLD + "=== PORTHUNTER ===" + RESET)
    print(CYAN   + " ─────────────────────────────────────────────")
    print(GREEN  + " Advanced Port Scanner | V1.0")
    print(YELLOW + " By CyberStrom")
    print(CYAN   + " ─────────────────────────────────────────────\n" + RESET)


def print_report(scan_results):
    for host, data in scan_results.items():
        info = data.get("info", {})
        open_ports = data.get("open_ports", [])

        print(CYAN + "═" * 60 + RESET)
        print(BOLD + "HOST REPORT" + RESET)
        print(CYAN + "═" * 60 + RESET)
        print(f"IP Address  : {info.get('ip', host)}")
        print(f"Hostname    : {info.get('hostname', 'N/A')}")
        print(f"IP Version  : {info.get('ip_version', 'IPv4')}")
        print(f"Status      : {info.get('status', 'Up')}")
        print(f"Open Ports  : {len(open_ports)}")
        print(CYAN + "═" * 60 + RESET)

        if not open_ports:
            print(YELLOW + "  no open ports found" + RESET)
            continue

        for p in open_ports:
            risk_color = GREEN if p["risk"] == "LOW" else YELLOW if p["risk"] == "MEDIUM" else CYAN
            print(GREEN + f"\n[+] Port {p['port']}/tcp")
            print(f"    Service   : {p['service']}")
            print(f"    Category  : {p['category']}")
            print(risk_color + f"    Risk      : {p['risk']}" + RESET)
            if p["banner"]:
                print(f"    Banner    : {p['banner']}")


def main():
    show_banner()
    print(YELLOW + "[!] only scan systems you own or have permission to test\n" + RESET)

    parser = argparse.ArgumentParser(add_help=False, prog="porthunter.py")
    parser.add_argument("-H", "--hosts",   required=True)
    parser.add_argument("-p", "--ports",   default="1-1024")
    parser.add_argument("--top",           action="store_true")
    parser.add_argument("-t", "--threads", type=int, default=400)
    parser.add_argument("-T", "--timing",  type=int, choices=range(1, 6), default=3)
    parser.add_argument("-b", "--banner",  action="store_true")
    parser.add_argument("-o", "--output",  help="save to json file")
    parser.add_argument("-h", "--help",    action="help")
    args = parser.parse_args()

    timeout, retries = TIMING[args.timing]
    hosts = resolve_targets(args.hosts)
    ports = parse_ports(args.ports, args.top)
    num_threads = min(args.threads, 600)

    for h in hosts:
        try:
            hostname = socket.gethostbyaddr(h)[0]
        except socket.herror:
            hostname = h
        results[h] = {
            "info": {
                "ip":         h,
                "hostname":   hostname,
                "ip_version": "IPv4",
                "status":     "Up",
            },
            "open_ports": [],
        }

    total = len(hosts) * len(ports)
    for h in hosts:
        for p in ports:
            q.put((h, p))

    start_time = time.time()

    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(timeout, retries, args.banner), daemon=True)
        t.start()

    spin = 0
    while q.unfinished_tasks:
        done = total - q.unfinished_tasks
        print(f"\r{GREEN}{SPINNER[spin % 10]} {done}/{total}{RESET}", end="")
        spin += 1
        time.sleep(0.1)

    q.join()
    elapsed = time.time() - start_time
    print(f"\r{GREEN}done in {elapsed:.2f}s{RESET}           ")

    print_report(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"\n{GREEN}saved to {args.output}{RESET}")


if __name__ == "__main__":
    main()
